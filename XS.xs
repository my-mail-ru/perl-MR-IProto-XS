#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <iproto.h>

typedef iproto_t * MR__IProto__XS;

static SV *stat_callback = NULL;

static void iprotoxs_stat_callback(const char *key, uint32_t error, const iproto_stat_data_t *data) {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHp(key, strlen(key));
    SV *errsv = newSVuv(error);
    sv_setpv(errsv, iproto_error_string(error));
    SvIOK_on(errsv);
    XPUSHs(sv_2mortal(errsv));
    HV *datahv = newHV();
    hv_store(datahv, "registered", 10, newSViv(data->registered), 0);
    hv_store(datahv, "wallclock", 9, newSVnv(data->wallclock.tv_sec + (data->wallclock.tv_usec / 1000000.)), 0);
    hv_store(datahv, "count", 5, newSVuv(data->count), 0);
    XPUSHs(sv_2mortal(newRV_noinc((SV *)datahv)));
    PUTBACK;
    call_sv(stat_callback, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in statistics' callback: %s", SvPV_nolen(ERRSV));
    }
    FREETMPS;
    LEAVE;
}

static void iprotoxs_servers_set(iproto_shard_t *shard, bool is_replica, AV *config) {
    int cur = 0;
    int pri = 0;
    int has_scalar = 0;
    int has_array = 0;
    for (int i = 0; i <= av_len(config); i++) {
        SV **val = av_fetch(config, i, 0);
        if (SvPOK(*val)) {
            if (has_array) croak("Elements of servers configuration should be either ARRAY references or SCALARs");
            has_scalar = 1;
        } else if (SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV) {
            if (has_scalar) croak("Elements of servers configuration should be either ARRAY references or SCALARs");
            has_array = 1;
        } else {
            croak("Elements of servers configuration should be either ARRAY references or SCALARs");
        }
    }
    if (has_scalar) {
        SV *tmp = newRV_inc((SV*)config);
        config = newAV();
        av_push(config, tmp);
    }

    for (int i = 0; i <= av_len(config); i++) {
        SV **val = av_fetch(config, i, 0);
        AV *list = (AV*)SvRV(*val);
        int size = av_len(list) + 1;
        iproto_server_t **servers;
        Newxz(servers, size, iproto_server_t *);
        for (int j = 0; j < size; j++) {
            char *addr, *del, *host;
            int port;
            SV **val = av_fetch(list, j, 0);
            if (!SvPOK(*val)) croak("Server address should be SCALAR");
            addr = SvPV_nolen(*val);
            del = rindex(addr, ':');
            if (del == NULL) croak("Server address should conform to \"host:port\" format");
            Newxz(host, del - addr + 1, char);
            memcpy(host, addr, del - addr);
            port = atoi(del + 1);
            iproto_server_t *server = iproto_server_init(host, port);
            servers[j] = server;
            Safefree(host);
            cur++;
        }
        iproto_shard_add_servers(shard, is_replica, servers, size);
        for (int j = 0; j < size; j++) {
            iproto_server_free(servers[j]);
        }
        Safefree(servers);
        pri++;
    }
    
    if (has_scalar) av_undef(config);
}

static void iprotoxs_shard_set(iproto_shard_t *shard, HV *config) {
    SV **val = hv_fetch(config, "masters", 7, 0);
    if (!val) croak("Shard configuration should contains \"masters\" section");
    if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV))
        croak("Masters configuration should contain ARRAY reference");
    AV *masters = (AV*)SvRV(*val);
    AV *replicas = NULL;
    if ((val = hv_fetch(config, "replicas", 8, 0))) {
        if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV))
            croak("Replicas configuration should contain ARRAY reference");
        replicas = (AV*)SvRV(*val);
    }
    iprotoxs_servers_set(shard, 0, masters);
    if (replicas) iprotoxs_servers_set(shard, 1, replicas);
}

static void iprotoxs_set_shards(iproto_t *iproto, HV *config) {
    char *key;
    SV *val;
    I32 keylen;
    int maxshard = 0;
    hv_iterinit(config);
    while ((val = hv_iternextsv(config, &key, &keylen))) {
        int n = atoi(key);
        if (n > maxshard) maxshard = n;
    }
    for (int i = 0; i < maxshard; i++) {
        char key[16];
        SV **val;
        snprintf(key, sizeof(key), "%d", i + 1);
        if ((val = hv_fetch(config, key, strlen(key), 0))) {
            if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVHV))
                croak("Shard configuration should be HASH reference");
            iproto_shard_t *shard = iproto_shard_init();
            iprotoxs_shard_set(shard, (HV*)SvRV(*val));
            iproto_add_shard(iproto, shard);
        } else {
            croak("Shard no %s not found in configuration", key);
        }
    }
}

char *iproto_pack_data(HV *opts, STRLEN *length) {
    SV **sv = hv_fetch(opts, "format", 6, 0);
    if (!(sv && SvPOK(*sv)))
        croak("\"format\" should be SCALAR if method \"pack\" is used");
    size_t formatlen;
    char *format = SvPV(*sv, formatlen);
    sv = hv_fetch(opts, "data", 4, 0);
    if (!(SvROK(*sv) && SvTYPE(SvRV(*sv)) == SVt_PVAV))
        croak("\"data\" should be ARRAY reference if method \"pack\" is used");
    AV *data = (AV *)SvRV(*sv);
    size_t size = av_len(data) + 1;
    size_t listsize = size * sizeof(SV *);
    SV **list = av_fetch(data, 0, 0);
    SV *cat = sv_2mortal(newSVpv("", 0));
    SvUTF8_off(cat);
    packlist(cat, format, format + formatlen, list, list + listsize);
    return SvPV(cat, (*length));
}

AV *iprotoxs_unpack_data(HV *opts, char *data, STRLEN length) {
    SV **sv = hv_fetch(opts, "format", 6, 0);
    if (!(sv && SvPOK(*sv)))
        croak("\"format\" should be SCALAR if method \"unpack\" is used");
    size_t formatlen;
    char *format = SvPV(*sv, formatlen);
    dSP;
    ENTER;
    SAVETMPS;
    PUTBACK;
    I32 cnt = unpackstring(format, format + formatlen, data, data + length, 0);
    SPAGAIN;
    AV *result = av_make(cnt, SP - cnt + 1);
    FREETMPS;
    LEAVE;
    return result;
}

iproto_message_t *iproto_hv_to_message(iproto_t *iproto, HV *request) {
    SV **val;
    uint32_t code;
    void *data;
    size_t size;

    val = hv_fetch(request, "code", 4, 0);
    if (!val) croak("\"code\" should be specified");
    if (!SvIOK(*val)) croak("Invalid \"code\" value");
    code = SvUV(*val);

    val = hv_fetch(request, "request", 7, 0);
    if (!val) croak("\"request\" should be specified");
    if (SvPOK(*val)) {
        data = SvPV(*val, size);
    } else if (SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVHV) {
        HV *hv = (HV *)SvRV(*val);
        SV **sv = hv_fetch(hv, "method", 6, 0);
        if (!sv) croak("\"method\" should be specified in \"data\" hash");
        if (!SvPOK(*sv)) croak("\"method\" should be SCALAR");
        char *method = SvPV_nolen(*sv);
        if (strcmp(method, "pack") == 0) {
            data = iproto_pack_data(hv, &size);
        } else {
            croak("invalid \"method\" value");
        }
    } else {
        croak("Invalid \"request\" value");
    }

    iproto_message_t *message = iproto_message_init(code, data, size);
    iproto_message_opts_t *opts = iproto_message_options(message);

    if ((val = hv_fetch(request, "shard_num", 9, 0))) {
        if (!SvIOK(*val)) croak("Invalid \"shard_num\" value: \"%s\"", SvPV_nolen(*val));
        opts->shard_num = SvUV(*val);
    }

    if ((val = hv_fetch(request, "from", 4, 0))) {
        if (!SvPOK(*val)) croak("Invalid \"from\" value");
        char *str = SvPV_nolen(*val);
        if (strcmp(str, "master") == 0) {
            opts->from = FROM_MASTER;
        } else if (strcmp(str, "replica") == 0) {
            opts->from = FROM_REPLICA;
        } else if (strcmp(str, "master,replica") == 0) {
            opts->from = FROM_MASTER_REPLICA;
        } else if (strcmp(str, "replica,master") == 0) {
            opts->from = FROM_REPLICA_MASTER;
        } else {
            croak("Invalid \"from\" value: \"%s\"", str);
        }
    }

    if ((val = hv_fetch(request, "early_retry", 11, 0))) {
        opts->early_retry = SvTRUE(*val);
    }

    return message;
}

HV *iproto_message_to_hv(iproto_t *iproto, iproto_message_t *message, HV *request) {
    if (!message) return NULL;
    iproto_error_t error = iproto_message_error(message);
    SV *errsv = newSVuv(error);
    sv_setpv(errsv, iproto_error_string(error));
    SvIOK_on(errsv);
    HV *result = newHV();
    if (error == ERR_CODE_OK) {
        bool replica;
        size_t size;
        void *data = iproto_message_response(message, &size, &replica);
        if (replica)
            hv_store(result, "replica", 7, &PL_sv_yes, 0);

        SV *datasv;
        SV **val;
        if ((val = hv_fetch(request, "response", 8, 0))) {
            if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVHV)) croak("Invalid \"response\" value");
            HV *hv = (HV *)SvRV(*val);
            SV **sv = hv_fetch(hv, "method", 6, 0);
            if (!sv) croak("\"method\" should be specified in \"response\" hash");
            if (!SvPOK(*sv)) croak("\"method\" should be SCALAR");
            char *method = SvPV_nolen(*sv);
            if (strcmp(method, "unpack") == 0) {
                datasv = newRV_noinc((SV *)iprotoxs_unpack_data(hv, data, size));
            } else {
                croak("invalid \"method\" value");
            }
        } else {
            datasv = newSVpv(data, size);
        }
        hv_store(result, "data", 4, datasv, 0);
    }
    hv_store(result, "error", 5, errsv, 0);
    iproto_message_free(message);
    return result;
}

MODULE = MR::IProto::XS		PACKAGE = MR::IProto::XS		PREFIX = ixs_

PROTOTYPES: ENABLE

BOOT:
    HV *stash = gv_stashpv("MR::IProto::XS", 1);
#define IPROTOXS_CONST(s, ...) newCONSTSUB(stash, #s, newSVuv(s));
    IPROTOXS_CONST(ERR_CODE_OK);
    LIBIPROTO_ERROR_CODES(IPROTOXS_CONST);
    IPROTO_ERROR_CODES(IPROTOXS_CONST);
    IPROTO_LOGMASK(IPROTOXS_CONST);
#undef IPROTOXS_CONST

MR::IProto::XS
ixs_new(klass, ...)
    PREINIT:
        HV *shards_config = NULL;
        int emulate_shards = 0;
    CODE:
        if (items % 2 == 0) croak("Odd number of elements in hash assignment");
        for (int i = 1; i < items; i += 2) {
            char *key = SvPV_nolen(ST(i));
            SV *value = ST(i + 1);
            if (strcmp(key, "shards") == 0) {
                if (!(SvROK(value) && SvTYPE(SvRV(value)) == SVt_PVHV)) croak("Argument \"shards\" should be HASH reference");
                if (shards_config) {
                    hv_undef(shards_config);
                    croak("Only one argument \"shards\" or \"masters\" could be specified");
                }
                shards_config = (HV*)SvRV(value);
            } else if (strcmp(key, "masters") == 0 || strcmp(key, "replicas") == 0) {
                SV **elem;
                if (!shards_config) {
                    HV *shard_config = newHV();
                    shards_config = newHV();
                    hv_store(shards_config, "1", 1, newRV_inc((SV*)shard_config), 0);
                    emulate_shards = 1;
                } else if (!emulate_shards) {
                    croak("Only one argument \"shards\" or \"%s\" could be specified", key);
                }
                elem = hv_fetch(shards_config, "1", 1, 0);
                if (!elem) croak("Impossible");
                hv_store((HV*)SvRV(*elem), key, strlen(key), SvREFCNT_inc(value), 0);
            }
        }
        if (!shards_config) croak("Argument \"shards\" or \"masters\" should be specified");
        RETVAL = iproto_init();
        iprotoxs_set_shards(RETVAL, shards_config);
        if (emulate_shards) hv_undef(shards_config);
    OUTPUT:
        RETVAL

void
ixs_DESTROY(iproto)
        MR::IProto::XS iproto
    CODE:
        iproto_free(iproto);

AV *
ixs_bulk(iproto, list)
        MR::IProto::XS iproto
        AV *list
    CODE:
        int nmessages = av_len(list) + 1;
        iproto_message_t **messages;
        Newx(messages, nmessages, iproto_message_t *);
        for (int i = 0; i < nmessages; i++) {
            SV **sv = av_fetch(list, i, 0);
            if (!(sv && SvROK(*sv) && SvTYPE(SvRV(*sv)) == SVt_PVHV))
                croak("Messages should be HASH references");
            messages[i] = iproto_hv_to_message(iproto, (HV *)SvRV(*sv));
        }
        iproto_bulk(iproto, messages, nmessages, NULL);
        RETVAL = newAV();
        for (int i = 0; i < nmessages; i++) {
            SV **sv = av_fetch(list, i, 0);
            av_push(RETVAL, newRV_noinc((SV*)iproto_message_to_hv(iproto, messages[i], (HV *)SvRV(*sv))));
        }
        sv_2mortal((SV*)RETVAL);
        Safefree(messages);
    OUTPUT:
        RETVAL

HV *
ixs_do(iproto, request)
        MR::IProto::XS iproto
        HV *request
    CODE:
        iproto_message_t *message = iproto_hv_to_message(iproto, request);
        iproto_do(iproto, message, NULL);
        RETVAL = (HV *)sv_2mortal((SV *)iproto_message_to_hv(iproto, message, request));
    OUTPUT:
        RETVAL

void
ixs_set_logmask(klass, mask)
        unsigned mask
    CODE:
        iproto_set_logmask(mask);

#ifdef WITH_GRAPHITE

SV *
ixs_set_graphite(klass, host, port, prefix)
        char *host
        short port
        char *prefix
    CODE:
        RETVAL = iproto_stat_graphite_set(host, port, prefix) == ERR_CODE_OK ? &PL_sv_yes : &PL_sv_no;
    OUTPUT:
        RETVAL

#endif

void
ixs_set_stat_flush_interval(klass, interval)
        time_t interval
    CODE:
        iproto_stat_set_flush_interval(interval);

void
ixs_set_stat_callback(klass, callback)
        SV *callback
    CODE:
        if (callback == NULL) {
            SvREFCNT_dec(stat_callback);
            stat_callback = NULL;
            iproto_stat_set_callback(NULL);
        } else if (stat_callback == NULL) {
            stat_callback = newSVsv(callback);
            iproto_stat_set_callback(iprotoxs_stat_callback);
        } else {
            SvSetSV(stat_callback, callback);
        }
