#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <iprotocluster.h>
#include "iprotoxs.h"

#define MY_CXT_KEY "MR::IProto::XS::_guts" XS_VERSION

typedef struct {
    HV *singletons;
    SV *stat_callback;
    HV *soft_retry_callbacks;
    CV *unpack;
} my_cxt_t;

START_MY_CXT;

typedef SV * MR__IProto__XS;

static void iprotoxs_stat_callback(const char *type, const char *server, uint32_t error, const iproto_stat_data_t *data) {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHp(type, strlen(type));
    if (server) mXPUSHp(server, strlen(server));
    else XPUSHs(&PL_sv_undef);
    SV *errsv = newSVuv(error);
    sv_setpv(errsv, iproto_error_string(error));
    SvIOK_on(errsv);
    mXPUSHs(errsv);
    HV *datahv = newHV();
    hv_store(datahv, "registered", 10, newSViv(data->registered), 0);
    hv_store(datahv, "wallclock", 9, newSVnv(data->wallclock.tv_sec + (data->wallclock.tv_usec / 1000000.)), 0);
    hv_store(datahv, "count", 5, newSVuv(data->count), 0);
    mXPUSHs(newRV_noinc((SV *)datahv));
    PUTBACK;
    dMY_CXT;
    call_sv(MY_CXT.stat_callback, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in statistics' callback: %s", SvPV_nolen(ERRSV));
    }
    FREETMPS;
    LEAVE;
}

static bool iprotoxs_soft_retry_callback(iproto_message_t *message) {
    dMY_CXT;
    SV **val = hv_fetch(MY_CXT.soft_retry_callbacks, (char *)&message, sizeof(message), 0);
    if (!val) return false;
    SV *callback = SvRV(*val);
    size_t size;
    bool replica;
    void *data = iproto_message_response(message, &size, &replica);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHp(data, size);
    PUTBACK;
    call_sv(callback, G_EVAL|G_SCALAR);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in soft_retry callback: %s", SvPV_nolen(ERRSV));
    }
    bool result = SvTRUEx(POPs);
    PUTBACK;
    FREETMPS;
    LEAVE;
    return result;
}

static void iprotoxs_servers_set(iproto_shard_t *shard, bool is_replica, AV *config) {
    int cur = 0;
    int pri = 0;
    int has_scalar = 0;
    int has_array = 0;
    for (int i = 0; i <= av_len(config); i++) {
        SV **val = av_fetch(config, i, 0);
        if (SvPOK(*val)) {
            if (has_array) croak("Elements of servers configuration should be either ARRAYREFs or SCALARs");
            has_scalar = 1;
        } else if (SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV) {
            if (has_scalar) croak("Elements of servers configuration should be either ARRAYREFs or SCALARs");
            has_array = 1;
        } else {
            croak("Elements of servers configuration should be either ARRAYREFs or SCALARs");
        }
    }
    if (has_scalar) {
        SV *tmp = newRV_inc((SV*)config);
        config = (AV *)sv_2mortal((SV *)newAV());
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
            if (!SvPOK(*val)) croak("Server address should be a SCALAR");
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
}

static void iprotoxs_shard_set(iproto_shard_t *shard, HV *config) {
    SV **val = hv_fetch(config, "masters", 7, 0);
    if (!val) croak("Shard configuration should contain \"masters\" section");
    if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV))
        croak("Masters configuration should be an ARRAYREF");
    AV *masters = (AV*)SvRV(*val);
    AV *replicas = NULL;
    if ((val = hv_fetch(config, "replicas", 8, 0))) {
        if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV))
            croak("Replicas configuration should be an ARRAYREF");
        replicas = (AV*)SvRV(*val);
    }
    iprotoxs_servers_set(shard, 0, masters);
    if (replicas) iprotoxs_servers_set(shard, 1, replicas);
}

static void iprotoxs_cluster_set_shards(iproto_cluster_t *cluster, HV *config) {
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
                croak("Shard configuration should be a HASHREF");
            iproto_shard_t *shard = iproto_shard_init();
            iprotoxs_shard_set(shard, (HV*)SvRV(*val));
            iproto_cluster_add_shard(cluster, shard);
        } else {
            croak("Shard no %s not found in configuration", key);
        }
    }
}

static XS(iprotoxs_unpack_wrapper) {
    dXSARGS;
    SP -= items;
    SV* pattern = ST(0);
    SV* string = ST(1);
    STRLEN plen;
    STRLEN slen;
    const char *pat = SvPV_const(pattern,  plen);
    const char *s   = SvPV_const(string, slen);
    const char *strend = s + slen;
    const char *patend = pat + plen;
    PUTBACK;
    unpackstring((char *)pat, (char *)patend, (char *)s, (char *)strend, 0);
    return;
}

char *iprotoxs_pack_data(HV *opts, STRLEN *length) {
    SV **sv = hv_fetch(opts, "format", 6, 0);
    if (!(sv && SvPOK(*sv)))
        croak("\"format\" should be a SCALAR if method \"pack\" is used");
    size_t formatlen;
    char *format = SvPV(*sv, formatlen);
    sv = hv_fetch(opts, "data", 4, 0);
    if (!(SvROK(*sv) && SvTYPE(SvRV(*sv)) == SVt_PVAV))
        croak("\"data\" should be an ARRAYREF if method \"pack\" is used");
    AV *data = (AV *)SvRV(*sv);
    SV **list = av_fetch(data, 0, 0);
    size_t listlen = av_len(data) + 1;
    SV *cat = sv_2mortal(newSVpv("", 0));
    SvUTF8_off(cat);
    packlist(cat, format, format + formatlen, list, list + listlen);
    return SvPV(cat, (*length));
}

AV *iprotoxs_unpack_data(HV *opts, char *data, STRLEN length, SV *errsv) {
    SV **sv = hv_fetch(opts, "format", 6, 0);
    if (!(sv && SvPOK(*sv)))
        croak("\"format\" should be a SCALAR if method \"unpack\" is used");
    /* We should use G_EVAL, so can't use unpackstring() function directly */
    SV *format = *sv;
    if (data == NULL && SvCUR(format) != 0) {
        sv_setuv(errsv, ERR_CODE_PROTO_ERR);
        sv_setpvf(errsv, "Response data is empty, should be '%s'", SvPV_nolen(format));
        SvIOK_on(errsv);
        return NULL;
    }
    dSP;
    dMY_CXT;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(format);
    XPUSHs(sv_2mortal(newSVpvn(data, length)));
    PUTBACK;
    I32 cnt = call_sv((SV *)MY_CXT.unpack, G_ARRAY | G_EVAL);
    SPAGAIN;
    AV *result;
    if (SvTRUE(ERRSV)) {
        result = NULL;
        STRLEN errlen;
        char *err = SvPV(ERRSV, errlen);
        char *last = NULL;
        char *at = err;
        while ((at = strstr(at + 1, " at ")))
            last = at;
        if (last)
            errlen = last - err;
        sv_setuv(errsv, ERR_CODE_PROTO_ERR);
        sv_setpv(errsv, "Failed to unpack response data: ");
        sv_catpvn(errsv, err, errlen);
        SvIOK_on(errsv);
    } else {
        result = av_make(cnt, SP - cnt + 1);
    }
    FREETMPS;
    LEAVE;
    return result;
}

void iprotoxs_timeval_set(SV *sv, struct timeval *timeout) {
    if (SvIOK(sv)) {
        timeout->tv_sec = SvIV(sv);
        timeout->tv_usec = 0;
    } else if (SvNOK(sv) || looks_like_number(sv)) {
        NV to = SvNV(sv);
        timeout->tv_sec = floor(to);
        timeout->tv_usec = floor((to - timeout->tv_sec) * 1000000);
    } else {
        croak("\"timeout\" should be a number or an integer");
    }
}

void iprotoxs_parse_opts(iproto_message_opts_t *opts, HV *request) {
    SV **val;

    if ((val = hv_fetch(request, "shard_num", 9, 0))) {
        if (!(SvIOK(*val) || looks_like_number(*val)))
            croak("Invalid \"shard_num\" value: \"%s\"", SvPV_nolen(*val));
        opts->shard_num = SvUV(*val);
    }

    if ((val = hv_fetch(request, "from", 4, 0))) {
        if (!SvPOK(*val)) croak("invalid \"from\" value");
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
            croak("invalid \"from\" value: \"%s\"", str);
        }
    }

    if ((val = hv_fetch(request, "timeout", 7, 0))) {
        iprotoxs_timeval_set(*val, &opts->timeout);
    }

    if ((val = hv_fetch(request, "early_retry", 11, 0))) {
        if (SvTRUE(*val)) {
            opts->retry |= RETRY_EARLY;
        } else {
            opts->retry &= ~RETRY_EARLY;
        }
    }

    if ((val = hv_fetch(request, "safe_retry", 10, 0))) {
        if (SvTRUE(*val)) {
            opts->retry |= RETRY_SAFE;
        } else {
            opts->retry &= ~RETRY_SAFE;
        }
    }

    if ((val = hv_fetch(request, "retry_same", 10, 0))) {
        if (SvTRUE(*val)) {
            opts->retry |= RETRY_SAME;
        } else {
            opts->retry &= ~RETRY_SAME;
        }
    }

    if ((val = hv_fetch(request, "max_tries", 9, 0))) {
        if (!(SvIOK(*val) || looks_like_number(*val)))
            croak("\"max_tries\" should be an integer");
        opts->max_tries = SvIV(*val);
    }
}

iproto_message_t *iprotoxs_hv_to_message(HV *request) {
    SV **val;
    uint32_t code;
    void *data;
    size_t size;

    val = hv_fetch(request, "code", 4, 0);
    if (!val) croak("\"code\" should be specified");
    if (!(SvIOK(*val) || looks_like_number(*val)))
        croak("Invalid \"code\" value");
    code = SvUV(*val);

    val = hv_fetch(request, "request", 7, 0);
    if (!val) croak("\"request\" should be specified");
    if (SvPOK(*val)) {
        data = SvPV(*val, size);
    } else if (SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVHV) {
        HV *hv = (HV *)SvRV(*val);
        SV **sv = hv_fetch(hv, "method", 6, 0);
        if (!sv) croak("\"method\" should be specified in \"data\" hash");
        if (!SvPOK(*sv)) croak("\"method\" should be a SCALAR");
        char *method = SvPV_nolen(*sv);
        if (strcmp(method, "pack") == 0) {
            data = iprotoxs_pack_data(hv, &size);
        } else {
            croak("invalid \"method\" value");
        }
    } else {
        croak("invalid \"request\" value");
    }

    iproto_message_t *message = iproto_message_init(code, data, size);
    iproto_message_opts_t *opts = iproto_message_options(message);
    iprotoxs_parse_opts(opts, request);

    if ((val = hv_fetch(request, "soft_retry_callback", 19, 0))) {
        if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVCV))
            croak("\"soft_retry_callback\" should be a CODEREF");
        opts->soft_retry_callback = iprotoxs_soft_retry_callback;
        dMY_CXT;
        hv_store(MY_CXT.soft_retry_callbacks, (char *)&message, sizeof(message), SvREFCNT_inc(*val), 0);
    }

    return message;
}

HV *iprotoxs_message_to_hv(iproto_message_t *message, HV *request) {
    iproto_error_t error = iproto_message_error(message);
    SV *errsv = newSVuv(error);
    sv_setpv(errsv, iproto_error_string(error));
    SvIOK_on(errsv);
    SV **val = hv_fetch(request, "inplace", 7, 0);
    HV *result = val && SvTRUE(*val) ? (HV *)SvREFCNT_inc((SV *)request) : newHV();
    if (error == ERR_CODE_OK) {
        bool replica;
        size_t size;
        void *data = iproto_message_response(message, &size, &replica);
        if (replica)
            hv_store(result, "replica", 7, &PL_sv_yes, 0);

        SV *datasv;
        SV **val;
        if ((val = hv_fetch(request, "response", 8, 0))) {
            if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVHV)) croak("invalid \"response\" value");
            HV *hv = (HV *)SvRV(*val);
            SV **sv = hv_fetch(hv, "method", 6, 0);
            if (!sv) croak("\"method\" should be specified in \"response\" hash");
            if (!SvPOK(*sv)) croak("\"method\" should be SCALAR");
            char *method = SvPV_nolen(*sv);
            if (strcmp(method, "unpack") == 0) {
                AV *dataav = iprotoxs_unpack_data(hv, data, size, errsv);
                datasv = dataav ? newRV_noinc((SV *)dataav) : NULL;
            } else {
                croak("invalid \"method\" value");
            }
        } else {
            datasv = newSVpvn(data, size);
        }
        if (datasv)
            hv_store(result, "data", 4, datasv, 0);
    }
    hv_store(result, "error", 5, errsv, 0);
    iproto_message_free(message);
    return result;
}

MODULE = MR::IProto::XS		PACKAGE = MR::IProto::XS		PREFIX = ixs_

PROTOTYPES: ENABLE

BOOT:
    iproto_initialize();
    HV *stash = gv_stashpv("MR::IProto::XS", 1);
#define IPROTOXS_CONST(s, ...) newCONSTSUB(stash, #s, newSVuv(s));
    IPROTOXS_CONST(ERR_CODE_OK);
    LIBIPROTO_ERROR_CODES(IPROTOXS_CONST);
    IPROTO_ERROR_CODES(IPROTOXS_CONST);
    IPROTO_LOGMASK(IPROTOXS_CONST);
#undef IPROTOXS_CONST
    MY_CXT_INIT;
    MY_CXT.singletons = newHV();
    MY_CXT.stat_callback = NULL;
    MY_CXT.soft_retry_callbacks = newHV();
    MY_CXT.unpack = newXSproto_portable(NULL, iprotoxs_unpack_wrapper, __FILE__, "$$");

MR::IProto::XS
ixs_new(klass, ...)
        SV *klass
    ALIAS:
        create_singleton = 1
    PREINIT:
        HV *shards_config = NULL;
        bool implicit_shard = false;
    CODE:
        if (items % 2 == 0)
            croak("Odd number of elements in hash assignment");
        for (int i = 1; i < items; i += 2) {
            char *key = SvPV_nolen(ST(i));
            SV *value = ST(i + 1);
            if (strcmp(key, "shards") == 0) {
                if (!(SvROK(value) && SvTYPE(SvRV(value)) == SVt_PVHV))
                    croak("Argument \"shards\" should be a HASHREF");
                if (shards_config)
                    croak("Only one argument \"shards\" or \"masters\" could be specified");
                shards_config = (HV*)SvRV(value);
            } else if (strcmp(key, "masters") == 0 || strcmp(key, "replicas") == 0) {
                SV **elem;
                if (!shards_config) {
                    HV *shard_config = newHV();
                    shards_config = (HV *)sv_2mortal((SV *)newHV());
                    hv_store(shards_config, "1", 1, newRV_noinc((SV*)shard_config), 0);
                    implicit_shard = true;
                } else if (!implicit_shard) {
                    croak("Only one argument \"shards\" or \"%s\" could be specified", key);
                }
                elem = hv_fetch(shards_config, "1", 1, 0);
                if (!elem) croak("Impossible");
                hv_store((HV*)SvRV(*elem), key, strlen(key), SvREFCNT_inc(value), 0);
            }
        }
        if (!shards_config)
            croak("Argument \"shards\" or \"masters\" should be specified");
        iproto_cluster_t *cluster = iproto_cluster_init();
        iprotoxs_cluster_set_shards(cluster, shards_config);
        RETVAL = newSV(0);
        sv_setref_pv(RETVAL, SvPV_nolen(klass), cluster);
        if (ix == 1) {
            dMY_CXT;
            if (hv_exists_ent(MY_CXT.singletons, klass, 0))
                croak("singleton %s already initialized", SvPV_nolen(klass));
            hv_store_ent(MY_CXT.singletons, klass, SvREFCNT_inc(RETVAL), 0);
        }
    OUTPUT:
        RETVAL

void
ixs_DESTROY(iprotoxs)
        MR::IProto::XS iprotoxs
    CODE:
        if (singleton_call)
            croak("DESTROY is called as a class method");
        iproto_cluster_free(cluster);

MR::IProto::XS
ixs_remove_singleton(klass)
        SV *klass
    CODE:
        dMY_CXT;
        RETVAL = SvREFCNT_inc(hv_delete_ent(MY_CXT.singletons, klass, 0, 0));
    OUTPUT:
        RETVAL

AV *
ixs_bulk(iprotoxs, list, ...)
        MR::IProto::XS iprotoxs
        AV *list
    CODE:
        iprotoxs_call_timeout(timeout, 2);
        int nmessages = av_len(list) + 1;
        iproto_message_t **messages;
        Newx(messages, nmessages, iproto_message_t *);
        for (int i = 0; i < nmessages; i++) {
            SV **sv = av_fetch(list, i, 0);
            if (!(sv && SvROK(*sv) && SvTYPE(SvRV(*sv)) == SVt_PVHV))
                croak("Messages should be HASH references");
            messages[i] = iprotoxs_hv_to_message((HV *)SvRV(*sv));
        }
        iproto_cluster_bulk(cluster, messages, nmessages, timeout);
        RETVAL = newAV();
        for (int i = 0; i < nmessages; i++) {
            SV **sv = av_fetch(list, i, 0);
            av_push(RETVAL, newRV_noinc((SV*)iprotoxs_message_to_hv(messages[i], (HV *)SvRV(*sv))));
        }
        sv_2mortal((SV*)RETVAL);
        Safefree(messages);
        dMY_CXT;
        hv_clear(MY_CXT.soft_retry_callbacks);
    OUTPUT:
        RETVAL

HV *
ixs_do(iprotoxs, request, ...)
        MR::IProto::XS iprotoxs
        HV *request
    CODE:
        iprotoxs_call_timeout(timeout, 2);
        iproto_message_t *message = iprotoxs_hv_to_message(request);
        iproto_cluster_do(cluster, message, timeout);
        RETVAL = (HV *)sv_2mortal((SV *)iprotoxs_message_to_hv(message, request));
        dMY_CXT;
        hv_clear(MY_CXT.soft_retry_callbacks);
    OUTPUT:
        RETVAL

void
ixs_set_logmask(klass, mask)
        unsigned mask
    CODE:
        iproto_set_logmask(mask);

MODULE = MR::IProto::XS		PACKAGE = MR::IProto::XS::Stat		PREFIX = ixs_stat_

#ifdef WITH_GRAPHITE

bool
ixs_stat_set_graphite(klass, host, port, prefix)
        char *host
        short port
        char *prefix
    CODE:
        RETVAL = iproto_stat_graphite_set(host, port, prefix) == ERR_CODE_OK;
    OUTPUT:
        RETVAL

#endif

void
ixs_stat_set_flush_interval(klass, interval)
        time_t interval
    CODE:
        iproto_stat_set_flush_interval(interval);

void
ixs_stat_set_callback(klass, callback)
        SV *callback
    CODE:
        dMY_CXT;
        if (callback == NULL) {
            SvREFCNT_dec(MY_CXT.stat_callback);
            MY_CXT.stat_callback = NULL;
            iproto_stat_set_callback(NULL);
        } else if (MY_CXT.stat_callback == NULL) {
            MY_CXT.stat_callback = newSVsv(callback);
            iproto_stat_set_callback(iprotoxs_stat_callback);
        } else {
            SvSetSV(MY_CXT.stat_callback, callback);
        }

void
ixs_stat_flush(klass)
    CODE:
        iproto_stat_flush();

void
ixs_stat_END()
    CODE:
        iproto_stat_flush();
