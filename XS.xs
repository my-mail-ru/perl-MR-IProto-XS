#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <EVAPI.h>
#include <CoroAPI.h>

#include <iprotocluster.h>
#include <iproto_evapi.h>
#include "iprotoxs.h"

static void xev_iproto_run(struct ev_loop *loop, void **data) {
    ev_run(loop, 0);
}

static void xev_iproto_ready(struct ev_loop *loop, void *data) {
    ev_break(loop, EVBREAK_ONE);
}

static ev_io *xev_io_new(void (*cb)(struct ev_loop *, ev_io *, int)) {
    ev_io *io = malloc(sizeof(*io));
    ev_init(io, cb);
    return io;
}

static void xev_io_free(ev_io *io) {
    free(io);
}

static void xev_io_set(ev_io *io, int fd, int events) {
    ev_io_set(io, fd, events);
}

static void xev_io_get(ev_io *io, int *fd, int *events) {
    *fd = io->fd;
    *events = io->events;
}

static void xev_io_set_data(ev_io *io, void *data) {
    io->data = data;
}

static void *xev_io_data(ev_io *io) {
    return io->data;
}

static ev_timer *xev_timer_new(void (*cb)(struct ev_loop *, ev_timer *, int)) {
    ev_timer *timer = malloc(sizeof(*timer));
    ev_init(timer, cb);
    return timer;
}

static void xev_timer_free(ev_timer *timer) {
    free(timer);
}

static void xev_timer_set(ev_timer *timer, ev_tstamp after, ev_tstamp repeat) {
    ev_timer_set(timer, after, repeat);
}

static void xev_timer_set_data(ev_timer *timer, void *data) {
    timer->data = data;
}

static void *xev_timer_data(ev_timer *timer) {
    return timer->data;
}

static void xev_timer_set_priority(ev_timer *timer, int priority) {
    ev_set_priority(timer, priority);
}

#ifdef ev_depth
# undef ev_depth
# define ev_depth(loop) GEVAPI->depth ((loop))
#endif

static void xevev_iproto_run(struct ev_loop *loop, void **data) {
    if (ev_depth(loop) > 0)
        croak("MR::IProto::XS FATAL: did you try to block inside an event loop callback? Caught");
    ev_run(loop, 0);
}

static void xevev_iproto_ready(struct ev_loop *loop, void *data) {
    ev_break(loop, EVBREAK_ONE);
}

#define MY_CXT_KEY "MR::IProto::XS::_guts" XS_VERSION

typedef enum { ENGINE_UNINITIALIZED, ENGINE_INTERNAL, ENGINE_EV, ENGINE_CORO } iprotoxs_engine_t;

typedef struct {
    HV *singletons;
    SV *stat_callback;
    CV *unpack;
    SV *logfunc;
    iprotoxs_engine_t engine;
    struct {
        struct ev_loop *loop;
    } internal;
    struct {
        SV *loop_coro;
        ev_prepare prepare;
    } coro;
} my_cxt_t;

START_MY_CXT;

typedef struct {
    SV *coro;
    bool ready;
} xcoro_state_t;

static void xcoro_iproto_run(struct ev_loop *loop, void **data) {
    dMY_CXT;
    if (CORO_CURRENT == MY_CXT.coro.loop_coro) {
        croak("MR::IProto::XS FATAL: did you try to block inside an event loop callback? Caught");
    }
    xcoro_state_t state;
    state.coro = SvREFCNT_inc(CORO_CURRENT);
    state.ready = false;
    *data = &state;
    while (!state.ready)
        CORO_SCHEDULE;
    SvREFCNT_dec(state.coro);
}

static void xcoro_iproto_ready(struct ev_loop *loop, void *data) {
    xcoro_state_t *state = (xcoro_state_t *)data;
    state->ready = true;
    CORO_READY(state->coro);
}

static void xcoro_prepare_cb(EV_P_ ev_prepare *w, int revents) {
    dMY_CXT;
    MY_CXT.coro.loop_coro = CORO_CURRENT;
}

typedef SV * MR__IProto__XS;
typedef SV * EV__Loop;

typedef struct {
    SV *callback;
    SV *soft_retry_callback;
    HV *request;
    SV *data;
} iprotoxs_data_t;

HV *iprotoxs_message_to_hv(iproto_message_t *message, HV *request);

static void iprotoxs_logfunc_warn(iproto_logmask_t mask, const char *str) {
    char *level;
    switch (mask & LOG_LEVEL) {
        case LOG_ERROR:   level = "error";   break;
        case LOG_WARNING: level = "warning"; break;
        case LOG_INFO:    level = "info";    break;
        case LOG_DEBUG:   level = "debug";   break;
        default:          level = "unknown";
    }
    warn("%s: %s\n", level, str);
}

static void iprotoxs_logfunc_call(iproto_logmask_t mask, const char *str) {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHu(mask);
    mXPUSHp(str, strlen(str));
    PUTBACK;
    dMY_CXT;
    call_sv(MY_CXT.logfunc, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in logfunc's callback: %s", SvPV_nolen(ERRSV));
        iprotoxs_logfunc_warn(mask, str);
    }
    FREETMPS;
    LEAVE;
}

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
    (void)hv_store(datahv, "registered", 10, newSViv(data->registered), 0);
    (void)hv_store(datahv, "wallclock", 9, newSVnv(data->wallclock.tv_sec + (data->wallclock.tv_usec / 1000000.)), 0);
    (void)hv_store(datahv, "count", 5, newSVuv(data->count), 0);
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

static void iprotoxs_callback(iproto_message_t *message) {
    iprotoxs_data_t *data = (iprotoxs_data_t *)iproto_message_options(message)->data;
    SV *callback = SvREFCNT_inc(data->callback);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHs(newRV_noinc((SV *)iprotoxs_message_to_hv(message, data->request)));
    PUTBACK;
    call_sv(callback, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in callback: %s", SvPV_nolen(ERRSV));
    }
    FREETMPS;
    LEAVE;
    SvREFCNT_dec(callback);
}

static bool iprotoxs_soft_retry_callback(iproto_message_t *message) {
    SV *callback = ((iprotoxs_data_t *)iproto_message_options(message)->data)->soft_retry_callback;
    if (!callback) return false;
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

static void iprotoxs_set_engine(iprotoxs_engine_t engine) {
    dMY_CXT;
    if (engine == MY_CXT.engine)
        return;
    switch (MY_CXT.engine) {
        case ENGINE_INTERNAL:
            ev_loop_destroy(MY_CXT.internal.loop);
            break;
        case ENGINE_CORO:
            ev_prepare_stop(EV_DEFAULT, &MY_CXT.coro.prepare);
            break;
        default:
            break;
    }
    switch (engine) {
        case ENGINE_INTERNAL:
            MY_CXT.internal.loop = ev_loop_new(0);
            break;
        case ENGINE_CORO:
            load_module(0, newSVpvn("Coro::EV", 8), NULL, NULL);
            I_CORO_API("MR::IProto::XS");
            ev_prepare_init(&MY_CXT.coro.prepare, xcoro_prepare_cb);
            ev_set_priority(&MY_CXT.coro.prepare, EV_MAXPRI);
            ev_prepare_start(EV_DEFAULT, &MY_CXT.coro.prepare);
            break;
        default:
            break;
    }
    MY_CXT.engine = engine;
    iproto_evapi_t iproto_evapi = {
        .version = IPROTO_EVAPI_VERSION,
        .revision = IPROTO_EVAPI_REVISION,
        .loop = engine == ENGINE_INTERNAL ? MY_CXT.internal.loop : EV_DEFAULT,
        .loop_fork = GEVAPI->loop_fork,
        .now_update = GEVAPI->now_update,
        .iproto_run = engine == ENGINE_CORO ? xcoro_iproto_run : engine == ENGINE_INTERNAL ? xev_iproto_run : xevev_iproto_run,
        .iproto_ready = engine == ENGINE_CORO ? xcoro_iproto_ready : engine == ENGINE_INTERNAL ? xev_iproto_ready : xevev_iproto_ready,
        .suspend = GEVAPI->suspend,
        .resume = GEVAPI->resume,
        .io_new = xev_io_new,
        .io_free = xev_io_free,
        .io_set = xev_io_set,
        .io_get = xev_io_get,
        .io_set_data = xev_io_set_data,
        .io_data = xev_io_data,
        .io_start = GEVAPI->io_start,
        .io_stop = GEVAPI->io_stop,
        .timer_new = xev_timer_new,
        .timer_free = xev_timer_free,
        .timer_set = xev_timer_set,
        .timer_set_data = xev_timer_set_data,
        .timer_data = xev_timer_data,
        .timer_start = GEVAPI->timer_start,
        .timer_stop = GEVAPI->timer_stop,
        .timer_again = GEVAPI->timer_again,
        .timer_set_priority = xev_timer_set_priority
    };
    iproto_set_evapi(&iproto_evapi);
}

static void iprotoxs_set_engine_string(const char *name) {
    iprotoxs_engine_t engine;
    if (strcmp(name, "internal") == 0) {
        engine = ENGINE_INTERNAL;
    } else if (strcmp(name, "ev") == 0) {
        engine = ENGINE_EV;
    } else if (strcmp(name, "coro") == 0) {
        engine = ENGINE_CORO;
    } else {
        croak("Invalid engine name: %s", name);
    }
    iprotoxs_set_engine(engine);
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

static SV *iprotoxs_pack_data(HV *opts) {
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
    return cat;
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

SV *iprotoxs_instance(SV *sv) {
    if (!sv_derived_from(sv, "MR::IProto::XS")) {
        croak("\"%s\" is not of type MR::IProto::XS", SvPV_nolen(sv));
    } else if (SvPOK(sv)) {
        dMY_CXT;
        HE *he = hv_fetch_ent(MY_CXT.singletons, sv, 0, 0);
        return he ? HeVAL(he) : NULL;
    } else {
        return sv;
    }
}

static iproto_cluster_t *iprotoxs_extract_cluster(SV *sv) {
    if (!sv)
        return NULL;
    SV *instance = iprotoxs_instance(sv);
    return instance ? iprotoxs_instance_to_cluster(instance) : NULL;
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

    val = hv_fetch(request, "iproto", 6, 0);
    if (!val) croak("\"iproto\" should be specified");
    iproto_cluster_t *cluster = iprotoxs_extract_cluster(*val);
    if (!cluster) croak("\"iproto\" should be an instance or a singleton of type MR::IProto::XS");

    val = hv_fetch(request, "code", 4, 0);
    if (!val) croak("\"code\" should be specified");
    if (!(SvIOK(*val) || looks_like_number(*val)))
        croak("Invalid \"code\" value");
    uint32_t code = SvUV(*val);

    void *data;
    size_t size;
    SV *datasv = NULL;
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
            datasv = iprotoxs_pack_data(hv);
            data = SvPV(datasv, size);
        } else {
            croak("invalid \"method\" value");
        }
    } else {
        croak("invalid \"request\" value");
    }

    iproto_message_t *message = iproto_message_init(code, data, size);
    iproto_message_set_cluster(message, cluster);
    iproto_message_opts_t *opts = iproto_message_options(message);
    iprotoxs_parse_opts(opts, request);

    iprotoxs_data_t *optsdata;
    Newxz(optsdata, 1, iprotoxs_data_t);

    if ((val = hv_fetch(request, "callback", 8, 0))) {
        if (!(SvROK(*val) || SvTYPE(SvRV(*val)) == SVt_PVCV))
            croak("\"callback\" should be a CODEREF");
        opts->callback = iprotoxs_callback;
        optsdata->request = (HV *)SvREFCNT_inc((SV *)request);
        optsdata->callback = SvREFCNT_inc(*val);
    }

    if ((val = hv_fetch(request, "soft_retry_callback", 19, 0))) {
        if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVCV))
            croak("\"soft_retry_callback\" should be a CODEREF");
        opts->soft_retry_callback = iprotoxs_soft_retry_callback;
        optsdata->soft_retry_callback = SvREFCNT_inc(*val);
    }

    if (datasv)
        optsdata->data = SvREFCNT_inc(datasv);

    opts->data = optsdata;

    return message;
}

HV *iprotoxs_message_to_hv(iproto_message_t *message, HV *request) {
    iproto_error_t error = iproto_message_error(message);
    SV *errsv = newSVuv(error);
    sv_setpv(errsv, iproto_error_string(error));
    SvIOK_on(errsv);
    SV **val = hv_fetch(request, "inplace", 7, 0);
    bool inplace = val && SvTRUE(*val);
    HV *result = newHV();
    if (error == ERR_CODE_OK) {
        bool replica;
        size_t size;
        void *data = iproto_message_response(message, &size, &replica);
        if (replica)
            (void)hv_store(result, "replica", 7, &PL_sv_yes, 0);

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
            if (inplace && datasv) {
                if (hv_store(hv, "data", 4, datasv, 0))
                    SvREFCNT_inc(datasv);
            }
        } else {
            datasv = newSVpvn(data, size);
            if (inplace) {
                if (hv_store(request, "response", 8, datasv, 0))
                    SvREFCNT_inc(datasv);
            }
        }
        if (datasv)
            (void)hv_store(result, "data", 4, datasv, 0);
    }
    (void)hv_store(result, "error", 5, errsv, 0);
    if (inplace) {
        if (hv_store(request, "error", 5, errsv, 0))
            SvREFCNT_inc(errsv);
    }

    iprotoxs_data_t *optsdata = (iprotoxs_data_t *)iproto_message_options(message)->data;
    if (optsdata->callback) {
        SvREFCNT_dec(optsdata->callback);
        SvREFCNT_dec(optsdata->request);
    }
    if (optsdata->soft_retry_callback)
        SvREFCNT_dec(optsdata->soft_retry_callback);
    if (optsdata->data)
        SvREFCNT_dec(optsdata->data);
    Safefree(optsdata);

    iproto_message_free(message);
    return result;
}

MODULE = MR::IProto::XS		PACKAGE = MR::IProto::XS		PREFIX = ixs_

PROTOTYPES: ENABLE

BOOT:
    MY_CXT_INIT;
    MY_CXT.singletons = newHV();
    MY_CXT.stat_callback = NULL;
    MY_CXT.unpack = newXS(NULL, iprotoxs_unpack_wrapper, __FILE__);
    MY_CXT.engine = ENGINE_UNINITIALIZED;
    load_module(0, newSVpvn("EV", 2), NULL, NULL);
    I_EV_API("MR::IProto::XS");
    iprotoxs_set_engine(ENGINE_INTERNAL);
    iproto_initialize();
    iproto_set_logfunc(iprotoxs_logfunc_warn);
    HV *stash = gv_stashpv("MR::IProto::XS", 1);
#define IPROTOXS_CONST(s, ...) newCONSTSUB(stash, #s, newSVuv(s));
    IPROTO_ALL_ERROR_CODES(IPROTOXS_CONST);
    IPROTO_LOGMASK(IPROTOXS_CONST);
#undef IPROTOXS_CONST

void
ixs_import(klass, ...)
    CODE:
        if (items > 1 && SvOK(ST(1))) {
            iprotoxs_set_engine_string(SvPV_nolen(ST(1)));
        }

MR::IProto::XS
ixs_new(klass, ...)
        SV *klass
    ALIAS:
        create_singleton = 1
    PREINIT:
        HV *shards_config = NULL;
        bool implicit_shard = false;
        SV *connect_timeout = NULL;
        SV *server_freeze = NULL;
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
                    (void)hv_store(shards_config, "1", 1, newRV_noinc((SV*)shard_config), 0);
                    implicit_shard = true;
                } else if (!implicit_shard) {
                    croak("Only one argument \"shards\" or \"%s\" could be specified", key);
                }
                elem = hv_fetch(shards_config, "1", 1, 0);
                if (!elem) croak("Impossible");
                (void)hv_store((HV*)SvRV(*elem), key, strlen(key), SvREFCNT_inc(value), 0);
            } else if (strcmp(key, "connect_timeout") == 0) {
                connect_timeout = value;
            } else if (strcmp(key, "server_freeze") == 0) {
                server_freeze = value;
            }
        }
        if (!shards_config)
            croak("Argument \"shards\" or \"masters\" should be specified");
        iproto_cluster_t *cluster = iproto_cluster_init();
        iprotoxs_cluster_set_shards(cluster, shards_config);
        if (connect_timeout || server_freeze) {
            iproto_cluster_opts_t *opts = iproto_cluster_options(cluster);
            if (connect_timeout)
                iprotoxs_timeval_set(connect_timeout, &opts->connect_timeout);
            if (server_freeze)
                iprotoxs_timeval_set(server_freeze, &opts->server_freeze);
        }
        RETVAL = newSV(0);
        sv_setref_pv(RETVAL, SvPV_nolen(klass), cluster);
        if (ix == 1) {
            dMY_CXT;
            if (hv_exists_ent(MY_CXT.singletons, klass, 0))
                croak("singleton %s already initialized", SvPV_nolen(klass));
            (void)hv_store_ent(MY_CXT.singletons, klass, SvREFCNT_inc(RETVAL), 0);
        }
    OUTPUT:
        RETVAL

void
ixs_DESTROY(iprotoxs)
        MR::IProto::XS iprotoxs
    CODE:
        iproto_cluster_t *cluster = iprotoxs_extract_cluster(iprotoxs);
        if (!cluster)
            croak("DESTROY should be called as an instance method");
        iproto_cluster_free(cluster);

MR::IProto::XS
ixs_remove_singleton(klass)
        SV *klass
    CODE:
        if (!SvPOK(klass))
            croak("remove_singleton() should be called as a class method");
        dMY_CXT;
        SV *cluster = hv_delete_ent(MY_CXT.singletons, klass, 0, 0);
        RETVAL = cluster ? SvREFCNT_inc(cluster) : &PL_sv_undef;
    OUTPUT:
        RETVAL

MR::IProto::XS
ixs_instance(klass)
        SV *klass
    CODE:
        SV *instance = iprotoxs_instance(klass);
        RETVAL = instance ? SvREFCNT_inc(instance) : &PL_sv_undef;
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
                croak("Message should be a HASHREF");
            HV *request = (HV *)SvRV(*sv);
            if (iprotoxs && !hv_exists(request, "iproto", 6)) {
                (void)hv_store(request, "iproto", 6, SvREFCNT_inc(iprotoxs), 0);
                SAVEDELETE(request, savepvn("iproto", 6), 6);
            }
            messages[i] = iprotoxs_hv_to_message(request);
        }
        iproto_bulk(messages, nmessages, timeout);
        RETVAL = newAV();
        for (int i = 0; i < nmessages; i++) {
            SV **sv = av_fetch(list, i, 0);
            iproto_message_opts_t *opts = iproto_message_options(messages[i]);
            av_push(RETVAL, opts->callback ? &PL_sv_undef
                : newRV_noinc((SV*)iprotoxs_message_to_hv(messages[i], (HV *)SvRV(*sv))));
        }
        sv_2mortal((SV*)RETVAL);
        Safefree(messages);
    OUTPUT:
        RETVAL

HV *
ixs_do(iprotoxs, request, ...)
        MR::IProto::XS iprotoxs
        HV *request
    CODE:
        iprotoxs_call_timeout(timeout, 2);
        if (iprotoxs && !hv_exists(request, "iproto", 6)) {
            (void)hv_store(request, "iproto", 6, SvREFCNT_inc(iprotoxs), 0);
            SAVEDELETE(request, savepvn("iproto", 6), 6);
        }
        iproto_message_t *message = iprotoxs_hv_to_message(request);
        iproto_do(message, timeout);
        iproto_message_opts_t *opts = iproto_message_options(message);
        if (opts->callback)
            XSRETURN_UNDEF;
        RETVAL = (HV *)sv_2mortal((SV *)iprotoxs_message_to_hv(message, request));
    OUTPUT:
        RETVAL

IV
ixs_get_shard_count(iprotoxs)
        MR::IProto::XS iprotoxs
    CODE:
        iproto_cluster_t *cluster = iprotoxs_extract_cluster(iprotoxs);
        if (!cluster)
            croak("get_shard_count() should be called as an instance or a singleton method");
        RETVAL = iproto_cluster_get_shard_count(cluster);
    OUTPUT:
        RETVAL

void
ixs_set_logmask(klass, mask)
        unsigned mask
    CODE:
        iproto_set_logmask(mask);

void
ixs_set_logfunc(klass, callback)
        SV *callback
    CODE:
        dMY_CXT;
        if (SvOK(callback)) {
            if (MY_CXT.logfunc) {
                SvSetSV(MY_CXT.logfunc, callback);
            } else {
                MY_CXT.logfunc = newSVsv(callback);
                iproto_set_logfunc(iprotoxs_logfunc_call);
            }
        } else if (MY_CXT.logfunc) {
            SvREFCNT_dec(MY_CXT.logfunc);
            MY_CXT.logfunc = NULL;
            iproto_set_logfunc(iprotoxs_logfunc_warn);
        }

const char *
ixs_engine(klass, ...)
    CODE:
        dMY_CXT;
        if (items > 1 && SvOK(ST(1))) {
            iprotoxs_set_engine_string(SvPV_nolen(ST(1)));
        }
        RETVAL = MY_CXT.engine == ENGINE_CORO ? "coro" : MY_CXT.engine == ENGINE_EV ? "ev" : "internal";
    OUTPUT:
        RETVAL

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
        if (SvOK(callback)) {
            if (MY_CXT.stat_callback) {
                SvSetSV(MY_CXT.stat_callback, callback);
            } else {
                MY_CXT.stat_callback = newSVsv(callback);
                iproto_stat_set_callback(iprotoxs_stat_callback);
            }
        } else if (MY_CXT.stat_callback) {
            SvREFCNT_dec(MY_CXT.stat_callback);
            MY_CXT.stat_callback = NULL;
            iproto_stat_set_callback(NULL);
        }

void
ixs_stat_flush(klass)
    CODE:
        iproto_stat_flush();

void
ixs_stat_END()
    CODE:
        iproto_stat_flush();
