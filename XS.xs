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

#define SHARED_KEYS(_) \
    _(callback) \
    _(code) \
    _(count) \
    _(data) \
    _(early_retry) \
    _(errcode) \
    _(error) \
    _(errstr) \
    _(format) \
    _(from) \
    _(inplace) \
    _(iproto) \
    _(max_tries) \
    _(method) \
    _(registered) \
    _(replica) \
    _(request) \
    _(response) \
    _(retry_same) \
    _(safe_retry) \
    _(shard_num) \
    _(soft_retry_callback) \
    _(sub) \
    _(timeout) \
    _(wallclock)

#define SHARED_KEYS_STRUCT_DEF(k) SV *k;
#define SHARED_KEYS_STRUCT struct { SHARED_KEYS(SHARED_KEYS_STRUCT_DEF) }

#define SHARED_KEYS_INIT_DEF(k) MY_CXT.keys.k = newSVpvs_share(#k);
#define SHARED_KEYS_INIT SHARED_KEYS(SHARED_KEYS_INIT_DEF)

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
    SHARED_KEYS_STRUCT keys;
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
    MR__IProto__XS iprotoxs;
    SV *request;
    iproto_message_t *message;
    SV *error;
    SV *callback;
    SV *soft_retry_callback;
    SV *data;
} iprotoxs_data_t;

static SV *iprotoxs_context_response(iprotoxs_data_t *context);
static void iprotoxs_context_free(iprotoxs_data_t *context);

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
    dMY_CXT;
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
    (void)hv_store_ent(datahv, MY_CXT.keys.registered, newSViv(data->registered), 0);
    (void)hv_store_ent(datahv, MY_CXT.keys.wallclock, newSVnv(data->wallclock.tv_sec + (data->wallclock.tv_usec / 1000000.)), 0);
    (void)hv_store_ent(datahv, MY_CXT.keys.count, newSVuv(data->count), 0);
    mXPUSHs(newRV_noinc((SV *)datahv));
    PUTBACK;
    call_sv(MY_CXT.stat_callback, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in statistics' callback: %s", SvPV_nolen(ERRSV));
    }
    FREETMPS;
    LEAVE;
}

static void iprotoxs_context_callback(iprotoxs_data_t *context) {
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHs(iprotoxs_context_response(context));
    PUTBACK;
    call_sv(context->callback, G_EVAL|G_DISCARD);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        warn("MR::IProto::XS: died in callback: %s", SvPV_nolen(ERRSV));
    }
    FREETMPS;
    LEAVE;
    iprotoxs_context_free(context);
}

static void iprotoxs_callback(iproto_message_t *message) {
    iprotoxs_data_t *context = (iprotoxs_data_t *)iproto_message_options(message)->data;
    assert(context->message == message);
    iprotoxs_context_callback(context);
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
    SV **val = hv_fetchs(config, "masters", 0);
    if (!val) croak("Shard configuration should contain \"masters\" section");
    if (!(SvROK(*val) && SvTYPE(SvRV(*val)) == SVt_PVAV))
        croak("Masters configuration should be an ARRAYREF");
    AV *masters = (AV*)SvRV(*val);
    AV *replicas = NULL;
    if ((val = hv_fetchs(config, "replicas", 0))) {
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
    dMY_CXT;
    HE *he = hv_fetch_ent(opts, MY_CXT.keys.format, 0, 0);
    if (!(he && SvPOK(HeVAL(he))))
        croak("\"format\" should be a SCALAR if method \"pack\" is used");
    size_t formatlen;
    char *format = SvPV(HeVAL(he), formatlen);
    he = hv_fetch_ent(opts, MY_CXT.keys.data, 0, 0);
    if (!(he && SvROK(HeVAL(he)) && SvTYPE(SvRV(HeVAL(he))) == SVt_PVAV))
        croak("\"data\" should be an ARRAYREF if method \"pack\" is used");
    AV *data = (AV *)SvRV(HeVAL(he));
    SV **list = av_fetch(data, 0, 0);
    size_t listlen = av_len(data) + 1;
    SV *cat = newSVpv("", 0);
    SvUTF8_off(cat);
    packlist(cat, format, format + formatlen, list, list + listlen);
    return cat;
}

static AV *iprotoxs_unpack_data(HV *opts, SV *data, SV *errsv) {
    dMY_CXT;
    HE *he = hv_fetch_ent(opts, MY_CXT.keys.format, 0, 0);
    if (!(he && SvPOK(HeVAL(he))))
        croak("\"format\" should be a SCALAR if method \"unpack\" is used");
    /* We should use G_EVAL, so can't use unpackstring() function directly */
    SV *format = HeVAL(he);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(format);
    XPUSHs(data);
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

static SV *iprotoxs_call_coder(HV *opts, SV *data, SV *errsv) {
    dMY_CXT;
    HE *he = hv_fetch_ent(opts, MY_CXT.keys.sub, 0, 0);
    if (!(he && (SvPOK(HeVAL(he)) || (SvROK(HeVAL(he)) && SvTYPE(SvRV(HeVAL(he))) == SVt_PVCV))))
        croak("\"sub\" should be a CODEREF or subroutine name if method \"sub\" is used");
    SV *subsv = HeVAL(he);
    SV *result;
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(data);
    PUTBACK;
    call_sv(subsv, G_SCALAR | G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV)) {
        result = NULL;
        (void)POPs;
        STRLEN len;
        sv_setuv(errsv, ERR_CODE_PROTO_ERR);
        char *errstr = SvPV(ERRSV, len);
        sv_setpvn(errsv, errstr, len);
        SvIOK_on(errsv);
    } else {
        result = SvREFCNT_inc(POPs);
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
    dMY_CXT;
    HE *he;

    if ((he = hv_fetch_ent(request, MY_CXT.keys.shard_num, 0, 0))) {
        SV *val = HeVAL(he);
        if (!(SvIOK(val) || looks_like_number(val)))
            croak("Invalid \"shard_num\" value: \"%s\"", SvPV_nolen(val));
        opts->shard_num = SvUV(val);
    }

    if ((he = hv_fetch_ent(request, MY_CXT.keys.from, 0, 0))) {
        if (!SvPOK(HeVAL(he)))
            croak("invalid \"from\" value");
        char *str = SvPV_nolen(HeVAL(he));
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

    if ((he = hv_fetch_ent(request, MY_CXT.keys.timeout, 0, 0))) {
        iprotoxs_timeval_set(HeVAL(he), &opts->timeout);
    }

    if ((he = hv_fetch_ent(request, MY_CXT.keys.early_retry, 0, 0))) {
        if (SvTRUE(HeVAL(he))) {
            opts->retry |= RETRY_EARLY;
        } else {
            opts->retry &= ~RETRY_EARLY;
        }
    }

    if ((he = hv_fetch_ent(request, MY_CXT.keys.safe_retry, 0, 0))) {
        if (SvTRUE(HeVAL(he))) {
            opts->retry |= RETRY_SAFE;
        } else {
            opts->retry &= ~RETRY_SAFE;
        }
    }

    if ((he = hv_fetch_ent(request, MY_CXT.keys.retry_same, 0, 0))) {
        if (SvTRUE(HeVAL(he))) {
            opts->retry |= RETRY_SAME;
        } else {
            opts->retry &= ~RETRY_SAME;
        }
    }

    if ((he = hv_fetch_ent(request, MY_CXT.keys.max_tries, 0, 0))) {
        if (!(SvIOK(HeVAL(he)) || looks_like_number(HeVAL(he))))
            croak("\"max_tries\" should be an integer");
        opts->max_tries = SvIV(HeVAL(he));
    }
}

static SV *iprotoxs_request_data(SV *options, SV *errsv) {
    dMY_CXT;
    SV *data;
    if (SvPOK(options)) {
        data = SvREFCNT_inc(options);
    } else if (SvROK(options) && SvTYPE(SvRV(options)) == SVt_PVHV) {
        HV *optshv = (HV *)SvRV(options);
        HE *he = hv_fetch_ent(optshv, MY_CXT.keys.method, 0, 0);
        if (!(he && SvPOK(HeVAL(he))))
            croak("\"method\" in \"request\" should be a string");
        char *method = SvPV_nolen(HeVAL(he));
        if (strcmp(method, "raw") == 0) {
            HE *he = hv_fetch_ent(optshv, MY_CXT.keys.data, 0, 0);
            if (!(he && SvPOK(HeVAL(he))))
                croak("\"data\" should be a string if method \"raw\" is used");
            data = SvREFCNT_inc(HeVAL(he));
        } else if (strcmp(method, "pack") == 0) {
            data = iprotoxs_pack_data(optshv);
        } else if (strcmp(method, "sub") == 0) {
            HE *he = hv_fetch_ent(optshv, MY_CXT.keys.data, 0, 0);
            if (!he)
                croak("\"data\" should exist if method \"sub\" is used");
            data = iprotoxs_call_coder(optshv, HeVAL(he), errsv);
        } else {
            croak("invalid \"method\" value");
        }
    } else {
        croak("invalid \"request\" value");
    }
    if (data && SvUTF8(data)) {
        SvREFCNT_dec(data);
        sv_setuv(errsv, ERR_CODE_PROTO_ERR);
        sv_setpv(errsv, "Request should be byte string, not character");
        SvIOK_on(errsv);
        return NULL;
    }
    return data;
}

static iproto_message_t *iprotoxs_message_init(iprotoxs_data_t *context) {
    dMY_CXT;
    HV *reqhv = (HV *)SvRV(context->request);

    HE *he = hv_fetch_ent(reqhv, MY_CXT.keys.code, 0, 0);
    if (!he)
        croak("\"code\" should be specified");
    if (!(SvIOK(HeVAL(he)) || looks_like_number(HeVAL(he))))
        croak("Invalid \"code\" value");
    uint32_t code = SvUV(HeVAL(he));

    he = hv_fetch_ent(reqhv, MY_CXT.keys.request, 0, 0);
    if (!he)
        croak("\"request\" should be specified");
    SV *datasv = iprotoxs_request_data(HeVAL(he), context->error);
    if (!datasv)
        return NULL;

    context->data = datasv;

    size_t size;
    void *data = SvPV(datasv, size);
    iproto_message_t *message = iproto_message_init(code, data, size);

    iproto_cluster_t *cluster = iprotoxs_extract_cluster(context->iprotoxs);
    if (!cluster)
        croak("\"iproto\" should be an instance or a singleton of type MR::IProto::XS");
    iproto_message_set_cluster(message, cluster);

    iproto_message_opts_t *opts = iproto_message_options(message);
    opts->data = context;
    iprotoxs_parse_opts(opts, reqhv);

    if (context->callback)
        opts->callback = iprotoxs_callback;

    if ((he = hv_fetch_ent(reqhv, MY_CXT.keys.soft_retry_callback, 0, 0))) {
        SV *val = HeVAL(he);
        if (!(SvROK(val) && SvTYPE(SvRV(val)) == SVt_PVCV))
            croak("\"soft_retry_callback\" should be a CODEREF");
        opts->soft_retry_callback = iprotoxs_soft_retry_callback;
        context->soft_retry_callback = SvREFCNT_inc(val);
    }

    return message;
}

static SV *iprotoxs_message_response(iproto_message_t *message, HV *options, bool *replica, SV *errsv) {
    dMY_CXT;
    size_t size;
    void *data = iproto_message_response(message, &size, replica);
    SV *datasv = data ? newSVpvn(data, size) : newSVpvn("", 0);
    if (!options)
        return datasv;

    HE *he = hv_fetch_ent(options, MY_CXT.keys.errcode, 0, 0);
    if (he) {
        if (!SvIOK(HeVAL(he)))
            croak("\"errcode\" should be a number");
        UV errcode;
        size_t bytes = SvUV(HeVAL(he));
        if (size < bytes) {
            sv_setuv(errsv, ERR_CODE_PROTO_ERR);
            sv_setpvf(errsv, "Response is too short (%"UVuf" bytes when %"UVuf" is required)", (UV)size, (UV)bytes);
            SvIOK_on(errsv);
            return NULL;
        }
        switch (bytes) {
            case 1:
                errcode = *(uint8_t*)data;
                break;
            case 2:
                errcode = *(uint16_t*)data;
                break;
            case 4:
                errcode = *(uint32_t*)data;
                break;
            case 8:
                errcode = *(uint64_t*)data;
                break;
            default:
                croak("\"errcode\" should be 1, 2, 4 or 8");
        }
#if (PERL_BCDVERSION < 0x5010000)
        sv_chop(datasv, SvPVX(datasv) + bytes);
#else
        sv_chop(datasv, SvPVX_const(datasv) + bytes);
#endif
        if (errcode != ERR_CODE_OK) {
            sv_setuv(errsv, errcode);
            HE *he = hv_fetch_ent(options, MY_CXT.keys.errstr, 0, 0);
            if (he && SvTRUE(HeVAL(he)) && SvCUR(datasv) > 0) {
                sv_setpv(errsv, "server error: ");
                sv_catsv(errsv, datasv);
            } else {
                sv_setpvf(errsv, "server error: 0x%"UVxf, errcode);
            }
            SvIOK_on(errsv);
            SvREFCNT_dec(datasv);
            return NULL;
        }
    }

    he = hv_fetch_ent(options, MY_CXT.keys.method, 0, 0);
    if (!(he && SvPOK(HeVAL(he))))
        croak("\"method\" in \"response\" should be a string");
    char *method = SvPV_nolen(HeVAL(he));
    if (strcmp(method, "raw") == 0) {
        return datasv;
    } else if (strcmp(method, "unpack") == 0) {
        AV *dataav = iprotoxs_unpack_data(options, datasv, errsv);
        SvREFCNT_dec(datasv);
        return dataav ? newRV_noinc((SV *)dataav) : NULL;
    } else if (strcmp(method, "sub") == 0) {
        SV *resp = iprotoxs_call_coder(options, datasv, errsv);
        SvREFCNT_dec(datasv);
        return resp;
    } else {
        croak("invalid \"method\" value");
    }
}

static iprotoxs_data_t *iprotoxs_context_init(MR__IProto__XS iprotoxs, SV *request) {
    dMY_CXT;
    if (!(SvROK(request) && SvTYPE(SvRV(request)) == SVt_PVHV))
        croak("Message should be a HASHREF");

    iprotoxs_data_t *context;
    Newxz(context, 1, iprotoxs_data_t);
    context->request = SvREFCNT_inc(request);
    context->error = newSV(0);

    HV *reqhv = (HV *)SvRV(request);

    HE *he = hv_fetch_ent(reqhv, MY_CXT.keys.iproto, 0, 0);
    SV *ixs = he ? HeVAL(he) : iprotoxs;
    if (!ixs) croak("\"iproto\" should be specified");
    context->iprotoxs = SvREFCNT_inc(ixs);

    if ((he = hv_fetch_ent(reqhv, MY_CXT.keys.callback, 0, 0))) {
        SV *val = HeVAL(he);
        if (!(SvROK(val) || SvTYPE(SvRV(val)) == SVt_PVCV))
            croak("\"callback\" should be a CODEREF");
        context->callback = SvREFCNT_inc(val);
    }

    context->message = iprotoxs_message_init(context);

    return context;
}

static void iprotoxs_context_free(iprotoxs_data_t *context) {
    if (context->message)
        iproto_message_free(context->message);
    SvREFCNT_dec(context->iprotoxs);
    SvREFCNT_dec(context->request);
    if (context->data)
        SvREFCNT_dec(context->data);
    if (context->callback)
        SvREFCNT_dec(context->callback);
    if (context->soft_retry_callback)
        SvREFCNT_dec(context->soft_retry_callback);
    Safefree(context);
}

static SV *iprotoxs_context_response(iprotoxs_data_t *context) {
    dMY_CXT;
    HV *reqhv = (HV *)SvRV(context->request);
    HE *he = hv_fetch_ent(reqhv, MY_CXT.keys.inplace, 0, 0);
    bool inplace = he && SvTRUE(HeVAL(he));

    SV *errsv = context->error;

    HV *result = newHV();
    if (context->message) {
        iproto_error_t error = iproto_message_error(context->message);
        sv_setuv(errsv, error);
        sv_setpv(errsv, iproto_error_string(error));
        SvIOK_on(errsv);
        if (error == ERR_CODE_OK) {
            HV *ropts = NULL;
            if ((he = hv_fetch_ent(reqhv, MY_CXT.keys.response, 0, 0))) {
                SV *val = HeVAL(he);
                if (!(SvROK(val) && SvTYPE(SvRV(val)) == SVt_PVHV))
                    croak("invalid \"response\" value");
                ropts = (HV *)SvRV(val);
            }

            bool replica;
            SV *datasv = iprotoxs_message_response(context->message, ropts, &replica, errsv);
            if (replica) {
                (void)hv_store_ent(result, MY_CXT.keys.replica, &PL_sv_yes, 0);
                if (inplace)
                    (void)hv_store_ent(reqhv, MY_CXT.keys.replica, &PL_sv_yes, 0);
            }
            if (datasv) {
                (void)hv_store_ent(result, MY_CXT.keys.data, datasv, 0);
                if (inplace) {
                    if (ropts ? hv_store_ent(ropts, MY_CXT.keys.data, datasv, 0) : hv_store_ent(reqhv, MY_CXT.keys.response, datasv, 0))
                        SvREFCNT_inc(datasv);
                }
            }
        }
    }

    (void)hv_store_ent(result, MY_CXT.keys.error, errsv, 0);
    if (inplace) {
        if (hv_store_ent(reqhv, MY_CXT.keys.error, errsv, 0))
            SvREFCNT_inc(errsv);
    }

    return newRV_noinc((SV *)result);
}

static SV *iprotoxs_context_retval(iprotoxs_data_t *context) {
    if (context->callback) {
        if (!context->message)
            iprotoxs_context_callback(context);
        return &PL_sv_undef;
    }
    SV *retval = iprotoxs_context_response(context);
    iprotoxs_context_free(context);
    return retval;
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
    SHARED_KEYS_INIT;

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
                    (void)hv_stores(shards_config, "1", newRV_noinc((SV*)shard_config));
                    implicit_shard = true;
                } else if (!implicit_shard) {
                    croak("Only one argument \"shards\" or \"%s\" could be specified", key);
                }
                elem = hv_fetchs(shards_config, "1", 0);
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
        int nreqs = av_len(list) + 1;
        iprotoxs_data_t **contexts;
        Newx(contexts, nreqs, iprotoxs_data_t *);
        iproto_message_t **messages;
        Newx(messages, nreqs, iproto_message_t *);
        int nmessages = 0;
        for (int i = 0; i < nreqs; i++) {
            SV **sv = av_fetch(list, i, 0);
            iprotoxs_data_t *context = iprotoxs_context_init(iprotoxs, *sv);
            if (context->message)
                messages[nmessages++] = context->message;
            contexts[i] = context;
        }
        if (nmessages)
            iproto_bulk(messages, nmessages, timeout);
        RETVAL = newAV();
        for (int i = 0; i < nreqs; i++)
            av_push(RETVAL, iprotoxs_context_retval(contexts[i]));
        sv_2mortal((SV*)RETVAL);
        Safefree(messages);
        Safefree(contexts);
    OUTPUT:
        RETVAL

SV *
ixs_do(iprotoxs, request, ...)
        MR::IProto::XS iprotoxs
        SV *request
    CODE:
        iprotoxs_call_timeout(timeout, 2);
        iprotoxs_data_t *context = iprotoxs_context_init(iprotoxs, request);
        if (context->message)
            iproto_do(context->message, timeout);
        RETVAL = iprotoxs_context_retval(context);
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
