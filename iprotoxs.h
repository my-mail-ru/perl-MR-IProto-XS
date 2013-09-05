#ifndef IPROTOXS_H_INCLUDED
#define IPROTOXS_H_INCLUDED

void iprotoxs_timeval_set(SV *sv, struct timeval *timeout);
void iprotoxs_parse_opts(iproto_message_opts_t *opts, HV *request);

#define iprotoxs_call_timeout(var, n) \
    if ((items - n) % 2 != 0) \
        croak("Odd number of elements in hash assignment"); \
    struct timeval var ## _v; \
    struct timeval *var = NULL; \
    for (int i = n; i < items; i += 2) { \
        char *key = SvPV_nolen(ST(i)); \
        SV *value = ST(i + 1); \
        if (strcmp(key, "timeout") == 0) { \
            var = &var ## _v; \
            iprotoxs_timeval_set(value, var); \
        } \
    }

#define iprotoxs_object_to_cluster(iprotoxs) \
    (iprotoxs ? INT2PTR(iproto_cluster_t *, SvIV((SV*)SvRV(iprotoxs))) : NULL)

#endif
