/* Fuzz libsss_certmap's rule parser: sss_certmap_add_rule() parses the
 * matching rule (<SUBJECT>/<ISSUER>/<KU>/<EKU>/<SAN:...> grammar, KRB5:/AD:
 * prefixes) and the mapping template (LDAP:/LDAPU1: with {subject_dn} ...
 * conversions). Rules come from sssd.conf / IPA/AD certmap rule objects.
 *
 * Input: "<match rule>\n<map rule>\n<domain>,<domain>..." (missing parts are
 * NULL). On success the rule is applied to the fixed test certificates from
 * upstream's certmap test suite (match, search filter, expansion). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include "lib/certmap/sss_certmap.h"
#include "certmap_test_certs.h"

static const struct { const uint8_t *der; size_t len; } certs[] = {
    { test_cert_der, sizeof(test_cert_der) },
    { test_cert2_der, sizeof(test_cert2_der) },
    { test_cert3_der, sizeof(test_cert3_der) },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *buf = malloc(size + 1);
    if (buf == NULL) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    char *match = buf;
    char *map = NULL;
    char *doms = NULL;
    char *nl = strchr(match, '\n');
    if (nl != NULL) {
        *nl = '\0';
        map = nl + 1;
        nl = strchr(map, '\n');
        if (nl != NULL) {
            *nl = '\0';
            doms = nl + 1;
        }
    }

    const char *domains[9] = { NULL };
    if (doms != NULL) {
        size_t n = 0;
        char *save = NULL;
        for (char *d = strtok_r(doms, ",", &save); d != NULL && n < 8;
             d = strtok_r(NULL, ",", &save)) {
            domains[n++] = d;
        }
    }

    struct sss_certmap_ctx *ctx = NULL;
    if (sss_certmap_init(NULL, NULL, NULL, &ctx) != 0) {
        free(buf);
        return 0;
    }

    int ret = sss_certmap_add_rule(ctx, 1, match[0] ? match : NULL,
                                   (map && map[0]) ? map : NULL,
                                   doms ? domains : NULL);
    if (ret == 0) {
        for (size_t c = 0; c < sizeof(certs) / sizeof(certs[0]); c++) {
            char *filter = NULL;
            char **fdoms = NULL;
            sss_certmap_match_cert(ctx, certs[c].der, certs[c].len);
            if (sss_certmap_get_search_filter(ctx, certs[c].der, certs[c].len,
                                              &filter, &fdoms) == 0) {
                sss_certmap_free_filter_and_domains(filter, fdoms);
            }
            filter = NULL;
            fdoms = NULL;
            if (sss_certmap_expand_mapping_rule(ctx, certs[c].der, certs[c].len,
                                                &filter, &fdoms) == 0) {
                sss_certmap_free_filter_and_domains(filter, fdoms);
            }
        }
    }

    sss_certmap_free_ctx(ctx);
    free(buf);
    return 0;
}
