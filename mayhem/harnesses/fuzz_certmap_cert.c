/* Fuzz libsss_certmap's certificate side: the DER certificate a smartcard or
 * an LDAP userCertificate attribute supplies is decoded (subject/issuer, KU,
 * EKU, SAN incl. ntPrincipalName / pkinit principal ASN.1, SID extension) by
 * sss_certmap_match_cert(), sss_certmap_get_search_filter(),
 * sss_certmap_expand_mapping_rule() and sss_certmap_display_cert_content().
 * The rule set is fixed and mirrors rules from upstream's test_certmap.c. */
#include <stdint.h>
#include <stdlib.h>
#include <talloc.h>
#include "lib/certmap/sss_certmap.h"

static const struct { const char *match; const char *map; } rules[] = {
    { "<SAN:ntPrincipalName>.*@test.domain", "LDAP:(rule1={subject_dn})" },
    { "<SAN:pkinitSAN>.*", "LDAP:(rule2={subject_principal}{subject_principal.short_name})" },
    { "KRB5:<KU>digitalSignature,keyEncipherment<EKU>clientAuth,smartcardLogon",
      "LDAP:(rule3={issuer_dn!nss_x500}{subject_dn!ad_x500}{cert!base64})" },
    { "<SAN:rfc822Name>.*<SUBJECT>.*", "LDAPU1:(rule4={serial_number!HEX_U}{subject_key_id!hex_c}{sid})" },
    { "&&<ISSUER>^CN=.*<SAN:dNSName>.*", "LDAP:(rule5={cert!bin}{subject_x400_address}{subject_uri}{subject_ip_address})" },
    { "||<SAN:1.2.3.4>.*<SAN:upn>.*<SAN:otherName>.*", "LDAPU1:(rule6={issuer_dn!ad}{subject_registered_id}{subject_rfc822_name.short_name})" },
    { "<KU>cRLSign<EKU>1.3.6.1.5.2.3.4", "LDAP:(rule7={subject_dns_name}{subject_nt_principal.short_name}{cert!sha256_u})" },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct sss_certmap_ctx *ctx = NULL;
    if (sss_certmap_init(NULL, NULL, NULL, &ctx) != 0) return 0;
    for (size_t r = 0; r < sizeof(rules) / sizeof(rules[0]); r++) {
        sss_certmap_add_rule(ctx, (uint32_t) r, rules[r].match, rules[r].map, NULL);
    }

    char *filter = NULL;
    char **doms = NULL;
    sss_certmap_match_cert(ctx, data, size);
    if (sss_certmap_get_search_filter(ctx, data, size, &filter, &doms) == 0) {
        sss_certmap_free_filter_and_domains(filter, doms);
    }
    filter = NULL;
    doms = NULL;
    if (sss_certmap_expand_mapping_rule(ctx, data, size, &filter, &doms) == 0) {
        sss_certmap_free_filter_and_domains(filter, doms);
    }

    TALLOC_CTX *tmp = talloc_new(NULL);
    char *desc = NULL;
    sss_certmap_display_cert_content(tmp, data, size, &desc);
    talloc_free(tmp);

    sss_certmap_free_ctx(ctx);
    return 0;
}
