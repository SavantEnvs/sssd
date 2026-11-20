/* Fuzz libsss_idmap's SID parsers and the SID -> POSIX ID mapping. SIDs come
 * from AD/IPA LDAP objectSid attributes (binary) and from clients asking the
 * NSS responder for getsidbyname/getidbysid (string form).
 *
 * Byte 0 selects the form: even -> rest is a SID string, odd -> rest is a
 * binary SID. Every conversion the library offers from that form is run, the
 * results are converted back, and the SID is mapped through a context with two
 * fixed domains plus (for strings) a domain whose SID is the input itself. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lib/idmap/sss_idmap.h"

static void check_string_sid(struct sss_idmap_ctx *ctx, const char *sid)
{
    uint8_t *bin = NULL;
    size_t blen = 0;
    struct sss_dom_sid *dom = NULL;
    struct dom_sid *smb = NULL;
    char *back = NULL;
    uint32_t id;

    if (sss_idmap_sid_to_bin_sid(ctx, sid, &bin, &blen) == IDMAP_SUCCESS) {
        if (sss_idmap_bin_sid_to_sid(ctx, bin, blen, &back) == IDMAP_SUCCESS) {
            sss_idmap_free_sid(ctx, back);
        }
        sss_idmap_free_bin_sid(ctx, bin);
    }
    if (sss_idmap_sid_to_dom_sid(ctx, sid, &dom) == IDMAP_SUCCESS) {
        back = NULL;
        if (sss_idmap_dom_sid_to_sid(ctx, dom, &back) == IDMAP_SUCCESS) {
            sss_idmap_free_sid(ctx, back);
        }
        sss_idmap_dom_sid_to_unix(ctx, dom, &id);
        sss_idmap_free_dom_sid(ctx, dom);
    }
    if (sss_idmap_sid_to_smb_sid(ctx, sid, &smb) == IDMAP_SUCCESS) {
        back = NULL;
        if (sss_idmap_smb_sid_to_sid(ctx, smb, &back) == IDMAP_SUCCESS) {
            sss_idmap_free_sid(ctx, back);
        }
        sss_idmap_free_smb_sid(ctx, smb);
    }
    sss_idmap_sid_to_unix(ctx, sid, &id);
    sss_idmap_check_sid_unix(ctx, sid, 200000);

    /* The input as a domain SID: range calculation (murmurhash slice) and
     * adding the domain, then mapping a RID under it. */
    struct sss_idmap_range range;
    id_t slice;
    if (sss_idmap_calculate_range(ctx, sid, &slice, &range) == IDMAP_SUCCESS) {
        if (sss_idmap_add_domain_ex(ctx, "fuzz.dom", sid, &range, NULL, 0,
                                    false) == IDMAP_SUCCESS) {
            size_t n = strlen(sid);
            char *rid = malloc(n + 8);
            if (rid != NULL) {
                memcpy(rid, sid, n);
                memcpy(rid + n, "-1105", 6);
                sss_idmap_sid_to_unix(ctx, rid, &id);
                free(rid);
            }
        }
    }
}

static void check_binary_sid(struct sss_idmap_ctx *ctx, const uint8_t *bin,
                             size_t len)
{
    struct sss_dom_sid *dom = NULL;
    struct dom_sid *smb = NULL;
    char *sid = NULL;
    uint32_t id;

    if (sss_idmap_bin_sid_to_sid(ctx, bin, len, &sid) == IDMAP_SUCCESS) {
        sss_idmap_sid_to_unix(ctx, sid, &id);
        sss_idmap_free_sid(ctx, sid);
    }
    if (sss_idmap_bin_sid_to_dom_sid(ctx, bin, len, &dom) == IDMAP_SUCCESS) {
        sss_idmap_free_dom_sid(ctx, dom);
    }
    if (sss_idmap_bin_sid_to_smb_sid(ctx, bin, len, &smb) == IDMAP_SUCCESS) {
        sss_idmap_free_smb_sid(ctx, smb);
    }
    sss_idmap_bin_sid_to_unix(ctx, (uint8_t *) bin, len, &id);
    sss_idmap_check_bin_sid_unix(ctx, (uint8_t *) bin, len, 200000);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    struct sss_idmap_ctx *ctx = NULL;
    if (sss_idmap_init(NULL, NULL, NULL, &ctx) != IDMAP_SUCCESS) return 0;
    struct sss_idmap_range r1 = { 200000, 399999 };
    struct sss_idmap_range r2 = { 400000, 599999 };
    sss_idmap_add_domain(ctx, "test.dom", "S-1-5-21-2153326666-2176343378-3404031434", &r1);
    sss_idmap_add_domain_ex(ctx, "ext.dom", "S-1-5-21-1-2-3", &r2, "ext", 1000, true);

    if ((data[0] & 1) == 0) {
        char *sid = malloc(size);
        if (sid != NULL) {
            memcpy(sid, data + 1, size - 1);
            sid[size - 1] = '\0';
            check_string_sid(ctx, sid);
            free(sid);
        }
    } else {
        uint8_t *bin = malloc(size - 1 ? size - 1 : 1);
        if (bin != NULL) {
            memcpy(bin, data + 1, size - 1);
            check_binary_sid(ctx, bin, size - 1);
            free(bin);
        }
    }

    sss_idmap_free(ctx);
    return 0;
}
