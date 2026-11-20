/* Fuzz the NSS responder's request handling (src/responder/nss/nss_cmd.c and
 * nss_protocol*.c): the body of a packet any local user can write to the sssd
 * nss socket (/var/lib/sss/pipes/nss), parsed by the
 * sss_nss_protocol_parse_name, _id, _sid, _cert, _svc and _addr family into a
 * cache_req, looked up in the sysdb cache and turned into a reply packet.
 *
 * The responder is set up the way upstream's src/tests/cmocka/test_nss_srv.c
 * sets it up (mock nss_ctx/resp_ctx/cli_ctx, one LDAP-style test domain in a
 * scratch dir, created once), with the data provider replaced by
 * pam_dp_stubs.c (account lookups finish immediately, so answers come from the
 * cache). The cache holds one user and one group, written at start-up, so
 * lookups that match them run the reply builders too. The real packet code
 * carries the input: byte 0 selects the command from get_sss_nss_cmds(), the
 * rest becomes the body of a fresh sss_packet, and sss_cmd_execute()
 * dispatches it as the socket handler would.
 *
 * State reset per input (resp_fuzz_common.c): each input runs in an ldb
 * transaction on the sysdb that is cancelled afterwards, and gets a fresh
 * negative cache, fresh enumeration contexts and a fresh netgroup table.
 * Kept across inputs, read-only: the confdb, the domain list and the user and
 * group stored at start-up. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <talloc.h>
#include <tevent.h>
#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "util/util_sss_idmap.h"
#include "db/sysdb.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/common/negcache.h"
#include "responder/nss/nss_private.h"
#include "tests/common.h"
#include "resp_fuzz_common.h"

struct resp_ctx *mock_rctx(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                           struct sss_domain_info *domains, void *pvt_ctx);
struct cli_ctx *mock_cctx(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx);
struct cli_protocol *mock_prctx(TALLOC_CTX *mem_ctx);

#define TEST_DOM_NAME "nss_test"
#define TEST_DOM_SID "S-1-5-21-444379608-1639770488-2995963434"

/* the attribute list nsssrv.c:sss_nss_get_config() builds (as in
 * test_nss_srv.c's global_orig_attrs) */
static const char *orig_attrs[] = {
    SYSDB_SID_STR, ORIGINALAD_PREFIX SYSDB_NAME,
    ORIGINALAD_PREFIX SYSDB_UIDNUM, ORIGINALAD_PREFIX SYSDB_GIDNUM,
    ORIGINALAD_PREFIX SYSDB_HOMEDIR, ORIGINALAD_PREFIX SYSDB_GECOS,
    ORIGINALAD_PREFIX SYSDB_SHELL, SYSDB_UPN, SYSDB_DEFAULT_OVERRIDE_NAME,
    SYSDB_AD_ACCOUNT_EXPIRES, SYSDB_AD_USER_ACCOUNT_CONTROL, SYSDB_SSH_PUBKEY,
    SYSDB_USER_CERT, SYSDB_USER_EMAIL, SYSDB_ORIG_DN, SYSDB_ORIG_MEMBEROF,
    NULL
};

static struct sss_test_ctx *tctx;
static struct sss_nss_ctx *nctx;
static struct resp_ctx *rctx;
static struct sss_cmd_table *nss_cmds;
static size_t n_cmds;
static struct cli_protocol_version *proto_versions;

static void store_entries(void)
{
    struct sss_domain_info *dom = tctx->dom;
    time_t now = time(NULL);
    uint64_t timeout = 10 * 365 * 24 * 3600;
    char *user = sss_create_internal_fqname(tctx, "fuzzuser", dom->name);
    char *group = sss_create_internal_fqname(tctx, "fuzzgroup", dom->name);
    if (user == NULL || group == NULL) abort();

    struct sysdb_attrs *ua = sysdb_new_attrs(tctx);
    if (ua == NULL
        || sysdb_attrs_add_string(ua, SYSDB_UPN, "fuzzuser@NSS.TEST") != EOK
        || sysdb_attrs_add_string(ua, SYSDB_SID_STR, TEST_DOM_SID "-1001") != EOK) {
        abort();
    }
    if (sysdb_store_user(dom, user, "x", 1001, 1001, "Fuzz User",
                         "/home/fuzzuser", "/bin/sh", NULL, ua, NULL,
                         timeout, now) != EOK) abort();

    struct sysdb_attrs *ga = sysdb_new_attrs(tctx);
    if (ga == NULL
        || sysdb_attrs_add_string(ga, SYSDB_SID_STR, TEST_DOM_SID "-2001") != EOK) {
        abort();
    }
    if (sysdb_store_group(dom, group, 2001, ga, timeout, now) != EOK) abort();
    if (sysdb_add_group_member(dom, group, user, SYSDB_MEMBER_USER,
                               false) != EOK) abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { NULL, NULL },
    };
    tctx = resp_fuzz_setup("nss", TEST_DOM_NAME, dom_params);
    if (tctx == NULL) return 0;   /* n_cmds == 0: inputs are skipped */
    tctx->dom->domain_id = discard_const(TEST_DOM_SID);
    if (sss_names_init(tctx, tctx->confdb, TEST_DOM_NAME,
                       &tctx->dom->names) != EOK) abort();

    /* mock_nctx() of test_nss_srv.c */
    nctx = talloc_zero(tctx, struct sss_nss_ctx);
    if (nctx == NULL) abort();
    nctx->pwfield = discard_const("*");
    if (sss_idmap_init(sss_idmap_talloc, nctx, sss_idmap_talloc_free,
                       &nctx->idmap_ctx) != IDMAP_SUCCESS) abort();
    nctx->full_attribute_list = orig_attrs;

    rctx = mock_rctx(tctx, tctx->ev, tctx->dom, nctx);
    if (rctx == NULL) abort();
    rctx->cdb = tctx->confdb;
    nctx->rctx = rctx;
    if (sss_ad_default_names_ctx(nctx, &rctx->global_names) != EOK) abort();

    store_entries();

    nss_cmds = get_sss_nss_cmds();
    for (n_cmds = 0; nss_cmds[n_cmds].fn != NULL; n_cmds++);
    proto_versions = register_cli_protocol_version();
    return 0;
}

static void free_enum_ctxs(void)
{
    talloc_zfree(nctx->pwent);
    talloc_zfree(nctx->grent);
    talloc_zfree(nctx->svcent);
    talloc_zfree(nctx->hostent);
    talloc_zfree(nctx->netent);
    talloc_zfree(nctx->netgrent);
}

static void reset_nss_state(void)
{
    /* drops every non-permanent entry and repopulates the permanent ones
     * from the confdb, as the daemon does on start-up */
    if (sss_ncache_reset(rctx, rctx->ncache) != EOK) abort();
    /* created the way nsssrv.c:nss_process_init() creates them */
    free_enum_ctxs();
    nctx->pwent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    nctx->grent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    nctx->svcent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    nctx->hostent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    nctx->netent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    nctx->netgrent = sss_ptr_hash_create(nctx, NULL, NULL);
    if (nctx->pwent == NULL || nctx->grent == NULL || nctx->svcent == NULL
        || nctx->hostent == NULL || nctx->netent == NULL
        || nctx->netgrent == NULL) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || n_cmds == 0) return 0;

    TALLOC_CTX *iter = talloc_new(NULL);
    if (iter == NULL) return 0;

    resp_fuzz_begin(tctx);
    reset_nss_state();

    struct cli_ctx *cctx = mock_cctx(iter, rctx);
    if (cctx == NULL) goto done;
    cctx->ev = tctx->ev;
    /* nss specific state_ctx; it resets protocol_ctx, so set that after */
    if (sss_nss_connection_setup(cctx) != EOK) goto done;
    struct cli_protocol *prctx = mock_prctx(cctx);
    if (prctx == NULL) goto done;
    cctx->protocol_ctx = prctx;
    prctx->cli_protocol_version = proto_versions;

    enum sss_cli_command cmd = nss_cmds[data[0] % n_cmds].cmd;
    if (sss_packet_new(prctx->creq, size - 1, cmd, &prctx->creq->in) != EOK) {
        goto done;
    }
    uint8_t *body;
    size_t blen;
    sss_packet_get_body(prctx->creq->in, &body, &blen);
    if (blen != size - 1) goto done;
    memcpy(body, data + 1, size - 1);

    sss_cmd_execute(cctx, cmd, nss_cmds);

    resp_fuzz_drain(tctx->ev, iter);

done:
    talloc_free(iter);
    /* enumeration contexts can hold requests of this input's client */
    free_enum_ctxs();
    resp_fuzz_end(tctx);
    return 0;
}
