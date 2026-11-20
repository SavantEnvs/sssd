/* Fuzz the PAM responder's request handling (src/responder/pam/pamsrv_cmd.c):
 * the body of a packet any local user can write to the sssd pam socket, parsed
 * by pam_forwarder_parse_data() / pam_parse_in_data_v2() into a pam_data and
 * its sss_auth_token, then run through the responder's user lookup and
 * authentication path.
 *
 * The responder is set up the way upstream's src/tests/cmocka/test_pam_srv.c
 * sets it up (mock resp_ctx/cli_ctx, one LDAP-style test domain whose confdb
 * and sysdb live in a scratch dir under $TMPDIR, created once), with the data
 * provider replaced by pam_dp_stubs.c. The real packet code carries the input:
 * byte 0 selects the command from get_pam_cmds(), the rest becomes the body of
 * a fresh sss_packet, and sss_cmd_execute() dispatches it as the socket
 * handler would. The tevent loop is then run until the request has no more
 * work queued.
 *
 * State reset per input (resp_fuzz_common.c): each input runs in an ldb
 * transaction on the sysdb that is cancelled afterwards, and gets a fresh
 * negative cache and a fresh initgroups id_table, so its result depends
 * only on the input. Kept across inputs, read-only: the confdb, the domain
 * list and the certmap context. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <talloc.h>
#include <tevent.h>
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/pam/pamsrv.h"
#include "tests/common.h"
#include "responder/common/negcache.h"
#include "resp_fuzz_common.h"

struct resp_ctx *mock_rctx(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                           struct sss_domain_info *domains, void *pvt_ctx);
struct cli_ctx *mock_cctx(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx);
struct cli_protocol *mock_prctx(TALLOC_CTX *mem_ctx);
errno_t p11_refresh_certmap_ctx(struct pam_ctx *pctx,
                                struct sss_domain_info *domains);

#define TEST_DOM_NAME "pam_test"

static struct sss_test_ctx *tctx;
static struct pam_ctx *pctx;
static struct resp_ctx *rctx;
static struct sss_cmd_table *pam_cmds;
static size_t n_cmds;
static struct cli_protocol_version *proto_versions;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    struct sss_test_conf_param dom_params[] = {
        { "enumerate", "false" },
        { "cache_credentials", "true" },
        { "entry_cache_timeout", "300" },
        { NULL, NULL },
    };
    tctx = resp_fuzz_setup("pam", TEST_DOM_NAME, dom_params);
    if (tctx == NULL) return 0;   /* n_cmds == 0: inputs are skipped */
    tctx->dom->dns_name = talloc_strdup(tctx, TEST_DOM_NAME);
    if (sss_names_init(tctx, tctx->confdb, TEST_DOM_NAME,
                       &tctx->dom->names) != EOK) abort();

    pctx = talloc_zero(tctx, struct pam_ctx);
    if (pctx == NULL) abort();
    if (sss_hash_create(pctx, 10, &pctx->id_table) != EOK) abort();
    pctx->app_services = talloc_zero_array(pctx, char *, 2);
    if (p11_refresh_certmap_ctx(pctx, NULL) != 0) abort();
    pctx->initgroups_scheme = PAM_INITGR_NO_SESSION;

    rctx = mock_rctx(tctx, tctx->ev, tctx->dom, pctx);
    if (rctx == NULL) abort();
    rctx->cdb = tctx->confdb;
    pctx->rctx = rctx;

    pam_cmds = get_pam_cmds();
    for (n_cmds = 0; pam_cmds[n_cmds].fn != NULL; n_cmds++);
    proto_versions = register_cli_protocol_version();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || n_cmds == 0) return 0;

    TALLOC_CTX *iter = talloc_new(NULL);
    if (iter == NULL) return 0;

    /* fresh per-input state, see the header comment */
    resp_fuzz_begin(tctx);
    /* drops every non-permanent entry and repopulates the permanent ones
     * from the confdb, as the daemon does on start-up */
    if (sss_ncache_reset(rctx, rctx->ncache) != EOK) abort();
    talloc_zfree(pctx->id_table);
    if (sss_hash_create(pctx, 10, &pctx->id_table) != EOK) abort();

    struct cli_ctx *cctx = mock_cctx(iter, rctx);
    struct cli_protocol *prctx = cctx ? mock_prctx(cctx) : NULL;
    if (prctx == NULL) goto done;
    cctx->ev = tctx->ev;
    cctx->protocol_ctx = prctx;
    prctx->cli_protocol_version = proto_versions; /* newest: version 3 */

    enum sss_cli_command cmd = pam_cmds[data[0] % n_cmds].cmd;
    if (sss_packet_new(prctx->creq, size - 1, cmd, &prctx->creq->in) != EOK) {
        goto done;
    }
    uint8_t *body;
    size_t blen;
    sss_packet_get_body(prctx->creq->in, &body, &blen);
    if (blen != size - 1) goto done;
    memcpy(body, data + 1, size - 1);

    sss_cmd_execute(cctx, cmd, pam_cmds);

    resp_fuzz_drain(tctx->ev, iter);

done:
    talloc_free(iter);
    resp_fuzz_end(tctx);
    return 0;
}
