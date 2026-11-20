/* Shared set-up and per-input reset for the responder fuzz harnesses
 * (fuzz_pam_cmd.c, fuzz_nss_cmd.c).
 *
 * resp_fuzz_setup(): the test domain the way upstream's cmocka responder
 * tests create it (create_dom_test_ctx() in src/tests/common_dom.c): a
 * confdb and an on-disk sysdb in a scratch dir. The scratch dir is made
 * under RESP_FUZZ_SCRATCH first (a world-writable dir build.sh creates in
 * the build tree, so no writable /tmp or working directory is needed at
 * run time), then $TMPDIR, /tmp and the working directory. The ldb module
 * dir with SSSD's memberof.so (RESP_FUZZ_LDB_MODULES) is also made by
 * build.sh. Each failure is printed with errno, and the failing step is
 * re-run with SSSD's debug output on stderr. If no location works, the
 * reason is printed and resp_fuzz_setup() returns NULL: the harness then
 * runs no command (n_cmds == 0) instead of aborting in
 * LLVMFuzzerInitialize, which Mayhem would report as a defect of every
 * input. Mayhem's coverage (edges) shows whether set-up worked.
 *
 * resp_fuzz_begin()/resp_fuzz_end(): every input runs inside one ldb
 * transaction on the sysdb (cache and timestamp cache) that is cancelled
 * afterwards. ldb counts nested transactions, so the responder's own
 * sysdb_transaction_start/commit pairs nest inside it and nothing an input
 * writes survives into the next input. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ldb.h>
#include "util/util.h"
#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "tests/common.h"
#include "resp_fuzz_common.h"

static bool make_scratch(const char *base, const char *tag, char *dir,
                         size_t dlen)
{
    snprintf(dir, dlen, "%s/sssd-fuzz-%s-XXXXXX", base, tag);
    if (mkdtemp(dir) == NULL) {
        fprintf(stderr, "resp_fuzz: mkdtemp(%s) failed: %s\n", dir,
                strerror(errno));
        return false;
    }
    /* sysdb needs SSSD's memberof ldb module next to ldb's own modules:
     * use the dir build.sh made, else make one in the scratch dir */
    if (access(RESP_FUZZ_LDB_MODULES "/memberof.so", R_OK) == 0) {
        setenv("LDB_MODULES_PATH", RESP_FUZZ_LDB_MODULES, 1);
        return true;
    }
    fprintf(stderr, "resp_fuzz: %s/memberof.so: %s\n", RESP_FUZZ_LDB_MODULES,
            strerror(errno));
    char path[4096], link[4096];
    snprintf(path, sizeof(path), "%s/ldb_modules", dir);
    snprintf(link, sizeof(link), "%s/memberof.so", path);
    if (mkdir(path, 0700) != 0 || symlink(MEMBEROF_SO, link) != 0) {
        fprintf(stderr, "resp_fuzz: ldb module dir %s: %s\n", path,
                strerror(errno));
        return false;
    }
    if (access(MEMBEROF_SO, R_OK) != 0) {
        fprintf(stderr, "resp_fuzz: %s: %s\n", MEMBEROF_SO, strerror(errno));
    }
    setenv("LDB_MODULES_PATH", path, 1);
    return true;
}

static struct sss_test_ctx *try_setup(const char *dir, const char *domain,
                                      struct sss_test_conf_param *params)
{
    static char tests_path[4096];
    snprintf(tests_path, sizeof(tests_path), "%s/tp", dir);
    test_dom_suite_setup(tests_path);
    return create_dom_test_ctx(NULL, tests_path, RESP_FUZZ_CONF_DB, domain,
                               "ldap", params);
}

struct sss_test_ctx *resp_fuzz_setup(const char *tag, const char *domain,
                                     struct sss_test_conf_param *params)
{
    const char *env = getenv("TMPDIR");
    const char *bases[] = { RESP_FUZZ_SCRATCH,
                            env != NULL && *env != '\0' ? env : "/tmp",
                            "/tmp", ".", NULL };
    char dir[4096];

    debug_level = SSSDBG_FATAL_FAILURE;
    for (int i = 0; bases[i] != NULL; i++) {
        if (!make_scratch(bases[i], tag, dir, sizeof(dir))) continue;
        struct sss_test_ctx *tctx = try_setup(dir, domain, params);
        if (tctx != NULL) {
            if (i > 0) {
                fprintf(stderr, "resp_fuzz: using scratch dir %s\n", dir);
            }
            return tctx;
        }
        /* show why: run the same step again with SSSD's debug output */
        fprintf(stderr, "resp_fuzz: create_dom_test_ctx() failed under %s "
                "(errno %d: %s), retrying with debug output\n", dir, errno,
                strerror(errno));
        sss_logger = STDERR_LOGGER;
        debug_level = SSSDBG_MASK_ALL;
        if (make_scratch(bases[i], tag, dir, sizeof(dir))) {
            struct sss_test_ctx *tctx2 = try_setup(dir, domain, params);
            if (tctx2 != NULL) {
                debug_level = SSSDBG_FATAL_FAILURE;
                return tctx2;
            }
        }
        debug_level = SSSDBG_FATAL_FAILURE;
    }
    fprintf(stderr, "resp_fuzz: set-up failed in every scratch dir; "
            "this harness will run no input\n");
    return NULL;
}

static struct ldb_context *ts_ldb(struct sss_test_ctx *tctx)
{
    return tctx->dom->sysdb->ldb_ts;
}

void resp_fuzz_begin(struct sss_test_ctx *tctx)
{
    if (ldb_transaction_start(sysdb_ctx_get_ldb(tctx->dom->sysdb)) != LDB_SUCCESS) {
        abort();
    }
    if (ts_ldb(tctx) != NULL && ldb_transaction_start(ts_ldb(tctx)) != LDB_SUCCESS) {
        abort();
    }
}

void resp_fuzz_end(struct sss_test_ctx *tctx)
{
    if (ts_ldb(tctx) != NULL) ldb_transaction_cancel(ts_ldb(tctx));
    ldb_transaction_cancel(sysdb_ctx_get_ldb(tctx->dom->sysdb));
}

static void tick(struct tevent_context *ev, struct tevent_timer *te,
                 struct timeval tv, void *pvt)
{
    *(bool *) pvt = true;
}

void resp_fuzz_drain(struct tevent_context *ev, TALLOC_CTX *mem_ctx)
{
    /* Run the work the request queued: each round runs whatever is
     * pending, the zero timer only keeps tevent_loop_once() from blocking
     * once nothing is left. */
    for (int i = 0; i < 256; i++) {
        bool fired = false;
        struct tevent_timer *te = tevent_add_timer(ev, mem_ctx,
                                                   tevent_timeval_zero(),
                                                   tick, &fired);
        if (te == NULL) break;
        tevent_loop_once(ev);
        if (!fired) {
            talloc_free(te);
        } else if (i > 8) {
            /* the timer ran: everything queued before it has run too */
            break;
        }
    }
}
