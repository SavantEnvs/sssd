/* Data-provider stand-ins for the PAM responder fuzz harness.
 *
 * The real responder talks to the sssd_be data provider over sbus/D-Bus; in
 * the harness there is no back end. These replace the cmocka mocks of
 * upstream's src/tests/cmocka/common_mock_resp_dp.c (same functions, same
 * "finish immediately" behaviour) without cmocka's will_return queue: every
 * account lookup completes with no new data (the answer comes from the
 * sysdb cache), and pam_dp_send_req() answers like an unreachable back end
 * (PAM_AUTHINFO_UNAVAIL), which is what upstream's pam_srv tests use the
 * --wrap of pam_dp_send_req for. */
#include <security/pam_appl.h>
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/pam/pamsrv.h"
#include "tests/common.h"

struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                        struct sss_domain_info *dom, bool fast_reply,
                        enum sss_dp_acct_type type, const char *opt_name,
                        uint32_t opt_id, const char *extra)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_account_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    return test_request_recv(req);
}

struct tevent_req *
sss_dp_resolver_get_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                         struct sss_domain_info *dom, bool fast_reply,
                         uint32_t entry_type, uint32_t query_type,
                         const char *query_value)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_resolver_get_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    return test_request_recv(req);
}

struct tevent_req *
sss_dp_get_ssh_host_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                         struct sss_domain_info *dom, bool fast_reply,
                         const char *name, const char *alias)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

/* sss_parse_inp_send/recv: the logic of the real implementation in
 * src/responder/common/responder_get_domains.c (that file also holds the
 * sbus-backed sss_dp_get_domains_send(), so it cannot be linked as is):
 * parse the name against the known domains, and on EAGAIN refresh the domain
 * list through the (stubbed) data provider and parse again. */
struct sss_parse_inp_state {
    char *name;
    char *domname;
    errno_t error;
};

struct tevent_req *
sss_parse_inp_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                   const char *default_domain, const char *rawinp)
{
    struct sss_parse_inp_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_parse_inp_state);
    if (req == NULL) return NULL;

    if (rawinp == NULL) {
        ret = EINVAL;
    } else {
        ret = sss_parse_name_for_domains(state, rctx->domains, default_domain,
                                         rawinp, &state->domname,
                                         &state->name);
        if (ret == EAGAIN && state->domname != NULL && state->name == NULL) {
            ret = ERR_DOMAIN_NOT_FOUND;
        } else if (ret != EOK) {
            ret = ERR_INPUT_PARSE;
        }
    }

    state->error = ret;
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);
    return req;
}

errno_t sss_parse_inp_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           char **_name, char **_domname)
{
    struct sss_parse_inp_state *state = tevent_req_data(req,
                                                struct sss_parse_inp_state);

    if (state->error != ERR_DOMAIN_NOT_FOUND) {
        TEVENT_REQ_RETURN_ON_ERROR(req);
    }

    if (_name != NULL) *_name = talloc_steal(mem_ctx, state->name);
    if (_domname != NULL) *_domname = talloc_steal(mem_ctx, state->domname);
    return state->error;
}

struct tevent_req *
sss_dp_get_domains_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                        bool force, const char *hint)
{
    if (sss_resp_populate_cr_domains(rctx) != EOK) {
        return NULL;
    }
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    return test_request_recv(req);
}

struct tevent_req *
sss_dp_get_account_domain_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                               struct sss_domain_info *domain, bool fast_reply,
                               enum sss_dp_acct_type type, uint32_t opt_id,
                               const char *opt_str)
{
    return test_req_succeed_send(mem_ctx, rctx->ev);
}

errno_t sss_dp_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       char **_domain)
{
    return ERR_GET_ACCT_DOM_NOT_SUPPORTED;
}

errno_t pam_dp_send_req(struct pam_auth_req *preq)
{
    preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
    preq->callback(preq);
    return EOK;
}
