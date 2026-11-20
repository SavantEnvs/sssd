#ifndef RESP_FUZZ_COMMON_H
#define RESP_FUZZ_COMMON_H

#include <talloc.h>
#include <tevent.h>
#include "tests/common.h"

#define RESP_FUZZ_CONF_DB "fuzz_resp_conf.ldb"

struct sss_test_ctx *resp_fuzz_setup(const char *tag, const char *domain,
                                     struct sss_test_conf_param *params);
void resp_fuzz_begin(struct sss_test_ctx *tctx);
void resp_fuzz_end(struct sss_test_ctx *tctx);
void resp_fuzz_drain(struct tevent_context *ev, TALLOC_CTX *mem_ctx);

#endif
