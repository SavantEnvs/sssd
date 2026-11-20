/* Fuzz SSSD's authentication-token blobs (src/util/authtok.c). The PAM
 * responder copies the authtok a PAM client sends over the pam socket into
 * an sss_auth_token with sss_authtok_set(); the providers and children then
 * unpack it with the typed getters (2FA, smartcard, passkey, OAuth2 ...).
 *
 * Byte 0 picks the token type (the SSS_AUTHTOK_TYPE_* values the protocol
 * carries), the rest is the blob. After sss_authtok_set() every getter is
 * called and the token is copied, as the PAM path does. */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include "util/util.h"
#include "util/authtok.h"

static const enum sss_authtok_type types[] = {
    SSS_AUTHTOK_TYPE_EMPTY, SSS_AUTHTOK_TYPE_PASSWORD, SSS_AUTHTOK_TYPE_CCFILE,
    SSS_AUTHTOK_TYPE_2FA, SSS_AUTHTOK_TYPE_SC_PIN, SSS_AUTHTOK_TYPE_SC_KEYPAD,
    SSS_AUTHTOK_TYPE_2FA_SINGLE, SSS_AUTHTOK_TYPE_OAUTH2,
    SSS_AUTHTOK_TYPE_PASSKEY, SSS_AUTHTOK_TYPE_PASSKEY_KRB,
    SSS_AUTHTOK_TYPE_PASSKEY_REPLY, SSS_AUTHTOK_TYPE_PAM_STACKED,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    debug_level = SSSDBG_FATAL_FAILURE;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    TALLOC_CTX *mem = talloc_new(NULL);
    if (mem == NULL) return 0;
    struct sss_auth_token *tok = sss_authtok_new(mem);
    struct sss_auth_token *copy = sss_authtok_new(mem);
    if (tok == NULL || copy == NULL) goto done;

    enum sss_authtok_type type = types[data[0] % (sizeof(types) / sizeof(types[0]))];
    /* sss_authtok_set() treats len == 0 as "data is a NUL-terminated
     * string" (authtok.h), so the blob is always followed by a NUL. */
    uint8_t *blob = malloc(size);
    if (blob == NULL) goto done;
    memcpy(blob, data + 1, size - 1);
    blob[size - 1] = '\0';
    errno_t ret = sss_authtok_set(tok, type, blob, size - 1);
    free(blob);
    if (ret != EOK) goto done;

    const char *s1 = NULL, *s2 = NULL, *s3 = NULL, *s4 = NULL, *s5 = NULL;
    size_t l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0;
    const uint8_t *b = NULL;
    size_t bl = 0;

    (void) sss_authtok_get_type(tok);
    (void) sss_authtok_get_size(tok);
    (void) sss_authtok_get_data(tok);
    sss_authtok_get_password(tok, &s1, &l1);
    sss_authtok_get_ccfile(tok, &s1, &l1);
    sss_authtok_get_2fa(tok, &s1, &l1, &s2, &l2);
    sss_authtok_get_2fa_single(tok, &s1, &l1);
    sss_authtok_get_sc_pin(tok, &s1, &l1);
    sss_authtok_get_sc(tok, &s1, &l1, &s2, &l2, &s3, &l3, &s4, &l4, &s5, &l5);
    sss_authtok_get_oauth2(tok, &s1, &l1);
    sss_authtok_get_passkey_reply(tok, &s1, &l1);
    sss_authtok_get_passkey_pin(tok, &s1, &l1);
    sss_authtok_get_passkey(mem, tok, &s1, &s2, &s3, &l3);
    (void) b; (void) bl;

    if (sss_authtok_copy(tok, copy) == EOK) {
        sss_authtok_get_2fa(copy, &s1, &l1, &s2, &l2);
        sss_authtok_get_passkey(mem, copy, &s1, &s2, &s3, &l3);
    }
    sss_authtok_wipe_password(tok);

done:
    talloc_free(mem);
    return 0;
}
