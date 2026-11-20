/* Fuzz SSSD's certificate / SSH public-key utilities (src/util/cert/,
 * src/util/sss_ssh.c). They turn LDAP userCertificate / sshPublicKey values and
 * smartcard certificates into the SSH keys the ssh responder hands to sshd
 * (sss_ssh_authorizedkeys) and into LDAP filter values.
 *
 * Byte 0 selects the form of the rest:
 *   0: DER certificate -> PEM round trip, SSH key extraction + formatting,
 *      LDAP filter escaping
 *   1: text -> PEM -> DER / base64-DER, and base64-DER -> PEM / SSH key
 *   2: raw SSH public-key blob -> sss_ssh_format_pubkey() */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include "util/util.h"
#include "util/cert.h"
#include "util/sss_ssh.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    debug_level = SSSDBG_FATAL_FAILURE;
    return 0;
}

static void format_key(TALLOC_CTX *mem, uint8_t *blob, size_t len)
{
    struct sss_ssh_pubkey key = { .data = blob, .data_len = len };
    char *out = NULL;
    sss_ssh_format_pubkey(mem, &key, &out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    TALLOC_CTX *mem = talloc_new(NULL);
    if (mem == NULL) return 0;

    size_t len = size - 1;
    /* heap copy with a trailing NUL: the text APIs take C strings */
    uint8_t *buf = talloc_size(mem, size);
    if (buf == NULL) goto done;
    memcpy(buf, data + 1, len);
    buf[len] = '\0';

    uint8_t *der = NULL, *key = NULL;
    size_t der_len = 0, key_len = 0, pem_len = 0;
    char *pem = NULL, *b64 = NULL, *filter = NULL;

    switch (data[0] % 3) {
    case 0:
        if (sss_cert_der_to_pem(mem, buf, len, &pem, &pem_len) == EOK) {
            sss_cert_pem_to_der(mem, pem, &der, &der_len);
        }
        if (get_ssh_key_from_cert(mem, buf, len, &key, &key_len) == EOK) {
            format_key(mem, key, key_len);
        }
        bin_to_ldap_filter_value(mem, buf, len, &filter);
        break;
    case 1:
        if (sss_cert_pem_to_der(mem, (const char *) buf, &der, &der_len) == EOK) {
            bin_to_ldap_filter_value(mem, der, der_len, &filter);
        }
        sss_cert_pem_to_derb64(mem, (const char *) buf, &b64);
        sss_cert_derb64_to_pem(mem, (const char *) buf, &pem, &pem_len);
        if (get_ssh_key_from_derb64(mem, (const char *) buf, &key, &key_len) == EOK) {
            format_key(mem, key, key_len);
        }
        break;
    default:
        format_key(mem, buf, len);
        break;
    }

done:
    talloc_free(mem);
    return 0;
}
