#ifndef SECUREPM_AUTH_H
#define SECUREPM_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define AUTH_VERIFIER_BYTES 32
#define AUTH_VMK_BYTES 32
#define AUTH_WRAPPED_VMK_BYTES 32
#define AUTH_VMK_NONCE_BYTES 12
#define AUTH_VMK_TAG_BYTES 16
#define AUTH_USER_ID_MAX_BYTES 255
#define AUTH_VMK_FORMAT_VERSION UINT32_C(1)
#define AUTH_VERIFIER_MESSAGE "securepm:auth-verifier:v1"
#define AUTH_VMK_AAD_PREFIX "securepm:vmk-wrap"

/* The verifier is HMAC-SHA256(authentication_key,
 * "securepm:auth-verifier:v1"), excluding the terminating NUL. */
int auth_create_verifier(const unsigned char *authentication_key,
                         size_t authentication_key_length,
                         unsigned char *verifier, size_t verifier_capacity);
int auth_verify_verifier(const unsigned char *authentication_key,
                         size_t authentication_key_length,
                         const unsigned char *stored_verifier,
                         size_t stored_verifier_length);

/* Generates a random VMK and wraps it under the KEK. The VMK is returned only
 * for immediate in-memory use; callers must clear it when the vault is locked.
 * All input and output buffers must be distinct. Outputs are published together
 * only after every operation succeeds and are otherwise left untouched. */
int auth_generate_wrapped_vmk(const unsigned char *kek, size_t kek_length,
                              const unsigned char *user_id, size_t user_id_length,
                              uint32_t format_version,
                              unsigned char *vmk, size_t vmk_capacity,
                              unsigned char *wrapped_vmk,
                              size_t wrapped_vmk_capacity,
                              unsigned char *nonce, size_t nonce_capacity,
                              unsigned char *tag, size_t tag_capacity);

/* Releases the VMK only after AES-GCM authenticates the wrapped key and AAD.
 * Failed unwrapping leaves the caller's VMK buffer untouched. */
int auth_unwrap_vmk(const unsigned char *kek, size_t kek_length,
                    const unsigned char *user_id, size_t user_id_length,
                    uint32_t format_version,
                    const unsigned char *wrapped_vmk,
                    size_t wrapped_vmk_length,
                    const unsigned char *nonce, size_t nonce_length,
                    const unsigned char *tag, size_t tag_length,
                    unsigned char *vmk, size_t vmk_capacity);

#endif
