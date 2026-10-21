#include "auth.h"

#include "crypto.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define AUTH_VMK_AAD_MAX_BYTES \
    ((sizeof(AUTH_VMK_AAD_PREFIX) - 1) + 4 + 2 + AUTH_USER_ID_MAX_BYTES)

static int ranges_overlap(const void *first, size_t first_length,
                          const void *second, size_t second_length)
{
    uintptr_t first_address;
    uintptr_t second_address;

    if (first_length == 0 || second_length == 0) {
        return 0;
    }
    first_address = (uintptr_t)first;
    second_address = (uintptr_t)second;
    if (first_address <= second_address) {
        return second_address - first_address < first_length;
    }
    return first_address - second_address < second_length;
}

static int create_hmac_sha256(const unsigned char *key, size_t key_length,
                              const unsigned char *message, size_t message_length,
                              unsigned char output[AUTH_VERIFIER_BYTES])
{
    EVP_MAC *algorithm = NULL;
    EVP_MAC_CTX *context = NULL;
    char digest[] = "SHA256";
    size_t output_length = 0;
    int success = 0;
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };

    algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (algorithm == NULL) {
        goto cleanup;
    }
    context = EVP_MAC_CTX_new(algorithm);
    if (context == NULL ||
        EVP_MAC_init(context, key, key_length, parameters) != 1 ||
        EVP_MAC_update(context, message, message_length) != 1 ||
        EVP_MAC_final(context, output, &output_length, AUTH_VERIFIER_BYTES) != 1 ||
        output_length != AUTH_VERIFIER_BYTES) {
        goto cleanup;
    }
    success = 1;

cleanup:
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(algorithm);
    return success;
}

int auth_create_verifier(const unsigned char *authentication_key,
                         size_t authentication_key_length,
                         unsigned char *verifier, size_t verifier_capacity)
{
    static const unsigned char message[] = AUTH_VERIFIER_MESSAGE;
    unsigned char temporary[AUTH_VERIFIER_BYTES] = {0};
    int success = 0;

    if (authentication_key == NULL ||
        authentication_key_length != CRYPTO_KEY_BYTES ||
        verifier == NULL || verifier_capacity < AUTH_VERIFIER_BYTES ||
        ranges_overlap(authentication_key, authentication_key_length,
                       verifier, AUTH_VERIFIER_BYTES)) {
        return 0;
    }
    if (!create_hmac_sha256(authentication_key, authentication_key_length,
                            message, sizeof(message) - 1, temporary)) {
        goto cleanup;
    }
    memcpy(verifier, temporary, sizeof(temporary));
    success = 1;

cleanup:
    OPENSSL_cleanse(temporary, sizeof(temporary));
    return success;
}

int auth_verify_verifier(const unsigned char *authentication_key,
                         size_t authentication_key_length,
                         const unsigned char *stored_verifier,
                         size_t stored_verifier_length)
{
    unsigned char expected[AUTH_VERIFIER_BYTES] = {0};
    int matches = 0;

    if (stored_verifier == NULL || stored_verifier_length != AUTH_VERIFIER_BYTES) {
        return 0;
    }
    if (auth_create_verifier(authentication_key, authentication_key_length,
                             expected, sizeof(expected))) {
        matches = CRYPTO_memcmp(expected, stored_verifier,
                                AUTH_VERIFIER_BYTES) == 0;
    }
    OPENSSL_cleanse(expected, sizeof(expected));
    return matches;
}

static int build_vmk_aad(const unsigned char *user_id, size_t user_id_length,
                         uint32_t format_version,
                         unsigned char aad[AUTH_VMK_AAD_MAX_BYTES],
                         size_t *aad_length)
{
    static const unsigned char prefix[] = AUTH_VMK_AAD_PREFIX;
    size_t position = 0;

    if (user_id == NULL || user_id_length == 0 ||
        user_id_length > AUTH_USER_ID_MAX_BYTES ||
        format_version != AUTH_VMK_FORMAT_VERSION || aad_length == NULL) {
        return 0;
    }
    memcpy(aad + position, prefix, sizeof(prefix) - 1);
    position += sizeof(prefix) - 1;
    aad[position++] = (unsigned char)(format_version >> 24);
    aad[position++] = (unsigned char)(format_version >> 16);
    aad[position++] = (unsigned char)(format_version >> 8);
    aad[position++] = (unsigned char)format_version;
    aad[position++] = (unsigned char)(user_id_length >> 8);
    aad[position++] = (unsigned char)user_id_length;
    memcpy(aad + position, user_id, user_id_length);
    position += user_id_length;
    *aad_length = position;
    return 1;
}

static int valid_wrap_outputs(const unsigned char *kek, size_t kek_length,
                              const unsigned char *user_id, size_t user_id_length,
                              unsigned char *vmk, unsigned char *wrapped_vmk,
                              unsigned char *nonce, unsigned char *tag)
{
    return !ranges_overlap(vmk, AUTH_VMK_BYTES, wrapped_vmk,
                           AUTH_WRAPPED_VMK_BYTES) &&
           !ranges_overlap(vmk, AUTH_VMK_BYTES, nonce, AUTH_VMK_NONCE_BYTES) &&
           !ranges_overlap(vmk, AUTH_VMK_BYTES, tag, AUTH_VMK_TAG_BYTES) &&
           !ranges_overlap(wrapped_vmk, AUTH_WRAPPED_VMK_BYTES,
                           nonce, AUTH_VMK_NONCE_BYTES) &&
           !ranges_overlap(wrapped_vmk, AUTH_WRAPPED_VMK_BYTES,
                           tag, AUTH_VMK_TAG_BYTES) &&
           !ranges_overlap(nonce, AUTH_VMK_NONCE_BYTES, tag, AUTH_VMK_TAG_BYTES) &&
           !ranges_overlap(vmk, AUTH_VMK_BYTES, kek, kek_length) &&
           !ranges_overlap(wrapped_vmk, AUTH_WRAPPED_VMK_BYTES, kek, kek_length) &&
           !ranges_overlap(nonce, AUTH_VMK_NONCE_BYTES, kek, kek_length) &&
           !ranges_overlap(tag, AUTH_VMK_TAG_BYTES, kek, kek_length) &&
           !ranges_overlap(vmk, AUTH_VMK_BYTES, user_id, user_id_length) &&
           !ranges_overlap(wrapped_vmk, AUTH_WRAPPED_VMK_BYTES,
                           user_id, user_id_length) &&
           !ranges_overlap(nonce, AUTH_VMK_NONCE_BYTES, user_id, user_id_length) &&
           !ranges_overlap(tag, AUTH_VMK_TAG_BYTES, user_id, user_id_length);
}

int auth_generate_wrapped_vmk(const unsigned char *kek, size_t kek_length,
                              const unsigned char *user_id, size_t user_id_length,
                              uint32_t format_version,
                              unsigned char *vmk, size_t vmk_capacity,
                              unsigned char *wrapped_vmk,
                              size_t wrapped_vmk_capacity,
                              unsigned char *nonce, size_t nonce_capacity,
                              unsigned char *tag, size_t tag_capacity)
{
    unsigned char aad[AUTH_VMK_AAD_MAX_BYTES] = {0};
    unsigned char temporary_vmk[AUTH_VMK_BYTES] = {0};
    unsigned char temporary_wrapped[AUTH_WRAPPED_VMK_BYTES] = {0};
    unsigned char temporary_nonce[AUTH_VMK_NONCE_BYTES] = {0};
    unsigned char temporary_tag[AUTH_VMK_TAG_BYTES] = {0};
    size_t aad_length = 0;
    size_t wrapped_length = 0;
    int success = 0;

    if (kek == NULL || kek_length != CRYPTO_KEY_BYTES ||
        vmk == NULL || vmk_capacity < AUTH_VMK_BYTES ||
        wrapped_vmk == NULL || wrapped_vmk_capacity < AUTH_WRAPPED_VMK_BYTES ||
        nonce == NULL || nonce_capacity < AUTH_VMK_NONCE_BYTES ||
        tag == NULL || tag_capacity < AUTH_VMK_TAG_BYTES ||
        !build_vmk_aad(user_id, user_id_length, format_version,
                       aad, &aad_length) ||
        !valid_wrap_outputs(kek, kek_length, user_id, user_id_length,
                            vmk, wrapped_vmk, nonce, tag)) {
        goto cleanup;
    }
    if (!crypto_random(temporary_vmk, sizeof(temporary_vmk)) ||
        !crypto_aes256_gcm_encrypt(kek, kek_length,
                                   temporary_vmk, sizeof(temporary_vmk),
                                   aad, aad_length,
                                   temporary_wrapped, sizeof(temporary_wrapped),
                                   &wrapped_length,
                                   temporary_nonce, sizeof(temporary_nonce),
                                   temporary_tag, sizeof(temporary_tag)) ||
        wrapped_length != AUTH_WRAPPED_VMK_BYTES) {
        goto cleanup;
    }
    memcpy(vmk, temporary_vmk, sizeof(temporary_vmk));
    memcpy(wrapped_vmk, temporary_wrapped, sizeof(temporary_wrapped));
    memcpy(nonce, temporary_nonce, sizeof(temporary_nonce));
    memcpy(tag, temporary_tag, sizeof(temporary_tag));
    success = 1;

cleanup:
    OPENSSL_cleanse(aad, sizeof(aad));
    OPENSSL_cleanse(temporary_vmk, sizeof(temporary_vmk));
    OPENSSL_cleanse(temporary_wrapped, sizeof(temporary_wrapped));
    OPENSSL_cleanse(temporary_nonce, sizeof(temporary_nonce));
    OPENSSL_cleanse(temporary_tag, sizeof(temporary_tag));
    return success;
}

int auth_unwrap_vmk(const unsigned char *kek, size_t kek_length,
                    const unsigned char *user_id, size_t user_id_length,
                    uint32_t format_version,
                    const unsigned char *wrapped_vmk,
                    size_t wrapped_vmk_length,
                    const unsigned char *nonce, size_t nonce_length,
                    const unsigned char *tag, size_t tag_length,
                    unsigned char *vmk, size_t vmk_capacity)
{
    unsigned char aad[AUTH_VMK_AAD_MAX_BYTES] = {0};
    unsigned char temporary_vmk[AUTH_VMK_BYTES] = {0};
    size_t aad_length = 0;
    size_t vmk_length = 0;
    int success = 0;

    if (kek == NULL || kek_length != CRYPTO_KEY_BYTES ||
        wrapped_vmk == NULL || wrapped_vmk_length != AUTH_WRAPPED_VMK_BYTES ||
        nonce == NULL || nonce_length != AUTH_VMK_NONCE_BYTES ||
        tag == NULL || tag_length != AUTH_VMK_TAG_BYTES ||
        vmk == NULL || vmk_capacity < AUTH_VMK_BYTES ||
        !build_vmk_aad(user_id, user_id_length, format_version,
                       aad, &aad_length) ||
        ranges_overlap(vmk, AUTH_VMK_BYTES, kek, kek_length) ||
        ranges_overlap(vmk, AUTH_VMK_BYTES, user_id, user_id_length) ||
        ranges_overlap(vmk, AUTH_VMK_BYTES,
                       wrapped_vmk, wrapped_vmk_length) ||
        ranges_overlap(vmk, AUTH_VMK_BYTES, nonce, nonce_length) ||
        ranges_overlap(vmk, AUTH_VMK_BYTES, tag, tag_length)) {
        goto cleanup;
    }
    if (!crypto_aes256_gcm_decrypt(kek, kek_length,
                                   wrapped_vmk, wrapped_vmk_length,
                                   aad, aad_length,
                                   nonce, nonce_length, tag, tag_length,
                                   temporary_vmk, sizeof(temporary_vmk),
                                   &vmk_length) ||
        vmk_length != AUTH_VMK_BYTES) {
        goto cleanup;
    }
    memcpy(vmk, temporary_vmk, sizeof(temporary_vmk));
    success = 1;

cleanup:
    OPENSSL_cleanse(aad, sizeof(aad));
    OPENSSL_cleanse(temporary_vmk, sizeof(temporary_vmk));
    return success;
}
