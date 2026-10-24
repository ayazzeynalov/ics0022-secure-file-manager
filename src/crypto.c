#include "crypto.h"

#include <limits.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

const struct crypto_scrypt_params crypto_scrypt_defaults = {
    32768, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY
};

int crypto_random(unsigned char *output, size_t length)
{
    if (output == NULL || length == 0 || length > INT_MAX) {
        return 0;
    }
    if (RAND_bytes(output, (int)length) != 1) {
        OPENSSL_cleanse(output, length);
        return 0;
    }
    return 1;
}

static int valid_scrypt_params(const struct crypto_scrypt_params *params)
{
    /* Bound work as well as memory before accepting future stored parameters.
     * Lower costs are supported for compatibility/testing, not new user records. */
    return params != NULL && params->n >= 2 && params->n <= 32768 &&
           (params->n & (params->n - 1)) == 0 &&
           params->r >= 1 && params->r <= 8 &&
           params->p == 1 && params->max_memory > 0 &&
           params->max_memory <= CRYPTO_SCRYPT_MAX_MEMORY;
}

int crypto_derive_root(const char *password, size_t password_length,
                       const unsigned char *salt, size_t salt_length,
                       const struct crypto_scrypt_params *params,
                       unsigned char *root, size_t root_length)
{
    unsigned char temporary[CRYPTO_KEY_BYTES] = {0};
    int success = 0;

    if (root == NULL || root_length != CRYPTO_KEY_BYTES) {
        return 0;
    }
    if (password == NULL || password_length == 0 ||
        password_length > CRYPTO_PASSWORD_MAX_BYTES ||
        salt == NULL || salt_length != CRYPTO_SALT_BYTES ||
        !valid_scrypt_params(params)) {
        goto cleanup;
    }
    if (EVP_PBE_scrypt(password, password_length, salt, salt_length,
                       params->n, params->r, params->p, params->max_memory,
                       temporary, sizeof(temporary)) != 1) {
        goto cleanup;
    }
    memcpy(root, temporary, sizeof(temporary));
    success = 1;

cleanup:
    OPENSSL_cleanse(temporary, sizeof(temporary));
    if (!success) {
        OPENSSL_cleanse(root, root_length);
    }
    return success;
}

int crypto_hkdf_sha256(const unsigned char *key, size_t key_length,
                       const unsigned char *salt, size_t salt_length,
                       const unsigned char *info, size_t info_length,
                       unsigned char *output, size_t output_length)
{
    EVP_KDF *algorithm = NULL;
    EVP_KDF_CTX *context = NULL;
    unsigned char empty = 0;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    char digest[] = "SHA256";
    int success = 0;

    if (output == NULL || output_length == 0 || output_length > 255 * 32) {
        return 0;
    }
    if (key == NULL || key_length == 0 || key_length > 1024 ||
        (salt == NULL && salt_length != 0) || salt_length > 1024 ||
        (info == NULL && info_length != 0) || info_length > 1024) {
        goto cleanup;
    }
    /* OpenSSL's parameter constructors take void *, but derivation only reads
     * these input buffers. An empty salt follows RFC 5869's default salt rule. */
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, key_length),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          salt == NULL ? &empty : (void *)salt, salt_length),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          info == NULL ? &empty : (void *)info, info_length),
        OSSL_PARAM_construct_end()
    };
    algorithm = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (algorithm == NULL) {
        goto cleanup;
    }
    context = EVP_KDF_CTX_new(algorithm);
    if (context == NULL || EVP_KDF_derive(context, output, output_length, parameters) != 1) {
        goto cleanup;
    }
    success = 1;

cleanup:
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(algorithm);
    if (!success) {
        OPENSSL_cleanse(output, output_length);
    }
    return success;
}

int crypto_derive_keys(const unsigned char *root, size_t root_length,
                       struct crypto_keys *keys)
{
    struct crypto_keys temporary = {0};
    int success = 0;

    if (keys == NULL) {
        return 0;
    }
    if (root == NULL || root_length != CRYPTO_KEY_BYTES) {
        goto cleanup;
    }
    if (!crypto_hkdf_sha256(root, root_length, NULL, 0,
                            (const unsigned char *)CRYPTO_AUTH_CONTEXT,
                            sizeof(CRYPTO_AUTH_CONTEXT) - 1,
                            temporary.authentication, sizeof(temporary.authentication)) ||
        !crypto_hkdf_sha256(root, root_length, NULL, 0,
                            (const unsigned char *)CRYPTO_KEK_CONTEXT,
                            sizeof(CRYPTO_KEK_CONTEXT) - 1,
                            temporary.kek, sizeof(temporary.kek))) {
        goto cleanup;
    }
    memcpy(keys, &temporary, sizeof(temporary));
    success = 1;

cleanup:
    OPENSSL_cleanse(&temporary, sizeof(temporary));
    if (!success) {
        OPENSSL_cleanse(keys, sizeof(*keys));
    }
    return success;
}

static int valid_gcm_input(const unsigned char *key, size_t key_length,
                           const unsigned char *data, size_t data_length,
                           const unsigned char *aad, size_t aad_length)
{
    return key != NULL && key_length == CRYPTO_KEY_BYTES &&
           (data != NULL || data_length == 0) && data_length <= INT_MAX &&
           (aad != NULL || aad_length == 0) && aad_length <= INT_MAX;
}

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

int crypto_aes256_gcm_encrypt(const unsigned char *key, size_t key_length,
                              const unsigned char *plaintext, size_t plaintext_length,
                              const unsigned char *aad, size_t aad_length,
                              unsigned char *ciphertext, size_t ciphertext_capacity,
                              size_t *ciphertext_length,
                              unsigned char *nonce, size_t nonce_capacity,
                              unsigned char *tag, size_t tag_capacity)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char temporary_nonce[CRYPTO_GCM_NONCE_BYTES] = {0};
    unsigned char temporary_tag[CRYPTO_GCM_TAG_BYTES] = {0};
    unsigned char empty_output = 0;
    unsigned char *output = ciphertext == NULL ? &empty_output : ciphertext;
    int written = 0;
    int final_written = 0;
    int aad_written = 0;
    int success = 0;

    if (ciphertext_length == NULL) {
        return 0;
    }
    *ciphertext_length = 0;
    if (!valid_gcm_input(key, key_length, plaintext, plaintext_length, aad, aad_length) ||
        (ciphertext == NULL && (plaintext_length != 0 || ciphertext_capacity != 0)) ||
        ciphertext_capacity < plaintext_length ||
        nonce == NULL || nonce_capacity < CRYPTO_GCM_NONCE_BYTES ||
        tag == NULL || tag_capacity < CRYPTO_GCM_TAG_BYTES ||
        ranges_overlap(ciphertext, plaintext_length, plaintext, plaintext_length) ||
        ranges_overlap(ciphertext, plaintext_length, key, key_length) ||
        ranges_overlap(ciphertext, plaintext_length, aad, aad_length) ||
        ranges_overlap(ciphertext, plaintext_length, nonce, CRYPTO_GCM_NONCE_BYTES) ||
        ranges_overlap(ciphertext, plaintext_length, tag, CRYPTO_GCM_TAG_BYTES) ||
        ranges_overlap(nonce, CRYPTO_GCM_NONCE_BYTES, tag, CRYPTO_GCM_TAG_BYTES) ||
        ranges_overlap(nonce, CRYPTO_GCM_NONCE_BYTES, plaintext, plaintext_length) ||
        ranges_overlap(nonce, CRYPTO_GCM_NONCE_BYTES, key, key_length) ||
        ranges_overlap(nonce, CRYPTO_GCM_NONCE_BYTES, aad, aad_length) ||
        ranges_overlap(tag, CRYPTO_GCM_TAG_BYTES, plaintext, plaintext_length) ||
        ranges_overlap(tag, CRYPTO_GCM_TAG_BYTES, key, key_length) ||
        ranges_overlap(tag, CRYPTO_GCM_TAG_BYTES, aad, aad_length)) {
        return 0;
    }
    if (!crypto_random(temporary_nonce, sizeof(temporary_nonce))) {
        goto cleanup;
    }
    context = EVP_CIPHER_CTX_new();
    if (context == NULL ||
        EVP_EncryptInit_ex2(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                            CRYPTO_GCM_NONCE_BYTES, NULL) != 1 ||
        EVP_EncryptInit_ex2(context, NULL, key, temporary_nonce, NULL) != 1) {
        goto cleanup;
    }
    if (aad_length != 0 &&
        EVP_EncryptUpdate(context, NULL, &aad_written, aad, (int)aad_length) != 1) {
        goto cleanup;
    }
    if (plaintext_length != 0 &&
        EVP_EncryptUpdate(context, output, &written,
                          plaintext, (int)plaintext_length) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(context, output + written, &final_written) != 1 ||
        written < 0 || final_written < 0 ||
        (size_t)written + (size_t)final_written != plaintext_length ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG,
                            CRYPTO_GCM_TAG_BYTES, temporary_tag) != 1) {
        goto cleanup;
    }
    memcpy(nonce, temporary_nonce, sizeof(temporary_nonce));
    memcpy(tag, temporary_tag, sizeof(temporary_tag));
    *ciphertext_length = plaintext_length;
    success = 1;

cleanup:
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(temporary_nonce, sizeof(temporary_nonce));
    OPENSSL_cleanse(temporary_tag, sizeof(temporary_tag));
    if (!success && ciphertext != NULL && plaintext_length != 0) {
        OPENSSL_cleanse(ciphertext, plaintext_length);
    }
    return success;
}

int crypto_aes256_gcm_decrypt(const unsigned char *key, size_t key_length,
                              const unsigned char *ciphertext, size_t ciphertext_length,
                              const unsigned char *aad, size_t aad_length,
                              const unsigned char *nonce, size_t nonce_length,
                              const unsigned char *tag, size_t tag_length,
                              unsigned char *plaintext, size_t plaintext_capacity,
                              size_t *plaintext_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *temporary = NULL;
    int written = 0;
    int final_written = 0;
    int aad_written = 0;
    int success = 0;
    size_t temporary_length = ciphertext_length == 0 ? 1 : ciphertext_length;

    if (plaintext_length == NULL) {
        return 0;
    }
    *plaintext_length = 0;
    if (!valid_gcm_input(key, key_length, ciphertext, ciphertext_length, aad, aad_length) ||
        nonce == NULL || nonce_length != CRYPTO_GCM_NONCE_BYTES ||
        tag == NULL || tag_length != CRYPTO_GCM_TAG_BYTES ||
        (plaintext == NULL && (ciphertext_length != 0 || plaintext_capacity != 0)) ||
        plaintext_capacity < ciphertext_length ||
        ranges_overlap(plaintext, ciphertext_length, ciphertext, ciphertext_length) ||
        ranges_overlap(plaintext, ciphertext_length, key, key_length) ||
        ranges_overlap(plaintext, ciphertext_length, aad, aad_length) ||
        ranges_overlap(plaintext, ciphertext_length, nonce, nonce_length) ||
        ranges_overlap(plaintext, ciphertext_length, tag, tag_length)) {
        return 0;
    }
    temporary = OPENSSL_malloc(temporary_length);
    context = EVP_CIPHER_CTX_new();
    if (temporary == NULL || context == NULL ||
        EVP_DecryptInit_ex2(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                            CRYPTO_GCM_NONCE_BYTES, NULL) != 1 ||
        EVP_DecryptInit_ex2(context, NULL, key, nonce, NULL) != 1) {
        goto cleanup;
    }
    if (aad_length != 0 &&
        EVP_DecryptUpdate(context, NULL, &aad_written, aad, (int)aad_length) != 1) {
        goto cleanup;
    }
    if (ciphertext_length != 0 &&
        EVP_DecryptUpdate(context, temporary, &written,
                          ciphertext, (int)ciphertext_length) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG,
                            CRYPTO_GCM_TAG_BYTES, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(context, temporary + written, &final_written) != 1 ||
        written < 0 || final_written < 0 ||
        (size_t)written + (size_t)final_written != ciphertext_length) {
        goto cleanup;
    }
    if (ciphertext_length != 0) {
        memcpy(plaintext, temporary, ciphertext_length);
    }
    *plaintext_length = ciphertext_length;
    success = 1;

cleanup:
    EVP_CIPHER_CTX_free(context);
    if (temporary != NULL) {
        OPENSSL_clear_free(temporary, temporary_length);
    }
    return success;
}
