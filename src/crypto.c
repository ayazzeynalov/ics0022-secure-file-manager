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
