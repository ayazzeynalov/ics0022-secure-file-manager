#include "crypto.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int all_zero(const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    for (size_t i = 0; i < length; ++i) {
        if (bytes[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void test_random(void)
{
    struct {
        unsigned char before;
        unsigned char salt[CRYPTO_SALT_BYTES];
        unsigned char after;
    } buffer = {0};
    buffer.before = buffer.after = 0xa5;
    CHECK(crypto_random(buffer.salt, sizeof(buffer.salt)) == 1);
    CHECK(buffer.before == 0xa5 && buffer.after == 0xa5);
    CHECK(crypto_random(NULL, 16) == 0);
    CHECK(crypto_random(buffer.salt, 0) == 0);
    CHECK(crypto_random(buffer.salt, (size_t)INT_MAX + 1) == 0);
    /* Successful generation is tested without probabilistic assertions about
     * specific random bytes or claiming to measure entropy. */
    OPENSSL_cleanse(&buffer, sizeof(buffer));
}

static void test_scrypt(void)
{
    char password[] = "dummy master password";
    unsigned char salt[CRYPTO_SALT_BYTES] = {0};
    unsigned char first[CRYPTO_KEY_BYTES] = {0};
    unsigned char second[CRYPTO_KEY_BYTES] = {0};
    struct {
        unsigned char before;
        unsigned char root[CRYPTO_KEY_BYTES];
        unsigned char after;
    } guarded = {0};
    struct crypto_scrypt_params params = crypto_scrypt_defaults;

    CHECK(params.n == 32768 && params.r == 8 && params.p == 1 &&
          params.max_memory == UINT64_C(67108864));
    CHECK(crypto_derive_root(password, sizeof(password) - 1, salt, sizeof(salt),
                             &params, first, sizeof(first)) == 1);
    CHECK(crypto_derive_root(password, sizeof(password) - 1, salt, sizeof(salt),
                             &params, second, sizeof(second)) == 1);
    CHECK(memcmp(first, second, sizeof(first)) == 0);
    salt[0] = 1;
    guarded.before = guarded.after = 0xa5;
    CHECK(crypto_derive_root(password, sizeof(password) - 1, salt, sizeof(salt),
                             &params, guarded.root, sizeof(guarded.root)) == 1);
    CHECK(memcmp(first, guarded.root, sizeof(first)) != 0);
    CHECK(guarded.before == 0xa5 && guarded.after == 0xa5);

#define BAD_ROOT(pass, plen, s, slen, par) do { \
    memset(second, 0xa5, sizeof(second)); \
    CHECK(crypto_derive_root(pass, plen, s, slen, par, second, sizeof(second)) == 0); \
    CHECK(all_zero(second, sizeof(second))); \
} while (0)
    BAD_ROOT(NULL, 1, salt, sizeof(salt), &params);
    BAD_ROOT(password, 0, salt, sizeof(salt), &params);
    BAD_ROOT(password, SIZE_MAX, salt, sizeof(salt), &params);
    BAD_ROOT(password, sizeof(password) - 1, NULL, sizeof(salt), &params);
    BAD_ROOT(password, sizeof(password) - 1, salt, 15, &params);
    BAD_ROOT(password, sizeof(password) - 1, salt, 17, &params);
    BAD_ROOT(password, sizeof(password) - 1, salt, sizeof(salt), NULL);
    const struct crypto_scrypt_params invalid[] = {
        {0, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {1, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {3, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {65536, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {UINT64_MAX, 8, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {32768, 0, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {32768, UINT64_MAX, 1, CRYPTO_SCRYPT_MAX_MEMORY},
        {32768, 8, 0, CRYPTO_SCRYPT_MAX_MEMORY},
        {32768, 8, UINT64_MAX, CRYPTO_SCRYPT_MAX_MEMORY},
        {32768, 8, 1, 0},
        {32768, 8, 1, UINT64_MAX},
        {32768, 8, 1, 1} /* Valid policy bounds; OpenSSL rejects insufficient memory. */
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        BAD_ROOT(password, sizeof(password) - 1, salt, sizeof(salt), &invalid[i]);
    }
#undef BAD_ROOT
    CHECK(crypto_derive_root(password, 1, salt, sizeof(salt), &params, NULL, 32) == 0);
    memset(second, 0xa5, sizeof(second));
    CHECK(crypto_derive_root(password, 1, salt, sizeof(salt), &params, second, 31) == 0);
    CHECK(second[0] == 0xa5 && second[31] == 0xa5);
    CHECK(crypto_derive_root(password, 1, salt, sizeof(salt), &params, second, SIZE_MAX) == 0);
    /* Small costs exercise input boundaries without changing production defaults. */
    params.n = 16;
    params.r = 1;
    char binary_password[] = {'a', '\0', 'b'};
    char maximum_password[CRYPTO_PASSWORD_MAX_BYTES];
    memset(maximum_password, 'x', sizeof(maximum_password));
    CHECK(crypto_derive_root(binary_password, sizeof(binary_password), salt, sizeof(salt),
                             &params, first, sizeof(first)) == 1);
    CHECK(crypto_derive_root(binary_password, 1, salt, sizeof(salt),
                             &params, second, sizeof(second)) == 1);
    CHECK(memcmp(first, second, sizeof(first)) != 0);
    CHECK(crypto_derive_root(maximum_password, sizeof(maximum_password), salt, sizeof(salt),
                             &params, second, sizeof(second)) == 1);
    OPENSSL_cleanse(binary_password, sizeof(binary_password));
    OPENSSL_cleanse(maximum_password, sizeof(maximum_password));
    ERR_clear_error();
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    OPENSSL_cleanse(&guarded, sizeof(guarded));
}

static void test_hkdf_vectors(void)
{
    /* RFC 5869 Appendix A.1: https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1 */
    unsigned char key[22];
    unsigned char salt[13];
    unsigned char info[10];
    struct {
        unsigned char before;
        unsigned char output[42];
        unsigned char after;
    } guarded = {0};
    const unsigned char expected[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,
        0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,
        0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    /* RFC 5869 Appendix A.3: no salt or info. */
    const unsigned char expected_empty[42] = {
        0x8d,0xa4,0xe7,0x75,0xa5,0x63,0xc1,0x8f,0x71,0x5f,0x80,0x2a,0x06,0x3c,
        0x5a,0x31,0xb8,0xa1,0x1f,0x5c,0x5e,0xe1,0x87,0x9e,0xc3,0x45,0x4e,0x5f,
        0x3c,0x73,0x8d,0x2d,0x9d,0x20,0x13,0x95,0xfa,0xa4,0xb6,0x1a,0x96,0xc8
    };
    memset(key, 0x0b, sizeof(key));
    for (size_t i = 0; i < sizeof(salt); ++i) {
        salt[i] = (unsigned char)i;
    }
    for (size_t i = 0; i < sizeof(info); ++i) {
        info[i] = (unsigned char)(0xf0 + i);
    }
    guarded.before = guarded.after = 0xa5;
    CHECK(crypto_hkdf_sha256(key, sizeof(key), salt, sizeof(salt), info, sizeof(info),
                            guarded.output, sizeof(guarded.output)) == 1);
    CHECK(memcmp(guarded.output, expected, sizeof(expected)) == 0);
    CHECK(guarded.before == 0xa5 && guarded.after == 0xa5);
    CHECK(crypto_hkdf_sha256(key, sizeof(key), NULL, 0, NULL, 0,
                            guarded.output, sizeof(guarded.output)) == 1);
    CHECK(memcmp(guarded.output, expected_empty, sizeof(expected_empty)) == 0);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(&guarded, sizeof(guarded));
}

static void test_separation(void)
{
    unsigned char root[CRYPTO_KEY_BYTES] = {1};
    unsigned char expected[CRYPTO_KEY_BYTES] = {0};
    struct crypto_keys first = {0};
    struct crypto_keys second = {0};
    CHECK(sizeof(first.authentication) == 32 && sizeof(first.kek) == 32);
    CHECK(crypto_derive_keys(root, sizeof(root), &first) == 1);
    CHECK(crypto_derive_keys(root, sizeof(root), &second) == 1);
    CHECK(memcmp(&first, &second, sizeof(first)) == 0);
    CHECK(memcmp(first.authentication, first.kek, CRYPTO_KEY_BYTES) != 0);
    /* Pin the literal contexts and exclude their NUL terminators. */
    CHECK(crypto_hkdf_sha256(root, sizeof(root), NULL, 0,
                            (const unsigned char *)"securepm:v1:auth", 16,
                            expected, sizeof(expected)) == 1);
    CHECK(memcmp(expected, first.authentication, sizeof(expected)) == 0);
    CHECK(crypto_hkdf_sha256(root, sizeof(root), NULL, 0,
                            (const unsigned char *)"securepm:v1:kek", 15,
                            expected, sizeof(expected)) == 1);
    CHECK(memcmp(expected, first.kek, sizeof(expected)) == 0);
    CHECK(crypto_derive_keys(NULL, sizeof(root), &second) == 0);
    CHECK(all_zero(&second, sizeof(second)));
    CHECK(crypto_derive_keys(root, 31, &second) == 0);
    CHECK(crypto_derive_keys(root, sizeof(root), NULL) == 0);
    OPENSSL_cleanse(root, sizeof(root));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(&first, sizeof(first));
    OPENSSL_cleanse(&second, sizeof(second));
}

static void test_hkdf_errors(void)
{
    unsigned char key[32] = {0};
    unsigned char output[32] = {0};
    struct crypto_keys separated = {0};
#define BAD_HKDF(k, kl, s, sl, i, il) do { \
    memset(output, 0xa5, sizeof(output)); \
    CHECK(crypto_hkdf_sha256(k, kl, s, sl, i, il, output, sizeof(output)) == 0); \
    CHECK(all_zero(output, sizeof(output))); \
} while (0)
    BAD_HKDF(NULL, 32, NULL, 0, NULL, 0);
    BAD_HKDF(key, 0, NULL, 0, NULL, 0);
    BAD_HKDF(key, SIZE_MAX, NULL, 0, NULL, 0);
    BAD_HKDF(key, 32, NULL, 1, NULL, 0);
    BAD_HKDF(key, 32, key, SIZE_MAX, NULL, 0);
    BAD_HKDF(key, 32, NULL, 0, NULL, 1);
    BAD_HKDF(key, 32, NULL, 0, key, SIZE_MAX);
    CHECK(crypto_hkdf_sha256(key, 32, NULL, 0, NULL, 0, NULL, 32) == 0);
    memset(output, 0xa5, sizeof(output));
    CHECK(crypto_hkdf_sha256(key, 32, NULL, 0, NULL, 0, output, 0) == 0);
    CHECK(crypto_hkdf_sha256(key, 32, NULL, 0, NULL, 0, output, 8161) == 0);
    CHECK(output[0] == 0xa5 && output[31] == 0xa5);
    /* Force a real provider-fetch failure in this standalone test process. */
    CHECK(EVP_set_default_properties(NULL, "provider=securepm_missing_provider") == 1);
    BAD_HKDF(key, 32, NULL, 0, NULL, 0);
    memset(&separated, 0xa5, sizeof(separated));
    CHECK(crypto_derive_keys(key, sizeof(key), &separated) == 0);
    CHECK(all_zero(&separated, sizeof(separated)));
    CHECK(EVP_set_default_properties(NULL, "") == 1);
#undef BAD_HKDF
    ERR_clear_error();
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(&separated, sizeof(separated));
}

static int encrypt_fixture(const unsigned char *key,
                           const unsigned char *plaintext, size_t plaintext_length,
                           const unsigned char *aad, size_t aad_length,
                           unsigned char *ciphertext, size_t *ciphertext_length,
                           unsigned char *nonce, unsigned char *tag)
{
    return crypto_aes256_gcm_encrypt(key, CRYPTO_KEY_BYTES,
                                     plaintext, plaintext_length,
                                     aad, aad_length,
                                     ciphertext, plaintext_length,
                                     ciphertext_length,
                                     nonce, CRYPTO_GCM_NONCE_BYTES,
                                     tag, CRYPTO_GCM_TAG_BYTES);
}

static void test_aes_gcm_round_trip(void)
{
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    unsigned char plaintext[] = "dummy vault contents";
    unsigned char aad[] = "securepm test metadata";
    unsigned char ciphertext[sizeof(plaintext) - 1] = {0};
    unsigned char decrypted[sizeof(plaintext) - 1] = {0};
    unsigned char nonce[CRYPTO_GCM_NONCE_BYTES] = {0};
    unsigned char tag[CRYPTO_GCM_TAG_BYTES] = {0};
    size_t ciphertext_length = 0;
    size_t plaintext_length = 0;

    key[0] = 1;
    CHECK(encrypt_fixture(key, plaintext, sizeof(plaintext) - 1,
                          aad, sizeof(aad) - 1, ciphertext,
                          &ciphertext_length, nonce, tag) == 1);
    CHECK(ciphertext_length == sizeof(plaintext) - 1);
    CHECK(crypto_aes256_gcm_decrypt(key, sizeof(key),
                                    ciphertext, ciphertext_length,
                                    aad, sizeof(aad) - 1,
                                    nonce, sizeof(nonce), tag, sizeof(tag),
                                    decrypted, sizeof(decrypted),
                                    &plaintext_length) == 1);
    CHECK(plaintext_length == sizeof(plaintext) - 1);
    CHECK(memcmp(decrypted, plaintext, plaintext_length) == 0);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(decrypted, sizeof(decrypted));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
}

static void test_aes_gcm_empty_plaintext(void)
{
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    unsigned char aad[] = "empty record";
    unsigned char nonce[CRYPTO_GCM_NONCE_BYTES] = {0};
    unsigned char tag[CRYPTO_GCM_TAG_BYTES] = {0};
    size_t ciphertext_length = SIZE_MAX;
    size_t plaintext_length = SIZE_MAX;

    CHECK(crypto_aes256_gcm_encrypt(key, sizeof(key), NULL, 0,
                                    aad, sizeof(aad) - 1, NULL, 0,
                                    &ciphertext_length, nonce, sizeof(nonce),
                                    tag, sizeof(tag)) == 1);
    CHECK(ciphertext_length == 0);
    CHECK(crypto_aes256_gcm_decrypt(key, sizeof(key), NULL, 0,
                                    aad, sizeof(aad) - 1,
                                    nonce, sizeof(nonce), tag, sizeof(tag),
                                    NULL, 0, &plaintext_length) == 1);
    CHECK(plaintext_length == 0);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
}

static void test_aes_gcm_reference_vector(void)
{
    /* Published AES-256-GCM known-answer vector: zero key, IV, and plaintext. */
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    const unsigned char ciphertext[16] = {
        0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
        0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18
    };
    const unsigned char nonce[CRYPTO_GCM_NONCE_BYTES] = {0};
    const unsigned char tag[CRYPTO_GCM_TAG_BYTES] = {
        0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
        0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19
    };
    unsigned char plaintext[16] = {0xa5};
    size_t plaintext_length = 0;

    CHECK(crypto_aes256_gcm_decrypt(key, sizeof(key),
                                    ciphertext, sizeof(ciphertext), NULL, 0,
                                    nonce, sizeof(nonce), tag, sizeof(tag),
                                    plaintext, sizeof(plaintext),
                                    &plaintext_length) == 1);
    CHECK(plaintext_length == sizeof(plaintext));
    CHECK(all_zero(plaintext, sizeof(plaintext)));
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
}

static void expect_decryption_failure(const unsigned char *key,
                                      const unsigned char *ciphertext,
                                      size_t ciphertext_length,
                                      const unsigned char *aad, size_t aad_length,
                                      const unsigned char *nonce,
                                      const unsigned char *tag)
{
    unsigned char plaintext[64];
    size_t plaintext_length = SIZE_MAX;

    memset(plaintext, 0xa5, sizeof(plaintext));
    CHECK(ciphertext_length <= sizeof(plaintext));
    CHECK(crypto_aes256_gcm_decrypt(key, CRYPTO_KEY_BYTES,
                                    ciphertext, ciphertext_length,
                                    aad, aad_length,
                                    nonce, CRYPTO_GCM_NONCE_BYTES,
                                    tag, CRYPTO_GCM_TAG_BYTES,
                                    plaintext, sizeof(plaintext),
                                    &plaintext_length) == 0);
    CHECK(plaintext_length == 0);
    for (size_t i = 0; i < sizeof(plaintext); ++i) {
        CHECK(plaintext[i] == 0xa5);
    }
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
}

static void test_aes_gcm_authentication_failures(void)
{
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    unsigned char wrong_key[CRYPTO_KEY_BYTES] = {0};
    unsigned char plaintext[] = "authenticated dummy secret";
    unsigned char aad[] = "record metadata";
    unsigned char ciphertext[sizeof(plaintext) - 1] = {0};
    unsigned char nonce[CRYPTO_GCM_NONCE_BYTES] = {0};
    unsigned char tag[CRYPTO_GCM_TAG_BYTES] = {0};
    size_t ciphertext_length = 0;

    key[0] = 1;
    wrong_key[0] = 2;
    CHECK(encrypt_fixture(key, plaintext, sizeof(plaintext) - 1,
                          aad, sizeof(aad) - 1, ciphertext,
                          &ciphertext_length, nonce, tag) == 1);

    ciphertext[0] ^= 1;
    expect_decryption_failure(key, ciphertext, ciphertext_length,
                              aad, sizeof(aad) - 1, nonce, tag);
    ciphertext[0] ^= 1;

    tag[0] ^= 1;
    expect_decryption_failure(key, ciphertext, ciphertext_length,
                              aad, sizeof(aad) - 1, nonce, tag);
    tag[0] ^= 1;

    expect_decryption_failure(wrong_key, ciphertext, ciphertext_length,
                              aad, sizeof(aad) - 1, nonce, tag);

    nonce[0] ^= 1;
    expect_decryption_failure(key, ciphertext, ciphertext_length,
                              aad, sizeof(aad) - 1, nonce, tag);
    nonce[0] ^= 1;

    aad[0] ^= 1;
    expect_decryption_failure(key, ciphertext, ciphertext_length,
                              aad, sizeof(aad) - 1, nonce, tag);
    aad[0] ^= 1;

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(wrong_key, sizeof(wrong_key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
}

static void test_aes_gcm_invalid_inputs(void)
{
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    unsigned char data[4] = {1, 2, 3, 4};
    unsigned char output[4];
    unsigned char nonce[CRYPTO_GCM_NONCE_BYTES];
    unsigned char tag[CRYPTO_GCM_TAG_BYTES];
    size_t length = SIZE_MAX;

#define BAD_ENCRYPT(k, kl, p, pl, a, al, out, cap, lp, n, nc, t, tc) do { \
    length = SIZE_MAX; \
    CHECK(crypto_aes256_gcm_encrypt(k, kl, p, pl, a, al, out, cap, lp, \
                                    n, nc, t, tc) == 0); \
    if ((lp) != NULL) { \
        CHECK(length == 0); \
    } \
} while (0)
    BAD_ENCRYPT(NULL, 32, data, 4, NULL, 0, output, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 31, data, 4, NULL, 0, output, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, NULL, 4, NULL, 0, output, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, (size_t)INT_MAX + 1, NULL, 0,
                output, SIZE_MAX, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 1, output, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, data, (size_t)INT_MAX + 1,
                output, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, NULL, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 3, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, NULL, 0, NULL, 0, NULL, 1, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, NULL, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, &length, NULL, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, &length, nonce, 11, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, &length, nonce, 12, NULL, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, &length, nonce, 12, tag, 15);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, data, 4, &length, nonce, 12, tag, 16);
    BAD_ENCRYPT(key, 32, data, 4, NULL, 0, output, 4, &length, tag, 12, tag, 16);
#undef BAD_ENCRYPT

    CHECK(encrypt_fixture(key, data, sizeof(data), NULL, 0, output,
                          &length, nonce, tag) == 1);

#define BAD_DECRYPT(k, kl, c, cl, a, al, n, nl, t, tl, out, cap, lp) do { \
    length = SIZE_MAX; \
    CHECK(crypto_aes256_gcm_decrypt(k, kl, c, cl, a, al, n, nl, t, tl, \
                                    out, cap, lp) == 0); \
    if ((lp) != NULL) { \
        CHECK(length == 0); \
    } \
} while (0)
    BAD_DECRYPT(NULL, 32, output, 4, NULL, 0, nonce, 12, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 31, output, 4, NULL, 0, nonce, 12, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, NULL, 4, NULL, 0, nonce, 12, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, output, (size_t)INT_MAX + 1, NULL, 0,
                nonce, 12, tag, 16, data, SIZE_MAX, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 1, nonce, 12, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, NULL, 12, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 11, tag, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, NULL, 16, data, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, tag, 15, data, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, tag, 16, NULL, 4, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, tag, 16, data, 3, &length);
    BAD_DECRYPT(key, 32, NULL, 0, NULL, 0, nonce, 12, tag, 16, NULL, 1, &length);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, tag, 16, data, 4, NULL);
    BAD_DECRYPT(key, 32, output, 4, NULL, 0, nonce, 12, tag, 16, output, 4, &length);
#undef BAD_DECRYPT
    ERR_clear_error();
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(data, sizeof(data));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));
}

int main(void)
{
    test_random();
    test_scrypt();
    test_hkdf_vectors();
    test_separation();
    test_hkdf_errors();
    test_aes_gcm_round_trip();
    test_aes_gcm_empty_plaintext();
    test_aes_gcm_reference_vector();
    test_aes_gcm_authentication_failures();
    test_aes_gcm_invalid_inputs();
    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u crypto checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u crypto checks\n", checks);
    return 0;
}
