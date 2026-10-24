#ifndef SECUREPM_CRYPTO_H
#define SECUREPM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_KEY_BYTES 32
#define CRYPTO_SALT_BYTES 16
#define CRYPTO_GCM_NONCE_BYTES 12
#define CRYPTO_GCM_TAG_BYTES 16
#define CRYPTO_PASSWORD_MAX_BYTES 1024
#define CRYPTO_SCRYPT_MAX_MEMORY (UINT64_C(64) * 1024 * 1024)
#define CRYPTO_AUTH_CONTEXT "securepm:v1:auth"
#define CRYPTO_KEK_CONTEXT "securepm:v1:kek"

struct crypto_scrypt_params {
    uint64_t n;
    uint64_t r;
    uint64_t p;
    uint64_t max_memory;
};

extern const struct crypto_scrypt_params crypto_scrypt_defaults;

/* Supported parameters: power-of-two N in 2..32768, r in 1..8, p = 1,
 * and max_memory in 1..64 MiB. OpenSSL also checks the required memory.
 * Use crypto_scrypt_defaults for new users; smaller costs are not a production
 * recommendation. Passwords are 1..1024 bytes; salt and root are exactly 16/32. */

struct crypto_keys {
    unsigned char authentication[CRYPTO_KEY_BYTES];
    unsigned char kek[CRYPTO_KEY_BYTES];
};

/* Return 1 on success, 0 on failure. Buffers must span their declared lengths
 * and outputs must not overlap inputs. Invalid output lengths are left untouched;
 * otherwise failed derivations clear the output. Callers must OPENSSL_cleanse()
 * passwords, root keys, and returned keys when finished, including error paths. */
int crypto_random(unsigned char *output, size_t length);
int crypto_derive_root(const char *password, size_t password_length,
                       const unsigned char *salt, size_t salt_length,
                       const struct crypto_scrypt_params *params,
                       unsigned char *root, size_t root_length);

/* HKDF-SHA256 extract-and-expand. NULL salt/info are allowed only at length 0.
 * Inputs are limited to 1024 bytes each; output is 1..8160 bytes (RFC 5869).
 * This primitive also permits verification against published reference vectors. */
int crypto_hkdf_sha256(const unsigned char *key, size_t key_length,
                       const unsigned char *salt, size_t salt_length,
                       const unsigned char *info, size_t info_length,
                       unsigned char *output, size_t output_length);

/* Uses no additional HKDF salt and the versioned context bytes above, excluding
 * their terminating NUL. Both keys are published together only on success. */
int crypto_derive_keys(const unsigned char *root, size_t root_length,
                       struct crypto_keys *keys);

/* AES-256-GCM uses a fresh random nonce for every encryption. AAD is optional:
 * NULL is accepted only when aad_length is zero. Plaintext may be empty, in
 * which case plaintext and ciphertext may be NULL with zero capacity. All
 * other buffers must be distinct. Length outputs are set to zero on failure. */
int crypto_aes256_gcm_encrypt(const unsigned char *key, size_t key_length,
                              const unsigned char *plaintext, size_t plaintext_length,
                              const unsigned char *aad, size_t aad_length,
                              unsigned char *ciphertext, size_t ciphertext_capacity,
                              size_t *ciphertext_length,
                              unsigned char *nonce, size_t nonce_capacity,
                              unsigned char *tag, size_t tag_capacity);

/* Plaintext is copied to the caller only after authentication succeeds. On
 * authentication or other failure, plaintext is left untouched. */
int crypto_aes256_gcm_decrypt(const unsigned char *key, size_t key_length,
                              const unsigned char *ciphertext, size_t ciphertext_length,
                              const unsigned char *aad, size_t aad_length,
                              const unsigned char *nonce, size_t nonce_length,
                              const unsigned char *tag, size_t tag_length,
                              unsigned char *plaintext, size_t plaintext_capacity,
                              size_t *plaintext_length);

#endif
