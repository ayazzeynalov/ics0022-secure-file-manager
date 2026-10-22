#include "vault.h"

#include "crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#define VAULT_MAGIC_BYTES 8
#define VAULT_AAD_BYTES 32
#define VAULT_NONCE_OFFSET VAULT_AAD_BYTES
#define VAULT_CIPHERTEXT_OFFSET (VAULT_AAD_BYTES + CRYPTO_GCM_NONCE_BYTES)
#define VAULT_FIXED_BYTES \
    (VAULT_CIPHERTEXT_OFFSET + CRYPTO_GCM_TAG_BYTES)
#define VAULT_MAX_FILE_BYTES (VAULT_FIXED_BYTES + VAULT_MAX_PLAINTEXT_BYTES)
#define VAULT_FILENAME_BYTES \
    (USER_DB_USER_ID_BYTES * 2 + sizeof(".vault"))

static const unsigned char vault_magic[VAULT_MAGIC_BYTES] = {
    'S', 'P', 'M', 'V', 'A', 'U', 'L', 'T'
};

static int valid_session(const struct account_session *session)
{
    return session != NULL && session->unlocked == 1;
}

static int vault_filename(const unsigned char user_id[USER_DB_USER_ID_BYTES],
                          char filename[VAULT_FILENAME_BYTES])
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t position = 0;

    if (user_id == NULL || filename == NULL) {
        return 0;
    }
    for (size_t index = 0; index < USER_DB_USER_ID_BYTES; ++index) {
        filename[position++] = hexadecimal[user_id[index] >> 4];
        filename[position++] = hexadecimal[user_id[index] & 0x0f];
    }
    memcpy(filename + position, ".vault", sizeof(".vault"));
    return 1;
}

static void write_u32(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static uint32_t read_u32(const unsigned char input[4])
{
    return (uint32_t)input[0] << 24 |
           (uint32_t)input[1] << 16 |
           (uint32_t)input[2] << 8 |
           input[3];
}

static void build_aad(unsigned char aad[VAULT_AAD_BYTES],
                      const unsigned char user_id[USER_DB_USER_ID_BYTES],
                      uint32_t ciphertext_length)
{
    memcpy(aad, vault_magic, sizeof(vault_magic));
    write_u32(aad + VAULT_MAGIC_BYTES, VAULT_FORMAT_VERSION);
    memcpy(aad + VAULT_MAGIC_BYTES + 4,
           user_id, USER_DB_USER_ID_BYTES);
    write_u32(aad + VAULT_MAGIC_BYTES + 4 + USER_DB_USER_ID_BYTES,
              ciphertext_length);
}

int vault_write(const struct storage *storage,
                const struct account_session *session,
                const unsigned char *plaintext, size_t plaintext_length)
{
    unsigned char *serialized = NULL;
    unsigned char *ciphertext;
    unsigned char *nonce;
    unsigned char *tag;
    char filename[VAULT_FILENAME_BYTES];
    size_t ciphertext_length = 0;
    size_t serialized_length;
    int success = 0;

    if (storage == NULL || !valid_session(session) ||
        (plaintext == NULL && plaintext_length != 0) ||
        plaintext_length > VAULT_MAX_PLAINTEXT_BYTES ||
        !vault_filename(session->user_id, filename)) {
        errno = EINVAL;
        return 0;
    }
    serialized_length = VAULT_FIXED_BYTES + plaintext_length;
    serialized = malloc(serialized_length);
    if (serialized == NULL) {
        return 0;
    }
    build_aad(serialized, session->user_id, (uint32_t)plaintext_length);
    nonce = serialized + VAULT_NONCE_OFFSET;
    ciphertext = serialized + VAULT_CIPHERTEXT_OFFSET;
    tag = ciphertext + plaintext_length;
    if (!crypto_aes256_gcm_encrypt(session->vmk, sizeof(session->vmk),
                                   plaintext, plaintext_length,
                                   serialized, VAULT_AAD_BYTES,
                                   ciphertext, plaintext_length,
                                   &ciphertext_length,
                                   nonce, CRYPTO_GCM_NONCE_BYTES,
                                   tag, CRYPTO_GCM_TAG_BYTES) ||
        ciphertext_length != plaintext_length ||
        !storage_atomic_write(storage, STORAGE_AREA_VAULTS, filename,
                              serialized, serialized_length)) {
        goto cleanup;
    }
    success = 1;

cleanup:
    free(serialized);
    return success;
}

static int validate_serialized(const unsigned char *serialized,
                               size_t serialized_length,
                               const struct account_session *session,
                               size_t *ciphertext_length)
{
    uint32_t encoded_length;

    if (serialized == NULL || session == NULL || ciphertext_length == NULL ||
        serialized_length < VAULT_FIXED_BYTES ||
        memcmp(serialized, vault_magic, sizeof(vault_magic)) != 0 ||
        read_u32(serialized + VAULT_MAGIC_BYTES) != VAULT_FORMAT_VERSION ||
        memcmp(serialized + VAULT_MAGIC_BYTES + 4, session->user_id,
               USER_DB_USER_ID_BYTES) != 0) {
        return 0;
    }
    encoded_length = read_u32(serialized + VAULT_MAGIC_BYTES + 4 +
                              USER_DB_USER_ID_BYTES);
    if (encoded_length > VAULT_MAX_PLAINTEXT_BYTES ||
        serialized_length != VAULT_FIXED_BYTES + (size_t)encoded_length) {
        return 0;
    }
    *ciphertext_length = encoded_length;
    return 1;
}

int vault_read(const struct storage *storage,
               const struct account_session *session,
               unsigned char **plaintext, size_t *plaintext_length)
{
    unsigned char *serialized = NULL;
    unsigned char *result = NULL;
    char filename[VAULT_FILENAME_BYTES];
    size_t serialized_length = 0;
    size_t ciphertext_length = 0;
    size_t decrypted_length = 0;
    int read_result;
    int result_status = VAULT_READ_ERROR;

    if (plaintext == NULL || plaintext_length == NULL) {
        errno = EINVAL;
        return VAULT_READ_ERROR;
    }
    *plaintext = NULL;
    *plaintext_length = 0;
    if (storage == NULL || !valid_session(session) ||
        !vault_filename(session->user_id, filename)) {
        errno = EINVAL;
        return VAULT_READ_ERROR;
    }
    read_result = storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                                    VAULT_MAX_FILE_BYTES,
                                    &serialized, &serialized_length);
    if (read_result == STORAGE_READ_MISSING) {
        return VAULT_READ_MISSING;
    }
    if (read_result != STORAGE_READ_OK ||
        !validate_serialized(serialized, serialized_length, session,
                             &ciphertext_length)) {
        goto cleanup;
    }
    result = OPENSSL_malloc(ciphertext_length == 0 ? 1 : ciphertext_length);
    if (result == NULL ||
        !crypto_aes256_gcm_decrypt(
            session->vmk, sizeof(session->vmk),
            serialized + VAULT_CIPHERTEXT_OFFSET, ciphertext_length,
            serialized, VAULT_AAD_BYTES,
            serialized + VAULT_NONCE_OFFSET, CRYPTO_GCM_NONCE_BYTES,
            serialized + VAULT_CIPHERTEXT_OFFSET + ciphertext_length,
            CRYPTO_GCM_TAG_BYTES,
            result, ciphertext_length, &decrypted_length) ||
        decrypted_length != ciphertext_length) {
        goto cleanup;
    }
    *plaintext = result;
    *plaintext_length = decrypted_length;
    result = NULL;
    result_status = VAULT_READ_OK;

cleanup:
    storage_free(serialized);
    if (result != NULL) {
        OPENSSL_clear_free(result,
                           ciphertext_length == 0 ? 1 : ciphertext_length);
    }
    return result_status;
}

void vault_secure_free(void *plaintext, size_t plaintext_length)
{
    if (plaintext != NULL) {
        OPENSSL_clear_free(plaintext,
                           plaintext_length == 0 ? 1 : plaintext_length);
    }
}
