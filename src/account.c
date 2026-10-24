#include "account.h"

#include "crypto.h"

#include <errno.h>
#include <string.h>
#include <openssl/crypto.h>

#define ACCOUNT_USER_ID_ATTEMPTS 128

static int valid_credentials(const char *username, size_t username_length,
                             const char *password, size_t password_length,
                             size_t minimum_password_length)
{
    return user_db_username_valid(username, username_length) &&
           password != NULL && password_length >= minimum_password_length &&
           password_length <= CRYPTO_PASSWORD_MAX_BYTES;
}

static int generate_unique_user_id(const struct user_database *database,
                                   unsigned char user_id[USER_DB_USER_ID_BYTES])
{
    for (unsigned int attempt = 0;
         attempt < ACCOUNT_USER_ID_ATTEMPTS; ++attempt) {
        if (!crypto_random(user_id, USER_DB_USER_ID_BYTES)) {
            return 0;
        }
        if (user_db_find_user_id(database, user_id,
                                 USER_DB_USER_ID_BYTES) == NULL) {
            return 1;
        }
    }
    OPENSSL_cleanse(user_id, USER_DB_USER_ID_BYTES);
    return 0;
}

void account_session_lock(struct account_session *session)
{
    if (session == NULL) {
        return;
    }
    OPENSSL_cleanse(session->vmk, sizeof(session->vmk));
    OPENSSL_cleanse(session->user_id, sizeof(session->user_id));
    session->unlocked = 0;
}

int account_register(const struct storage *storage,
                     const char *username, size_t username_length,
                     const char *master_password, size_t password_length)
{
    struct user_database database;
    struct user_record record;
    struct crypto_keys keys = {0};
    unsigned char root[CRYPTO_KEY_BYTES] = {0};
    unsigned char vmk[AUTH_VMK_BYTES] = {0};
    int success = 0;

    user_db_init(&database);
    memset(&record, 0, sizeof(record));
    if (storage == NULL ||
        !valid_credentials(username, username_length, master_password,
                           password_length,
                           ACCOUNT_MASTER_PASSWORD_MIN_BYTES)) {
        errno = EINVAL;
        goto cleanup;
    }
    if (!user_db_load(storage, &database) ||
        database.count == USER_DB_MAX_USERS ||
        user_db_find_username(&database, username, username_length) != NULL) {
        goto cleanup;
    }

    record.format_version = USER_DB_RECORD_VERSION;
    memcpy(record.username, username, username_length);
    record.username[username_length] = '\0';
    record.scrypt = crypto_scrypt_defaults;
    if (!generate_unique_user_id(&database, record.user_id) ||
        !crypto_random(record.salt, sizeof(record.salt)) ||
        !crypto_derive_root(master_password, password_length,
                            record.salt, sizeof(record.salt),
                            &record.scrypt, root, sizeof(root)) ||
        !crypto_derive_keys(root, sizeof(root), &keys)) {
        goto cleanup;
    }
    OPENSSL_cleanse(root, sizeof(root));
    if (!auth_create_verifier(keys.authentication,
                              sizeof(keys.authentication),
                              record.authentication_verifier,
                              sizeof(record.authentication_verifier))) {
        goto cleanup;
    }
    OPENSSL_cleanse(keys.authentication, sizeof(keys.authentication));
    if (!auth_generate_wrapped_vmk(keys.kek, sizeof(keys.kek),
                                   record.user_id, sizeof(record.user_id),
                                   record.format_version,
                                   vmk, sizeof(vmk),
                                   record.wrapped_vmk,
                                   sizeof(record.wrapped_vmk),
                                   record.vmk_nonce,
                                   sizeof(record.vmk_nonce),
                                   record.vmk_tag,
                                   sizeof(record.vmk_tag))) {
        goto cleanup;
    }
    OPENSSL_cleanse(keys.kek, sizeof(keys.kek));
    OPENSSL_cleanse(vmk, sizeof(vmk));
    if (!user_db_add(&database, &record) ||
        !user_db_save(storage, &database)) {
        goto cleanup;
    }
    success = 1;

cleanup:
    OPENSSL_cleanse(vmk, sizeof(vmk));
    OPENSSL_cleanse(&keys, sizeof(keys));
    OPENSSL_cleanse(root, sizeof(root));
    return success;
}

int account_unlock(const struct storage *storage,
                   const char *username, size_t username_length,
                   const char *master_password, size_t password_length,
                   struct account_session *session)
{
    struct user_database database;
    const struct user_record *record = NULL;
    struct crypto_keys keys = {0};
    unsigned char root[CRYPTO_KEY_BYTES] = {0};
    unsigned char vmk[AUTH_VMK_BYTES] = {0};
    int success = 0;

    if (session == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    account_session_lock(session);
    user_db_init(&database);
    if (storage == NULL ||
        !valid_credentials(username, username_length, master_password,
                           password_length, 1)) {
        errno = EINVAL;
        goto cleanup;
    }
    if (!user_db_load(storage, &database)) {
        goto cleanup;
    }
    record = user_db_find_username(&database, username, username_length);
    if (record == NULL ||
        !crypto_derive_root(master_password, password_length,
                            record->salt, sizeof(record->salt),
                            &record->scrypt, root, sizeof(root)) ||
        !crypto_derive_keys(root, sizeof(root), &keys)) {
        goto cleanup;
    }
    OPENSSL_cleanse(root, sizeof(root));
    if (!auth_verify_verifier(keys.authentication,
                              sizeof(keys.authentication),
                              record->authentication_verifier,
                              sizeof(record->authentication_verifier))) {
        goto cleanup;
    }
    OPENSSL_cleanse(keys.authentication, sizeof(keys.authentication));
    if (!auth_unwrap_vmk(keys.kek, sizeof(keys.kek),
                         record->user_id, sizeof(record->user_id),
                         record->format_version,
                         record->wrapped_vmk, sizeof(record->wrapped_vmk),
                         record->vmk_nonce, sizeof(record->vmk_nonce),
                         record->vmk_tag, sizeof(record->vmk_tag),
                         vmk, sizeof(vmk))) {
        goto cleanup;
    }
    OPENSSL_cleanse(keys.kek, sizeof(keys.kek));
    memcpy(session->user_id, record->user_id, sizeof(session->user_id));
    memcpy(session->vmk, vmk, sizeof(session->vmk));
    session->unlocked = 1;
    success = 1;

cleanup:
    OPENSSL_cleanse(vmk, sizeof(vmk));
    OPENSSL_cleanse(&keys, sizeof(keys));
    OPENSSL_cleanse(root, sizeof(root));
    return success;
}
