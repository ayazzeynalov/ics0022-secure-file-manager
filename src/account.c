#include "account.h"

#include "crypto.h"

#include <errno.h>
#include <string.h>
#include <openssl/crypto.h>

#define ACCOUNT_USER_ID_ATTEMPTS 128
#define ACCOUNT_DATABASE_LOCK "users.lock"
#define ACCOUNT_PENDING_FILENAME_BYTES \
    (USER_DB_USER_ID_BYTES * 2 + sizeof(".pending"))
#define ACCOUNT_PENDING_ERROR (-1)
#define ACCOUNT_PENDING_MISSING 0
#define ACCOUNT_PENDING_PRESENT 1

static const unsigned char pending_magic[] = {
    'S', 'P', 'M', 'P', 'E', 'N', 'D', '1'
};

static int pending_filename(
    const unsigned char user_id[USER_DB_USER_ID_BYTES],
    char filename[ACCOUNT_PENDING_FILENAME_BYTES])
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
    memcpy(filename + position, ".pending", sizeof(".pending"));
    return 1;
}

static int pending_registration_status(
    const struct storage *storage,
    const unsigned char user_id[USER_DB_USER_ID_BYTES])
{
    unsigned char *stored = NULL;
    size_t stored_length = 0;
    char filename[ACCOUNT_PENDING_FILENAME_BYTES];
    int read_result;
    int valid;

    if (!pending_filename(user_id, filename)) {
        return ACCOUNT_PENDING_ERROR;
    }
    read_result = storage_read_file(storage, STORAGE_AREA_ROOT, filename,
                                    sizeof(pending_magic),
                                    &stored, &stored_length);
    if (read_result == STORAGE_READ_MISSING) {
        storage_free(stored);
        return ACCOUNT_PENDING_MISSING;
    }
    valid = read_result == STORAGE_READ_OK &&
            stored_length == sizeof(pending_magic) &&
            CRYPTO_memcmp(stored, pending_magic, sizeof(pending_magic)) == 0;
    storage_free(stored);
    return valid ? ACCOUNT_PENDING_PRESENT : ACCOUNT_PENDING_ERROR;
}

static int registration_record_status(
    const struct storage *storage, const struct user_record *record)
{
    struct user_database stored;
    const struct user_record *found;
    size_t username_length;

    user_db_init(&stored);
    username_length = strlen(record->username);
    if (!user_db_load(storage, &stored)) {
        return -1;
    }
    found = user_db_find_username(&stored, record->username, username_length);
    if (found == NULL) {
        return 0;
    }
    return memcmp(found->user_id, record->user_id,
                  sizeof(record->user_id)) == 0 ? 1 : -1;
}

static int authenticate_record(const struct user_record *record,
                               const char *master_password,
                               size_t password_length)
{
    struct crypto_keys keys = {0};
    unsigned char root[CRYPTO_KEY_BYTES] = {0};
    unsigned char vmk[AUTH_VMK_BYTES] = {0};
    int success = 0;

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
    success = auth_unwrap_vmk(
        keys.kek, sizeof(keys.kek),
        record->user_id, sizeof(record->user_id),
        record->format_version,
        record->wrapped_vmk, sizeof(record->wrapped_vmk),
        record->vmk_nonce, sizeof(record->vmk_nonce),
        record->vmk_tag, sizeof(record->vmk_tag),
        vmk, sizeof(vmk));

cleanup:
    OPENSSL_cleanse(vmk, sizeof(vmk));
    OPENSSL_cleanse(&keys, sizeof(keys));
    OPENSSL_cleanse(root, sizeof(root));
    return success;
}

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
    struct storage_lock database_lock = STORAGE_LOCK_INITIALIZER;
    char pending[ACCOUNT_PENDING_FILENAME_BYTES];
    const struct user_record *existing;
    int save_attempted = 0;
    int marker_written = 0;
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
    if (!storage_lock_acquire(storage, STORAGE_AREA_ROOT,
                              ACCOUNT_DATABASE_LOCK, &database_lock) ||
        !user_db_load(storage, &database)) {
        goto cleanup;
    }
    existing = user_db_find_username(&database, username, username_length);
    if (existing != NULL) {
        if (pending_registration_status(storage, existing->user_id) ==
                ACCOUNT_PENDING_PRESENT &&
            authenticate_record(existing, master_password, password_length)) {
            success = ACCOUNT_REGISTER_RECOVERY;
        }
        goto cleanup;
    }
    if (database.count == USER_DB_MAX_USERS) {
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
    if (!pending_filename(record.user_id, pending) ||
        !storage_atomic_write(storage, STORAGE_AREA_ROOT, pending,
                              pending_magic, sizeof(pending_magic))) {
        goto cleanup;
    }
    marker_written = 1;
    if (!user_db_add(&database, &record)) {
        goto cleanup;
    }
    save_attempted = 1;
    if (!user_db_save(storage, &database)) {
        goto cleanup;
    }
    success = ACCOUNT_REGISTER_CREATED;

cleanup:
    if (marker_written && success != ACCOUNT_REGISTER_CREATED &&
        (!save_attempted || registration_record_status(storage, &record) == 0)) {
        (void)storage_remove_file(storage, STORAGE_AREA_ROOT, pending);
    }
    storage_lock_release(&database_lock);
    OPENSSL_cleanse(vmk, sizeof(vmk));
    OPENSSL_cleanse(&keys, sizeof(keys));
    OPENSSL_cleanse(root, sizeof(root));
    return success;
}

int account_registration_complete(const struct storage *storage,
                                  const struct account_session *session)
{
    struct storage_lock database_lock = STORAGE_LOCK_INITIALIZER;
    struct user_database database;
    char filename[ACCOUNT_PENDING_FILENAME_BYTES];
    int pending_status;
    int success = 0;

    user_db_init(&database);
    if (storage == NULL || session == NULL || session->unlocked != 1 ||
        !pending_filename(session->user_id, filename) ||
        !storage_lock_acquire(storage, STORAGE_AREA_ROOT,
                              ACCOUNT_DATABASE_LOCK, &database_lock) ||
        !user_db_load(storage, &database) ||
        user_db_find_user_id(&database, session->user_id,
                             sizeof(session->user_id)) == NULL) {
        goto cleanup;
    }
    pending_status = pending_registration_status(storage, session->user_id);
    if (pending_status == ACCOUNT_PENDING_ERROR ||
        (pending_status == ACCOUNT_PENDING_PRESENT &&
         !storage_remove_file(storage, STORAGE_AREA_ROOT, filename))) {
        goto cleanup;
    }
    success = 1;

cleanup:
    storage_lock_release(&database_lock);
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
