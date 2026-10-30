#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "account.h"
#include "credentials.h"
#include "storage.h"
#include "user_db.h"
#include "vault.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>

#define TEST_PATH_BYTES 4096
#define TEST_VAULT_FILENAME_BYTES 39

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int make_path(char output[TEST_PATH_BYTES],
                     const char *first, const char *second)
{
    int length = snprintf(output, TEST_PATH_BYTES, "%s/%s", first, second);
    return length >= 0 && (size_t)length < TEST_PATH_BYTES;
}

static char *make_temporary_home(char home_template[TEST_PATH_BYTES])
{
    const char *temporary_parent = getenv("TMPDIR");
    char *canonical_parent;
    int path_ready;

    if (temporary_parent == NULL || temporary_parent[0] == '\0') {
        temporary_parent = "/tmp";
    }
    canonical_parent = realpath(temporary_parent, NULL);
    if (canonical_parent == NULL) {
        return NULL;
    }
    path_ready = make_path(home_template, canonical_parent,
                           "securepm-access-test.XXXXXX");
    free(canonical_parent);
    if (!path_ready) {
        return NULL;
    }
    return mkdtemp(home_template);
}

static int remove_tree(const char *path)
{
    struct stat status;
    DIR *directory;
    struct dirent *entry;
    int success = 1;

    if (lstat(path, &status) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        return unlink(path) == 0;
    }
    directory = opendir(path);
    if (directory == NULL) {
        return 0;
    }
    while ((entry = readdir(directory)) != NULL) {
        char child[TEST_PATH_BYTES];

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!make_path(child, path, entry->d_name) || !remove_tree(child)) {
            success = 0;
        }
    }
    if (closedir(directory) != 0) {
        success = 0;
    }
    if (success && rmdir(path) != 0) {
        success = 0;
    }
    return success;
}

static int all_zero(const unsigned char *data, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        if (data[index] != 0) {
            return 0;
        }
    }
    return 1;
}

static void user_filename(
    const unsigned char user_id[USER_DB_USER_ID_BYTES],
    const char *suffix,
    char filename[TEST_VAULT_FILENAME_BYTES])
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t position = 0;

    for (size_t index = 0; index < USER_DB_USER_ID_BYTES; ++index) {
        filename[position++] = hexadecimal[user_id[index] >> 4];
        filename[position++] = hexadecimal[user_id[index] & 0x0f];
    }
    memcpy(filename + position, suffix, strlen(suffix) + 1);
}

static int store_collection(
    const struct storage *storage, const struct account_session *session,
    const struct credential_collection *collection)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int success = credentials_serialize(collection, &payload, &payload_length) &&
                  vault_write(storage, session, payload, payload_length);

    credentials_serialized_free(payload, payload_length);
    return success;
}

static int load_collection(
    const struct storage *storage, const struct account_session *session,
    struct credential_collection *collection)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int success = vault_read(storage, session, &payload, &payload_length) ==
                      VAULT_READ_OK &&
                  credentials_deserialize(payload, payload_length, collection);

    vault_secure_free(payload, payload_length);
    return success;
}

static int read_vault(const struct storage *storage, const char *filename,
                      unsigned char **data, size_t *length)
{
    return storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                             STORAGE_MAX_FILE_BYTES, data, length) ==
           STORAGE_READ_OK;
}

static void check_vault_unchanged(const struct storage *storage,
                                  const char *filename,
                                  const unsigned char *expected,
                                  size_t expected_length)
{
    unsigned char *actual = NULL;
    size_t actual_length = 0;

    CHECK(read_vault(storage, filename, &actual, &actual_length));
    CHECK(actual_length == expected_length);
    if (actual != NULL && actual_length == expected_length) {
        CHECK(memcmp(actual, expected, expected_length) == 0);
    }
    storage_free(actual);
}

int main(void)
{
    static const char alpha_password[] = "dummy-alpha-master-password";
    static const char beta_password[] = "dummy-beta-master-password";
    static const char wrong_password[] = "dummy-incorrect-password";
    static const unsigned char label[] = "identical-service";
    static const unsigned char username[] = "identical-user";
    static const unsigned char alpha_secret[] = "dummy-alpha-secret";
    static const unsigned char beta_secret[] = "dummy-beta-secret";
    static const unsigned char alpha_notes[] = "alpha private notes";
    static const unsigned char beta_notes[] = "beta private notes";
    static const unsigned char changed[] = "unauthorized-change";
    char home_template[TEST_PATH_BYTES];
    char alpha_filename[TEST_VAULT_FILENAME_BYTES];
    char beta_filename[TEST_VAULT_FILENAME_BYTES];
    char alpha_lock_filename[TEST_VAULT_FILENAME_BYTES];
    char beta_lock_filename[TEST_VAULT_FILENAME_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    struct account_session fabricated = ACCOUNT_SESSION_INITIALIZER;
    struct storage_lock lock = STORAGE_LOCK_INITIALIZER;
    struct credential_collection *alpha = NULL;
    struct credential_collection *beta = NULL;
    struct credential_collection *loaded = NULL;
    unsigned char alpha_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    unsigned char beta_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    unsigned char alpha_user_id[USER_DB_USER_ID_BYTES] = {0};
    unsigned char beta_user_id[USER_DB_USER_ID_BYTES] = {0};
    unsigned char *alpha_vault = NULL;
    unsigned char *beta_vault = NULL;
    unsigned char *mutated = NULL;
    unsigned char *plaintext = NULL;
    size_t alpha_vault_length = 0;
    size_t beta_vault_length = 0;
    size_t plaintext_length = 99;

    CHECK(home != NULL);
    if (home == NULL) {
        return 1;
    }
    CHECK(setenv("HOME", home, 1) == 0);
    CHECK(storage_init(&storage) == 1);
    alpha = calloc(1, sizeof(*alpha));
    beta = calloc(1, sizeof(*beta));
    loaded = calloc(1, sizeof(*loaded));
    CHECK(alpha != NULL && beta != NULL && loaded != NULL);
    if (alpha == NULL || beta == NULL || loaded == NULL) {
        goto cleanup;
    }
    credentials_init(alpha);
    credentials_init(beta);
    credentials_init(loaded);

    CHECK(account_register(&storage, "Alpha", 5,
                           alpha_password, sizeof(alpha_password) - 1) ==
          ACCOUNT_REGISTER_CREATED);
    CHECK(account_register(&storage, "Beta", 4,
                           beta_password, sizeof(beta_password) - 1) ==
          ACCOUNT_REGISTER_CREATED);

    CHECK(account_unlock(&storage, "Alpha", 5,
                         alpha_password, sizeof(alpha_password) - 1,
                         &session) == 1);
    CHECK(account_session_is_valid(&session) == 1);
    memcpy(alpha_user_id, session.user_id, sizeof(alpha_user_id));
    CHECK(credentials_add(alpha, label, sizeof(label) - 1,
                          username, sizeof(username) - 1,
                          alpha_secret, sizeof(alpha_secret) - 1,
                          alpha_notes, sizeof(alpha_notes) - 1,
                          alpha_id) == 1);
    CHECK(store_collection(&storage, &session, alpha));
    CHECK(account_registration_complete(&storage, &session) == 1);
    user_filename(alpha_user_id, ".vault", alpha_filename);
    user_filename(alpha_user_id, ".lock", alpha_lock_filename);
    CHECK(read_vault(&storage, alpha_filename,
                     &alpha_vault, &alpha_vault_length));
    if (alpha_vault == NULL || alpha_vault_length <= 12) {
        goto cleanup;
    }
    CHECK(vault_lock_acquire(&storage, &session, &lock) == 1);
    CHECK(storage_lock_is_held(&lock) == 1);
    storage_lock_release(&lock);
    CHECK(storage_lock_is_held(&lock) == 0);
    account_session_lock(&session);
    CHECK(account_session_is_valid(&session) == 0);
    CHECK(all_zero(session.user_id, sizeof(session.user_id)));
    CHECK(all_zero(session.vmk, sizeof(session.vmk)));
    CHECK(all_zero(session.authenticator, sizeof(session.authenticator)));
    CHECK(vault_read(&storage, &session, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    vault_secure_free(plaintext, plaintext_length);
    plaintext = NULL;
    plaintext_length = 0;

    CHECK(account_unlock(&storage, "Beta", 4,
                         beta_password, sizeof(beta_password) - 1,
                         &session) == 1);
    memcpy(beta_user_id, session.user_id, sizeof(beta_user_id));
    CHECK(memcmp(alpha_user_id, beta_user_id,
                 sizeof(alpha_user_id)) != 0);
    CHECK(credentials_add(beta, label, sizeof(label) - 1,
                          username, sizeof(username) - 1,
                          beta_secret, sizeof(beta_secret) - 1,
                          beta_notes, sizeof(beta_notes) - 1,
                          beta_id) == 1);
    CHECK(credentials_find(beta, alpha_id, sizeof(alpha_id)) == NULL);
    CHECK(credentials_update(beta, alpha_id, sizeof(alpha_id),
                             changed, sizeof(changed) - 1,
                             username, sizeof(username) - 1,
                             beta_secret, sizeof(beta_secret) - 1,
                             beta_notes, sizeof(beta_notes) - 1) == 0);
    CHECK(credentials_delete(beta, alpha_id, sizeof(alpha_id)) == 0);
    CHECK(beta->count == 1);
    CHECK(credentials_find(beta, beta_id, sizeof(beta_id)) != NULL);
    CHECK(store_collection(&storage, &session, beta));
    CHECK(account_registration_complete(&storage, &session) == 1);
    user_filename(beta_user_id, ".vault", beta_filename);
    user_filename(beta_user_id, ".lock", beta_lock_filename);
    CHECK(read_vault(&storage, beta_filename,
                     &beta_vault, &beta_vault_length));
    if (beta_vault == NULL || beta_vault_length == 0) {
        goto cleanup;
    }
    CHECK(vault_lock_acquire(&storage, &session, &lock) == 1);
    CHECK(storage_lock_is_held(&lock) == 1);
    storage_lock_release(&lock);
    CHECK(storage_lock_is_held(&lock) == 0);
    CHECK(strcmp(alpha_lock_filename, beta_lock_filename) != 0);
    {
        unsigned char *lock_data = NULL;
        size_t lock_length = 99;

        CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS,
                                alpha_lock_filename, 0,
                                &lock_data, &lock_length) == STORAGE_READ_OK);
        CHECK(lock_length == 0);
        storage_free(lock_data);
        lock_data = NULL;
        lock_length = 99;
        CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS,
                                beta_lock_filename, 0,
                                &lock_data, &lock_length) == STORAGE_READ_OK);
        CHECK(lock_length == 0);
        storage_free(lock_data);
    }

    CHECK(account_unlock(&storage, "Alpha", 5,
                         alpha_password, sizeof(alpha_password) - 1,
                         &session) == 1);
    credentials_cleanup(loaded);
    CHECK(load_collection(&storage, &session, loaded));
    CHECK(credentials_find(loaded, alpha_id, sizeof(alpha_id)) != NULL);
    CHECK(credentials_find(loaded, beta_id, sizeof(beta_id)) == NULL);
    CHECK(credentials_update(loaded, beta_id, sizeof(beta_id),
                             changed, sizeof(changed) - 1,
                             username, sizeof(username) - 1,
                             alpha_secret, sizeof(alpha_secret) - 1,
                             alpha_notes, sizeof(alpha_notes) - 1) == 0);
    CHECK(credentials_delete(loaded, beta_id, sizeof(beta_id)) == 0);
    CHECK(account_unlock(&storage, "Beta", 4,
                         wrong_password, sizeof(wrong_password) - 1,
                         &session) == 0);
    CHECK(account_session_is_valid(&session) == 0);
    CHECK(vault_read(&storage, &session, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    vault_secure_free(plaintext, plaintext_length);
    plaintext = NULL;
    plaintext_length = 0;

    storage_close(&storage);
    CHECK(storage_init(&storage) == 1);
    CHECK(account_unlock(&storage, "Beta", 4,
                         beta_password, sizeof(beta_password) - 1,
                         &session) == 1);
    credentials_cleanup(loaded);
    CHECK(load_collection(&storage, &session, loaded));
    {
        const struct credential_record *record =
            credentials_find(loaded, beta_id, sizeof(beta_id));

        CHECK(record != NULL);
        if (record != NULL) {
            CHECK(record->password_length == sizeof(beta_secret) - 1);
            CHECK(memcmp(record->password, beta_secret,
                         sizeof(beta_secret) - 1) == 0);
        }
    }

    fabricated = session;
    memcpy(fabricated.user_id, alpha_user_id, sizeof(alpha_user_id));
    CHECK(account_session_is_valid(&fabricated) == 0);
    CHECK(vault_lock_acquire(&storage, &fabricated, &lock) == 0);
    CHECK(vault_read(&storage, &fabricated, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    vault_secure_free(plaintext, plaintext_length);
    plaintext = NULL;
    plaintext_length = 0;
    CHECK(vault_write(&storage, &fabricated,
                      changed, sizeof(changed) - 1) == 0);
    check_vault_unchanged(&storage, alpha_filename,
                          alpha_vault, alpha_vault_length);
    check_vault_unchanged(&storage, beta_filename,
                          beta_vault, beta_vault_length);

    CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                               alpha_filename,
                               beta_vault, beta_vault_length) == 1);
    CHECK(account_unlock(&storage, "Alpha", 5,
                         alpha_password, sizeof(alpha_password) - 1,
                         &session) == 1);
    CHECK(vault_read(&storage, &session, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    vault_secure_free(plaintext, plaintext_length);
    plaintext = NULL;
    plaintext_length = 0;
    check_vault_unchanged(&storage, alpha_filename,
                          beta_vault, beta_vault_length);
    check_vault_unchanged(&storage, beta_filename,
                          beta_vault, beta_vault_length);
    CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                               alpha_filename,
                               alpha_vault, alpha_vault_length) == 1);

    mutated = malloc(alpha_vault_length);
    CHECK(mutated != NULL);
    if (mutated != NULL) {
        memcpy(mutated, alpha_vault, alpha_vault_length);
        mutated[alpha_vault_length - 1] ^= 1;
        CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                                   alpha_filename,
                                   mutated, alpha_vault_length) == 1);
        CHECK(vault_read(&storage, &session, &plaintext,
                         &plaintext_length) == VAULT_READ_ERROR);
        vault_secure_free(plaintext, plaintext_length);
        plaintext = NULL;
        plaintext_length = 0;
        check_vault_unchanged(&storage, alpha_filename,
                              mutated, alpha_vault_length);
        check_vault_unchanged(&storage, beta_filename,
                              beta_vault, beta_vault_length);

        CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                                   alpha_filename,
                                   alpha_vault, alpha_vault_length - 1) == 1);
        CHECK(vault_read(&storage, &session, &plaintext,
                         &plaintext_length) == VAULT_READ_ERROR);
        vault_secure_free(plaintext, plaintext_length);
        plaintext = NULL;
        plaintext_length = 0;
        check_vault_unchanged(&storage, beta_filename,
                              beta_vault, beta_vault_length);

        memcpy(mutated, alpha_vault, alpha_vault_length);
        mutated[12] ^= 1;
        CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                                   alpha_filename,
                                   mutated, alpha_vault_length) == 1);
        CHECK(vault_read(&storage, &session, &plaintext,
                         &plaintext_length) == VAULT_READ_ERROR);
        vault_secure_free(plaintext, plaintext_length);
        plaintext = NULL;
        plaintext_length = 0;
        check_vault_unchanged(&storage, beta_filename,
                              beta_vault, beta_vault_length);
    }
    CHECK(storage_atomic_write(&storage, STORAGE_AREA_VAULTS,
                               alpha_filename,
                               alpha_vault, alpha_vault_length) == 1);
    credentials_cleanup(loaded);
    CHECK(load_collection(&storage, &session, loaded));
    CHECK(credentials_find(loaded, alpha_id, sizeof(alpha_id)) != NULL);
    CHECK(account_unlock(&storage, "Beta", 4,
                         beta_password, sizeof(beta_password) - 1,
                         &session) == 1);
    credentials_cleanup(loaded);
    CHECK(load_collection(&storage, &session, loaded));
    CHECK(credentials_find(loaded, beta_id, sizeof(beta_id)) != NULL);

cleanup:
    storage_lock_release(&lock);
    account_session_lock(&session);
    OPENSSL_cleanse(&fabricated, sizeof(fabricated));
    if (alpha != NULL) {
        credentials_cleanup(alpha);
        free(alpha);
    }
    if (beta != NULL) {
        credentials_cleanup(beta);
        free(beta);
    }
    if (loaded != NULL) {
        credentials_cleanup(loaded);
        free(loaded);
    }
    storage_free(alpha_vault);
    storage_free(beta_vault);
    vault_secure_free(plaintext, plaintext_length);
    free(mutated);
    storage_close(&storage);
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u access-control checks\n",
                failures, checks);
        return 1;
    }
    printf("PASS: %u access-control checks\n", checks);
    return 0;
}
