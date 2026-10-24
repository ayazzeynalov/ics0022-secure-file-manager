#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "account.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/crypto.h>

#define TEST_PATH_BYTES 4096

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int read_exact(int descriptor, void *buffer, size_t length)
{
    unsigned char *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(descriptor, bytes + offset, length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int write_exact(int descriptor, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(descriptor, bytes + offset, length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

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
                           "securepm-account-test.XXXXXX");
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

static int contains_bytes(const unsigned char *data, size_t data_length,
                          const unsigned char *needle, size_t needle_length)
{
    if (needle_length == 0 || needle_length > data_length) {
        return 0;
    }
    for (size_t offset = 0; offset <= data_length - needle_length; ++offset) {
        if (memcmp(data + offset, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static void check_locked(const struct account_session *session)
{
    CHECK(session->unlocked == 0);
    CHECK(all_zero(session->user_id, sizeof(session->user_id)));
    CHECK(all_zero(session->vmk, sizeof(session->vmk)));
}

static void test_invalid_inputs(const struct storage *storage,
                                const char *password, size_t password_length)
{
    struct account_session session;
    unsigned char *data = NULL;
    size_t data_length = 0;
    char oversized_password[CRYPTO_PASSWORD_MAX_BYTES + 1];
    char short_password[ACCOUNT_MASTER_PASSWORD_MIN_BYTES - 1];

    memset(oversized_password, 'p', sizeof(oversized_password));
    memset(short_password, 'p', sizeof(short_password));
    memset(&session, 0xa5, sizeof(session));

    CHECK(account_register(NULL, "Alice", 5,
                           password, password_length) == 0);
    CHECK(account_register(storage, "has space", 9,
                           password, password_length) == 0);
    CHECK(account_register(storage, "Alice", 5, NULL,
                           password_length) == 0);
    CHECK(account_register(storage, "Alice", 5, password, 0) == 0);
    CHECK(account_register(storage, "Alice", 5, short_password,
                           sizeof(short_password)) == 0);
    CHECK(account_register(storage, "Alice", 5, oversized_password,
                           sizeof(oversized_password)) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                            STORAGE_MAX_FILE_BYTES, &data,
                            &data_length) == STORAGE_READ_MISSING);

    CHECK(account_unlock(storage, "Alice", 5, password, password_length,
                         NULL) == 0);
    CHECK(account_unlock(NULL, "Alice", 5, password, password_length,
                         &session) == 0);
    check_locked(&session);
    account_session_lock(NULL);
    OPENSSL_cleanse(short_password, sizeof(short_password));
    OPENSSL_cleanse(oversized_password, sizeof(oversized_password));
}

static void test_legacy_short_password(const struct storage *storage,
                                       struct account_session *session)
{
    char password[] = "old-pass-1";
    struct user_database database;
    struct user_record record = {0};
    struct crypto_keys keys = {0};
    unsigned char root[CRYPTO_KEY_BYTES] = {0};
    unsigned char vmk[AUTH_VMK_BYTES] = {0};
    int prepared;

    CHECK(sizeof(password) - 1 < ACCOUNT_MASTER_PASSWORD_MIN_BYTES);
    user_db_init(&database);
    CHECK(user_db_load(storage, &database) == 1);
    record.format_version = USER_DB_RECORD_VERSION;
    memcpy(record.username, "Legacy", sizeof("Legacy"));
    record.scrypt = crypto_scrypt_defaults;
    for (size_t index = 0; index < sizeof(record.user_id); ++index) {
        record.user_id[index] = (unsigned char)(0xd0 + index);
    }
    for (size_t index = 0; index < sizeof(record.salt); ++index) {
        record.salt[index] = (unsigned char)(0x70 + index);
    }
    prepared = crypto_derive_root(password, sizeof(password) - 1,
                                  record.salt, sizeof(record.salt),
                                  &record.scrypt, root, sizeof(root)) &&
               crypto_derive_keys(root, sizeof(root), &keys) &&
               auth_create_verifier(
                   keys.authentication, sizeof(keys.authentication),
                   record.authentication_verifier,
                   sizeof(record.authentication_verifier)) &&
               auth_generate_wrapped_vmk(
                   keys.kek, sizeof(keys.kek),
                   record.user_id, sizeof(record.user_id),
                   record.format_version,
                   vmk, sizeof(vmk),
                   record.wrapped_vmk, sizeof(record.wrapped_vmk),
                   record.vmk_nonce, sizeof(record.vmk_nonce),
                   record.vmk_tag, sizeof(record.vmk_tag));
    CHECK(prepared == 1);
    if (prepared) {
        CHECK(user_db_add(&database, &record) == 1);
        CHECK(user_db_save(storage, &database) == 1);
        CHECK(account_unlock(storage, "Legacy", 6,
                             password, sizeof(password) - 1,
                             session) == 1);
        CHECK(session->unlocked == 1);
        account_session_lock(session);
        check_locked(session);
    }
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(&record, sizeof(record));
    OPENSSL_cleanse(&keys, sizeof(keys));
    OPENSSL_cleanse(root, sizeof(root));
    OPENSSL_cleanse(vmk, sizeof(vmk));
}

static void test_registration(const struct storage *storage,
                              const char *alice_password,
                              size_t alice_password_length,
                              const char *carol_password,
                              size_t carol_password_length,
                              struct user_record *alice_record)
{
    struct user_database database;
    int ready_pipe[2] = {-1, -1};
    int start_pipe[2] = {-1, -1};
    pid_t children[2] = {-1, -1};
    int statuses[2] = {0, 0};
    char ready[2];

    CHECK(pipe(ready_pipe) == 0);
    CHECK(pipe(start_pipe) == 0);
    if (ready_pipe[0] < 0 || start_pipe[0] < 0) {
        return;
    }
    for (size_t index = 0; index < 2; ++index) {
        children[index] = fork();
        CHECK(children[index] >= 0);
        if (children[index] == 0) {
            const char *name = index == 0 ? "Alice" : "Carol";
            const char *password = index == 0 ? alice_password : carol_password;
            size_t length = index == 0 ? alice_password_length :
                                         carol_password_length;
            char start;

            close(ready_pipe[0]);
            close(start_pipe[1]);
            if (!write_exact(ready_pipe[1], "R", 1) ||
                !read_exact(start_pipe[0], &start, 1) ||
                !account_register(storage, name, 5, password, length)) {
                _exit(1);
            }
            _exit(0);
        }
    }
    close(ready_pipe[1]);
    close(start_pipe[0]);
    ready_pipe[1] = -1;
    start_pipe[0] = -1;
    CHECK(read_exact(ready_pipe[0], ready, sizeof(ready)));
    CHECK(write_exact(start_pipe[1], "GG", 2));
    for (size_t index = 0; index < 2; ++index) {
        if (children[index] > 0) {
            CHECK(waitpid(children[index], &statuses[index], 0) ==
                  children[index]);
            CHECK(WIFEXITED(statuses[index]) &&
                  WEXITSTATUS(statuses[index]) == 0);
        }
    }
    close(ready_pipe[0]);
    close(start_pipe[1]);
    CHECK(account_register(storage, "Alice", 5,
                           carol_password, carol_password_length) == 0);

    user_db_init(&database);
    CHECK(user_db_load(storage, &database) == 1);
    CHECK(database.count == 2);
    CHECK(user_db_find_username(&database, "Alice", 5) != NULL);
    CHECK(user_db_find_username(&database, "Carol", 5) != NULL);
    CHECK(memcmp(database.records[0].user_id, database.records[1].user_id,
                 USER_DB_USER_ID_BYTES) != 0);
    CHECK(memcmp(database.records[0].salt, database.records[1].salt,
                 CRYPTO_SALT_BYTES) != 0);
    CHECK(database.records[0].scrypt.n == crypto_scrypt_defaults.n);
    CHECK(database.records[0].scrypt.r == crypto_scrypt_defaults.r);
    CHECK(database.records[0].scrypt.p == crypto_scrypt_defaults.p);
    CHECK(database.records[0].scrypt.max_memory ==
          crypto_scrypt_defaults.max_memory);
    *alice_record = *user_db_find_username(&database, "Alice", 5);
}

static void test_unlock_and_no_plaintext(
    struct storage *storage,
    const char *alice_password, size_t alice_password_length,
    const char *carol_password, size_t carol_password_length,
    const struct user_record *alice_record,
    struct account_session *session)
{
    unsigned char *serialized = NULL;
    size_t serialized_length = 0;

    storage_close(storage);
    CHECK(storage_init(storage) == 1);
    CHECK(account_unlock(storage, "Alice", 5,
                         alice_password, alice_password_length,
                         session) == 1);
    CHECK(session->unlocked == 1);
    CHECK(memcmp(session->user_id, alice_record->user_id,
                 sizeof(session->user_id)) == 0);
    CHECK(!all_zero(session->vmk, sizeof(session->vmk)));

    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                            STORAGE_MAX_FILE_BYTES, &serialized,
                            &serialized_length) == STORAGE_READ_OK);
    CHECK(!contains_bytes(serialized, serialized_length,
                          (const unsigned char *)alice_password,
                          alice_password_length));
    CHECK(!contains_bytes(serialized, serialized_length,
                          (const unsigned char *)carol_password,
                          carol_password_length));
    CHECK(!contains_bytes(serialized, serialized_length,
                          session->vmk, sizeof(session->vmk)));
    storage_free(serialized);
}

static void test_authentication_failures(
    const struct storage *storage,
    const char *alice_password, size_t alice_password_length,
    const char *wrong_password, size_t wrong_password_length,
    struct account_session *session)
{
    CHECK(account_unlock(storage, "Alice", 5,
                         wrong_password, wrong_password_length,
                         session) == 0);
    check_locked(session);

    memset(session, 0xa5, sizeof(*session));
    session->unlocked = 1;
    CHECK(account_unlock(storage, "Missing", 7,
                         alice_password, alice_password_length,
                         session) == 0);
    check_locked(session);
}

static void test_corrupted_record(
    const struct storage *storage,
    const char *alice_password, size_t alice_password_length,
    const struct user_record *alice_record,
    struct account_session *session)
{
    struct user_database database;
    const struct user_record *stored_alice;
    size_t alice_index;

    user_db_init(&database);
    CHECK(user_db_load(storage, &database) == 1);
    CHECK(database.count == 2);
    stored_alice = user_db_find_username(&database, "Alice", 5);
    CHECK(stored_alice != NULL);
    if (stored_alice == NULL) {
        return;
    }
    alice_index = (size_t)(stored_alice - database.records);

    database.records[alice_index].authentication_verifier[0] ^= 1;
    CHECK(user_db_save(storage, &database) == 1);
    memset(session, 0xa5, sizeof(*session));
    session->unlocked = 1;
    CHECK(account_unlock(storage, "Alice", 5,
                         alice_password, alice_password_length,
                         session) == 0);
    check_locked(session);

    database.records[alice_index] = *alice_record;
    database.records[alice_index].wrapped_vmk[0] ^= 1;
    CHECK(user_db_save(storage, &database) == 1);
    memset(session, 0xa5, sizeof(*session));
    session->unlocked = 1;
    CHECK(account_unlock(storage, "Alice", 5,
                         alice_password, alice_password_length,
                         session) == 0);
    check_locked(session);

    database.records[alice_index] = *alice_record;
    CHECK(user_db_save(storage, &database) == 1);
    CHECK(account_unlock(storage, "Alice", 5,
                         alice_password, alice_password_length,
                         session) == 1);
}

static void test_malformed_database(
    const struct storage *storage,
    const char *alice_password, size_t alice_password_length,
    struct account_session *session)
{
    static const unsigned char malformed[] = {
        'S', 'P', 'M', 'U', 'S', 'R', 'D', 'B', 0x00
    };
    unsigned char *stored = NULL;
    size_t stored_length = 0;

    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                               malformed, sizeof(malformed)) == 1);
    memset(session, 0xa5, sizeof(*session));
    session->unlocked = 1;
    CHECK(account_unlock(storage, "Alice", 5,
                         alice_password, alice_password_length,
                         session) == 0);
    check_locked(session);
    CHECK(account_register(storage, "Dave", 4,
                           alice_password, alice_password_length) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                            sizeof(malformed), &stored,
                            &stored_length) == STORAGE_READ_OK);
    CHECK(stored_length == sizeof(malformed));
    CHECK(memcmp(stored, malformed, sizeof(malformed)) == 0);
    storage_free(stored);
}

static void test_session_lock(struct account_session *session)
{
    account_session_lock(session);
    check_locked(session);
    account_session_lock(session);
    check_locked(session);
}

int main(void)
{
    char home_template[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct user_record alice_record = {0};
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    char alice_password[] = "dummy-master-password-alpha";
    char carol_password[] = "dummy-pass12";
    char wrong_password[] = "dummy-wrong-password";
    const size_t alice_password_length = sizeof(alice_password) - 1;
    const size_t carol_password_length = sizeof(carol_password) - 1;
    const size_t wrong_password_length = sizeof(wrong_password) - 1;
    int home_set;

    CHECK(carol_password_length == ACCOUNT_MASTER_PASSWORD_MIN_BYTES);
    CHECK(home != NULL);
    if (home == NULL) {
        return 1;
    }
    home_set = setenv("HOME", home, 1) == 0;
    CHECK(home_set);
    if (!home_set) {
        CHECK(remove_tree(home));
        return 1;
    }
    CHECK(storage_init(&storage) == 1);
    if (storage.root_fd >= 0 && storage.vaults_fd >= 0) {
        test_invalid_inputs(&storage, alice_password, alice_password_length);
        test_registration(&storage,
                          alice_password, alice_password_length,
                          carol_password, carol_password_length,
                          &alice_record);
        test_unlock_and_no_plaintext(&storage,
                                     alice_password, alice_password_length,
                                     carol_password, carol_password_length,
                                     &alice_record, &session);
        test_authentication_failures(&storage,
                                     alice_password, alice_password_length,
                                     wrong_password, wrong_password_length,
                                     &session);
        test_corrupted_record(&storage,
                              alice_password, alice_password_length,
                              &alice_record, &session);
        test_legacy_short_password(&storage, &session);
        test_session_lock(&session);
        test_malformed_database(&storage,
                                alice_password, alice_password_length,
                                &session);
    }
    account_session_lock(&session);
    storage_close(&storage);
    OPENSSL_cleanse(&alice_record, sizeof(alice_record));
    OPENSSL_cleanse(alice_password, sizeof(alice_password));
    OPENSSL_cleanse(carol_password, sizeof(carol_password));
    OPENSSL_cleanse(wrong_password, sizeof(wrong_password));
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u account checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u account checks\n", checks);
    return 0;
}
