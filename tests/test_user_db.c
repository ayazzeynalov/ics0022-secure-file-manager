#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "user_db.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_PATH_BYTES 4096
#define FILE_HEADER_BYTES 16
#define RECORD_FIXED_BYTES 162

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
                           "securepm-user-db-test.XXXXXX");
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

static void make_record(struct user_record *record, const char *username,
                        unsigned char seed)
{
    memset(record, 0, sizeof(*record));
    record->format_version = USER_DB_RECORD_VERSION;
    (void)snprintf(record->username, sizeof(record->username), "%s", username);
    record->scrypt = crypto_scrypt_defaults;
    for (size_t index = 0; index < sizeof(record->user_id); ++index) {
        record->user_id[index] = (unsigned char)(seed + index);
    }
    for (size_t index = 0; index < sizeof(record->salt); ++index) {
        record->salt[index] = (unsigned char)(seed + 0x20 + index);
    }
    for (size_t index = 0;
         index < sizeof(record->authentication_verifier); ++index) {
        record->authentication_verifier[index] =
            (unsigned char)(seed + 0x40 + index);
    }
    for (size_t index = 0; index < sizeof(record->wrapped_vmk); ++index) {
        record->wrapped_vmk[index] = (unsigned char)(seed + 0x60 + index);
    }
    for (size_t index = 0; index < sizeof(record->vmk_nonce); ++index) {
        record->vmk_nonce[index] = (unsigned char)(seed + 0x80 + index);
    }
    for (size_t index = 0; index < sizeof(record->vmk_tag); ++index) {
        record->vmk_tag[index] = (unsigned char)(seed + 0xa0 + index);
    }
}

static int records_equal(const struct user_record *left,
                         const struct user_record *right)
{
    return left->format_version == right->format_version &&
           strcmp(left->username, right->username) == 0 &&
           memcmp(left->user_id, right->user_id, sizeof(left->user_id)) == 0 &&
           memcmp(left->salt, right->salt, sizeof(left->salt)) == 0 &&
           left->scrypt.n == right->scrypt.n &&
           left->scrypt.r == right->scrypt.r &&
           left->scrypt.p == right->scrypt.p &&
           left->scrypt.max_memory == right->scrypt.max_memory &&
           memcmp(left->authentication_verifier,
                  right->authentication_verifier,
                  sizeof(left->authentication_verifier)) == 0 &&
           memcmp(left->wrapped_vmk, right->wrapped_vmk,
                  sizeof(left->wrapped_vmk)) == 0 &&
           memcmp(left->vmk_nonce, right->vmk_nonce,
                  sizeof(left->vmk_nonce)) == 0 &&
           memcmp(left->vmk_tag, right->vmk_tag,
                  sizeof(left->vmk_tag)) == 0;
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

static void write_u32_at(unsigned char *data, size_t offset, uint32_t value)
{
    data[offset] = (unsigned char)(value >> 24);
    data[offset + 1] = (unsigned char)(value >> 16);
    data[offset + 2] = (unsigned char)(value >> 8);
    data[offset + 3] = (unsigned char)value;
}

static void test_username_validation(void)
{
    char maximum[USER_DB_USERNAME_MAX_BYTES];
    char too_long[USER_DB_USERNAME_MAX_BYTES + 1];
    const char control[] = {'a', '\n'};
    const char non_ascii[] = {'a', (char)0x80};

    memset(maximum, 'a', sizeof(maximum));
    memset(too_long, 'b', sizeof(too_long));
    CHECK(user_db_username_valid("alice", 5) == 1);
    CHECK(user_db_username_valid(maximum, sizeof(maximum)) == 1);
    CHECK(user_db_username_valid(NULL, 5) == 0);
    CHECK(user_db_username_valid("", 0) == 0);
    CHECK(user_db_username_valid(too_long, sizeof(too_long)) == 0);
    CHECK(user_db_username_valid("has space", 9) == 0);
    CHECK(user_db_username_valid(control, sizeof(control)) == 0);
    CHECK(user_db_username_valid(non_ascii, sizeof(non_ascii)) == 0);
}

static void test_empty_database(const struct storage *storage)
{
    struct user_database database;
    unsigned char id[USER_DB_USER_ID_BYTES] = {0};

    memset(&database, 0xa5, sizeof(database));
    CHECK(user_db_load(storage, &database) == 1);
    CHECK(database.count == 0);
    CHECK(user_db_find_username(&database, "alice", 5) == NULL);
    CHECK(user_db_find_user_id(&database, id, sizeof(id)) == NULL);
    CHECK(user_db_save(storage, &database) == 1);
    memset(&database, 0xa5, sizeof(database));
    CHECK(user_db_load(storage, &database) == 1);
    CHECK(database.count == 0);
}

static void test_invalid_api_inputs(const struct storage *storage,
                                    const struct user_record *record)
{
    struct user_database database;

    user_db_init(&database);
    CHECK(user_db_add(NULL, record) == 0);
    CHECK(user_db_add(&database, NULL) == 0);
    CHECK(user_db_find_username(NULL, "Alice", 5) == NULL);
    CHECK(user_db_find_username(&database, NULL, 5) == NULL);
    CHECK(user_db_find_user_id(NULL, record->user_id,
                               sizeof(record->user_id)) == NULL);
    CHECK(user_db_find_user_id(&database, record->user_id,
                               sizeof(record->user_id) - 1) == NULL);
    CHECK(user_db_load(NULL, &database) == 0);
    CHECK(user_db_load(storage, NULL) == 0);
    CHECK(user_db_save(NULL, &database) == 0);
    CHECK(user_db_save(storage, NULL) == 0);
}

static void test_add_save_load(struct storage *storage,
                               const char *home,
                               struct user_record *alice,
                               struct user_record *carol)
{
    static const unsigned char forbidden_password[] =
        "dummy-plaintext-master-password";
    static const unsigned char forbidden_vmk[] =
        "dummy-plaintext-unwrapped-vmk";
    static const unsigned char encoded_n[8] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00
    };
    static const unsigned char encoded_memory[8] = {
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
    };
    struct user_database database;
    struct user_database loaded;
    struct user_record duplicate;
    const struct user_record *found;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0;
    struct stat status;
    char root[TEST_PATH_BYTES];
    char path[TEST_PATH_BYTES];

    user_db_init(&database);
    CHECK(user_db_add(&database, alice) == 1);

    make_record(&duplicate, "Alice", 0x30);
    CHECK(user_db_add(&database, &duplicate) == 0);
    make_record(&duplicate, "Other", 0x30);
    memcpy(duplicate.user_id, alice->user_id, sizeof(duplicate.user_id));
    CHECK(user_db_add(&database, &duplicate) == 0);
    duplicate = *carol;
    duplicate.scrypt.n = 2;
    CHECK(user_db_add(&database, &duplicate) == 0);

    CHECK(user_db_save(storage, &database) == 1);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                            STORAGE_MAX_FILE_BYTES,
                            &serialized, &serialized_length) == STORAGE_READ_OK);
    CHECK(serialized_length == FILE_HEADER_BYTES + RECORD_FIXED_BYTES + 5);
    CHECK(memcmp(serialized, "SPMUSRDB", 8) == 0);
    CHECK(serialized[8] == 0 && serialized[9] == 0 &&
          serialized[10] == 0 && serialized[11] == 1);
    CHECK(serialized[12] == 0 && serialized[13] == 0 &&
          serialized[14] == 0 && serialized[15] == 1);
    CHECK(serialized[16] == 0 && serialized[17] == 0 &&
          serialized[18] == 0 && serialized[19] == 1);
    CHECK(serialized[20] == 0 && serialized[21] == 5);
    CHECK(memcmp(serialized + 59, encoded_n, sizeof(encoded_n)) == 0);
    CHECK(memcmp(serialized + 83, encoded_memory,
                 sizeof(encoded_memory)) == 0);
    CHECK(!contains_bytes(serialized, serialized_length,
                          forbidden_password, sizeof(forbidden_password) - 1));
    CHECK(!contains_bytes(serialized, serialized_length,
                          forbidden_vmk, sizeof(forbidden_vmk) - 1));
    storage_free(serialized);

    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(path, root, USER_DB_FILENAME));
    CHECK(lstat(path, &status) == 0);
    CHECK(S_ISREG(status.st_mode));
    CHECK((status.st_mode & 07777) == STORAGE_FILE_MODE);
    CHECK(status.st_uid == geteuid());

    user_db_init(&loaded);
    CHECK(user_db_load(storage, &loaded) == 1);
    CHECK(loaded.count == 1);
    CHECK(records_equal(&loaded.records[0], alice));
    found = user_db_find_username(&loaded, "Alice", 5);
    CHECK(found != NULL && records_equal(found, alice));
    CHECK(user_db_find_username(&loaded, "alice", 5) == NULL);
    found = user_db_find_user_id(&loaded, alice->user_id,
                                 sizeof(alice->user_id));
    CHECK(found != NULL && records_equal(found, alice));

    CHECK(user_db_add(&loaded, carol) == 1);
    CHECK(user_db_save(storage, &loaded) == 1);
    user_db_init(&database);
    CHECK(user_db_load(storage, &database) == 1);
    CHECK(database.count == 2);
    CHECK(user_db_find_username(&database, "Carol", 5) != NULL);
}

static void test_persistence_after_reopen(struct storage *storage,
                                          const struct user_record *alice,
                                          const struct user_record *carol)
{
    struct user_database loaded;

    storage_close(storage);
    CHECK(storage_init(storage) == 1);
    user_db_init(&loaded);
    CHECK(user_db_load(storage, &loaded) == 1);
    CHECK(loaded.count == 2);
    CHECK(records_equal(&loaded.records[0], alice));
    CHECK(records_equal(&loaded.records[1], carol));
}

static void expect_invalid_blob(const struct storage *storage,
                                const unsigned char *data, size_t data_length)
{
    struct user_database database;

    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                               data, data_length) == 1);
    user_db_init(&database);
    database.count = 7;
    CHECK(user_db_load(storage, &database) == 0);
    CHECK(database.count == 7);
}

static void test_malformed_files(const struct storage *storage)
{
    unsigned char *valid = NULL;
    unsigned char *mutated;
    unsigned char *with_trailing;
    size_t valid_length = 0;
    const size_t first_username_length = 5;
    const size_t first_record = FILE_HEADER_BYTES;
    const size_t first_user_id = first_record + 6 + first_username_length;
    const size_t first_scrypt_n = first_user_id + USER_DB_USER_ID_BYTES +
                                  CRYPTO_SALT_BYTES;
    const size_t second_record = first_record + RECORD_FIXED_BYTES +
                                 first_username_length;
    const size_t second_user_id = second_record + 6 + 5;

    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, USER_DB_FILENAME,
                            STORAGE_MAX_FILE_BYTES,
                            &valid, &valid_length) == STORAGE_READ_OK);
    CHECK(valid_length == FILE_HEADER_BYTES +
                          2 * (RECORD_FIXED_BYTES + 5));
    mutated = malloc(valid_length);
    with_trailing = malloc(valid_length + 1);
    CHECK(mutated != NULL && with_trailing != NULL);
    if (mutated == NULL || with_trailing == NULL) {
        free(mutated);
        free(with_trailing);
        storage_free(valid);
        return;
    }

    memcpy(mutated, valid, valid_length);
    mutated[0] ^= 1;
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    write_u32_at(mutated, 8, USER_DB_FILE_VERSION + 1);
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    write_u32_at(mutated, 12, USER_DB_MAX_USERS + 1);
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    write_u32_at(mutated, first_record, USER_DB_RECORD_VERSION + 1);
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    mutated[first_record + 4] = 0;
    mutated[first_record + 5] = 0;
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    mutated[first_record + 6] = '\n';
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    memset(mutated + first_scrypt_n, 0, sizeof(uint64_t));
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    memcpy(mutated + second_record + 6,
           mutated + first_record + 6, first_username_length);
    expect_invalid_blob(storage, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    memcpy(mutated + second_user_id, mutated + first_user_id,
           USER_DB_USER_ID_BYTES);
    expect_invalid_blob(storage, mutated, valid_length);

    expect_invalid_blob(storage, valid, 0);
    expect_invalid_blob(storage, valid, FILE_HEADER_BYTES - 1);
    expect_invalid_blob(storage, valid, valid_length - 1);

    memcpy(with_trailing, valid, valid_length);
    with_trailing[valid_length] = 0xa5;
    expect_invalid_blob(storage, with_trailing, valid_length + 1);

    free(mutated);
    free(with_trailing);
    storage_free(valid);
}

static void test_save_validation(const struct storage *storage,
                                 const struct user_record *alice,
                                 const struct user_record *carol)
{
    struct user_database invalid;

    user_db_init(&invalid);
    invalid.count = 1;
    invalid.records[0] = *alice;
    invalid.records[0].scrypt.max_memory = 1;
    CHECK(user_db_save(storage, &invalid) == 0);

    user_db_init(&invalid);
    invalid.count = 2;
    invalid.records[0] = *alice;
    invalid.records[1] = *carol;
    memcpy(invalid.records[1].user_id, invalid.records[0].user_id,
           USER_DB_USER_ID_BYTES);
    CHECK(user_db_save(storage, &invalid) == 0);

    invalid.count = USER_DB_MAX_USERS + 1;
    CHECK(user_db_save(storage, &invalid) == 0);
}

int main(void)
{
    char home_template[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct user_record alice;
    struct user_record carol;
    int home_set;

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
    make_record(&alice, "Alice", 0x10);
    make_record(&carol, "Carol", 0x70);

    if (storage.root_fd >= 0 && storage.vaults_fd >= 0) {
        test_username_validation();
        test_empty_database(&storage);
        test_invalid_api_inputs(&storage, &alice);
        test_add_save_load(&storage, home, &alice, &carol);
        test_persistence_after_reopen(&storage, &alice, &carol);
        test_save_validation(&storage, &alice, &carol);
        test_malformed_files(&storage);
    }
    storage_close(&storage);
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u user database checks\n",
                failures, checks);
        return 1;
    }
    printf("PASS: %u user database checks\n", checks);
    return 0;
}
