#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "vault.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_PATH_BYTES 4096
#define TEST_FILENAME_BYTES 39
#define TEST_AAD_BYTES 32
#define TEST_NONCE_OFFSET 32
#define TEST_CIPHERTEXT_OFFSET 44
#define TEST_FIXED_BYTES 60

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
                           "securepm-vault-test.XXXXXX");
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

static void make_session(struct account_session *session,
                         unsigned char id_seed, unsigned char key_seed)
{
    memset(session, 0, sizeof(*session));
    session->unlocked = 1;
    for (size_t index = 0; index < sizeof(session->user_id); ++index) {
        session->user_id[index] = (unsigned char)(id_seed + index);
    }
    for (size_t index = 0; index < sizeof(session->vmk); ++index) {
        session->vmk[index] = (unsigned char)(key_seed + index);
    }
}

static void make_filename(const unsigned char user_id[USER_DB_USER_ID_BYTES],
                          char filename[TEST_FILENAME_BYTES])
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t position = 0;

    for (size_t index = 0; index < USER_DB_USER_ID_BYTES; ++index) {
        filename[position++] = hexadecimal[user_id[index] >> 4];
        filename[position++] = hexadecimal[user_id[index] & 0x0f];
    }
    memcpy(filename + position, ".vault", sizeof(".vault"));
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

static void write_u32_at(unsigned char *data, size_t offset, uint32_t value)
{
    data[offset] = (unsigned char)(value >> 24);
    data[offset + 1] = (unsigned char)(value >> 16);
    data[offset + 2] = (unsigned char)(value >> 8);
    data[offset + 3] = (unsigned char)value;
}

static void test_locked_and_missing(const struct storage *storage,
                                    const struct account_session *session)
{
    static const unsigned char payload[] = "dummy";
    struct account_session locked = *session;
    struct account_session missing;
    unsigned char *plaintext = (unsigned char *)1;
    size_t plaintext_length = 123;

    locked.unlocked = 0;
    make_session(&missing, 0x60, 0x90);
    CHECK(vault_write(storage, &locked, payload, sizeof(payload) - 1) == 0);
    CHECK(vault_read(storage, &locked, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    CHECK(vault_read(storage, &missing, &plaintext,
                     &plaintext_length) == VAULT_READ_MISSING);
    CHECK(plaintext == NULL && plaintext_length == 0);
    CHECK(vault_write(storage, session, NULL, 1) == 0);
    CHECK(vault_write(storage, session, payload,
                      VAULT_MAX_PLAINTEXT_BYTES + 1U) == 0);
    CHECK(vault_read(storage, session, NULL, &plaintext_length) ==
          VAULT_READ_ERROR);
    CHECK(vault_read(storage, session, &plaintext, NULL) == VAULT_READ_ERROR);
}

static void check_round_trip(const struct storage *storage,
                             const struct account_session *session,
                             const unsigned char *expected,
                             size_t expected_length)
{
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;

    CHECK(vault_read(storage, session, &plaintext,
                     &plaintext_length) == VAULT_READ_OK);
    CHECK(plaintext != NULL);
    CHECK(plaintext_length == expected_length);
    if (plaintext != NULL && plaintext_length == expected_length) {
        CHECK(memcmp(plaintext, expected, expected_length) == 0);
    }
    vault_secure_free(plaintext, plaintext_length);
}

static void test_write_read_and_reopen(struct storage *storage,
                                       const struct account_session *session)
{
    static const unsigned char payload[] =
        "recognizable dummy plaintext inside the encrypted vault";

    CHECK(vault_write(storage, session, payload, sizeof(payload) - 1) == 1);
    storage_close(storage);
    CHECK(storage_init(storage) == 1);
    check_round_trip(storage, session, payload, sizeof(payload) - 1);
}

static void test_file_format_and_replacement(
    const struct storage *storage,
    const struct account_session *session,
    unsigned char **valid_file, size_t *valid_file_length)
{
    static const unsigned char first_payload[] =
        "recognizable dummy plaintext inside the encrypted vault";
    static const unsigned char replacement[] =
        "replacement encrypted vault payload";
    static const char expected_filename[] =
        "000102030405060708090a0b0c0d0e0f.vault";
    unsigned char first_nonce[CRYPTO_GCM_NONCE_BYTES];
    unsigned char *first_file = NULL;
    size_t first_file_length = 0;
    struct stat before;
    struct stat after;
    char filename[TEST_FILENAME_BYTES];

    make_filename(session->user_id, filename);
    CHECK(strcmp(filename, expected_filename) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES,
                            &first_file, &first_file_length) == STORAGE_READ_OK);
    CHECK(first_file_length == TEST_FIXED_BYTES + sizeof(first_payload) - 1);
    CHECK(memcmp(first_file, "SPMVAULT", 8) == 0);
    CHECK(first_file[8] == 0 && first_file[9] == 0 &&
          first_file[10] == 0 && first_file[11] == 1);
    CHECK(memcmp(first_file + 12, session->user_id,
                 USER_DB_USER_ID_BYTES) == 0);
    CHECK(first_file[28] == 0 && first_file[29] == 0 &&
          first_file[30] == 0 &&
          first_file[31] == (unsigned char)(sizeof(first_payload) - 1));
    CHECK(!contains_bytes(first_file, first_file_length,
                          first_payload, sizeof(first_payload) - 1));
    CHECK(!all_zero(first_file + TEST_NONCE_OFFSET,
                    CRYPTO_GCM_NONCE_BYTES));
    memcpy(first_nonce, first_file + TEST_NONCE_OFFSET, sizeof(first_nonce));
    CHECK(fstatat(storage->vaults_fd, filename, &before,
                  AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(S_ISREG(before.st_mode));
    CHECK((before.st_mode & 07777) == STORAGE_FILE_MODE);
    CHECK(before.st_uid == geteuid());

    CHECK(vault_write(storage, session,
                      replacement, sizeof(replacement) - 1) == 1);
    CHECK(fstatat(storage->vaults_fd, filename, &after,
                  AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    CHECK(storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES,
                            valid_file, valid_file_length) == STORAGE_READ_OK);
    CHECK(*valid_file_length == TEST_FIXED_BYTES + sizeof(replacement) - 1);
    CHECK(memcmp(first_nonce, *valid_file + TEST_NONCE_OFFSET,
                 sizeof(first_nonce)) != 0);
    CHECK(!contains_bytes(*valid_file, *valid_file_length,
                          replacement, sizeof(replacement) - 1));
    check_round_trip(storage, session, replacement, sizeof(replacement) - 1);
    storage_free(first_file);
}

static void test_empty_vault(const struct storage *storage)
{
    struct account_session empty_session;
    unsigned char *plaintext = NULL;
    unsigned char *serialized = NULL;
    size_t plaintext_length = 99;
    size_t serialized_length = 0;
    char filename[TEST_FILENAME_BYTES];

    make_session(&empty_session, 0x20, 0x40);
    make_filename(empty_session.user_id, filename);
    CHECK(vault_write(storage, &empty_session, NULL, 0) == 1);
    CHECK(vault_read(storage, &empty_session, &plaintext,
                     &plaintext_length) == VAULT_READ_OK);
    CHECK(plaintext != NULL && plaintext_length == 0);
    vault_secure_free(plaintext, plaintext_length);
    CHECK(storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES, &serialized,
                            &serialized_length) == STORAGE_READ_OK);
    CHECK(serialized_length == TEST_FIXED_BYTES);
    storage_free(serialized);
}

static void expect_read_error(const struct storage *storage,
                              const struct account_session *session,
                              const char *filename,
                              const unsigned char *data, size_t data_length)
{
    unsigned char *plaintext = (unsigned char *)1;
    unsigned char *stored = NULL;
    size_t plaintext_length = 123;
    size_t stored_length = 0;

    CHECK(storage_atomic_write(storage, STORAGE_AREA_VAULTS, filename,
                               data, data_length) == 1);
    CHECK(vault_read(storage, session, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES,
                            &stored, &stored_length) == STORAGE_READ_OK);
    CHECK(stored_length == data_length);
    if (stored != NULL && stored_length == data_length) {
        CHECK(memcmp(stored, data, data_length) == 0);
    }
    storage_free(stored);
}

static void test_wrong_session_and_authenticated_header(
    const struct storage *storage,
    const struct account_session *session,
    const unsigned char *valid, size_t valid_length)
{
    struct account_session wrong_key = *session;
    struct account_session wrong_id = *session;
    struct account_session changed_header = *session;
    unsigned char *mutated = malloc(valid_length);
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    char filename[TEST_FILENAME_BYTES];

    CHECK(mutated != NULL);
    if (mutated == NULL) {
        return;
    }
    make_filename(session->user_id, filename);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_VAULTS, filename,
                               valid, valid_length) == 1);
    wrong_key.vmk[0] ^= 1;
    CHECK(vault_read(storage, &wrong_key, &plaintext,
                     &plaintext_length) == VAULT_READ_ERROR);
    CHECK(plaintext == NULL && plaintext_length == 0);

    wrong_id.user_id[0] ^= 1;
    make_filename(wrong_id.user_id, filename);
    expect_read_error(storage, &wrong_id, filename, valid, valid_length);

    memcpy(mutated, valid, valid_length);
    changed_header.user_id[1] ^= 1;
    mutated[13] ^= 1;
    make_filename(changed_header.user_id, filename);
    expect_read_error(storage, &changed_header, filename,
                      mutated, valid_length);
    free(mutated);
}

static void test_corrupted_files(const struct storage *storage,
                                 const struct account_session *session,
                                 const unsigned char *valid,
                                 size_t valid_length)
{
    unsigned char *mutated = malloc(valid_length + 1);
    char filename[TEST_FILENAME_BYTES];
    size_t ciphertext_length = valid_length - TEST_FIXED_BYTES;

    CHECK(mutated != NULL);
    if (mutated == NULL) {
        return;
    }
    make_filename(session->user_id, filename);

    memcpy(mutated, valid, valid_length);
    mutated[TEST_CIPHERTEXT_OFFSET] ^= 1;
    expect_read_error(storage, session, filename, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    mutated[TEST_NONCE_OFFSET] ^= 1;
    expect_read_error(storage, session, filename, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    mutated[TEST_CIPHERTEXT_OFFSET + ciphertext_length] ^= 1;
    expect_read_error(storage, session, filename, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    mutated[0] ^= 1;
    expect_read_error(storage, session, filename, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    write_u32_at(mutated, 8, VAULT_FORMAT_VERSION + 1);
    expect_read_error(storage, session, filename, mutated, valid_length);

    memcpy(mutated, valid, valid_length);
    write_u32_at(mutated, 28, VAULT_MAX_PLAINTEXT_BYTES + 1U);
    expect_read_error(storage, session, filename, mutated, valid_length);

    expect_read_error(storage, session, filename, valid, 0);
    expect_read_error(storage, session, filename, valid,
                      TEST_CIPHERTEXT_OFFSET - 1);
    expect_read_error(storage, session, filename, valid, valid_length - 1);

    memcpy(mutated, valid, valid_length);
    mutated[valid_length] = 0xa5;
    expect_read_error(storage, session, filename, mutated, valid_length + 1);

    CHECK(storage_atomic_write(storage, STORAGE_AREA_VAULTS, filename,
                               valid, valid_length) == 1);
    free(mutated);
}

int main(void)
{
    char home_template[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct account_session session;
    unsigned char *valid_file = NULL;
    size_t valid_file_length = 0;
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
    make_session(&session, 0x00, 0x80);

    if (storage.root_fd >= 0 && storage.vaults_fd >= 0) {
        test_locked_and_missing(&storage, &session);
        test_write_read_and_reopen(&storage, &session);
        test_file_format_and_replacement(&storage, &session,
                                         &valid_file, &valid_file_length);
        test_empty_vault(&storage);
        if (valid_file != NULL) {
            test_wrong_session_and_authenticated_header(
                &storage, &session, valid_file, valid_file_length);
            test_corrupted_files(&storage, &session,
                                 valid_file, valid_file_length);
        }
    }
    storage_free(valid_file);
    account_session_lock(&session);
    vault_secure_free(NULL, 0);
    storage_close(&storage);
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u vault checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u vault checks\n", checks);
    return 0;
}
