#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "credentials.h"

#include "account.h"
#include "storage.h"
#include "vault.h"

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
#define TEST_VAULT_FILENAME_BYTES 39
#define TEST_HEADER_BYTES 16
#define TEST_RECORD_HEADER_BYTES 32

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static struct credential_collection *new_collection(void)
{
    struct credential_collection *collection = malloc(sizeof(*collection));

    if (collection != NULL) {
        credentials_init(collection);
    }
    return collection;
}

static int all_zero(const void *data, size_t length)
{
    const unsigned char *bytes = data;

    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] != 0) {
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

static uint32_t read_u32(const unsigned char input[4])
{
    return (uint32_t)input[0] << 24 |
           (uint32_t)input[1] << 16 |
           (uint32_t)input[2] << 8 |
           input[3];
}

static void write_u32(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static int add_record(struct credential_collection *collection,
                      const unsigned char *label, size_t label_length,
                      const unsigned char *username, size_t username_length,
                      const unsigned char *password, size_t password_length,
                      const unsigned char *notes, size_t notes_length,
                      unsigned char id[CREDENTIALS_RECORD_ID_BYTES])
{
    return credentials_add(collection, label, label_length,
                           username, username_length,
                           password, password_length,
                           notes, notes_length, id);
}

static void test_empty_collection(void)
{
    struct credential_collection *collection = new_collection();
    struct credential_collection *decoded = new_collection();
    unsigned char *payload = (unsigned char *)1;
    size_t payload_length = 123;

    CHECK(collection != NULL && decoded != NULL);
    if (collection == NULL || decoded == NULL) {
        free(collection);
        free(decoded);
        return;
    }
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 1);
    CHECK(payload != NULL && payload_length == TEST_HEADER_BYTES);
    if (payload != NULL && payload_length == TEST_HEADER_BYTES) {
        CHECK(memcmp(payload, "SPMCREDS", 8) == 0);
        CHECK(read_u32(payload + 8) == CREDENTIALS_FORMAT_VERSION);
        CHECK(read_u32(payload + 12) == 0);
        CHECK(credentials_deserialize(payload, payload_length, decoded) == 1);
    }
    CHECK(decoded->count == 0);
    credentials_serialized_free(payload, payload_length);
    credentials_cleanup(collection);
    credentials_cleanup(decoded);
    free(collection);
    free(decoded);
}

static void test_add_find_and_round_trip(void)
{
    static const unsigned char label_one[] = "mail/account\nprimary";
    static const unsigned char username_one[] = "dummy+user@example.test";
    static const unsigned char password_one[] = {0x00, 'a', '\n', 0xff, 'Z'};
    static const unsigned char notes_one[] = "symbols: !@#$%^&*()";
    static const unsigned char label_two[] = "server";
    static const unsigned char password_two[] = "second-dummy-password";
    struct credential_collection *collection = new_collection();
    struct credential_collection *decoded = new_collection();
    unsigned char first_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char second_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char missing_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    const struct credential_record *record;

    CHECK(collection != NULL && decoded != NULL);
    if (collection == NULL || decoded == NULL) {
        free(collection);
        free(decoded);
        return;
    }
    CHECK(add_record(collection,
                     label_one, sizeof(label_one) - 1,
                     username_one, sizeof(username_one) - 1,
                     password_one, sizeof(password_one),
                     notes_one, sizeof(notes_one) - 1, first_id) == 1);
    CHECK(add_record(collection,
                     label_two, sizeof(label_two) - 1,
                     NULL, 0,
                     password_two, sizeof(password_two) - 1,
                     NULL, 0, second_id) == 1);
    CHECK(collection->count == 2);
    CHECK(memcmp(first_id, second_id, sizeof(first_id)) != 0);
    record = credentials_find(collection, first_id, sizeof(first_id));
    CHECK(record != NULL);
    if (record != NULL) {
        CHECK(record->label_length == sizeof(label_one) - 1);
        CHECK(memcmp(record->label, label_one, record->label_length) == 0);
        CHECK(record->password_length == sizeof(password_one));
        CHECK(memcmp(record->password, password_one,
                     record->password_length) == 0);
    }
    CHECK(credentials_find(collection, missing_id, sizeof(missing_id)) == NULL);
    CHECK(credentials_find(collection, first_id, sizeof(first_id) - 1) == NULL);
    CHECK(credentials_find(NULL, first_id, sizeof(first_id)) == NULL);

    CHECK(credentials_serialize(collection, &payload, &payload_length) == 1);
    CHECK(payload_length <= VAULT_MAX_PLAINTEXT_BYTES);
    CHECK(read_u32(payload + 12) == 2);
    CHECK(memcmp(payload + TEST_HEADER_BYTES, first_id,
                 CREDENTIALS_RECORD_ID_BYTES) == 0);
    CHECK(read_u32(payload + 32) == sizeof(label_one) - 1);
    CHECK(read_u32(payload + 36) == sizeof(username_one) - 1);
    CHECK(read_u32(payload + 40) == sizeof(password_one));
    CHECK(read_u32(payload + 44) == sizeof(notes_one) - 1);
    CHECK(credentials_deserialize(payload, payload_length, decoded) == 1);
    CHECK(decoded->count == 2);
    record = credentials_find(decoded, first_id, sizeof(first_id));
    CHECK(record != NULL);
    if (record != NULL) {
        CHECK(memcmp(record->id, first_id, sizeof(first_id)) == 0);
        CHECK(record->username_length == sizeof(username_one) - 1);
        CHECK(memcmp(record->username, username_one,
                     record->username_length) == 0);
        CHECK(record->password_length == sizeof(password_one));
        CHECK(memcmp(record->password, password_one,
                     record->password_length) == 0);
        CHECK(record->notes_length == sizeof(notes_one) - 1);
        CHECK(memcmp(record->notes, notes_one, record->notes_length) == 0);
    }
    record = credentials_find(decoded, second_id, sizeof(second_id));
    CHECK(record != NULL);
    if (record != NULL) {
        CHECK(record->username_length == 0 && record->notes_length == 0);
    }
    credentials_serialized_free(payload, payload_length);
    credentials_cleanup(collection);
    credentials_cleanup(decoded);
    free(collection);
    free(decoded);
}

static void test_update_and_delete(void)
{
    static const unsigned char first_label[] = "first";
    static const unsigned char first_password[] = "old-secret-value";
    static const unsigned char second_label[] = "second";
    static const unsigned char new_label[] = "updated";
    static const unsigned char new_username[] = "new-user";
    static const unsigned char new_password[] = {0x00, 'n', 'e', 'w', 0xff};
    static const unsigned char new_notes[] = "new notes";
    struct credential_collection *collection = new_collection();
    unsigned char first_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char second_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char stable_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char missing_id[CREDENTIALS_RECORD_ID_BYTES] = {0};
    struct credential_collection *before_failed_update = NULL;
    const struct credential_record *record;

    CHECK(collection != NULL);
    if (collection == NULL) {
        return;
    }
    CHECK(add_record(collection, first_label, sizeof(first_label) - 1,
                     NULL, 0, first_password, sizeof(first_password) - 1,
                     NULL, 0, first_id) == 1);
    CHECK(add_record(collection, second_label, sizeof(second_label) - 1,
                     NULL, 0, NULL, 0, NULL, 0, second_id) == 1);
    memcpy(stable_id, first_id, sizeof(stable_id));

    CHECK(credentials_update(collection, first_id, sizeof(first_id),
                             new_label, sizeof(new_label) - 1,
                             new_username, sizeof(new_username) - 1,
                             new_password, sizeof(new_password),
                             new_notes, sizeof(new_notes) - 1) == 1);
    CHECK(collection->count == 2);
    record = credentials_find(collection, first_id, sizeof(first_id));
    CHECK(record != NULL);
    if (record != NULL) {
        CHECK(memcmp(record->id, stable_id, sizeof(stable_id)) == 0);
        CHECK(record->label_length == sizeof(new_label) - 1);
        CHECK(memcmp(record->label, new_label,
                     sizeof(new_label) - 1) == 0);
        CHECK(record->username_length == sizeof(new_username) - 1);
        CHECK(memcmp(record->username, new_username,
                     sizeof(new_username) - 1) == 0);
        CHECK(record->password_length == sizeof(new_password));
        CHECK(memcmp(record->password, new_password,
                     sizeof(new_password)) == 0);
        CHECK(record->notes_length == sizeof(new_notes) - 1);
        CHECK(memcmp(record->notes, new_notes,
                     sizeof(new_notes) - 1) == 0);
        CHECK(!contains_bytes((const unsigned char *)record, sizeof(*record),
                              first_password,
                              sizeof(first_password) - 1));
    }
    CHECK(credentials_update(collection, missing_id, sizeof(missing_id),
                             new_label, sizeof(new_label) - 1,
                             NULL, 0, NULL, 0, NULL, 0) == 0);
    CHECK(credentials_update(collection, first_id, sizeof(first_id) - 1,
                             new_label, sizeof(new_label) - 1,
                             NULL, 0, NULL, 0, NULL, 0) == 0);
    before_failed_update = malloc(sizeof(*before_failed_update));
    CHECK(before_failed_update != NULL);
    if (before_failed_update != NULL) {
        memcpy(before_failed_update, collection, sizeof(*collection));
    }
    CHECK(credentials_update(collection, first_id, sizeof(first_id),
                             NULL, 0, NULL, 0, NULL, 0, NULL, 0) == 0);
    CHECK(credentials_update(collection, first_id, sizeof(first_id),
                             new_label, sizeof(new_label) - 1,
                             NULL, 0, new_password,
                             CREDENTIALS_PASSWORD_MAX_BYTES + 1U,
                             NULL, 0) == 0);
    if (before_failed_update != NULL) {
        CHECK(memcmp(before_failed_update, collection,
                     sizeof(*collection)) == 0);
        credentials_cleanup(before_failed_update);
        free(before_failed_update);
    }
    record = credentials_find(collection, first_id, sizeof(first_id));
    CHECK(record != NULL && record->password_length == sizeof(new_password));

    CHECK(credentials_delete(collection, first_id, sizeof(first_id)) == 1);
    CHECK(collection->count == 1);
    CHECK(credentials_find(collection, first_id, sizeof(first_id)) == NULL);
    record = credentials_find(collection, second_id, sizeof(second_id));
    CHECK(record == &collection->records[0]);
    CHECK(all_zero(&collection->records[1], sizeof(collection->records[1])));
    CHECK(credentials_delete(collection, first_id, sizeof(first_id)) == 0);
    CHECK(credentials_delete(collection, second_id, sizeof(second_id) - 1) == 0);
    CHECK(credentials_delete(NULL, second_id, sizeof(second_id)) == 0);
    CHECK(credentials_delete(collection, second_id, sizeof(second_id)) == 1);
    CHECK(collection->count == 0);
    CHECK(all_zero(&collection->records[0], sizeof(collection->records[0])));

    credentials_cleanup(collection);
    free(collection);
}

static void test_collection_isolation(void)
{
    static const unsigned char label[] = "isolated";
    static const unsigned char changed[] = "changed";
    struct credential_collection *first = new_collection();
    struct credential_collection *second = new_collection();
    unsigned char first_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char second_id[CREDENTIALS_RECORD_ID_BYTES];

    CHECK(first != NULL && second != NULL);
    if (first == NULL || second == NULL) {
        free(first);
        free(second);
        return;
    }
    CHECK(add_record(first, label, sizeof(label) - 1,
                     NULL, 0, NULL, 0, NULL, 0, first_id) == 1);
    CHECK(add_record(second, label, sizeof(label) - 1,
                     NULL, 0, NULL, 0, NULL, 0, second_id) == 1);
    CHECK(credentials_find(second, first_id, sizeof(first_id)) == NULL);
    CHECK(credentials_update(second, first_id, sizeof(first_id),
                             changed, sizeof(changed) - 1,
                             NULL, 0, NULL, 0, NULL, 0) == 0);
    CHECK(credentials_delete(second, first_id, sizeof(first_id)) == 0);
    CHECK(second->count == 1);
    CHECK(credentials_find(second, second_id, sizeof(second_id)) != NULL);

    credentials_cleanup(first);
    credentials_cleanup(second);
    free(first);
    free(second);
}

static void test_limits_and_invalid_inputs(void)
{
    struct credential_collection *collection = new_collection();
    struct credential_collection *decoded = new_collection();
    unsigned char label[CREDENTIALS_LABEL_MAX_BYTES];
    unsigned char username[CREDENTIALS_USERNAME_MAX_BYTES];
    unsigned char password[CREDENTIALS_PASSWORD_MAX_BYTES];
    unsigned char notes[CREDENTIALS_NOTES_MAX_BYTES];
    unsigned char id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char *payload = (unsigned char *)1;
    size_t payload_length = 99;

    CHECK(collection != NULL && decoded != NULL);
    if (collection == NULL || decoded == NULL) {
        free(collection);
        free(decoded);
        return;
    }
    memset(label, 'l', sizeof(label));
    memset(username, 'u', sizeof(username));
    memset(password, 0xa5, sizeof(password));
    memset(notes, 'n', sizeof(notes));
    CHECK(add_record(collection, label, sizeof(label), username,
                     sizeof(username), password, sizeof(password),
                     notes, sizeof(notes), id) == 1);
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 1);
    CHECK(payload_length == TEST_HEADER_BYTES + TEST_RECORD_HEADER_BYTES +
                            sizeof(label) + sizeof(username) +
                            sizeof(password) + sizeof(notes));
    CHECK(credentials_deserialize(payload, payload_length, decoded) == 1);
    CHECK(decoded->records[0].label_length == sizeof(label));
    CHECK(decoded->records[0].password_length == sizeof(password));
    credentials_serialized_free(payload, payload_length);

    CHECK(add_record(collection, NULL, 0, NULL, 0, NULL, 0,
                     NULL, 0, id) == 0);
    CHECK(add_record(collection, label, sizeof(label) + 1,
                     NULL, 0, NULL, 0, NULL, 0, id) == 0);
    CHECK(add_record(collection, label, 1,
                     username, sizeof(username) + 1,
                     NULL, 0, NULL, 0, id) == 0);
    CHECK(add_record(collection, label, 1, NULL, 0,
                     password, sizeof(password) + 1,
                     NULL, 0, id) == 0);
    CHECK(add_record(collection, label, 1, NULL, 0, NULL, 0,
                     notes, sizeof(notes) + 1, id) == 0);
    CHECK(add_record(collection, label, 1, NULL, 1,
                     NULL, 0, NULL, 0, id) == 0);
    CHECK(credentials_add(NULL, label, 1, NULL, 0, NULL, 0,
                          NULL, 0, id) == 0);
    CHECK(credentials_add(collection, label, 1, NULL, 0, NULL, 0,
                          NULL, 0, NULL) == 0);
    CHECK(credentials_serialize(NULL, &payload, &payload_length) == 0);
    CHECK(payload == NULL && payload_length == 0);
    CHECK(credentials_serialize(collection, NULL, &payload_length) == 0);
    CHECK(credentials_serialize(collection, &payload, NULL) == 0);
    CHECK(credentials_deserialize(NULL, TEST_HEADER_BYTES, decoded) == 0);
    CHECK(credentials_deserialize((const unsigned char *)"x",
                                  VAULT_MAX_PLAINTEXT_BYTES + 1U,
                                  decoded) == 0);
    CHECK(credentials_deserialize((const unsigned char *)"x", 1,
                                  decoded) == 0);
    CHECK(credentials_deserialize((const unsigned char *)"SPMCREDS",
                                  8, NULL) == 0);
    credentials_cleanup(collection);
    credentials_cleanup(decoded);
    OPENSSL_cleanse(password, sizeof(password));
    free(collection);
    free(decoded);
}

static void test_record_limit(void)
{
    static const unsigned char label[] = "x";
    struct credential_collection *collection = new_collection();
    unsigned char id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char previous[CREDENTIALS_RECORD_ID_BYTES] = {0};
    unsigned char *payload = NULL;
    size_t payload_length = 0;

    CHECK(collection != NULL);
    if (collection == NULL) {
        return;
    }
    for (size_t index = 0; index < CREDENTIALS_MAX_RECORDS; ++index) {
        CHECK(add_record(collection, label, sizeof(label) - 1,
                         NULL, 0, NULL, 0, NULL, 0, id) == 1);
        CHECK(credentials_find(collection, id, sizeof(id)) != NULL);
        if (index != 0) {
            CHECK(memcmp(id, previous, sizeof(id)) != 0);
        }
        memcpy(previous, id, sizeof(previous));
    }
    CHECK(collection->count == CREDENTIALS_MAX_RECORDS);
    CHECK(add_record(collection, label, sizeof(label) - 1,
                     NULL, 0, NULL, 0, NULL, 0, id) == 0);
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 1);
    CHECK(payload_length <= VAULT_MAX_PLAINTEXT_BYTES);
    credentials_serialized_free(payload, payload_length);
    credentials_cleanup(collection);
    free(collection);
}

static void expect_deserialize_error(const unsigned char *payload,
                                     size_t payload_length)
{
    struct credential_collection *output = malloc(sizeof(*output));

    CHECK(output != NULL);
    if (output == NULL) {
        return;
    }
    memset(output, 0x5a, sizeof(*output));
    CHECK(credentials_deserialize(payload, payload_length, output) == 0);
    CHECK(((unsigned char *)output)[0] == 0x5a);
    OPENSSL_cleanse(output, sizeof(*output));
    free(output);
}

static void test_malformed_payloads(void)
{
    static const unsigned char label_one[] = "one";
    static const unsigned char label_two[] = "two";
    static const unsigned char password[] = "dummy-password";
    struct credential_collection *collection = new_collection();
    unsigned char first_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char second_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char *payload = NULL;
    unsigned char *mutated = NULL;
    size_t payload_length = 0;
    size_t second_offset;

    CHECK(collection != NULL);
    if (collection == NULL) {
        return;
    }
    CHECK(add_record(collection, label_one, sizeof(label_one) - 1,
                     NULL, 0, password, sizeof(password) - 1,
                     NULL, 0, first_id) == 1);
    CHECK(add_record(collection, label_two, sizeof(label_two) - 1,
                     NULL, 0, NULL, 0,
                     NULL, 0, second_id) == 1);
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 1);
    mutated = OPENSSL_malloc(payload_length + 1);
    CHECK(mutated != NULL);
    if (payload == NULL || mutated == NULL) {
        credentials_serialized_free(payload, payload_length);
        OPENSSL_free(mutated);
        credentials_cleanup(collection);
        free(collection);
        return;
    }
    for (size_t length = 0; length < payload_length; ++length) {
        expect_deserialize_error(payload, length);
    }
    memcpy(mutated, payload, payload_length);
    mutated[0] ^= 1;
    expect_deserialize_error(mutated, payload_length);

    memcpy(mutated, payload, payload_length);
    write_u32(mutated + 8, CREDENTIALS_FORMAT_VERSION + 1);
    expect_deserialize_error(mutated, payload_length);

    memcpy(mutated, payload, payload_length);
    write_u32(mutated + 12, CREDENTIALS_MAX_RECORDS + 1U);
    expect_deserialize_error(mutated, payload_length);

    for (size_t field = 0; field < 4; ++field) {
        memcpy(mutated, payload, payload_length);
        write_u32(mutated + 32 + field * 4, UINT32_MAX);
        expect_deserialize_error(mutated, payload_length);
    }
    memcpy(mutated, payload, payload_length);
    write_u32(mutated + 32, 0);
    expect_deserialize_error(mutated, payload_length);

    second_offset = TEST_HEADER_BYTES + TEST_RECORD_HEADER_BYTES +
                    sizeof(label_one) - 1 + sizeof(password) - 1;
    memcpy(mutated, payload, payload_length);
    memcpy(mutated + second_offset, mutated + TEST_HEADER_BYTES,
           CREDENTIALS_RECORD_ID_BYTES);
    expect_deserialize_error(mutated, payload_length);

    memcpy(mutated, payload, payload_length);
    mutated[payload_length] = 0xa5;
    expect_deserialize_error(mutated, payload_length + 1);

    memcpy(collection->records[1].id, collection->records[0].id,
           CREDENTIALS_RECORD_ID_BYTES);
    OPENSSL_clear_free(mutated, payload_length + 1);
    mutated = NULL;
    credentials_serialized_free(payload, payload_length);
    payload = (unsigned char *)1;
    payload_length = 88;
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 0);
    CHECK(payload == NULL && payload_length == 0);

    collection->count = SIZE_MAX;
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 0);
    collection->count = 1;
    collection->records[0].label_length = SIZE_MAX;
    CHECK(credentials_serialize(collection, &payload, &payload_length) == 0);
    credentials_cleanup(collection);
    free(collection);
}

static void test_secure_cleanup(void)
{
    static const unsigned char label[] = "cleanup";
    static const unsigned char password[] = "sensitive-dummy-password";
    struct credential_collection *collection = new_collection();
    unsigned char id[CREDENTIALS_RECORD_ID_BYTES];

    CHECK(collection != NULL);
    if (collection == NULL) {
        return;
    }
    CHECK(add_record(collection, label, sizeof(label) - 1,
                     NULL, 0, password, sizeof(password) - 1,
                     NULL, 0, id) == 1);
    credentials_cleanup(collection);
    CHECK(all_zero(collection, sizeof(*collection)));
    credentials_cleanup(NULL);
    credentials_serialized_free(NULL, 0);
    free(collection);
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
                           "securepm-credentials-test.XXXXXX");
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

static void vault_filename(const unsigned char user_id[USER_DB_USER_ID_BYTES],
                           char filename[TEST_VAULT_FILENAME_BYTES])
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t position = 0;

    for (size_t index = 0; index < USER_DB_USER_ID_BYTES; ++index) {
        filename[position++] = hexadecimal[user_id[index] >> 4];
        filename[position++] = hexadecimal[user_id[index] & 0x0f];
    }
    memcpy(filename + position, ".vault", sizeof(".vault"));
}

static int transfer_byte(int descriptor, char *byte, int writing)
{
    ssize_t result;

    do {
        result = writing ? write(descriptor, byte, 1) :
                           read(descriptor, byte, 1);
    } while (result < 0 && errno == EINTR);
    return result == 1;
}

static int recover_pending_account(int ready_fd, int start_fd, int done_fd)
{
    static const char password[] = "dummy-concurrent-recovery-password";
    struct storage storage = STORAGE_INITIALIZER;
    struct storage_lock vault_lock = STORAGE_LOCK_INITIALIZER;
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    struct credential_collection *collection = new_collection();
    unsigned char *payload = NULL;
    unsigned char *serialized = NULL;
    size_t payload_length = 0;
    size_t serialized_length = 0;
    char byte = 'R';
    int vault_result;
    int success = collection != NULL && storage_init(&storage) == 1 &&
                  account_register(&storage, "Concurrent", 10,
                                   password, sizeof(password) - 1) ==
                      ACCOUNT_REGISTER_RECOVERY;

    byte = success ? 'R' : 'F';
    success = transfer_byte(ready_fd, &byte, 1) && success;
    if (transfer_byte(start_fd, &byte, 0) && success) {
        success = account_unlock(&storage, "Concurrent", 10,
                                 password, sizeof(password) - 1,
                                 &session) == 1 &&
                  vault_lock_acquire(&storage, &session, &vault_lock) == 1;
    } else {
        success = 0;
    }

    if (success) {
        vault_result = vault_read(&storage, &session,
                                  &payload, &payload_length);
        if (vault_result == VAULT_READ_MISSING) {
            success = credentials_serialize(collection, &serialized,
                                            &serialized_length) == 1 &&
                      vault_write(&storage, &session,
                                  serialized, serialized_length) == 1;
        } else if (vault_result == VAULT_READ_OK) {
            success = credentials_deserialize(payload, payload_length,
                                              collection) == 1 &&
                      collection->count == 0;
        } else {
            success = 0;
        }
    }
    if (success) {
        success = account_registration_complete(&storage, &session) == 1;
    }
    byte = success ? 'D' : 'F';
    (void)transfer_byte(done_fd, &byte, 1);
    vault_secure_free(payload, payload_length);
    credentials_serialized_free(serialized, serialized_length);
    if (collection != NULL) {
        credentials_cleanup(collection);
        free(collection);
    }
    account_session_lock(&session);
    storage_lock_release(&vault_lock);
    storage_close(&storage);
    return success;
}

static void test_concurrent_registration_recovery(void)
{
    static const char password[] = "dummy-concurrent-recovery-password";
    char home_template[TEST_PATH_BYTES];
    char filename[TEST_VAULT_FILENAME_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct user_database database;
    const struct user_record *record;
    unsigned char *first_vault = NULL;
    unsigned char *second_vault = NULL;
    size_t first_length = 0;
    size_t second_length = 0;
    int ready_pipe[2] = {-1, -1};
    int done_pipe[2] = {-1, -1};
    int start_pipes[2][2] = {{-1, -1}, {-1, -1}};
    pid_t children[2] = {-1, -1};
    int statuses[2] = {0, 0};
    char byte;
    int home_set;

    CHECK(home != NULL);
    if (home == NULL) {
        return;
    }
    home_set = setenv("HOME", home, 1) == 0;
    CHECK(home_set);
    CHECK(home_set && storage_init(&storage) == 1);
    CHECK(account_register(&storage, "Concurrent", 10,
                           password, sizeof(password) - 1) ==
          ACCOUNT_REGISTER_CREATED);
    user_db_init(&database);
    CHECK(user_db_load(&storage, &database) == 1);
    record = user_db_find_username(&database, "Concurrent", 10);
    CHECK(record != NULL);
    if (record != NULL) {
        vault_filename(record->user_id, filename);
    }
    storage_close(&storage);

    CHECK(pipe(ready_pipe) == 0);
    CHECK(pipe(done_pipe) == 0);
    CHECK(pipe(start_pipes[0]) == 0);
    CHECK(pipe(start_pipes[1]) == 0);
    if (record != NULL && ready_pipe[0] >= 0 && done_pipe[0] >= 0 &&
        start_pipes[0][0] >= 0 && start_pipes[1][0] >= 0) {
        for (size_t index = 0; index < 2; ++index) {
            children[index] = fork();
            CHECK(children[index] >= 0);
            if (children[index] == 0) {
                close(ready_pipe[0]);
                close(done_pipe[0]);
                close(start_pipes[index][1]);
                close(start_pipes[1 - index][0]);
                close(start_pipes[1 - index][1]);
                _exit(recover_pending_account(ready_pipe[1],
                                              start_pipes[index][0],
                                              done_pipe[1]) ? 0 : 1);
            }
        }
        close(ready_pipe[1]);
        close(done_pipe[1]);
        close(start_pipes[0][0]);
        close(start_pipes[1][0]);
        ready_pipe[1] = -1;
        done_pipe[1] = -1;
        start_pipes[0][0] = -1;
        start_pipes[1][0] = -1;
        CHECK(transfer_byte(ready_pipe[0], &byte, 0) && byte == 'R');
        CHECK(transfer_byte(ready_pipe[0], &byte, 0) && byte == 'R');

        byte = 'S';
        CHECK(transfer_byte(start_pipes[0][1], &byte, 1));
        CHECK(transfer_byte(done_pipe[0], &byte, 0) && byte == 'D');
        CHECK(storage_init(&storage) == 1);
        CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS, filename,
                                STORAGE_MAX_FILE_BYTES, &first_vault,
                                &first_length) == STORAGE_READ_OK);
        storage_close(&storage);

        byte = 'S';
        CHECK(transfer_byte(start_pipes[1][1], &byte, 1));
        CHECK(transfer_byte(done_pipe[0], &byte, 0) && byte == 'D');
        CHECK(storage_init(&storage) == 1);
        CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS, filename,
                                STORAGE_MAX_FILE_BYTES, &second_vault,
                                &second_length) == STORAGE_READ_OK);
        storage_close(&storage);
        CHECK(first_length == second_length);
        if (first_vault != NULL && second_vault != NULL &&
            first_length == second_length) {
            CHECK(memcmp(first_vault, second_vault, first_length) == 0);
        }
        for (size_t index = 0; index < 2; ++index) {
            CHECK(waitpid(children[index], &statuses[index], 0) ==
                  children[index]);
            CHECK(WIFEXITED(statuses[index]) &&
                  WEXITSTATUS(statuses[index]) == 0);
        }
    }
    storage_free(first_vault);
    storage_free(second_vault);
    storage_close(&storage);
    for (size_t index = 0; index < 2; ++index) {
        if (ready_pipe[index] >= 0) {
            close(ready_pipe[index]);
        }
        if (done_pipe[index] >= 0) {
            close(done_pipe[index]);
        }
        for (size_t pipe_index = 0; pipe_index < 2; ++pipe_index) {
            if (start_pipes[index][pipe_index] >= 0) {
                close(start_pipes[index][pipe_index]);
            }
        }
    }
    CHECK(remove_tree(home));
}

static void test_vault_integration(void)
{
    static const unsigned char label[] = "integration service";
    static const unsigned char username[] = "integration-user";
    static const unsigned char password[] = "vault-only-dummy-password";
    static const unsigned char notes[] = "dummy integration notes";
    char master_password[] = "dummy-master-password-for-integration";
    char home_template[TEST_PATH_BYTES];
    char filename[TEST_VAULT_FILENAME_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    struct storage_lock vault_lock = STORAGE_LOCK_INITIALIZER;
    struct account_session session = ACCOUNT_SESSION_INITIALIZER;
    struct credential_collection *collection = new_collection();
    struct credential_collection *decoded = new_collection();
    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES];
    unsigned char *serialized = NULL;
    unsigned char *decrypted = NULL;
    unsigned char *encrypted_file = NULL;
    unsigned char *after_recovery = NULL;
    size_t serialized_length = 0;
    size_t decrypted_length = 0;
    size_t encrypted_length = 0;
    size_t after_recovery_length = 0;
    int home_set;

    CHECK(home != NULL && collection != NULL && decoded != NULL);
    if (home == NULL || collection == NULL || decoded == NULL) {
        if (home != NULL) {
            CHECK(remove_tree(home));
        }
        free(collection);
        free(decoded);
        OPENSSL_cleanse(master_password, sizeof(master_password));
        return;
    }
    home_set = setenv("HOME", home, 1) == 0;
    CHECK(home_set);
    if (!home_set) {
        CHECK(remove_tree(home));
        credentials_cleanup(collection);
        credentials_cleanup(decoded);
        free(collection);
        free(decoded);
        OPENSSL_cleanse(master_password, sizeof(master_password));
        return;
    }
    CHECK(storage_init(&storage) == 1);
    CHECK(account_register(&storage, "Integration", 11,
                           master_password,
                           sizeof(master_password) - 1) == 1);
    CHECK(account_unlock(&storage, "Integration", 11,
                         master_password, sizeof(master_password) - 1,
                         &session) == 1);
    CHECK(add_record(collection, label, sizeof(label) - 1,
                     username, sizeof(username) - 1,
                     password, sizeof(password) - 1,
                     notes, sizeof(notes) - 1, record_id) == 1);
    CHECK(credentials_serialize(collection, &serialized,
                                &serialized_length) == 1);
    CHECK(vault_lock_acquire(&storage, &session, &vault_lock) == 1);
    CHECK(vault_write(&storage, &session,
                      serialized, serialized_length) == 1);
    vault_filename(session.user_id, filename);
    CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES, &encrypted_file,
                            &encrypted_length) == STORAGE_READ_OK);
    CHECK(!contains_bytes(encrypted_file, encrypted_length,
                          password, sizeof(password) - 1));
    CHECK(!contains_bytes(encrypted_file, encrypted_length,
                          username, sizeof(username) - 1));
    credentials_serialized_free(serialized, serialized_length);
    serialized = NULL;
    serialized_length = 0;
    account_session_lock(&session);
    storage_lock_release(&vault_lock);
    storage_close(&storage);

    CHECK(storage_init(&storage) == 1);
    CHECK(account_register(&storage, "Integration", 11,
                           master_password,
                           sizeof(master_password) - 1) ==
          ACCOUNT_REGISTER_RECOVERY);
    CHECK(account_unlock(&storage, "Integration", 11,
                         master_password, sizeof(master_password) - 1,
                         &session) == 1);
    CHECK(vault_lock_acquire(&storage, &session, &vault_lock) == 1);
    CHECK(vault_read(&storage, &session, &decrypted,
                     &decrypted_length) == VAULT_READ_OK);
    CHECK(credentials_deserialize(decrypted, decrypted_length, decoded) == 1);
    CHECK(decoded->count == 1);
    const struct credential_record *record =
        credentials_find(decoded, record_id, sizeof(record_id));
    CHECK(record != NULL);
    if (record != NULL) {
        CHECK(record->password_length == sizeof(password) - 1);
        CHECK(memcmp(record->password, password,
                     record->password_length) == 0);
        CHECK(record->notes_length == sizeof(notes) - 1);
        CHECK(memcmp(record->notes, notes, record->notes_length) == 0);
    }
    CHECK(account_registration_complete(&storage, &session) == 1);
    CHECK(storage_read_file(&storage, STORAGE_AREA_VAULTS, filename,
                            STORAGE_MAX_FILE_BYTES, &after_recovery,
                            &after_recovery_length) == STORAGE_READ_OK);
    CHECK(after_recovery_length == encrypted_length);
    if (after_recovery != NULL && after_recovery_length == encrypted_length) {
        CHECK(memcmp(after_recovery, encrypted_file, encrypted_length) == 0);
    }

    vault_secure_free(decrypted, decrypted_length);
    credentials_serialized_free(serialized, serialized_length);
    storage_free(encrypted_file);
    storage_free(after_recovery);
    credentials_cleanup(collection);
    credentials_cleanup(decoded);
    account_session_lock(&session);
    storage_lock_release(&vault_lock);
    storage_close(&storage);
    OPENSSL_cleanse(master_password, sizeof(master_password));
    free(collection);
    free(decoded);
    CHECK(remove_tree(home));
}

int main(void)
{
    test_empty_collection();
    test_add_find_and_round_trip();
    test_update_and_delete();
    test_collection_isolation();
    test_limits_and_invalid_inputs();
    test_record_limit();
    test_malformed_payloads();
    test_secure_cleanup();
    test_vault_integration();
    test_concurrent_registration_recovery();

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u credential checks\n",
                failures, checks);
        return 1;
    }
    printf("PASS: %u credential checks\n", checks);
    return 0;
}
