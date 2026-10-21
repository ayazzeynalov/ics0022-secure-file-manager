#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "user_db.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define USER_DB_MAGIC_BYTES 8
#define USER_DB_HEADER_BYTES 16
#define USER_DB_RECORD_FIXED_BYTES 162
#define USER_DB_MAX_FILE_BYTES \
    (USER_DB_HEADER_BYTES + \
     USER_DB_MAX_USERS * (USER_DB_RECORD_FIXED_BYTES + \
                          USER_DB_USERNAME_MAX_BYTES))

static const unsigned char user_db_magic[USER_DB_MAGIC_BYTES] = {
    'S', 'P', 'M', 'U', 'S', 'R', 'D', 'B'
};

struct read_cursor {
    const unsigned char *data;
    size_t length;
    size_t offset;
};

static int valid_database(const struct user_database *database);

void user_db_init(struct user_database *database)
{
    if (database != NULL) {
        memset(database, 0, sizeof(*database));
    }
}

int user_db_username_valid(const char *username, size_t username_length)
{
    if (username == NULL || username_length == 0 ||
        username_length > USER_DB_USERNAME_MAX_BYTES) {
        return 0;
    }
    for (size_t index = 0; index < username_length; ++index) {
        unsigned char character = (unsigned char)username[index];

        if (character < 0x21 || character > 0x7e) {
            return 0;
        }
    }
    return 1;
}

static int username_length(const struct user_record *record, size_t *length)
{
    size_t value;

    if (record == NULL || length == NULL) {
        return 0;
    }
    value = strnlen(record->username, sizeof(record->username));
    if (value == sizeof(record->username) ||
        !user_db_username_valid(record->username, value)) {
        return 0;
    }
    *length = value;
    return 1;
}

static int production_scrypt_params(const struct crypto_scrypt_params *params)
{
    return params != NULL &&
           params->n == crypto_scrypt_defaults.n &&
           params->r == crypto_scrypt_defaults.r &&
           params->p == crypto_scrypt_defaults.p &&
           params->max_memory == crypto_scrypt_defaults.max_memory;
}

static int valid_record(const struct user_record *record,
                        size_t *record_username_length)
{
    size_t length;

    if (record == NULL || record->format_version != USER_DB_RECORD_VERSION ||
        !username_length(record, &length) ||
        !production_scrypt_params(&record->scrypt)) {
        return 0;
    }
    if (record_username_length != NULL) {
        *record_username_length = length;
    }
    return 1;
}

const struct user_record *user_db_find_username(
    const struct user_database *database,
    const char *username, size_t username_length_value)
{
    if (database == NULL || database->count > USER_DB_MAX_USERS ||
        !user_db_username_valid(username, username_length_value)) {
        return NULL;
    }
    for (size_t index = 0; index < database->count; ++index) {
        size_t stored_length;

        if (!username_length(&database->records[index], &stored_length)) {
            return NULL;
        }
        if (stored_length == username_length_value &&
            memcmp(database->records[index].username, username,
                   username_length_value) == 0) {
            return &database->records[index];
        }
    }
    return NULL;
}

const struct user_record *user_db_find_user_id(
    const struct user_database *database,
    const unsigned char *user_id, size_t user_id_length)
{
    if (database == NULL || database->count > USER_DB_MAX_USERS ||
        user_id == NULL || user_id_length != USER_DB_USER_ID_BYTES) {
        return NULL;
    }
    for (size_t index = 0; index < database->count; ++index) {
        if (memcmp(database->records[index].user_id, user_id,
                   USER_DB_USER_ID_BYTES) == 0) {
            return &database->records[index];
        }
    }
    return NULL;
}

int user_db_add(struct user_database *database,
                const struct user_record *record)
{
    size_t record_username_length;

    if (!valid_database(database) || database->count == USER_DB_MAX_USERS ||
        !valid_record(record, &record_username_length) ||
        user_db_find_username(database, record->username,
                              record_username_length) != NULL ||
        user_db_find_user_id(database, record->user_id,
                             sizeof(record->user_id)) != NULL) {
        errno = EINVAL;
        return 0;
    }
    database->records[database->count] = *record;
    ++database->count;
    return 1;
}

static int valid_database(const struct user_database *database)
{
    if (database == NULL || database->count > USER_DB_MAX_USERS) {
        return 0;
    }
    for (size_t index = 0; index < database->count; ++index) {
        size_t current_length;

        if (!valid_record(&database->records[index], &current_length)) {
            return 0;
        }
        for (size_t previous = 0; previous < index; ++previous) {
            size_t previous_length;

            if (!username_length(&database->records[previous],
                                 &previous_length)) {
                return 0;
            }
            if ((current_length == previous_length &&
                 memcmp(database->records[index].username,
                        database->records[previous].username,
                        current_length) == 0) ||
                memcmp(database->records[index].user_id,
                       database->records[previous].user_id,
                       USER_DB_USER_ID_BYTES) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

static void write_u16(unsigned char **output, uint16_t value)
{
    (*output)[0] = (unsigned char)(value >> 8);
    (*output)[1] = (unsigned char)value;
    *output += 2;
}

static void write_u32(unsigned char **output, uint32_t value)
{
    (*output)[0] = (unsigned char)(value >> 24);
    (*output)[1] = (unsigned char)(value >> 16);
    (*output)[2] = (unsigned char)(value >> 8);
    (*output)[3] = (unsigned char)value;
    *output += 4;
}

static void write_u64(unsigned char **output, uint64_t value)
{
    for (unsigned int index = 0; index < 8; ++index) {
        (*output)[index] = (unsigned char)(value >> (56 - index * 8));
    }
    *output += 8;
}

static void write_bytes(unsigned char **output, const void *data, size_t length)
{
    memcpy(*output, data, length);
    *output += length;
}

int user_db_save(const struct storage *storage,
                 const struct user_database *database)
{
    unsigned char *serialized;
    unsigned char *output;
    size_t serialized_length = USER_DB_HEADER_BYTES;
    int result;

    if (storage == NULL || !valid_database(database)) {
        errno = EINVAL;
        return 0;
    }
    for (size_t index = 0; index < database->count; ++index) {
        size_t length;

        if (!username_length(&database->records[index], &length) ||
            length > SIZE_MAX - USER_DB_RECORD_FIXED_BYTES ||
            serialized_length > SIZE_MAX - USER_DB_RECORD_FIXED_BYTES - length) {
            errno = EOVERFLOW;
            return 0;
        }
        serialized_length += USER_DB_RECORD_FIXED_BYTES + length;
    }
    serialized = malloc(serialized_length);
    if (serialized == NULL) {
        return 0;
    }
    output = serialized;
    write_bytes(&output, user_db_magic, sizeof(user_db_magic));
    write_u32(&output, USER_DB_FILE_VERSION);
    write_u32(&output, (uint32_t)database->count);
    for (size_t index = 0; index < database->count; ++index) {
        const struct user_record *record = &database->records[index];
        size_t length;

        if (!username_length(record, &length)) {
            free(serialized);
            errno = EINVAL;
            return 0;
        }
        write_u32(&output, record->format_version);
        write_u16(&output, (uint16_t)length);
        write_bytes(&output, record->username, length);
        write_bytes(&output, record->user_id, sizeof(record->user_id));
        write_bytes(&output, record->salt, sizeof(record->salt));
        write_u64(&output, record->scrypt.n);
        write_u64(&output, record->scrypt.r);
        write_u64(&output, record->scrypt.p);
        write_u64(&output, record->scrypt.max_memory);
        write_bytes(&output, record->authentication_verifier,
                    sizeof(record->authentication_verifier));
        write_bytes(&output, record->wrapped_vmk,
                    sizeof(record->wrapped_vmk));
        write_bytes(&output, record->vmk_nonce, sizeof(record->vmk_nonce));
        write_bytes(&output, record->vmk_tag, sizeof(record->vmk_tag));
    }
    result = storage_atomic_write(storage, STORAGE_AREA_ROOT,
                                  USER_DB_FILENAME,
                                  serialized, serialized_length);
    free(serialized);
    return result;
}

static int read_bytes(struct read_cursor *cursor, void *output, size_t length)
{
    if (cursor == NULL || output == NULL ||
        cursor->offset > cursor->length ||
        length > cursor->length - cursor->offset) {
        return 0;
    }
    memcpy(output, cursor->data + cursor->offset, length);
    cursor->offset += length;
    return 1;
}

static int read_u16(struct read_cursor *cursor, uint16_t *value)
{
    unsigned char bytes[2];

    if (value == NULL || !read_bytes(cursor, bytes, sizeof(bytes))) {
        return 0;
    }
    *value = (uint16_t)((uint16_t)bytes[0] << 8 | bytes[1]);
    return 1;
}

static int read_u32(struct read_cursor *cursor, uint32_t *value)
{
    unsigned char bytes[4];

    if (value == NULL || !read_bytes(cursor, bytes, sizeof(bytes))) {
        return 0;
    }
    *value = (uint32_t)bytes[0] << 24 |
             (uint32_t)bytes[1] << 16 |
             (uint32_t)bytes[2] << 8 |
             bytes[3];
    return 1;
}

static int read_u64(struct read_cursor *cursor, uint64_t *value)
{
    unsigned char bytes[8];
    uint64_t result = 0;

    if (value == NULL || !read_bytes(cursor, bytes, sizeof(bytes))) {
        return 0;
    }
    for (size_t index = 0; index < sizeof(bytes); ++index) {
        result = result << 8 | bytes[index];
    }
    *value = result;
    return 1;
}

static int parse_record(struct read_cursor *cursor,
                        struct user_record *record)
{
    uint16_t username_length_value;

    memset(record, 0, sizeof(*record));
    if (!read_u32(cursor, &record->format_version) ||
        !read_u16(cursor, &username_length_value) ||
        username_length_value == 0 ||
        username_length_value > USER_DB_USERNAME_MAX_BYTES ||
        !read_bytes(cursor, record->username, username_length_value) ||
        !read_bytes(cursor, record->user_id, sizeof(record->user_id)) ||
        !read_bytes(cursor, record->salt, sizeof(record->salt)) ||
        !read_u64(cursor, &record->scrypt.n) ||
        !read_u64(cursor, &record->scrypt.r) ||
        !read_u64(cursor, &record->scrypt.p) ||
        !read_u64(cursor, &record->scrypt.max_memory) ||
        !read_bytes(cursor, record->authentication_verifier,
                    sizeof(record->authentication_verifier)) ||
        !read_bytes(cursor, record->wrapped_vmk,
                    sizeof(record->wrapped_vmk)) ||
        !read_bytes(cursor, record->vmk_nonce, sizeof(record->vmk_nonce)) ||
        !read_bytes(cursor, record->vmk_tag, sizeof(record->vmk_tag))) {
        return 0;
    }
    record->username[username_length_value] = '\0';
    return valid_record(record, NULL);
}

static int parse_database(const unsigned char *data, size_t data_length,
                          struct user_database *database)
{
    struct read_cursor cursor = {data, data_length, 0};
    struct user_database parsed;
    unsigned char magic[USER_DB_MAGIC_BYTES];
    uint32_t file_version;
    uint32_t record_count;

    user_db_init(&parsed);
    if (!read_bytes(&cursor, magic, sizeof(magic)) ||
        memcmp(magic, user_db_magic, sizeof(magic)) != 0 ||
        !read_u32(&cursor, &file_version) ||
        file_version != USER_DB_FILE_VERSION ||
        !read_u32(&cursor, &record_count) ||
        record_count > USER_DB_MAX_USERS) {
        return 0;
    }
    for (uint32_t index = 0; index < record_count; ++index) {
        struct user_record record;

        if (!parse_record(&cursor, &record) ||
            !user_db_add(&parsed, &record)) {
            return 0;
        }
    }
    if (cursor.offset != cursor.length) {
        return 0;
    }
    *database = parsed;
    return 1;
}

int user_db_load(const struct storage *storage,
                 struct user_database *database)
{
    unsigned char *serialized = NULL;
    size_t serialized_length = 0;
    int read_result;
    int result;

    if (storage == NULL || database == NULL) {
        errno = EINVAL;
        return 0;
    }
    read_result = storage_read_file(storage, STORAGE_AREA_ROOT,
                                    USER_DB_FILENAME,
                                    USER_DB_MAX_FILE_BYTES,
                                    &serialized, &serialized_length);
    if (read_result == STORAGE_READ_MISSING) {
        user_db_init(database);
        return 1;
    }
    if (read_result != STORAGE_READ_OK) {
        return 0;
    }
    result = parse_database(serialized, serialized_length, database);
    storage_free(serialized);
    if (!result) {
        errno = EINVAL;
    }
    return result;
}
