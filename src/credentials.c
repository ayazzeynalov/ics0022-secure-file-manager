#include "credentials.h"

#include "crypto.h"
#include "vault.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>

#define CREDENTIALS_MAGIC_BYTES 8
#define CREDENTIALS_HEADER_BYTES 16
#define CREDENTIALS_RECORD_HEADER_BYTES 32
#define CREDENTIALS_ID_ATTEMPTS 128

static const unsigned char credentials_magic[CREDENTIALS_MAGIC_BYTES] = {
    'S', 'P', 'M', 'C', 'R', 'E', 'D', 'S'
};

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

static int valid_field(const unsigned char *field, size_t length,
                       size_t maximum, int required)
{
    return length <= maximum && (!required || length != 0) &&
           (field != NULL || length == 0);
}

static int valid_record(const struct credential_record *record)
{
    return record != NULL &&
           valid_field(record->label, record->label_length,
                       CREDENTIALS_LABEL_MAX_BYTES, 1) &&
           valid_field(record->username, record->username_length,
                       CREDENTIALS_USERNAME_MAX_BYTES, 0) &&
           valid_field(record->password, record->password_length,
                       CREDENTIALS_PASSWORD_MAX_BYTES, 0) &&
           valid_field(record->notes, record->notes_length,
                       CREDENTIALS_NOTES_MAX_BYTES, 0);
}

static int unique_ids(const struct credential_collection *collection)
{
    for (size_t first = 0; first < collection->count; ++first) {
        for (size_t second = first + 1; second < collection->count; ++second) {
            if (memcmp(collection->records[first].id,
                       collection->records[second].id,
                       CREDENTIALS_RECORD_ID_BYTES) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

void credentials_init(struct credential_collection *collection)
{
    if (collection != NULL) {
        memset(collection, 0, sizeof(*collection));
    }
}

const struct credential_record *credentials_find(
    const struct credential_collection *collection,
    const unsigned char *record_id, size_t record_id_length)
{
    if (collection == NULL || record_id == NULL ||
        record_id_length != CREDENTIALS_RECORD_ID_BYTES ||
        collection->count > CREDENTIALS_MAX_RECORDS) {
        return NULL;
    }
    for (size_t index = 0; index < collection->count; ++index) {
        if (memcmp(collection->records[index].id, record_id,
                   CREDENTIALS_RECORD_ID_BYTES) == 0) {
            return &collection->records[index];
        }
    }
    return NULL;
}

static struct credential_record *find_mutable_record(
    struct credential_collection *collection,
    const unsigned char *record_id, size_t record_id_length)
{
    if (collection == NULL || record_id == NULL ||
        record_id_length != CREDENTIALS_RECORD_ID_BYTES ||
        collection->count > CREDENTIALS_MAX_RECORDS) {
        return NULL;
    }
    for (size_t index = 0; index < collection->count; ++index) {
        if (memcmp(collection->records[index].id, record_id,
                   CREDENTIALS_RECORD_ID_BYTES) == 0) {
            return &collection->records[index];
        }
    }
    return NULL;
}

int credentials_update(struct credential_collection *collection,
                       const unsigned char *record_id,
                       size_t record_id_length,
                       const unsigned char *label, size_t label_length,
                       const unsigned char *username, size_t username_length,
                       const unsigned char *password, size_t password_length,
                       const unsigned char *notes, size_t notes_length)
{
    struct credential_record replacement;
    struct credential_record *record;

    if (!valid_field(label, label_length,
                     CREDENTIALS_LABEL_MAX_BYTES, 1) ||
        !valid_field(username, username_length,
                     CREDENTIALS_USERNAME_MAX_BYTES, 0) ||
        !valid_field(password, password_length,
                     CREDENTIALS_PASSWORD_MAX_BYTES, 0) ||
        !valid_field(notes, notes_length,
                     CREDENTIALS_NOTES_MAX_BYTES, 0)) {
        errno = EINVAL;
        return 0;
    }
    record = find_mutable_record(collection, record_id, record_id_length);
    if (record == NULL) {
        errno = EINVAL;
        return 0;
    }
    memset(&replacement, 0, sizeof(replacement));
    memcpy(replacement.id, record->id, sizeof(replacement.id));
    replacement.label_length = label_length;
    memcpy(replacement.label, label, label_length);
    replacement.username_length = username_length;
    if (username_length != 0) {
        memcpy(replacement.username, username, username_length);
    }
    replacement.password_length = password_length;
    if (password_length != 0) {
        memcpy(replacement.password, password, password_length);
    }
    replacement.notes_length = notes_length;
    if (notes_length != 0) {
        memcpy(replacement.notes, notes, notes_length);
    }
    OPENSSL_cleanse(record, sizeof(*record));
    memcpy(record, &replacement, sizeof(*record));
    OPENSSL_cleanse(&replacement, sizeof(replacement));
    return 1;
}

int credentials_delete(struct credential_collection *collection,
                       const unsigned char *record_id,
                       size_t record_id_length)
{
    struct credential_record *record;
    size_t index;

    record = find_mutable_record(collection, record_id, record_id_length);
    if (record == NULL) {
        errno = EINVAL;
        return 0;
    }
    index = (size_t)(record - collection->records);
    OPENSSL_cleanse(record, sizeof(*record));
    if (index + 1 < collection->count) {
        memmove(record, record + 1,
                (collection->count - index - 1) * sizeof(*record));
    }
    --collection->count;
    OPENSSL_cleanse(&collection->records[collection->count],
                    sizeof(collection->records[collection->count]));
    return 1;
}

static int generate_unique_id(const struct credential_collection *collection,
                              unsigned char id[CREDENTIALS_RECORD_ID_BYTES])
{
    for (unsigned int attempt = 0;
         attempt < CREDENTIALS_ID_ATTEMPTS; ++attempt) {
        if (!crypto_random(id, CREDENTIALS_RECORD_ID_BYTES)) {
            return 0;
        }
        if (credentials_find(collection, id,
                             CREDENTIALS_RECORD_ID_BYTES) == NULL) {
            return 1;
        }
    }
    OPENSSL_cleanse(id, CREDENTIALS_RECORD_ID_BYTES);
    return 0;
}

int credentials_add(struct credential_collection *collection,
                    const unsigned char *label, size_t label_length,
                    const unsigned char *username, size_t username_length,
                    const unsigned char *password, size_t password_length,
                    const unsigned char *notes, size_t notes_length,
                    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES])
{
    struct credential_record *record;

    if (collection == NULL || record_id == NULL ||
        collection->count >= CREDENTIALS_MAX_RECORDS ||
        !valid_field(label, label_length,
                     CREDENTIALS_LABEL_MAX_BYTES, 1) ||
        !valid_field(username, username_length,
                     CREDENTIALS_USERNAME_MAX_BYTES, 0) ||
        !valid_field(password, password_length,
                     CREDENTIALS_PASSWORD_MAX_BYTES, 0) ||
        !valid_field(notes, notes_length,
                     CREDENTIALS_NOTES_MAX_BYTES, 0)) {
        errno = EINVAL;
        return 0;
    }
    record = &collection->records[collection->count];
    memset(record, 0, sizeof(*record));
    if (!generate_unique_id(collection, record->id)) {
        OPENSSL_cleanse(record, sizeof(*record));
        return 0;
    }
    record->label_length = label_length;
    memcpy(record->label, label, label_length);
    record->username_length = username_length;
    if (username_length != 0) {
        memcpy(record->username, username, username_length);
    }
    record->password_length = password_length;
    if (password_length != 0) {
        memcpy(record->password, password, password_length);
    }
    record->notes_length = notes_length;
    if (notes_length != 0) {
        memcpy(record->notes, notes, notes_length);
    }
    memcpy(record_id, record->id, CREDENTIALS_RECORD_ID_BYTES);
    ++collection->count;
    return 1;
}

static int serialized_size(const struct credential_collection *collection,
                           size_t *total)
{
    size_t length = CREDENTIALS_HEADER_BYTES;

    if (collection == NULL || total == NULL ||
        collection->count > CREDENTIALS_MAX_RECORDS ||
        !unique_ids(collection)) {
        return 0;
    }
    for (size_t index = 0; index < collection->count; ++index) {
        const struct credential_record *record = &collection->records[index];
        size_t fields;

        if (!valid_record(record) ||
            record->label_length > SIZE_MAX - record->username_length ||
            record->label_length + record->username_length >
                SIZE_MAX - record->password_length ||
            record->label_length + record->username_length +
                record->password_length > SIZE_MAX - record->notes_length) {
            return 0;
        }
        fields = record->label_length + record->username_length +
                 record->password_length + record->notes_length;
        if (length > SIZE_MAX - CREDENTIALS_RECORD_HEADER_BYTES ||
            length + CREDENTIALS_RECORD_HEADER_BYTES > SIZE_MAX - fields) {
            return 0;
        }
        length += CREDENTIALS_RECORD_HEADER_BYTES + fields;
        if (length > VAULT_MAX_PLAINTEXT_BYTES) {
            return 0;
        }
    }
    *total = length;
    return 1;
}

int credentials_serialize(const struct credential_collection *collection,
                          unsigned char **payload, size_t *payload_length)
{
    unsigned char *result;
    size_t total;
    size_t offset = CREDENTIALS_HEADER_BYTES;

    if (payload == NULL || payload_length == NULL) {
        errno = EINVAL;
        return 0;
    }
    *payload = NULL;
    *payload_length = 0;
    if (!serialized_size(collection, &total)) {
        errno = EINVAL;
        return 0;
    }
    result = OPENSSL_malloc(total);
    if (result == NULL) {
        return 0;
    }
    memcpy(result, credentials_magic, sizeof(credentials_magic));
    write_u32(result + 8, CREDENTIALS_FORMAT_VERSION);
    write_u32(result + 12, (uint32_t)collection->count);
    for (size_t index = 0; index < collection->count; ++index) {
        const struct credential_record *record = &collection->records[index];

        memcpy(result + offset, record->id, CREDENTIALS_RECORD_ID_BYTES);
        offset += CREDENTIALS_RECORD_ID_BYTES;
        write_u32(result + offset, (uint32_t)record->label_length);
        write_u32(result + offset + 4, (uint32_t)record->username_length);
        write_u32(result + offset + 8, (uint32_t)record->password_length);
        write_u32(result + offset + 12, (uint32_t)record->notes_length);
        offset += 16;
        memcpy(result + offset, record->label, record->label_length);
        offset += record->label_length;
        if (record->username_length != 0) {
            memcpy(result + offset, record->username,
                   record->username_length);
            offset += record->username_length;
        }
        if (record->password_length != 0) {
            memcpy(result + offset, record->password,
                   record->password_length);
            offset += record->password_length;
        }
        if (record->notes_length != 0) {
            memcpy(result + offset, record->notes, record->notes_length);
            offset += record->notes_length;
        }
    }
    if (offset != total) {
        OPENSSL_clear_free(result, total);
        return 0;
    }
    *payload = result;
    *payload_length = total;
    return 1;
}

static int read_field(const unsigned char *payload, size_t payload_length,
                      size_t *offset, unsigned char *output, size_t length)
{
    if (*offset > payload_length || length > payload_length - *offset) {
        return 0;
    }
    if (length != 0) {
        memcpy(output, payload + *offset, length);
    }
    *offset += length;
    return 1;
}

int credentials_deserialize(const unsigned char *payload,
                            size_t payload_length,
                            struct credential_collection *collection)
{
    struct credential_collection *candidate = NULL;
    uint32_t encoded_count;
    size_t offset = CREDENTIALS_HEADER_BYTES;
    int success = 0;

    if (payload == NULL || collection == NULL ||
        payload_length < CREDENTIALS_HEADER_BYTES ||
        payload_length > VAULT_MAX_PLAINTEXT_BYTES ||
        memcmp(payload, credentials_magic, sizeof(credentials_magic)) != 0 ||
        read_u32(payload + 8) != CREDENTIALS_FORMAT_VERSION) {
        errno = EINVAL;
        return 0;
    }
    encoded_count = read_u32(payload + 12);
    if (encoded_count > CREDENTIALS_MAX_RECORDS) {
        errno = EINVAL;
        return 0;
    }
    candidate = OPENSSL_zalloc(sizeof(*candidate));
    if (candidate == NULL) {
        return 0;
    }
    candidate->count = encoded_count;
    for (size_t index = 0; index < candidate->count; ++index) {
        struct credential_record *record = &candidate->records[index];
        uint32_t lengths[4];

        if (offset > payload_length ||
            CREDENTIALS_RECORD_HEADER_BYTES > payload_length - offset) {
            goto cleanup;
        }
        memcpy(record->id, payload + offset, CREDENTIALS_RECORD_ID_BYTES);
        offset += CREDENTIALS_RECORD_ID_BYTES;
        for (size_t field = 0; field < 4; ++field) {
            lengths[field] = read_u32(payload + offset + field * 4);
        }
        offset += 16;
        if (lengths[0] == 0 || lengths[0] > CREDENTIALS_LABEL_MAX_BYTES ||
            lengths[1] > CREDENTIALS_USERNAME_MAX_BYTES ||
            lengths[2] > CREDENTIALS_PASSWORD_MAX_BYTES ||
            lengths[3] > CREDENTIALS_NOTES_MAX_BYTES) {
            goto cleanup;
        }
        record->label_length = lengths[0];
        record->username_length = lengths[1];
        record->password_length = lengths[2];
        record->notes_length = lengths[3];
        if (!read_field(payload, payload_length, &offset,
                        record->label, record->label_length) ||
            !read_field(payload, payload_length, &offset,
                        record->username, record->username_length) ||
            !read_field(payload, payload_length, &offset,
                        record->password, record->password_length) ||
            !read_field(payload, payload_length, &offset,
                        record->notes, record->notes_length)) {
            goto cleanup;
        }
        for (size_t prior = 0; prior < index; ++prior) {
            if (memcmp(candidate->records[prior].id, record->id,
                       CREDENTIALS_RECORD_ID_BYTES) == 0) {
                goto cleanup;
            }
        }
    }
    if (offset != payload_length) {
        goto cleanup;
    }
    OPENSSL_cleanse(collection, sizeof(*collection));
    memcpy(collection, candidate, sizeof(*collection));
    success = 1;

cleanup:
    OPENSSL_clear_free(candidate, sizeof(*candidate));
    if (!success) {
        errno = EINVAL;
    }
    return success;
}

void credentials_serialized_free(void *payload, size_t payload_length)
{
    if (payload != NULL) {
        OPENSSL_clear_free(payload, payload_length);
    }
}

void credentials_cleanup(struct credential_collection *collection)
{
    if (collection != NULL) {
        OPENSSL_cleanse(collection, sizeof(*collection));
    }
}
