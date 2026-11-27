#include "credentials.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct credential_collection *collection;
    unsigned char *encoded = NULL;
    size_t encoded_length = 0;
    int parsed;

    collection = calloc(1, sizeof(*collection));
    if (collection == NULL) {
        return 0;
    }
    credentials_init(collection);
    parsed = credentials_deserialize(data, size, collection);

    if (parsed) {
        if (collection->count > CREDENTIALS_MAX_RECORDS) {
            abort();
        }
        for (size_t i = 0; i < collection->count; ++i) {
            const struct credential_record *record = &collection->records[i];
            if (record->label_length == 0 ||
                record->label_length > CREDENTIALS_LABEL_MAX_BYTES ||
                record->username_length > CREDENTIALS_USERNAME_MAX_BYTES ||
                record->password_length > CREDENTIALS_PASSWORD_MAX_BYTES ||
                record->notes_length > CREDENTIALS_NOTES_MAX_BYTES) {
                abort();
            }
        }
        if (!credentials_serialize(collection, &encoded, &encoded_length) ||
            encoded_length != size ||
            memcmp(encoded, data, size) != 0) {
            credentials_serialized_free(encoded, encoded_length);
            credentials_cleanup(collection);
            free(collection);
            abort();
        }
        credentials_serialized_free(encoded, encoded_length);
    } else {
        if (collection->count != 0) {
            credentials_cleanup(collection);
            free(collection);
            abort();
        }
    }

    credentials_cleanup(collection);
    free(collection);
    return 0;
}
