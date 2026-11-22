#ifndef SECUREPM_CREDENTIALS_H
#define SECUREPM_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>

#define CREDENTIALS_FORMAT_VERSION UINT32_C(1)
#define CREDENTIALS_MAX_RECORDS 256
#define CREDENTIALS_RECORD_ID_BYTES 16
#define CREDENTIALS_LABEL_MAX_BYTES 128
#define CREDENTIALS_USERNAME_MAX_BYTES 256
#define CREDENTIALS_PASSWORD_MAX_BYTES 1024
#define CREDENTIALS_NOTES_MAX_BYTES 1024

struct credential_record {
    unsigned char id[CREDENTIALS_RECORD_ID_BYTES];
    size_t label_length;
    unsigned char label[CREDENTIALS_LABEL_MAX_BYTES];
    size_t username_length;
    unsigned char username[CREDENTIALS_USERNAME_MAX_BYTES];
    size_t password_length;
    unsigned char password[CREDENTIALS_PASSWORD_MAX_BYTES];
    size_t notes_length;
    unsigned char notes[CREDENTIALS_NOTES_MAX_BYTES];
};

struct credential_collection {
    size_t count;
    struct credential_record records[CREDENTIALS_MAX_RECORDS];
};

void credentials_init(struct credential_collection *collection);

int credentials_add(struct credential_collection *collection,
                    const unsigned char *label, size_t label_length,
                    const unsigned char *username, size_t username_length,
                    const unsigned char *password, size_t password_length,
                    const unsigned char *notes, size_t notes_length,
                    unsigned char record_id[CREDENTIALS_RECORD_ID_BYTES]);

const struct credential_record *credentials_find(
    const struct credential_collection *collection,
    const unsigned char *record_id, size_t record_id_length);

int credentials_update(struct credential_collection *collection,
                       const unsigned char *record_id,
                       size_t record_id_length,
                       const unsigned char *label, size_t label_length,
                       const unsigned char *username, size_t username_length,
                       const unsigned char *password, size_t password_length,
                       const unsigned char *notes, size_t notes_length);

int credentials_delete(struct credential_collection *collection,
                       const unsigned char *record_id,
                       size_t record_id_length);

int credentials_serialize(const struct credential_collection *collection,
                          unsigned char **payload, size_t *payload_length);
int credentials_deserialize(const unsigned char *payload,
                            size_t payload_length,
                            struct credential_collection *collection);
void credentials_serialized_free(void *payload, size_t payload_length);

void credentials_cleanup(struct credential_collection *collection);

#endif
