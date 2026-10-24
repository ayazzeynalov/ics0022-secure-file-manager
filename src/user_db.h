#ifndef SECUREPM_USER_DB_H
#define SECUREPM_USER_DB_H

#include "auth.h"
#include "crypto.h"
#include "storage.h"

#include <stddef.h>
#include <stdint.h>

#define USER_DB_FILENAME "users.db"
#define USER_DB_FILE_VERSION UINT32_C(1)
#define USER_DB_RECORD_VERSION AUTH_VMK_FORMAT_VERSION
#define USER_DB_USERNAME_MAX_BYTES 64
#define USER_DB_USER_ID_BYTES 16
#define USER_DB_MAX_USERS 256

struct user_record {
    uint32_t format_version;
    char username[USER_DB_USERNAME_MAX_BYTES + 1];
    unsigned char user_id[USER_DB_USER_ID_BYTES];
    unsigned char salt[CRYPTO_SALT_BYTES];
    struct crypto_scrypt_params scrypt;
    unsigned char authentication_verifier[AUTH_VERIFIER_BYTES];
    unsigned char wrapped_vmk[AUTH_WRAPPED_VMK_BYTES];
    unsigned char vmk_nonce[AUTH_VMK_NONCE_BYTES];
    unsigned char vmk_tag[AUTH_VMK_TAG_BYTES];
};

struct user_database {
    size_t count;
    struct user_record records[USER_DB_MAX_USERS];
};

void user_db_init(struct user_database *database);

/* Version 1 accepts 1..64 visible ASCII bytes. Comparisons are byte-exact and
 * case-sensitive. The supplied string does not need a NUL terminator. */
int user_db_username_valid(const char *username, size_t username_length);

/* Adds only fully valid version 1 records using the production scrypt profile.
 * Usernames and 16-byte application-generated user IDs must be unique. */
int user_db_add(struct user_database *database,
                const struct user_record *record);
const struct user_record *user_db_find_username(
    const struct user_database *database,
    const char *username, size_t username_length);
const struct user_record *user_db_find_user_id(
    const struct user_database *database,
    const unsigned char *user_id, size_t user_id_length);

/* A missing users.db loads as an empty database. Malformed files fail and do
 * not replace the caller's database. All persistence uses the storage module. */
int user_db_load(const struct storage *storage,
                 struct user_database *database);
int user_db_save(const struct storage *storage,
                 const struct user_database *database);

#endif
