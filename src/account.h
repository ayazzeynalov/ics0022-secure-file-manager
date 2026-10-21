#ifndef SECUREPM_ACCOUNT_H
#define SECUREPM_ACCOUNT_H

#include "auth.h"
#include "storage.h"
#include "user_db.h"

#include <stddef.h>

struct account_session {
    int unlocked;
    unsigned char user_id[USER_DB_USER_ID_BYTES];
    unsigned char vmk[AUTH_VMK_BYTES];
};

#define ACCOUNT_SESSION_INITIALIZER {0, {0}, {0}}

/* Both operations return 1 on success and 0 for invalid input, authentication
 * failure, malformed metadata, or storage errors. Passwords are explicit byte
 * strings of 1..CRYPTO_PASSWORD_MAX_BYTES. The caller owns and clears them. */
int account_register(const struct storage *storage,
                     const char *username, size_t username_length,
                     const char *master_password, size_t password_length);

/* The session is locked before every unlock attempt. The VMK is published only
 * after verifier validation and authenticated VMK unwrapping both succeed. */
int account_unlock(const struct storage *storage,
                   const char *username, size_t username_length,
                   const char *master_password, size_t password_length,
                   struct account_session *session);

void account_session_lock(struct account_session *session);

#endif
