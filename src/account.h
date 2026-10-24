#ifndef SECUREPM_ACCOUNT_H
#define SECUREPM_ACCOUNT_H

#include "auth.h"
#include "storage.h"
#include "user_db.h"

#include <stddef.h>

#define ACCOUNT_MASTER_PASSWORD_MIN_BYTES 12
#define ACCOUNT_REGISTER_ERROR 0
#define ACCOUNT_REGISTER_CREATED 1
#define ACCOUNT_REGISTER_RECOVERY 2

struct account_session {
    int unlocked;
    unsigned char user_id[USER_DB_USER_ID_BYTES];
    unsigned char vmk[AUTH_VMK_BYTES];
};

#define ACCOUNT_SESSION_INITIALIZER {0, {0}, {0}}

/* Registration returns CREATED for new metadata or RECOVERY when a matching
 * interrupted registration can resume. New passwords must contain at least
 * 12 bytes. The caller owns and clears supplied password buffers. */
int account_register(const struct storage *storage,
                     const char *username, size_t username_length,
                     const char *master_password, size_t password_length);

/* Removes the pending marker only after the caller has ensured that a valid
 * encrypted vault exists for the unlocked session. */
int account_registration_complete(const struct storage *storage,
                                  const struct account_session *session);

/* Unlock retains the 1..CRYPTO_PASSWORD_MAX_BYTES range for existing accounts.
 * The session is locked before every attempt, and the VMK is published only
 * after verifier validation and authenticated VMK unwrapping both succeed. */
int account_unlock(const struct storage *storage,
                   const char *username, size_t username_length,
                   const char *master_password, size_t password_length,
                   struct account_session *session);

void account_session_lock(struct account_session *session);

#endif
