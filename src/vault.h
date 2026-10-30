#ifndef SECUREPM_VAULT_H
#define SECUREPM_VAULT_H

#include "account.h"
#include "storage.h"

#include <stddef.h>
#include <stdint.h>

#define VAULT_FORMAT_VERSION UINT32_C(1)
#define VAULT_MAX_PLAINTEXT_BYTES (1U * 1024U * 1024U)

#define VAULT_READ_ERROR (-1)
#define VAULT_READ_MISSING 0
#define VAULT_READ_OK 1

int vault_lock_acquire(const struct storage *storage,
                       const struct account_session *session,
                       struct storage_lock *lock);

/* Writes require an authenticated, unlocked session capability. NULL plaintext
 * is accepted only for an explicitly encrypted empty payload. The file is
 * replaced atomically. */
int vault_write(const struct storage *storage,
                const struct account_session *session,
                const unsigned char *plaintext, size_t plaintext_length);

/* Missing vaults are distinct from malformed/authentication failures. Returned
 * plaintext must be released with vault_secure_free() and its returned length. */
int vault_read(const struct storage *storage,
               const struct account_session *session,
               unsigned char **plaintext, size_t *plaintext_length);
void vault_secure_free(void *plaintext, size_t plaintext_length);

#endif
