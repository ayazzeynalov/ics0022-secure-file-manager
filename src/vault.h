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
int vault_lock_validate(const struct storage *storage,
                        const struct account_session *session,
                        const struct storage_lock *lock);

int vault_write(const struct storage *storage,
                const struct account_session *session,
                const unsigned char *plaintext, size_t plaintext_length);

int vault_verify_current(const struct storage *storage,
                         const struct account_session *session,
                         const struct storage_lock *lock,
                         const unsigned char *expected,
                         size_t expected_length);
int vault_replace_if_current(const struct storage *storage,
                             const struct account_session *session,
                             const struct storage_lock *lock,
                             const unsigned char *expected,
                             size_t expected_length,
                             const unsigned char *plaintext,
                             size_t plaintext_length);

int vault_read(const struct storage *storage,
               const struct account_session *session,
               unsigned char **plaintext, size_t *plaintext_length);
void vault_secure_free(void *plaintext, size_t plaintext_length);

#endif
