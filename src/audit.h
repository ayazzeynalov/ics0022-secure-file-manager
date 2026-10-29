#ifndef SECUREPM_AUDIT_H
#define SECUREPM_AUDIT_H

#include "storage.h"

#define AUDIT_LOG_FILENAME "audit.log"
#define AUDIT_LOG_MAX_BYTES (1024U * 1024U)

enum audit_event {
    AUDIT_EVENT_USER_REGISTRATION = 0,
    AUDIT_EVENT_LOGIN,
    AUDIT_EVENT_VAULT_LOAD,
    AUDIT_EVENT_CREDENTIAL_CREATE,
    AUDIT_EVENT_CREDENTIAL_UPDATE,
    AUDIT_EVENT_CREDENTIAL_DELETE,
    AUDIT_EVENT_PASSWORD_REVEAL,
    AUDIT_EVENT_SESSION_LOCK
};

enum audit_outcome {
    AUDIT_OUTCOME_SUCCESS = 0,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_CANCELLED
};

/* Writes one fixed-schema JSON Lines record. No caller-controlled text or
 * identifying data is accepted. The caller's errno value is always restored. */
int audit_log_event(const struct storage *storage, enum audit_event event,
                    enum audit_outcome outcome);

#endif
