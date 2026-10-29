#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "audit.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>

#define AUDIT_TIMESTAMP_BYTES 21
#define AUDIT_RECORD_MAX_BYTES 160

static const char *event_name(enum audit_event event)
{
    switch (event) {
    case AUDIT_EVENT_USER_REGISTRATION:
        return "user_registration";
    case AUDIT_EVENT_LOGIN:
        return "login";
    case AUDIT_EVENT_VAULT_LOAD:
        return "vault_load";
    case AUDIT_EVENT_CREDENTIAL_CREATE:
        return "credential_create";
    case AUDIT_EVENT_CREDENTIAL_UPDATE:
        return "credential_update";
    case AUDIT_EVENT_CREDENTIAL_DELETE:
        return "credential_delete";
    case AUDIT_EVENT_PASSWORD_REVEAL:
        return "password_reveal";
    case AUDIT_EVENT_SESSION_LOCK:
        return "session_lock";
    }
    return NULL;
}

static const char *outcome_name(enum audit_outcome outcome)
{
    switch (outcome) {
    case AUDIT_OUTCOME_SUCCESS:
        return "success";
    case AUDIT_OUTCOME_FAILURE:
        return "failure";
    case AUDIT_OUTCOME_CANCELLED:
        return "cancelled";
    }
    return NULL;
}

int audit_log_event(const struct storage *storage, enum audit_event event,
                    enum audit_outcome outcome)
{
    char timestamp[AUDIT_TIMESTAMP_BYTES];
    char record[AUDIT_RECORD_MAX_BYTES];
    const char *event_text = event_name(event);
    const char *outcome_text = outcome_name(outcome);
    struct timespec now;
    struct tm utc;
    int record_length;
    int caller_errno = errno;
    int success = 0;

    if (storage == NULL || event_text == NULL || outcome_text == NULL ||
        clock_gettime(CLOCK_REALTIME, &now) != 0 ||
        gmtime_r(&now.tv_sec, &utc) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc) !=
            sizeof(timestamp) - 1) {
        goto cleanup;
    }
    record_length = snprintf(record, sizeof(record),
                             "{\"timestamp\":\"%s\",\"event\":\"%s\","
                             "\"outcome\":\"%s\"}\n",
                             timestamp, event_text, outcome_text);
    if (record_length < 0 || (size_t)record_length >= sizeof(record)) {
        goto cleanup;
    }
    success = storage_append_file(storage, STORAGE_AREA_ROOT,
                                  AUDIT_LOG_FILENAME,
                                  (const unsigned char *)record,
                                  (size_t)record_length,
                                  AUDIT_LOG_MAX_BYTES);

cleanup:
    errno = caller_errno;
    return success;
}
