#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "audit.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TEST_PATH_BYTES 4096
#define CONCURRENT_CHILDREN 3
#define CONCURRENT_EVENTS 12

void storage_test_fail_append_after(unsigned int writes);
void storage_test_interrupt_append_once(void);
void storage_test_limit_append_write_once(size_t maximum);

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int make_path(char output[TEST_PATH_BYTES],
                     const char *first, const char *second)
{
    int length = snprintf(output, TEST_PATH_BYTES, "%s/%s", first, second);
    return length >= 0 && (size_t)length < TEST_PATH_BYTES;
}

static char *make_temporary_home(char home_template[TEST_PATH_BYTES])
{
    const char *temporary_parent = getenv("TMPDIR");
    char *canonical_parent;
    int path_ready;

    if (temporary_parent == NULL || temporary_parent[0] == '\0') {
        temporary_parent = "/tmp";
    }
    canonical_parent = realpath(temporary_parent, NULL);
    if (canonical_parent == NULL) {
        return NULL;
    }
    path_ready = make_path(home_template, canonical_parent,
                           "securepm-audit-test.XXXXXX");
    free(canonical_parent);
    if (!path_ready) {
        return NULL;
    }
    return mkdtemp(home_template);
}

static int remove_tree(const char *path)
{
    struct stat status;
    DIR *directory;
    struct dirent *entry;
    int success = 1;

    if (lstat(path, &status) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
        return unlink(path) == 0;
    }
    directory = opendir(path);
    if (directory == NULL) {
        return 0;
    }
    while ((entry = readdir(directory)) != NULL) {
        char child[TEST_PATH_BYTES];

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!make_path(child, path, entry->d_name) || !remove_tree(child)) {
            success = 0;
        }
    }
    if (closedir(directory) != 0) {
        success = 0;
    }
    if (success && rmdir(path) != 0) {
        success = 0;
    }
    return success;
}

static int contains_bytes(const unsigned char *data, size_t data_length,
                          const char *needle)
{
    size_t needle_length = strlen(needle);

    if (needle_length == 0 || needle_length > data_length) {
        return 0;
    }
    for (size_t offset = 0; offset <= data_length - needle_length; ++offset) {
        if (memcmp(data + offset, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static unsigned char *read_audit(const struct storage *storage,
                                 size_t *length)
{
    unsigned char *data = NULL;

    if (storage_read_file(storage, STORAGE_AREA_ROOT, AUDIT_LOG_FILENAME,
                          AUDIT_LOG_MAX_BYTES, &data, length) !=
        STORAGE_READ_OK) {
        return NULL;
    }
    return data;
}

static int timestamp_valid(const char *timestamp)
{
    static const size_t digits[] = {
        0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18
    };

    if (strlen(timestamp) != 20 || timestamp[4] != '-' ||
        timestamp[7] != '-' || timestamp[10] != 'T' ||
        timestamp[13] != ':' || timestamp[16] != ':' ||
        timestamp[19] != 'Z') {
        return 0;
    }
    for (size_t index = 0; index < sizeof(digits) / sizeof(digits[0]); ++index) {
        char value = timestamp[digits[index]];

        if (value < '0' || value > '9') {
            return 0;
        }
    }
    return 1;
}

static int line_valid(const char *line, const char *event,
                      const char *outcome)
{
    static const char prefix[] = "{\"timestamp\":\"";
    char expected_suffix[96];
    char timestamp[21];
    int suffix_length;
    size_t prefix_length = sizeof(prefix) - 1;

    if (strncmp(line, prefix, prefix_length) != 0 ||
        strlen(line) < prefix_length + sizeof(timestamp) - 1) {
        return 0;
    }
    memcpy(timestamp, line + prefix_length, sizeof(timestamp) - 1);
    timestamp[sizeof(timestamp) - 1] = '\0';
    if (!timestamp_valid(timestamp)) {
        return 0;
    }
    suffix_length = snprintf(expected_suffix, sizeof(expected_suffix),
                             "\",\"event\":\"%s\",\"outcome\":\"%s\"}",
                             event, outcome);
    return suffix_length >= 0 && (size_t)suffix_length < sizeof(expected_suffix) &&
           strcmp(line + prefix_length + sizeof(timestamp) - 1,
                  expected_suffix) == 0;
}

static int line_timestamp_between(const char *line, time_t earliest,
                                  time_t latest)
{
    static const size_t prefix_length = sizeof("{\"timestamp\":\"") - 1;
    char formatted[21];

    if (latest < earliest || latest - earliest > 120) {
        return 0;
    }
    for (time_t candidate = earliest; candidate <= latest; ++candidate) {
        struct tm utc;

        if (gmtime_r(&candidate, &utc) != NULL &&
            strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ",
                     &utc) == sizeof(formatted) - 1 &&
            memcmp(line + prefix_length, formatted, sizeof(formatted) - 1) ==
                0) {
            return 1;
        }
    }
    return 0;
}

static size_t count_lines(const unsigned char *data, size_t length)
{
    size_t lines = 0;

    for (size_t index = 0; index < length; ++index) {
        if (data[index] == '\n') {
            ++lines;
        }
    }
    return lines;
}

static void test_schema_and_minimization(const struct storage *storage,
                                         const char *root)
{
    static const enum audit_event events[] = {
        AUDIT_EVENT_USER_REGISTRATION,
        AUDIT_EVENT_LOGIN,
        AUDIT_EVENT_VAULT_LOAD,
        AUDIT_EVENT_CREDENTIAL_CREATE,
        AUDIT_EVENT_CREDENTIAL_UPDATE,
        AUDIT_EVENT_CREDENTIAL_DELETE,
        AUDIT_EVENT_PASSWORD_REVEAL,
        AUDIT_EVENT_SESSION_LOCK
    };
    static const char *const event_names[] = {
        "user_registration", "login", "vault_load", "credential_create",
        "credential_update", "credential_delete", "password_reveal",
        "session_lock"
    };
    static const enum audit_outcome outcomes[] = {
        AUDIT_OUTCOME_SUCCESS, AUDIT_OUTCOME_FAILURE, AUDIT_OUTCOME_CANCELLED
    };
    static const char *const outcome_names[] = {
        "success", "failure", "cancelled"
    };
    static const char *const forbidden[] = {
        "dummy-master-secret", "dummy-credential-secret", "private label",
        "private username", "private notes",
        "00112233445566778899aabbccddeeff",
        "\"}\n{\"event\":\"forged"
    };
    char audit_path[TEST_PATH_BYTES];
    struct stat status;
    unsigned char *data;
    char *copy;
    char *line;
    char *state = NULL;
    size_t length = 0;
    size_t line_index = 0;
    int saved_errno = EDOM;
    time_t earliest = time(NULL);
    time_t latest;

    for (size_t event = 0; event < sizeof(events) / sizeof(events[0]); ++event) {
        for (size_t outcome = 0;
             outcome < sizeof(outcomes) / sizeof(outcomes[0]); ++outcome) {
            errno = saved_errno;
            CHECK(audit_log_event(storage, events[event], outcomes[outcome]) == 1);
            CHECK(errno == saved_errno);
        }
    }
    latest = time(NULL);
    CHECK(make_path(audit_path, root, AUDIT_LOG_FILENAME));
    CHECK(lstat(audit_path, &status) == 0);
    CHECK(S_ISREG(status.st_mode));
    CHECK((status.st_mode & 07777) == STORAGE_FILE_MODE);
    CHECK(status.st_uid == geteuid());
    CHECK(status.st_nlink == 1);
    data = read_audit(storage, &length);
    CHECK(data != NULL);
    if (data == NULL) {
        return;
    }
    CHECK(count_lines(data, length) ==
          (sizeof(events) / sizeof(events[0])) *
              (sizeof(outcomes) / sizeof(outcomes[0])));
    for (size_t index = 0; index < sizeof(forbidden) / sizeof(forbidden[0]);
         ++index) {
        CHECK(!contains_bytes(data, length, forbidden[index]));
    }
    copy = malloc(length + 1);
    CHECK(copy != NULL);
    if (copy != NULL) {
        memcpy(copy, data, length);
        copy[length] = '\0';
        line = strtok_r(copy, "\n", &state);
        while (line != NULL) {
            size_t event = line_index / 3;
            size_t outcome = line_index % 3;

            CHECK(event < sizeof(events) / sizeof(events[0]));
            if (event < sizeof(events) / sizeof(events[0])) {
                CHECK(line_valid(line, event_names[event],
                                 outcome_names[outcome]));
                CHECK(line_timestamp_between(line, earliest, latest));
            }
            ++line_index;
            line = strtok_r(NULL, "\n", &state);
        }
        free(copy);
    }
    CHECK(line_index == 24);
    storage_free(data);

    data = read_audit(storage, &length);
    CHECK(data != NULL);
    errno = ERANGE;
    CHECK(audit_log_event(storage, (enum audit_event)999,
                          AUDIT_OUTCOME_SUCCESS) == 0);
    CHECK(errno == ERANGE);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          (enum audit_outcome)999) == 0);
    CHECK(errno == ERANGE);
    {
        unsigned char *after;
        size_t after_length = 0;

        after = read_audit(storage, &after_length);
        CHECK(after != NULL && after_length == length);
        if (data != NULL && after != NULL && after_length == length) {
            CHECK(memcmp(data, after, length) == 0);
        }
        storage_free(after);
    }
    storage_free(data);
}

static void test_write_failures(const struct storage *storage,
                                const char *audit_path)
{
    unsigned char *before;
    unsigned char *after;
    size_t before_length = 0;
    size_t after_length = 0;

    CHECK(unlink(audit_path) == 0);
    storage_test_interrupt_append_once();
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_SUCCESS) == 1);
    storage_test_limit_append_write_once(5);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_FAILURE) == 1);
    before = read_audit(storage, &before_length);
    CHECK(before != NULL && count_lines(before, before_length) == 2);

    storage_test_limit_append_write_once(5);
    storage_test_fail_append_after(2);
    CHECK(audit_log_event(storage, AUDIT_EVENT_CREDENTIAL_CREATE,
                          AUDIT_OUTCOME_FAILURE) == 0);
    after = read_audit(storage, &after_length);
    CHECK(after != NULL && after_length == before_length);
    if (before != NULL && after != NULL && after_length == before_length) {
        CHECK(memcmp(before, after, before_length) == 0);
    }
    storage_free(after);

    storage_test_fail_append_after(1);
    CHECK(audit_log_event(storage, AUDIT_EVENT_SESSION_LOCK,
                          AUDIT_OUTCOME_SUCCESS) == 0);
    after = read_audit(storage, &after_length);
    CHECK(after != NULL && after_length == before_length);
    if (before != NULL && after != NULL && after_length == before_length) {
        CHECK(memcmp(before, after, before_length) == 0);
    }
    storage_free(before);
    storage_free(after);
}

static void test_unsafe_files(const struct storage *storage, const char *home,
                              const char *root, const char *audit_path)
{
    static const unsigned char outside_data[] = "outside sentinel";
    char outside_path[TEST_PATH_BYTES];
    char alias_path[TEST_PATH_BYTES];
    struct stat before;
    struct stat after;
    int outside_fd;
    unsigned char buffer[sizeof(outside_data)] = {0};

    CHECK(unlink(audit_path) == 0);
    CHECK(make_path(outside_path, home, "outside.log"));
    outside_fd = open(outside_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                      STORAGE_FILE_MODE);
    CHECK(outside_fd >= 0);
    if (outside_fd >= 0) {
        CHECK(write(outside_fd, outside_data, sizeof(outside_data) - 1) ==
              (ssize_t)(sizeof(outside_data) - 1));
        CHECK(close(outside_fd) == 0);
    }
    CHECK(symlink("../outside.log", audit_path) == 0);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_FAILURE) == 0);
    outside_fd = open(outside_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(outside_fd >= 0);
    if (outside_fd >= 0) {
        CHECK(read(outside_fd, buffer, sizeof(outside_data) - 1) ==
              (ssize_t)(sizeof(outside_data) - 1));
        CHECK(memcmp(buffer, outside_data, sizeof(outside_data) - 1) == 0);
        close(outside_fd);
    }
    CHECK(unlink(audit_path) == 0);
    CHECK(unlink(outside_path) == 0);

    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_SUCCESS) == 1);
    CHECK(make_path(alias_path, root, "audit-alias.log"));
    CHECK(link(audit_path, alias_path) == 0);
    CHECK(stat(audit_path, &before) == 0 && before.st_nlink == 2);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_FAILURE) == 0);
    CHECK(stat(audit_path, &after) == 0 && after.st_size == before.st_size);
    CHECK(unlink(alias_path) == 0);
    CHECK(unlink(audit_path) == 0);

    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_SUCCESS) == 1);
    CHECK(chmod(audit_path, 0644) == 0);
    CHECK(stat(audit_path, &before) == 0);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_FAILURE) == 0);
    CHECK(stat(audit_path, &after) == 0 && after.st_size == before.st_size);
    CHECK(chmod(audit_path, STORAGE_FILE_MODE) == 0);
}

static void test_resource_bound(const struct storage *storage,
                                const char *audit_path)
{
    struct stat before;
    struct stat after;
    int file_fd = open(audit_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);

    CHECK(file_fd >= 0);
    if (file_fd >= 0) {
        CHECK(ftruncate(file_fd, AUDIT_LOG_MAX_BYTES) == 0);
        CHECK(close(file_fd) == 0);
    }
    CHECK(stat(audit_path, &before) == 0);
    CHECK(audit_log_event(storage, AUDIT_EVENT_LOGIN,
                          AUDIT_OUTCOME_SUCCESS) == 0);
    CHECK(stat(audit_path, &after) == 0);
    CHECK(before.st_size == (off_t)AUDIT_LOG_MAX_BYTES &&
          after.st_size == before.st_size);
    CHECK(unlink(audit_path) == 0);
}

static void test_concurrent_append(const struct storage *storage)
{
    pid_t children[CONCURRENT_CHILDREN] = {0};
    unsigned char *data;
    size_t length = 0;

    for (size_t child_index = 0; child_index < CONCURRENT_CHILDREN;
         ++child_index) {
        children[child_index] = fork();
        CHECK(children[child_index] >= 0);
        if (children[child_index] == 0) {
            for (size_t event = 0; event < CONCURRENT_EVENTS; ++event) {
                if (!audit_log_event(storage, AUDIT_EVENT_CREDENTIAL_UPDATE,
                                     AUDIT_OUTCOME_SUCCESS)) {
                    _exit(1);
                }
            }
            _exit(0);
        }
    }
    for (size_t child_index = 0; child_index < CONCURRENT_CHILDREN;
         ++child_index) {
        if (children[child_index] > 0) {
            int status = 0;

            CHECK(waitpid(children[child_index], &status, 0) ==
                  children[child_index]);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    data = read_audit(storage, &length);
    CHECK(data != NULL);
    if (data != NULL) {
        size_t line_start = 0;
        size_t lines = 0;

        for (size_t index = 0; index < length; ++index) {
            if (data[index] == '\n') {
                size_t line_length = index - line_start;
                char line[160];

                CHECK(line_length < sizeof(line));
                if (line_length < sizeof(line)) {
                    memcpy(line, data + line_start, line_length);
                    line[line_length] = '\0';
                    CHECK(line_valid(line, "credential_update", "success"));
                }
                line_start = index + 1;
                ++lines;
            }
        }
        CHECK(line_start == length);
        CHECK(lines == CONCURRENT_CHILDREN * CONCURRENT_EVENTS);
    }
    storage_free(data);
}

int main(void)
{
    char home_template[TEST_PATH_BYTES];
    char root[TEST_PATH_BYTES];
    char audit_path[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;

    CHECK(home != NULL);
    if (home == NULL) {
        return 1;
    }
    CHECK(setenv("HOME", home, 1) == 0);
    CHECK(storage_init(&storage) == 1);
    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(audit_path, root, AUDIT_LOG_FILENAME));
    if (storage.root_fd >= 0) {
        test_schema_and_minimization(&storage, root);
        test_write_failures(&storage, audit_path);
        test_unsafe_files(&storage, home, root, audit_path);
        test_resource_bound(&storage, audit_path);
        test_concurrent_append(&storage);
    }
    storage_close(&storage);
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u audit checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u audit checks\n", checks);
    return 0;
}
