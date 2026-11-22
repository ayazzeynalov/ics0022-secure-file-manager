#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "storage.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/acl.h>
#endif

#define STORAGE_HOME_MAX_BYTES 4096
#define STORAGE_TEMP_NAME_BYTES 96
#define STORAGE_TEMP_ATTEMPTS 128
#define STORAGE_TEMP_PREFIX ".securepm.tmp."
#define STORAGE_APPEND_LOCK_SUFFIX ".lock"

static int sync_directory(int directory_fd)
{
    if (fsync(directory_fd) == 0) {
        return 1;
    }
#ifdef __APPLE__
    if (errno == EINVAL || errno == ENOTSUP) {
        return 1;
    }
#endif
    return 0;
}

#ifdef SECUREPM_TEST_FAULTS
static unsigned int atomic_sync_failure_countdown;
static int atomic_precommit_failure_once;
static unsigned int append_failure_countdown;
static int append_interrupt_once;
static size_t append_write_limit_once;
static int atomic_pause_ready_fd = -1;
static int atomic_pause_continue_fd = -1;

static int read_failure_once;

static int read_interrupt_once;
static int read_early_eof_once;
static int read_partial_error_stage;

static void (*read_postcheck_hook)(void *);
static void *read_postcheck_context;

void storage_test_after_read_once(void (*hook)(void *), void *context)
{
    read_postcheck_hook = hook;
    read_postcheck_context = context;
}

void storage_test_interrupt_read_once(void)
{
    read_interrupt_once = 1;
}

void storage_test_early_eof_once(void)
{
    read_early_eof_once = 1;
}

void storage_test_partial_read_then_error_once(void)
{
    read_partial_error_stage = 1;
}

void storage_test_fail_read_once(void)
{
    read_failure_once = 1;
}

void storage_test_fail_atomic_sync_after(unsigned int writes)
{
    atomic_sync_failure_countdown = writes;
}

void storage_test_fail_atomic_precommit_once(void)
{
    atomic_precommit_failure_once = 1;
}

void storage_test_fail_append_after(unsigned int writes)
{
    append_failure_countdown = writes;
}

void storage_test_interrupt_append_once(void)
{
    append_interrupt_once = 1;
}

void storage_test_limit_append_write_once(size_t maximum)
{
    append_write_limit_once = maximum;
}

void storage_test_pause_atomic_before_replace(int ready_fd, int continue_fd)
{
    atomic_pause_ready_fd = ready_fd;
    atomic_pause_continue_fd = continue_fd;
}
#endif

static int sync_atomic_directory(int directory_fd)
{
#ifdef SECUREPM_TEST_FAULTS
    if (atomic_sync_failure_countdown != 0 &&
        --atomic_sync_failure_countdown == 0) {
        errno = EIO;
        return 0;
    }
#endif
    return sync_directory(directory_fd);
}

static int sync_file(int file_fd)
{
#ifdef __APPLE__
    if (fcntl(file_fd, F_FULLFSYNC) == 0) {
        return 1;
    }
    if (errno != EINVAL && errno != ENOTSUP) {
        return 0;
    }
#endif
    return fsync(file_fd) == 0;
}

static int secure_extended_acl(int file_fd)
{
#ifdef __APPLE__
    acl_t acl;
    int saved_errno = errno;

    errno = 0;
    acl = acl_get_fd_np(file_fd, ACL_TYPE_EXTENDED);
    if (acl != NULL) {
        (void)acl_free(acl);
        errno = EACCES;
        return 0;
    }
    if (errno != ENOENT && errno != EOPNOTSUPP) {
        return 0;
    }
    errno = saved_errno;
#else
    (void)file_fd;
#endif
    return 1;
}

static int secure_directory_stat(int directory_fd, mode_t required_mode)
{
    struct stat status;

    if (fstat(directory_fd, &status) != 0) {
        return 0;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 07777) != required_mode ||
        !secure_extended_acl(directory_fd)) {
        errno = EACCES;
        return 0;
    }
    return 1;
}

static int same_object(const struct stat *first, const struct stat *second)
{
    return first->st_dev == second->st_dev &&
           first->st_ino == second->st_ino;
}

static int directory_binding_matches(int parent_fd, const char *name,
                                     int expected_fd)
{
    struct stat expected_status;
    struct stat current_status;
    int current_fd;
    int success;
    int saved_errno;

    if (parent_fd < 0 || expected_fd < 0) {
        errno = EINVAL;
        return 0;
    }
    current_fd = openat(parent_fd, name,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0) {
        return 0;
    }
    success = secure_directory_stat(expected_fd, STORAGE_DIRECTORY_MODE) &&
              secure_directory_stat(current_fd, STORAGE_DIRECTORY_MODE) &&
              fstat(expected_fd, &expected_status) == 0 &&
              fstat(current_fd, &current_status) == 0 &&
              same_object(&expected_status, &current_status);
    saved_errno = errno;
    if (close(current_fd) != 0 && success) {
        success = 0;
        saved_errno = errno;
    }
    if (!success && saved_errno == 0) {
        saved_errno = EACCES;
    }
    errno = saved_errno;
    return success;
}

static int open_home_directory(const char *path)
{
    char copy[STORAGE_HOME_MAX_BYTES + 1];
    char *component;
    char *state = NULL;
    size_t length;
    int directory_fd = -1;

    if (path == NULL || path[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    length = strnlen(path, sizeof(copy));
    if (length == 0 || length >= sizeof(copy)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(copy, path, length + 1);
    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) {
        return -1;
    }
    component = strtok_r(copy, "/", &state);
    while (component != NULL) {
        int next_fd;

        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
            errno = EINVAL;
            close(directory_fd);
            return -1;
        }
        next_fd = openat(directory_fd, component,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;
            close(directory_fd);
            errno = saved_errno;
            return -1;
        }
        close(directory_fd);
        directory_fd = next_fd;
        component = strtok_r(NULL, "/", &state);
    }
    return directory_fd;
}

static int open_private_directory_at(int parent_fd, const char *name,
                                     int *directory_fd)
{
    int created = 0;
    int opened_fd;

    if (mkdirat(parent_fd, name, STORAGE_DIRECTORY_MODE) == 0) {
        created = 1;
    } else if (errno != EEXIST) {
        return 0;
    }
    opened_fd = openat(parent_fd, name,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (opened_fd < 0) {
        return 0;
    }
    if (created && fchmod(opened_fd, STORAGE_DIRECTORY_MODE) != 0) {
        int saved_errno = errno;
        close(opened_fd);
        errno = saved_errno;
        return 0;
    }
    if (!secure_directory_stat(opened_fd, STORAGE_DIRECTORY_MODE)) {
        int saved_errno = errno;
        close(opened_fd);
        errno = saved_errno;
        return 0;
    }
    if (created && !sync_directory(parent_fd)) {
        int saved_errno = errno;
        close(opened_fd);
        errno = saved_errno;
        return 0;
    }
    *directory_fd = opened_fd;
    return 1;
}

int storage_init(struct storage *storage)
{
    const char *home;
    struct stat home_status;
    int home_fd = -1;
    int root_fd = -1;
    int vaults_fd = -1;
    int success = 0;

    if (storage == NULL || storage->home_fd != -1 ||
        storage->root_fd != -1 || storage->vaults_fd != -1) {
        errno = EINVAL;
        return 0;
    }
    home = getenv("HOME");
    home_fd = open_home_directory(home);
    if (home_fd < 0 || fstat(home_fd, &home_status) != 0) {
        goto cleanup;
    }
    if (!S_ISDIR(home_status.st_mode) || home_status.st_uid != geteuid()) {
        errno = EACCES;
        goto cleanup;
    }
    if (!open_private_directory_at(home_fd, ".securepm", &root_fd) ||
        !open_private_directory_at(root_fd, "vaults", &vaults_fd)) {
        goto cleanup;
    }
    storage->home_fd = home_fd;
    storage->root_fd = root_fd;
    storage->vaults_fd = vaults_fd;
    home_fd = -1;
    root_fd = -1;
    vaults_fd = -1;
    success = 1;

cleanup:
    {
        int saved_errno = errno;
        if (vaults_fd >= 0) {
            close(vaults_fd);
        }
        if (root_fd >= 0) {
            close(root_fd);
        }
        if (home_fd >= 0) {
            close(home_fd);
        }
        errno = saved_errno;
    }
    return success;
}

void storage_close(struct storage *storage)
{
    if (storage == NULL) {
        return;
    }
    if (storage->vaults_fd >= 0) {
        close(storage->vaults_fd);
    }
    if (storage->root_fd >= 0) {
        close(storage->root_fd);
    }
    if (storage->home_fd >= 0) {
        close(storage->home_fd);
    }
    storage->home_fd = -1;
    storage->root_fd = -1;
    storage->vaults_fd = -1;
}

static int valid_filename(const char *filename)
{
    size_t length;

    if (filename == NULL) {
        return 0;
    }
    length = strnlen(filename, STORAGE_FILENAME_MAX_BYTES + 1);
    if (length == 0 || length > STORAGE_FILENAME_MAX_BYTES ||
        !((filename[0] >= 'a' && filename[0] <= 'z') ||
          (filename[0] >= 'A' && filename[0] <= 'Z') ||
          (filename[0] >= '0' && filename[0] <= '9'))) {
        return 0;
    }
    for (size_t index = 1; index < length; ++index) {
        unsigned char character = (unsigned char)filename[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '.' || character == '_' || character == '-')) {
            return 0;
        }
    }
    return 1;
}

static int area_fd(const struct storage *storage, enum storage_area area)
{
    int directory_fd;

    if (storage == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (storage->home_fd < 0 || storage->root_fd < 0 ||
        !directory_binding_matches(storage->home_fd, ".securepm",
                                   storage->root_fd)) {
        errno = EACCES;
        return -1;
    }
    if (area == STORAGE_AREA_ROOT) {
        directory_fd = storage->root_fd;
    } else if (area == STORAGE_AREA_VAULTS) {
        if (storage->vaults_fd < 0 ||
            !directory_binding_matches(storage->root_fd, "vaults",
                                       storage->vaults_fd)) {
            errno = EACCES;
            return -1;
        }
        directory_fd = storage->vaults_fd;
    } else {
        errno = EINVAL;
        return -1;
    }
    if (directory_fd < 0 ||
        !secure_directory_stat(directory_fd, STORAGE_DIRECTORY_MODE)) {
        if (directory_fd < 0) {
            errno = EINVAL;
        }
        return -1;
    }
    return directory_fd;
}

static int secure_file_stat(const struct stat *status)
{
    if (!S_ISREG(status->st_mode) || status->st_uid != geteuid() ||
        (status->st_mode & 07777) != STORAGE_FILE_MODE ||
        status->st_nlink != 1) {
        errno = EACCES;
        return 0;
    }
    return 1;
}

static int secure_file_descriptor(int file_fd, struct stat *status)
{
    return fstat(file_fd, status) == 0 && secure_file_stat(status) &&
           secure_extended_acl(file_fd);
}

struct destination_state {
    int exists;
    struct stat status;
};

static int snapshot_destination(int directory_fd, const char *filename,
                                struct destination_state *state)
{
    int file_fd;
    int success;
    int saved_errno;

    memset(state, 0, sizeof(*state));
    file_fd = openat(directory_fd, filename,
                     O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0) {
        if (errno == ENOENT) {
            return 1;
        }
        return 0;
    }
    success = secure_file_descriptor(file_fd, &state->status);
    saved_errno = errno;
    if (close(file_fd) != 0 && success) {
        success = 0;
        saved_errno = errno;
    }
    if (success) {
        state->exists = 1;
    }
    errno = saved_errno;
    return success;
}

static int same_timestamp(const struct stat *first, const struct stat *second)
{
#ifdef __APPLE__
    return first->st_mtimespec.tv_sec == second->st_mtimespec.tv_sec &&
           first->st_mtimespec.tv_nsec == second->st_mtimespec.tv_nsec &&
           first->st_ctimespec.tv_sec == second->st_ctimespec.tv_sec &&
           first->st_ctimespec.tv_nsec == second->st_ctimespec.tv_nsec;
#else
    return first->st_mtim.tv_sec == second->st_mtim.tv_sec &&
           first->st_mtim.tv_nsec == second->st_mtim.tv_nsec &&
           first->st_ctim.tv_sec == second->st_ctim.tv_sec &&
           first->st_ctim.tv_nsec == second->st_ctim.tv_nsec;
#endif
}

static int same_destination_state(const struct destination_state *first,
                                  const struct destination_state *second)
{
    if (first->exists != second->exists) {
        return 0;
    }
    return !first->exists ||
           (same_object(&first->status, &second->status) &&
            first->status.st_size == second->status.st_size &&
            first->status.st_mode == second->status.st_mode &&
            first->status.st_uid == second->status.st_uid &&
            first->status.st_nlink == second->status.st_nlink &&
            same_timestamp(&first->status, &second->status));
}

static int validate_destination(int directory_fd, const char *filename)
{
    struct destination_state state;

    return snapshot_destination(directory_fd, filename, &state);
}

int storage_read_file(const struct storage *storage, enum storage_area area,
                      const char *filename, size_t maximum_size,
                      unsigned char **data, size_t *data_length)
{
    struct stat before;
    struct stat after;
    unsigned char extra;
    unsigned char *buffer = NULL;
    size_t expected;
    size_t offset = 0;
    int directory_fd;
    int file_fd = -1;
    int result = STORAGE_READ_ERROR;

    if (data == NULL || data_length == NULL) {
        errno = EINVAL;
        return STORAGE_READ_ERROR;
    }
    *data = NULL;
    *data_length = 0;
    directory_fd = area_fd(storage, area);
    if (directory_fd < 0 || !valid_filename(filename) ||
        maximum_size > STORAGE_MAX_FILE_BYTES) {
        errno = EINVAL;
        return STORAGE_READ_ERROR;
    }
    file_fd = openat(directory_fd, filename,
                     O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0) {
        return errno == ENOENT ? STORAGE_READ_MISSING : STORAGE_READ_ERROR;
    }
    if (!secure_file_descriptor(file_fd, &before)) {
        goto cleanup;
    }
    if (before.st_size < 0 || (uintmax_t)before.st_size > maximum_size ||
        (uintmax_t)before.st_size > STORAGE_MAX_FILE_BYTES) {
        errno = EFBIG;
        goto cleanup;
    }
    expected = (size_t)before.st_size;
    buffer = malloc(expected == 0 ? 1 : expected);
    if (buffer == NULL) {
        goto cleanup;
    }
    while (offset < expected) {
#ifdef SECUREPM_TEST_FAULTS
        ssize_t count;
        if (read_interrupt_once) {
            read_interrupt_once = 0;
            errno = EINTR;
            count = -1;
        } else if (read_early_eof_once) {
            read_early_eof_once = 0;
            count = 0;
        } else if (read_partial_error_stage == 1) {
            count = read(file_fd, buffer + offset, 1);
            read_partial_error_stage = count == 1 ? 2 : 0;
        } else if (read_partial_error_stage == 2) {
            read_partial_error_stage = 0;
            errno = EIO;
            count = -1;
        } else if (read_failure_once) {
            read_failure_once = 0;
            errno = EIO;
            count = -1;
        } else {
            count = read(file_fd, buffer + offset, expected - offset);
        }
#else
        ssize_t count = read(file_fd, buffer + offset, expected - offset);
#endif
        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            errno = EIO;
            goto cleanup;
        } else if (errno != EINTR) {
            goto cleanup;
        }
    }
    for (;;) {
        ssize_t count = read(file_fd, &extra, 1);
        if (count == 0) {
            break;
        }
        if (count > 0) {
            errno = EFBIG;
            goto cleanup;
        }
        if (errno != EINTR) {
            goto cleanup;
        }
    }
#ifdef SECUREPM_TEST_FAULTS
    if (read_postcheck_hook != NULL) {
        void (*hook)(void *) = read_postcheck_hook;
        void *context = read_postcheck_context;

        read_postcheck_hook = NULL;
        read_postcheck_context = NULL;
        hook(context);
    }
#endif
    if (!secure_file_descriptor(file_fd, &after) ||
        after.st_dev != before.st_dev ||
        after.st_ino != before.st_ino || after.st_size != before.st_size ||
        !secure_file_stat(&after)) {
        errno = EIO;
        goto cleanup;
    }
    *data = buffer;
    *data_length = expected;
    buffer = NULL;
    result = STORAGE_READ_OK;

cleanup:
    {
        int saved_errno = errno;
        free(buffer);
        if (file_fd >= 0) {
            close(file_fd);
        }
        errno = saved_errno;
    }
    return result;
}

void storage_free(void *data)
{
    free(data);
}

static int create_temporary_file(int directory_fd,
                                 char temporary_name[STORAGE_TEMP_NAME_BYTES])
{
    long process_id = (long)getpid();

    for (unsigned int attempt = 0; attempt < STORAGE_TEMP_ATTEMPTS; ++attempt) {
        int length = snprintf(temporary_name, STORAGE_TEMP_NAME_BYTES,
                              STORAGE_TEMP_PREFIX "%ld.%u",
                              process_id, attempt);
        int file_fd;

        if (length < 0 || (size_t)length >= STORAGE_TEMP_NAME_BYTES) {
            errno = ENAMETOOLONG;
            return -1;
        }
        file_fd = openat(directory_fd, temporary_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         STORAGE_FILE_MODE);
        if (file_fd >= 0) {
            return file_fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

static int write_all(int file_fd, const unsigned char *data, size_t data_length)
{
    size_t offset = 0;

    while (offset < data_length) {
        ssize_t count = write(file_fd, data + offset, data_length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            errno = EIO;
            return 0;
        } else if (errno != EINTR) {
            return 0;
        }
    }
    return 1;
}

static int destination_matches_bytes(const struct storage *storage,
                                     enum storage_area area,
                                     const char *filename,
                                     const unsigned char *expected,
                                     size_t expected_length)
{
    unsigned char *current = NULL;
    size_t current_length = 0;
    int success = storage_read_file(storage, area, filename,
                                    STORAGE_MAX_FILE_BYTES,
                                    &current, &current_length) ==
                      STORAGE_READ_OK &&
                  current_length == expected_length &&
                  (expected_length == 0 ||
                   memcmp(current, expected, expected_length) == 0);

    storage_free(current);
    if (!success) {
        errno = EAGAIN;
    }
    return success;
}

static int pause_atomic_before_replace(void)
{
#ifdef SECUREPM_TEST_FAULTS
    unsigned char byte = 1;
    int ready_fd = atomic_pause_ready_fd;
    int continue_fd = atomic_pause_continue_fd;

    atomic_pause_ready_fd = -1;
    atomic_pause_continue_fd = -1;
    if (ready_fd >= 0 && continue_fd >= 0) {
        ssize_t count;

        do {
            count = write(ready_fd, &byte, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1) {
            return 0;
        }
        do {
            count = read(continue_fd, &byte, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 1) {
            return 0;
        }
    }
#endif
    return 1;
}

static ssize_t append_write(int file_fd, const unsigned char *data,
                            size_t data_length)
{
#ifdef SECUREPM_TEST_FAULTS
    if (append_interrupt_once) {
        append_interrupt_once = 0;
        errno = EINTR;
        return -1;
    }
    if (append_failure_countdown != 0 &&
        --append_failure_countdown == 0) {
        errno = EIO;
        return -1;
    }
    if (append_write_limit_once != 0 &&
        data_length > append_write_limit_once) {
        data_length = append_write_limit_once;
        append_write_limit_once = 0;
    }
#endif
    return write(file_fd, data, data_length);
}

static int append_all(int file_fd, const unsigned char *data,
                      size_t data_length)
{
    size_t offset = 0;

    while (offset < data_length) {
        ssize_t count = append_write(file_fd, data + offset,
                                     data_length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            errno = EIO;
            return 0;
        } else if (errno != EINTR) {
            return 0;
        }
    }
    return 1;
}

static enum storage_atomic_result atomic_install(
    const struct storage *storage, enum storage_area area,
    const char *filename, const unsigned char *expected,
    size_t expected_length, int require_expected,
    const unsigned char *data, size_t data_length)
{
    struct destination_state initial_state;
    struct destination_state current_state;
    struct stat temporary_status;
    char temporary_name[STORAGE_TEMP_NAME_BYTES] = {0};
    int directory_fd = area_fd(storage, area);
    int temporary_fd = -1;
    int temporary_exists = 0;
    enum storage_atomic_result result = STORAGE_ATOMIC_ERROR;

    if (directory_fd < 0 || !valid_filename(filename) ||
        (expected == NULL && expected_length != 0) ||
        (data == NULL && data_length != 0) ||
        expected_length > STORAGE_MAX_FILE_BYTES ||
        data_length > STORAGE_MAX_FILE_BYTES) {
        errno = EINVAL;
        return STORAGE_ATOMIC_ERROR;
    }
    if (!snapshot_destination(directory_fd, filename, &initial_state) ||
        (require_expected &&
         (!initial_state.exists ||
          !destination_matches_bytes(storage, area, filename,
                                     expected, expected_length)))) {
        return STORAGE_ATOMIC_ERROR;
    }
    temporary_fd = create_temporary_file(directory_fd, temporary_name);
    if (temporary_fd < 0) {
        goto cleanup;
    }
    temporary_exists = 1;
    if (fchmod(temporary_fd, STORAGE_FILE_MODE) != 0 ||
        !secure_file_descriptor(temporary_fd, &temporary_status) ||
        !write_all(temporary_fd, data, data_length) ||
        !sync_file(temporary_fd)) {
        goto cleanup;
    }
    {
        int close_result = close(temporary_fd);
        temporary_fd = -1;
        if (close_result != 0) {
            goto cleanup;
        }
    }
#ifdef SECUREPM_TEST_FAULTS
    if (atomic_precommit_failure_once) {
        atomic_precommit_failure_once = 0;
        errno = EIO;
        goto cleanup;
    }
#endif
    if (!pause_atomic_before_replace() ||
        !snapshot_destination(directory_fd, filename, &current_state) ||
        !same_destination_state(&initial_state, &current_state) ||
        (require_expected &&
         !destination_matches_bytes(storage, area, filename,
                                    expected, expected_length)) ||
        renameat(directory_fd, temporary_name, directory_fd, filename) != 0) {
        goto cleanup;
    }
    temporary_exists = 0;
    result = STORAGE_ATOMIC_INSTALLED;
    if (!sync_atomic_directory(directory_fd)) {
        goto cleanup;
    }
    result = STORAGE_ATOMIC_DURABLE;

cleanup:
    {
        int saved_errno = errno;
        if (temporary_fd >= 0) {
            close(temporary_fd);
        }
        if (temporary_exists) {
            unlinkat(directory_fd, temporary_name, 0);
        }
        errno = saved_errno;
    }
    return result;
}

enum storage_atomic_result storage_atomic_write_result(
    const struct storage *storage, enum storage_area area,
    const char *filename, const unsigned char *data, size_t data_length)
{
    return atomic_install(storage, area, filename, NULL, 0, 0,
                          data, data_length);
}

int storage_atomic_write(const struct storage *storage, enum storage_area area,
                         const char *filename,
                         const unsigned char *data, size_t data_length)
{
    return storage_atomic_write_result(storage, area, filename,
                                       data, data_length) ==
           STORAGE_ATOMIC_DURABLE;
}

enum storage_atomic_result storage_atomic_replace_result(
    const struct storage *storage, enum storage_area area,
    const char *filename, const unsigned char *expected,
    size_t expected_length, const unsigned char *data, size_t data_length)
{
    return atomic_install(storage, area, filename,
                          expected, expected_length, 1,
                          data, data_length);
}

int storage_atomic_replace(const struct storage *storage,
                           enum storage_area area, const char *filename,
                           const unsigned char *expected,
                           size_t expected_length,
                           const unsigned char *data, size_t data_length)
{
    return storage_atomic_replace_result(storage, area, filename,
                                         expected, expected_length,
                                         data, data_length) ==
           STORAGE_ATOMIC_DURABLE;
}

static int open_append_file(int directory_fd, const char *filename,
                            int *created)
{
    int file_fd;

    *created = 0;
    file_fd = openat(directory_fd, filename,
                     O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NONBLOCK |
                         O_CLOEXEC | O_NOFOLLOW,
                     STORAGE_FILE_MODE);
    if (file_fd >= 0) {
        *created = 1;
        return file_fd;
    }
    if (errno != EEXIST) {
        return -1;
    }
    return openat(directory_fd, filename,
                  O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
}

int storage_append_file(const struct storage *storage, enum storage_area area,
                        const char *filename,
                        const unsigned char *data, size_t data_length,
                        size_t maximum_size)
{
    struct storage_lock lock = STORAGE_LOCK_INITIALIZER;
    struct stat status;
    char lock_name[STORAGE_FILENAME_MAX_BYTES + 1];
    size_t filename_length;
    size_t lock_suffix_length = sizeof(STORAGE_APPEND_LOCK_SUFFIX) - 1;
    off_t original_size = 0;
    int directory_fd;
    int file_fd = -1;
    int created = 0;
    int may_have_written = 0;
    int success = 0;

    directory_fd = area_fd(storage, area);
    if (directory_fd < 0 || !valid_filename(filename) ||
        (data == NULL && data_length != 0) ||
        maximum_size > STORAGE_MAX_FILE_BYTES || data_length > maximum_size) {
        errno = EINVAL;
        return 0;
    }
    filename_length = strlen(filename);
    if (filename_length > STORAGE_FILENAME_MAX_BYTES - lock_suffix_length) {
        errno = ENAMETOOLONG;
        return 0;
    }
    memcpy(lock_name, filename, filename_length);
    memcpy(lock_name + filename_length, STORAGE_APPEND_LOCK_SUFFIX,
           lock_suffix_length + 1);
    if (!storage_lock_acquire(storage, area, lock_name, &lock)) {
        return 0;
    }
    file_fd = open_append_file(directory_fd, filename, &created);
    if (file_fd < 0 ||
        (created && fchmod(file_fd, STORAGE_FILE_MODE) != 0) ||
        !secure_file_descriptor(file_fd, &status)) {
        goto cleanup;
    }
    if (status.st_size < 0 || (uintmax_t)status.st_size > maximum_size ||
        data_length > maximum_size - (size_t)status.st_size) {
        errno = EFBIG;
        goto cleanup;
    }
    original_size = status.st_size;
    may_have_written = data_length != 0;
    if (!append_all(file_fd, data, data_length) || !sync_file(file_fd)) {
        goto cleanup;
    }
    may_have_written = 0;
    if (created && !sync_directory(directory_fd)) {
        goto cleanup;
    }
    if (close(file_fd) != 0) {
        file_fd = -1;
        goto cleanup;
    }
    file_fd = -1;
    success = 1;

cleanup:
    {
        int saved_errno = errno;

        if (!success && file_fd >= 0 && may_have_written) {
            if (ftruncate(file_fd, original_size) == 0) {
                (void)sync_file(file_fd);
            }
        }
        if (file_fd >= 0) {
            (void)close(file_fd);
        }
        if (!success && created) {
            (void)unlinkat(directory_fd, filename, 0);
            (void)sync_directory(directory_fd);
        }
        storage_lock_release(&lock);
        errno = saved_errno;
    }
    return success;
}

int storage_remove_file(const struct storage *storage, enum storage_area area,
                        const char *filename)
{
    int directory_fd = area_fd(storage, area);

    if (directory_fd < 0 || !valid_filename(filename)) {
        errno = EINVAL;
        return 0;
    }
    if (!validate_destination(directory_fd, filename) ||
        unlinkat(directory_fd, filename, 0) != 0 ||
        !sync_directory(directory_fd)) {
        return 0;
    }
    return 1;
}

static int open_lock_file(int directory_fd, const char *filename)
{
    int created = 0;
    int file_fd;

    file_fd = openat(directory_fd, filename,
                     O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     STORAGE_FILE_MODE);
    if (file_fd >= 0) {
        created = 1;
    } else if (errno == EEXIST) {
        file_fd = openat(directory_fd, filename,
                         O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
    if (file_fd < 0) {
        return -1;
    }
    {
        struct stat status;

        if ((created && fchmod(file_fd, STORAGE_FILE_MODE) != 0) ||
            !secure_file_descriptor(file_fd, &status) ||
            (created && (!sync_file(file_fd) ||
                         !sync_directory(directory_fd)))) {
            int saved_errno = errno;

            close(file_fd);
            if (created) {
                unlinkat(directory_fd, filename, 0);
            }
            errno = saved_errno;
            return -1;
        }
    }
    return file_fd;
}

static int lock_descriptor_matches_path(int directory_fd,
                                        const char *filename,
                                        int lock_fd)
{
    struct stat held_status;
    struct stat path_status;

    if (!secure_file_descriptor(lock_fd, &held_status)) {
        return 0;
    }
    if (fstatat(directory_fd, filename, &path_status,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !secure_file_stat(&path_status) ||
        !same_object(&held_status, &path_status)) {
        errno = EACCES;
        return 0;
    }
    return 1;
}

int storage_lock_acquire(const struct storage *storage, enum storage_area area,
                         const char *filename, struct storage_lock *lock)
{
    struct flock operation = {0};
    int directory_fd;
    int file_fd;
    int result;

    if (lock == NULL || lock->held) {
        errno = EINVAL;
        return 0;
    }
    directory_fd = area_fd(storage, area);
    if (directory_fd < 0 || !valid_filename(filename)) {
        errno = EINVAL;
        return 0;
    }
    file_fd = open_lock_file(directory_fd, filename);
    if (file_fd < 0) {
        return 0;
    }
    operation.l_type = F_WRLCK;
    operation.l_whence = SEEK_SET;
    result = fcntl(file_fd, F_SETLKW, &operation);
    if (result != 0 ||
        !lock_descriptor_matches_path(directory_fd, filename, file_fd)) {
        int saved_errno = errno;

        if (result == 0) {
            operation.l_type = F_UNLCK;
            (void)fcntl(file_fd, F_SETLK, &operation);
        }
        close(file_fd);
        errno = saved_errno;
        return 0;
    }
    lock->descriptor = file_fd;
    lock->held = 1;
    return 1;
}

int storage_lock_is_held(const struct storage_lock *lock)
{
    return lock != NULL && lock->held == 1 && lock->descriptor >= 0;
}

int storage_lock_validate(const struct storage *storage,
                          enum storage_area area, const char *filename,
                          const struct storage_lock *lock)
{
    int directory_fd = area_fd(storage, area);

    if (directory_fd < 0 || !valid_filename(filename) ||
        !storage_lock_is_held(lock) ||
        !lock_descriptor_matches_path(directory_fd, filename,
                                      lock->descriptor)) {
        if (errno == 0) {
            errno = EACCES;
        }
        return 0;
    }
    return 1;
}

void storage_lock_release(struct storage_lock *lock)
{
    int saved_errno = errno;

    if (storage_lock_is_held(lock)) {
        struct flock operation = {0};

        operation.l_type = F_UNLCK;
        operation.l_whence = SEEK_SET;
        (void)fcntl(lock->descriptor, F_SETLK, &operation);
        (void)close(lock->descriptor);
    }
    if (lock != NULL) {
        lock->descriptor = -1;
        lock->held = 0;
    }
    errno = saved_errno;
}
