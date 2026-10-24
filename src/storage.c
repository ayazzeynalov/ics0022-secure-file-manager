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

#define STORAGE_HOME_MAX_BYTES 4096
#define STORAGE_TEMP_NAME_BYTES 96
#define STORAGE_TEMP_ATTEMPTS 128
#define STORAGE_TEMP_PREFIX ".securepm.tmp."

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

static int secure_directory_stat(int directory_fd, mode_t required_mode)
{
    struct stat status;

    if (fstat(directory_fd, &status) != 0) {
        return 0;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 07777) != required_mode) {
        errno = EACCES;
        return 0;
    }
    return 1;
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

    if (storage == NULL || storage->root_fd != -1 || storage->vaults_fd != -1) {
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
    storage->root_fd = root_fd;
    storage->vaults_fd = vaults_fd;
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
    if (area == STORAGE_AREA_ROOT) {
        directory_fd = storage->root_fd;
    } else if (area == STORAGE_AREA_VAULTS) {
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

static int validate_destination(int directory_fd, const char *filename)
{
    struct stat status;

    if (fstatat(directory_fd, filename, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        return secure_file_stat(&status);
    }
    return errno == ENOENT;
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
    if (fstat(file_fd, &before) != 0 || !secure_file_stat(&before)) {
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
        ssize_t count = read(file_fd, buffer + offset, expected - offset);
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
    if (fstat(file_fd, &after) != 0 || after.st_dev != before.st_dev ||
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

int storage_atomic_write(const struct storage *storage, enum storage_area area,
                         const char *filename,
                         const unsigned char *data, size_t data_length)
{
    struct stat temporary_status;
    char temporary_name[STORAGE_TEMP_NAME_BYTES] = {0};
    int directory_fd = area_fd(storage, area);
    int temporary_fd = -1;
    int temporary_exists = 0;
    int success = 0;

    if (directory_fd < 0 || !valid_filename(filename) ||
        (data == NULL && data_length != 0) ||
        data_length > STORAGE_MAX_FILE_BYTES) {
        errno = EINVAL;
        return 0;
    }
    if (!validate_destination(directory_fd, filename)) {
        return 0;
    }
    temporary_fd = create_temporary_file(directory_fd, temporary_name);
    if (temporary_fd < 0) {
        goto cleanup;
    }
    temporary_exists = 1;
    if (fchmod(temporary_fd, STORAGE_FILE_MODE) != 0 ||
        fstat(temporary_fd, &temporary_status) != 0 ||
        !secure_file_stat(&temporary_status) ||
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
    if (!validate_destination(directory_fd, filename) ||
        renameat(directory_fd, temporary_name, directory_fd, filename) != 0) {
        goto cleanup;
    }
    temporary_exists = 0;
    if (!sync_directory(directory_fd)) {
        goto cleanup;
    }
    success = 1;

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
    return success;
}

int storage_remove_file(const struct storage *storage, enum storage_area area,
                        const char *filename)
{
    struct stat status;
    int directory_fd = area_fd(storage, area);

    if (directory_fd < 0 || !valid_filename(filename)) {
        errno = EINVAL;
        return 0;
    }
    if (fstatat(directory_fd, filename, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !secure_file_stat(&status) ||
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
            fstat(file_fd, &status) != 0 || !secure_file_stat(&status) ||
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
    do {
        result = fcntl(file_fd, F_SETLKW, &operation);
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
        int saved_errno = errno;

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
