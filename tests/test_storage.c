#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "storage.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PATH_BYTES 4096
#define TEMP_PREFIX ".securepm.tmp."

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
                           "securepm-storage-test.XXXXXX");
    free(canonical_parent);
    if (!path_ready) {
        return NULL;
    }
    return mkdtemp(home_template);
}

static int write_direct(const char *path, const unsigned char *data,
                        size_t data_length, mode_t mode)
{
    int file_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                       STORAGE_FILE_MODE);
    size_t offset = 0;

    if (file_fd < 0 || fchmod(file_fd, mode) != 0) {
        if (file_fd >= 0) {
            close(file_fd);
        }
        return 0;
    }
    while (offset < data_length) {
        ssize_t count = write(file_fd, data + offset, data_length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(file_fd);
            return 0;
        }
    }
    return close(file_fd) == 0;
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

static int directory_has_temporary_file(const char *path)
{
    DIR *directory = opendir(path);
    struct dirent *entry;
    int found = 0;

    if (directory == NULL) {
        return 1;
    }
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, TEMP_PREFIX, sizeof(TEMP_PREFIX) - 1) == 0) {
            found = 1;
            break;
        }
    }
    closedir(directory);
    return found;
}

static void check_mode(const char *path, mode_t expected_mode, int directory)
{
    struct stat status;

    CHECK(lstat(path, &status) == 0);
    CHECK(directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode));
    CHECK((status.st_mode & 07777) == expected_mode);
    CHECK(status.st_uid == geteuid());
}

static void test_directories(const char *home)
{
    char root[TEST_PATH_BYTES];
    char vaults[TEST_PATH_BYTES];

    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(vaults, root, "vaults"));
    check_mode(root, STORAGE_DIRECTORY_MODE, 1);
    check_mode(vaults, STORAGE_DIRECTORY_MODE, 1);
}

static void test_read_write_and_replace(const struct storage *storage,
                                        const char *home)
{
    static const unsigned char first[] = "first metadata";
    static const unsigned char second[] = "replacement metadata";
    static const unsigned char vault_data[] = "dummy encrypted vault bytes";
    unsigned char *read_data = NULL;
    size_t read_length = 0;
    char root[TEST_PATH_BYTES];
    char users_path[TEST_PATH_BYTES];
    char vaults[TEST_PATH_BYTES];
    char vault_path[TEST_PATH_BYTES];
    struct stat first_status;
    struct stat second_status;

    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "users.db",
                               first, sizeof(first) - 1) == 1);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "users.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_OK);
    CHECK(read_length == sizeof(first) - 1);
    CHECK(memcmp(read_data, first, read_length) == 0);
    storage_free(read_data);
    read_data = NULL;
    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(users_path, root, "users.db"));
    CHECK(lstat(users_path, &first_status) == 0);

    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "users.db",
                               second, sizeof(second) - 1) == 1);
    CHECK(lstat(users_path, &second_status) == 0);
    CHECK(first_status.st_dev != second_status.st_dev ||
          first_status.st_ino != second_status.st_ino);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "users.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_OK);
    CHECK(read_length == sizeof(second) - 1);
    CHECK(memcmp(read_data, second, read_length) == 0);
    storage_free(read_data);

    CHECK(storage_atomic_write(storage, STORAGE_AREA_VAULTS,
                               "0011223344556677.vault",
                               vault_data, sizeof(vault_data) - 1) == 1);
    CHECK(make_path(vaults, root, "vaults"));
    CHECK(make_path(vault_path, vaults, "0011223344556677.vault"));
    check_mode(users_path, STORAGE_FILE_MODE, 0);
    check_mode(vault_path, STORAGE_FILE_MODE, 0);
}

static void test_missing_and_names(const struct storage *storage)
{
    static const unsigned char data[] = "dummy";
    unsigned char *read_data = (unsigned char *)1;
    size_t read_length = 123;

    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "missing.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_MISSING);
    CHECK(read_data == NULL && read_length == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "../escape", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "foo/bar",
                               data, sizeof(data) - 1) == 0);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, ".hidden",
                               data, sizeof(data) - 1) == 0);
    CHECK(storage_atomic_write(storage, (enum storage_area)99, "file.db",
                               data, sizeof(data) - 1) == 0);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "empty.db",
                               NULL, 0) == 1);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "empty.db", 0,
                            &read_data, &read_length) == STORAGE_READ_OK);
    CHECK(read_data != NULL && read_length == 0);
    storage_free(read_data);
    read_data = NULL;
    CHECK(storage_remove_file(storage, STORAGE_AREA_ROOT, "empty.db") == 1);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "empty.db", 0,
                            &read_data, &read_length) == STORAGE_READ_MISSING);
    CHECK(storage_remove_file(storage, STORAGE_AREA_ROOT, "empty.db") == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "users.db", 1,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(read_data == NULL && read_length == 0);
}

static void test_unsafe_storage_root_rejected(const char *home)
{
    struct storage storage = STORAGE_INITIALIZER;
    char root[TEST_PATH_BYTES];
    char target[TEST_PATH_BYTES];

    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(target, home, "redirect-target"));

    CHECK(mkdir(root, 0755) == 0);
    CHECK(storage_init(&storage) == 0);
    CHECK(storage.root_fd == -1 && storage.vaults_fd == -1);
    CHECK(rmdir(root) == 0);

    CHECK(write_direct(root, NULL, 0, STORAGE_FILE_MODE));
    CHECK(storage_init(&storage) == 0);
    CHECK(storage.root_fd == -1 && storage.vaults_fd == -1);
    CHECK(unlink(root) == 0);

    CHECK(mkdir(target, STORAGE_DIRECTORY_MODE) == 0);
    CHECK(symlink("redirect-target", root) == 0);
    CHECK(storage_init(&storage) == 0);
    CHECK(storage.root_fd == -1 && storage.vaults_fd == -1);
    storage_close(&storage);
    CHECK(unlink(root) == 0);
    CHECK(rmdir(target) == 0);
}

static void test_symlink_and_unsafe_objects(const struct storage *storage,
                                            const char *home)
{
    static const unsigned char original[] = "outside data";
    static const unsigned char replacement[] = "replacement";
    unsigned char *read_data = NULL;
    size_t read_length = 0;
    char root[TEST_PATH_BYTES];
    char outside[TEST_PATH_BYTES];
    char link_path[TEST_PATH_BYTES];
    char directory_path[TEST_PATH_BYTES];
    char fifo_path[TEST_PATH_BYTES];
    char permissive_path[TEST_PATH_BYTES];
    char hardlink_source[TEST_PATH_BYTES];
    char hardlink_alias[TEST_PATH_BYTES];
    unsigned char direct_buffer[sizeof(original)] = {0};
    int file_fd;

    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(outside, home, "outside.db"));
    CHECK(make_path(link_path, root, "link.db"));
    CHECK(write_direct(outside, original, sizeof(original) - 1, STORAGE_FILE_MODE));
    CHECK(symlink("../outside.db", link_path) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "link.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "link.db",
                               replacement, sizeof(replacement) - 1) == 0);
    CHECK(storage_remove_file(storage, STORAGE_AREA_ROOT, "link.db") == 0);
    file_fd = open(outside, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(file_fd >= 0);
    CHECK(read(file_fd, direct_buffer, sizeof(original) - 1) ==
          (ssize_t)(sizeof(original) - 1));
    CHECK(memcmp(direct_buffer, original, sizeof(original) - 1) == 0);
    if (file_fd >= 0) {
        close(file_fd);
    }

    CHECK(make_path(directory_path, root, "directory.db"));
    CHECK(mkdir(directory_path, STORAGE_DIRECTORY_MODE) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "directory.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "directory.db",
                               replacement, sizeof(replacement) - 1) == 0);

    CHECK(make_path(fifo_path, root, "pipe.db"));
    CHECK(mkfifo(fifo_path, STORAGE_FILE_MODE) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "pipe.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "pipe.db",
                               replacement, sizeof(replacement) - 1) == 0);

    CHECK(make_path(permissive_path, root, "permissive.db"));
    CHECK(write_direct(permissive_path, replacement,
                       sizeof(replacement) - 1, 0644));
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "permissive.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "permissive.db",
                               replacement, sizeof(replacement) - 1) == 0);

    CHECK(make_path(hardlink_source, root, "hardlink.db"));
    CHECK(make_path(hardlink_alias, root, "hardlink-alias.db"));
    CHECK(write_direct(hardlink_source, replacement,
                       sizeof(replacement) - 1, STORAGE_FILE_MODE));
    CHECK(link(hardlink_source, hardlink_alias) == 0);
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "hardlink.db", 1024,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "hardlink.db",
                               replacement, sizeof(replacement) - 1) == 0);
}

static void test_oversized_file(const struct storage *storage, const char *home)
{
    unsigned char *read_data = NULL;
    size_t read_length = 0;
    char root[TEST_PATH_BYTES];
    char oversized[TEST_PATH_BYTES];
    int file_fd;

    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(oversized, root, "oversized.db"));
    file_fd = open(oversized, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                   STORAGE_FILE_MODE);
    CHECK(file_fd >= 0);
    if (file_fd >= 0) {
        CHECK(fchmod(file_fd, STORAGE_FILE_MODE) == 0);
        CHECK(ftruncate(file_fd, (off_t)STORAGE_MAX_FILE_BYTES + 1) == 0);
        CHECK(close(file_fd) == 0);
    }
    CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "oversized.db",
                            STORAGE_MAX_FILE_BYTES,
                            &read_data, &read_length) == STORAGE_READ_ERROR);
    CHECK(read_data == NULL && read_length == 0);
}

static void test_failed_write_cleanup(const struct storage *storage,
                                      const char *home)
{
    static const unsigned char data[] = "failure data";
    struct rlimit original_limit;
    struct rlimit small_limit;
    struct sigaction ignore_action = {0};
    struct sigaction original_action;
    unsigned char *read_data = NULL;
    size_t read_length = 0;
    char root[TEST_PATH_BYTES];
    int limit_ready;
    int signal_ready;

    CHECK(make_path(root, home, ".securepm"));
    limit_ready = getrlimit(RLIMIT_FSIZE, &original_limit) == 0;
    CHECK(limit_ready);
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&ignore_action.sa_mask);
    signal_ready = sigaction(SIGXFSZ, &ignore_action, &original_action) == 0;
    CHECK(signal_ready);
    if (limit_ready && signal_ready) {
        small_limit = original_limit;
        small_limit.rlim_cur = 1;
        CHECK(setrlimit(RLIMIT_FSIZE, &small_limit) == 0);
        CHECK(storage_atomic_write(storage, STORAGE_AREA_ROOT, "failed.db",
                                   data, sizeof(data) - 1) == 0);
        CHECK(setrlimit(RLIMIT_FSIZE, &original_limit) == 0);
        CHECK(sigaction(SIGXFSZ, &original_action, NULL) == 0);
        CHECK(storage_read_file(storage, STORAGE_AREA_ROOT, "failed.db", 1024,
                                &read_data, &read_length) == STORAGE_READ_MISSING);
        CHECK(!directory_has_temporary_file(root));
    }
}

static void test_locking(const struct storage *storage, const char *home)
{
    struct storage_lock lock = STORAGE_LOCK_INITIALIZER;
    char root[TEST_PATH_BYTES];
    char lock_path[TEST_PATH_BYTES];
    int ready_pipe[2] = {-1, -1};
    int acquired_pipe[2] = {-1, -1};
    struct pollfd poll_descriptor;
    pid_t child = -1;
    char byte;
    int status = 0;

    CHECK(storage_lock_acquire(storage, STORAGE_AREA_ROOT,
                               "concurrent.lock", &lock) == 1);
    CHECK(storage_lock_is_held(&lock));
    CHECK(make_path(root, home, ".securepm"));
    CHECK(make_path(lock_path, root, "concurrent.lock"));
    check_mode(lock_path, STORAGE_FILE_MODE, 0);
    CHECK(pipe(ready_pipe) == 0);
    CHECK(pipe(acquired_pipe) == 0);
    if (ready_pipe[0] < 0 || acquired_pipe[0] < 0) {
        storage_lock_release(&lock);
        return;
    }
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct storage_lock child_lock = STORAGE_LOCK_INITIALIZER;

        close(ready_pipe[0]);
        close(acquired_pipe[0]);
        if (write(ready_pipe[1], "R", 1) != 1 ||
            !storage_lock_acquire(storage, STORAGE_AREA_ROOT,
                                  "concurrent.lock", &child_lock) ||
            write(acquired_pipe[1], "A", 1) != 1) {
            _exit(1);
        }
        storage_lock_release(&child_lock);
        _exit(0);
    }
    close(ready_pipe[1]);
    close(acquired_pipe[1]);
    ready_pipe[1] = -1;
    acquired_pipe[1] = -1;
    if (child > 0) {
        CHECK(read(ready_pipe[0], &byte, 1) == 1 && byte == 'R');
        poll_descriptor.fd = acquired_pipe[0];
        poll_descriptor.events = POLLIN;
        poll_descriptor.revents = 0;
        CHECK(poll(&poll_descriptor, 1, 200) == 0);
        storage_lock_release(&lock);
        CHECK(poll(&poll_descriptor, 1, 5000) == 1);
        CHECK(read(acquired_pipe[0], &byte, 1) == 1 && byte == 'A');
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    storage_lock_release(&lock);
    close(ready_pipe[0]);
    close(acquired_pipe[0]);
    CHECK(!storage_lock_is_held(&lock));
}

int main(void)
{
    char home_template[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct storage storage = STORAGE_INITIALIZER;
    int home_set;

    CHECK(home != NULL);
    if (home == NULL) {
        return 1;
    }
    home_set = setenv("HOME", home, 1) == 0;
    CHECK(home_set);
    if (!home_set) {
        CHECK(remove_tree(home));
        return 1;
    }
    test_unsafe_storage_root_rejected(home);
    CHECK(storage_init(&storage) == 1);
    if (storage.root_fd >= 0 && storage.vaults_fd >= 0) {
        test_directories(home);
        test_read_write_and_replace(&storage, home);
        test_missing_and_names(&storage);
        test_symlink_and_unsafe_objects(&storage, home);
        test_oversized_file(&storage, home);
        test_failed_write_cleanup(&storage, home);
        test_locking(&storage, home);
    }
    storage_close(&storage);
    CHECK(remove_tree(home));

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u storage checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u storage checks\n", checks);
    return 0;
}
