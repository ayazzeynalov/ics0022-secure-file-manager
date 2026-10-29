#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#include <util.h>
#else
#define _XOPEN_SOURCE 700
#include <pty.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define TEST_PATH_BYTES 4096
#define TEST_RECORD_ID_BYTES 16
#define TRANSCRIPT_BYTES (128U * 1024U)
#define DIALOG_TIMEOUT_SECONDS 60

struct dialog_step {
    const char *expected;
    const char *response;
};

struct transcript {
    unsigned char data[TRANSCRIPT_BYTES];
    size_t length;
    size_t search_offset;
};

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
                           "securepm-cli-test.XXXXXX");
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
                          const unsigned char *needle, size_t needle_length)
{
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

static size_t count_text(const unsigned char *data, size_t data_length,
                         const char *text)
{
    size_t text_length = strlen(text);
    size_t count = 0;

    if (text_length == 0 || text_length > data_length) {
        return 0;
    }
    for (size_t offset = 0; offset <= data_length - text_length; ++offset) {
        if (memcmp(data + offset, text, text_length) == 0) {
            ++count;
        }
    }
    return count;
}

static int transcript_find(struct transcript *transcript,
                           const char *expected)
{
    size_t expected_length = strlen(expected);

    if (expected_length > transcript->length - transcript->search_offset) {
        return 0;
    }
    for (size_t offset = transcript->search_offset;
         offset <= transcript->length - expected_length; ++offset) {
        if (memcmp(transcript->data + offset, expected, expected_length) == 0) {
            transcript->search_offset = offset + expected_length;
            return 1;
        }
    }
    return 0;
}

static int extract_record_id(const struct transcript *transcript,
                             char record_id[TEST_RECORD_ID_BYTES * 2 + 2])
{
    static const char prefix[] = "ID: ";
    size_t encoded_length = TEST_RECORD_ID_BYTES * 2;

    for (size_t offset = 0;
         offset + sizeof(prefix) - 1 + encoded_length <= transcript->length;
         ++offset) {
        if (memcmp(transcript->data + offset, prefix,
                   sizeof(prefix) - 1) == 0) {
            const unsigned char *encoded = transcript->data + offset +
                                            sizeof(prefix) - 1;

            for (size_t index = 0; index < encoded_length; ++index) {
                if (!((encoded[index] >= '0' && encoded[index] <= '9') ||
                      (encoded[index] >= 'a' && encoded[index] <= 'f'))) {
                    return 0;
                }
                record_id[index] = (char)encoded[index];
            }
            record_id[encoded_length] = '\n';
            record_id[encoded_length + 1] = '\0';
            return 1;
        }
    }
    return 0;
}

static int deadline_expired(const struct timespec *start)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 1;
    }
    return now.tv_sec - start->tv_sec >= DIALOG_TIMEOUT_SECONDS;
}

static int64_t elapsed_milliseconds(const struct timespec *start,
                                    const struct timespec *end)
{
    return (int64_t)(end->tv_sec - start->tv_sec) * 1000 +
           (end->tv_nsec - start->tv_nsec) / 1000000;
}

static int wait_for_text(int master, struct transcript *transcript,
                         const char *expected)
{
    struct timespec start;

    if (transcript_find(transcript, expected)) {
        return 1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return 0;
    }
    while (!deadline_expired(&start)) {
        struct pollfd descriptor = {master, POLLIN, 0};
        int poll_result = poll(&descriptor, 1, 250);

        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        if (poll_result == 0) {
            continue;
        }
        if ((descriptor.revents & POLLIN) != 0) {
            ssize_t received;

            if (transcript->length == sizeof(transcript->data)) {
                return 0;
            }
            received = read(master,
                            transcript->data + transcript->length,
                            sizeof(transcript->data) - transcript->length);
            if (received > 0) {
                transcript->length += (size_t)received;
                if (transcript_find(transcript, expected)) {
                    return 1;
                }
            } else if (received == 0 || errno == EIO) {
                return 0;
            }
        } else if ((descriptor.revents & (POLLHUP | POLLERR)) != 0) {
            return 0;
        }
    }
    return 0;
}

static int write_bytes(int descriptor, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(descriptor, bytes + offset, length - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int write_all(int descriptor, const char *text)
{
    return write_bytes(descriptor, text, strlen(text));
}

static pid_t start_program(const char *program, const char *home, int *master)
{
    pid_t child = forkpty(master, NULL, NULL, NULL);

    if (child == 0) {
        if (setenv("HOME", home, 1) != 0) {
            _exit(126);
        }
        execl(program, program, (char *)NULL);
        _exit(127);
    }
    return child;
}

static int wait_for_exit(pid_t child, int master, int *status)
{
    struct timespec start;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return 0;
    }
    while (!deadline_expired(&start)) {
        pid_t result = waitpid(child, status, WNOHANG);

        if (result == child) {
            return 1;
        }
        if (result < 0) {
            return 0;
        }
        struct pollfd descriptor = {master, POLLIN, 0};
        if (poll(&descriptor, 1, 50) > 0 &&
            (descriptor.revents & POLLIN) != 0) {
            unsigned char discarded[1024];
            ssize_t received = read(master, discarded, sizeof(discarded));

            if (received < 0 && errno != EINTR) {
                return 0;
            }
        }
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, status, 0);
    return 0;
}

static int run_dialog(const char *program, const char *home,
                      const struct dialog_step *steps, size_t step_count,
                      struct transcript *transcript)
{
    int master = -1;
    int status = 0;
    pid_t child = start_program(program, home, &master);
    int success = child > 0;

    memset(transcript, 0, sizeof(*transcript));
    if (!success) {
        return 0;
    }
    for (size_t index = 0; index < step_count && success; ++index) {
        success = wait_for_text(master, transcript, steps[index].expected);
        if (success && steps[index].response != NULL) {
            success = write_all(master, steps[index].response);
        }
    }
    if (success) {
        success = wait_for_exit(child, master, &status) &&
                  WIFEXITED(status) && WEXITSTATUS(status) == 0;
    } else {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    close(master);
    return success;
}

static int find_vault(const char *home, char path[TEST_PATH_BYTES])
{
    char vault_directory[TEST_PATH_BYTES];
    char securepm_directory[TEST_PATH_BYTES];
    DIR *directory;
    struct dirent *entry;
    int found = 0;

    if (!make_path(securepm_directory, home, ".securepm") ||
        !make_path(vault_directory, securepm_directory, "vaults")) {
        return 0;
    }
    directory = opendir(vault_directory);
    if (directory == NULL) {
        return 0;
    }
    while ((entry = readdir(directory)) != NULL) {
        size_t length = strlen(entry->d_name);

        if (length == 38 && strcmp(entry->d_name + 32, ".vault") == 0) {
            found = make_path(path, vault_directory, entry->d_name);
            break;
        }
    }
    closedir(directory);
    return found;
}

static unsigned char *read_file(const char *path, size_t *length)
{
    struct stat status;
    unsigned char *data;
    int descriptor;
    size_t offset = 0;

    *length = 0;
    descriptor = open(path, O_RDONLY);
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        status.st_size < 0 || (uintmax_t)status.st_size > SIZE_MAX) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return NULL;
    }
    data = malloc((size_t)status.st_size == 0 ? 1 : (size_t)status.st_size);
    if (data == NULL) {
        close(descriptor);
        return NULL;
    }
    while (offset < (size_t)status.st_size) {
        ssize_t received = read(descriptor, data + offset,
                                (size_t)status.st_size - offset);
        if (received > 0) {
            offset += (size_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            free(data);
            close(descriptor);
            return NULL;
        }
    }
    if (close(descriptor) != 0) {
        free(data);
        return NULL;
    }
    *length = offset;
    return data;
}

static int overwrite_file(const char *path, const unsigned char *data,
                          size_t length)
{
    int descriptor = open(path, O_WRONLY | O_TRUNC);
    size_t offset = 0;

    if (descriptor < 0) {
        return 0;
    }
    while (offset < length) {
        ssize_t written = write(descriptor, data + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            close(descriptor);
            return 0;
        }
    }
    return close(descriptor) == 0;
}

static void test_interrupted_secret(const char *program, const char *home)
{
    static const char partial_password[] = "partial-dummy-secret";
    struct transcript transcript = {{0}, 0, 0};
    struct termios terminal;
    int master = -1;
    int status = 0;
    pid_t child = start_program(program, home, &master);

    CHECK(child > 0);
    if (child <= 0) {
        return;
    }
    CHECK(wait_for_text(master, &transcript, "Choice: "));
    CHECK(write_all(master, "2\n"));
    CHECK(wait_for_text(master, &transcript, "Username: "));
    CHECK(write_all(master, "Alice\n"));
    CHECK(wait_for_text(master, &transcript, "Master password: "));
    CHECK(write_bytes(master, (const unsigned char *)partial_password,
                      sizeof(partial_password) - 1));
    CHECK(kill(child, SIGINT) == 0);
    CHECK(wait_for_exit(child, master, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 128 + SIGINT);
    CHECK(tcgetattr(master, &terminal) == 0);
    CHECK((terminal.c_lflag & ECHO) != 0);
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)partial_password,
                          sizeof(partial_password) - 1));
    close(master);
}

static void test_eof_at_secret(const char *program, const char *home)
{
    struct transcript transcript = {{0}, 0, 0};
    struct termios terminal;
    int master = -1;
    int status = 0;
    pid_t child = start_program(program, home, &master);

    CHECK(child > 0);
    if (child <= 0) {
        return;
    }
    CHECK(wait_for_text(master, &transcript, "Choice: "));
    CHECK(write_all(master, "2\n"));
    CHECK(wait_for_text(master, &transcript, "Username: "));
    CHECK(write_all(master, "Alice\n"));
    CHECK(wait_for_text(master, &transcript, "Master password: "));
    CHECK(write(master, "\004", 1) == 1);
    CHECK(wait_for_exit(child, master, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(tcgetattr(master, &terminal) == 0);
    CHECK((terminal.c_lflag & ECHO) != 0);
    close(master);
}

static void test_embedded_nul(const char *program, const char *home)
{
    static const unsigned char invalid_username[] = {
        'N', 'u', 'l', '\0', 'U', 's', 'e', 'r', '\n'
    };
    static const unsigned char invalid_password[] = {
        's', 'e', 'c', 'r', 'e', 't', '\0', 'x', '\n'
    };
    struct transcript transcript = {{0}, 0, 0};
    struct termios terminal;
    int master = -1;
    int status = 0;
    pid_t child = start_program(program, home, &master);

    CHECK(child > 0);
    if (child <= 0) {
        return;
    }
    CHECK(wait_for_text(master, &transcript, "Choice: "));
    CHECK(write_all(master, "1\n"));
    CHECK(wait_for_text(master, &transcript, "Username: "));
    CHECK(write_bytes(master, invalid_username, sizeof(invalid_username)));
    CHECK(wait_for_text(master, &transcript, "Invalid input."));
    CHECK(wait_for_text(master, &transcript, "Choice: "));
    CHECK(write_all(master, "1\n"));
    CHECK(wait_for_text(master, &transcript, "Username: "));
    CHECK(write_all(master, "NulUser\n"));
    CHECK(wait_for_text(master, &transcript, "Master password: "));
    CHECK(write_bytes(master, invalid_password, sizeof(invalid_password)));
    CHECK(wait_for_text(master, &transcript, "Invalid input."));
    CHECK(wait_for_text(master, &transcript, "Choice: "));
    CHECK(write_all(master, "3\n"));
    CHECK(wait_for_exit(child, master, &status));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(tcgetattr(master, &terminal) == 0);
    CHECK((terminal.c_lflag & ECHO) != 0);
    close(master);
}

static void test_registration_vault_failure(const char *program)
{
    static const char password[] = "dummy-incomplete-registration-password";
    static const char wrong_password[] = "dummy-incomplete-wrong-password";
    char home_template[TEST_PATH_BYTES];
    char securepm_path[TEST_PATH_BYTES] = {0};
    char vaults_path[TEST_PATH_BYTES] = {0};
    char vault_path[TEST_PATH_BYTES];
    char *home = make_temporary_home(home_template);
    struct transcript transcript = {{0}, 0, 0};
    int master = -1;
    int status = 0;
    int success = home != NULL;
    pid_t child = -1;

    CHECK(success);
    if (!success) {
        return;
    }
    child = start_program(program, home, &master);
    success = child > 0;
    CHECK(success);
    if (success) {
        success = wait_for_text(master, &transcript, "Choice: ");
        CHECK(success);
    }
    if (success) {
        success = make_path(securepm_path, home, ".securepm") &&
                  make_path(vaults_path, securepm_path, "vaults") &&
                  chmod(vaults_path, 0500) == 0;
        CHECK(success);
    }
    if (success) {
        success = write_all(master, "1\n") &&
                  wait_for_text(master, &transcript, "Username: ") &&
                  write_all(master, "Incomplete\n") &&
                  wait_for_text(master, &transcript, "Master password: ") &&
                  write_all(master,
                            "dummy-incomplete-registration-password\n") &&
                  wait_for_text(master, &transcript,
                                "Confirm master password: ") &&
                  write_all(master,
                            "dummy-incomplete-registration-password\n") &&
                  wait_for_text(master, &transcript,
                                "Registration is incomplete.");
        CHECK(success);
    }
    CHECK(vaults_path[0] != '\0' && chmod(vaults_path, 0700) == 0);
    if (success) {
        CHECK(!find_vault(home, vault_path));
        success = wait_for_text(master, &transcript, "Choice: ") &&
                  write_all(master, "1\n") &&
                  wait_for_text(master, &transcript, "Username: ") &&
                  write_all(master, "Incomplete\n") &&
                  wait_for_text(master, &transcript, "Master password: ") &&
                  write_all(master, "dummy-incomplete-wrong-password\n") &&
                  wait_for_text(master, &transcript,
                                "Confirm master password: ") &&
                  write_all(master, "dummy-incomplete-wrong-password\n") &&
                  wait_for_text(master, &transcript, "Registration failed.");
        CHECK(success);
    }
    if (success) {
        CHECK(!find_vault(home, vault_path));
        success = wait_for_text(master, &transcript, "Choice: ") &&
                  write_all(master, "1\n") &&
                  wait_for_text(master, &transcript, "Username: ") &&
                  write_all(master, "Incomplete\n") &&
                  wait_for_text(master, &transcript, "Master password: ") &&
                  write_all(master,
                            "dummy-incomplete-registration-password\n") &&
                  wait_for_text(master, &transcript,
                                "Confirm master password: ") &&
                  write_all(master,
                            "dummy-incomplete-registration-password\n") &&
                  wait_for_text(master, &transcript, "User created.") &&
                  wait_for_text(master, &transcript, "Choice: ") &&
                  write_all(master, "3\n") &&
                  wait_for_exit(child, master, &status) &&
                  WIFEXITED(status) && WEXITSTATUS(status) == 0;
        CHECK(success);
    }
    if (!success && child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
    }
    if (master >= 0) {
        close(master);
    }
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)password,
                          sizeof(password) - 1));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)wrong_password,
                          sizeof(wrong_password) - 1));
    CHECK(find_vault(home, vault_path));
    CHECK(remove_tree(home));
}

int main(int argc, char *argv[])
{
    static const char master_password[] = "dummy-master-password-42";
    static const char wrong_password[] = "dummy-wrong-password";
    static const char credential_password[] = "dummy-credential-secret-73";
    static const char updated_password[] = "updated-dummy-secret-91";
    static const char mismatch_password[] = "dummy-mismatch-password";
    static const struct dialog_step oversized_steps[] = {
        {"Choice: ", "1\n"},
        {"Username: ",
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"},
        {"Input too long.", NULL},
        {"Choice: ", "3\n"}
    };
    static const struct dialog_step register_steps[] = {
        {"Choice: ", "1\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-master-password-42\n"},
        {"Confirm master password: ", "dummy-master-password-42\n"},
        {"User created.", NULL},
        {"Choice: ", "3\n"}
    };
    static const struct dialog_step mismatch_steps[] = {
        {"Choice: ", "1\n"},
        {"Username: ", "Mismatch\n"},
        {"Master password: ", "dummy-mismatch-password\n"},
        {"Confirm master password: ", "different-dummy-password\n"},
        {"Master passwords do not match.", NULL},
        {"Choice: ", "3\n"}
    };
    static const struct dialog_step short_password_steps[] = {
        {"Choice: ", "1\n"},
        {"Username: ", "TooShort\n"},
        {"Master password: ", "short-pass1\n"},
        {"Confirm master password: ", "short-pass1\n"},
        {"Registration failed.", NULL},
        {"Choice: ", "3\n"}
    };
    static const struct dialog_step wrong_password_steps[] = {
        {"Choice: ", "2\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-wrong-password\n"},
        {"Login failed.", NULL},
        {"Choice: ", "2\n"},
        {"Username: ", "Missing\n"},
        {"Master password: ", "dummy-wrong-password\n"},
        {"Login failed.", NULL},
        {"Choice: ", "2\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-master-password-42\n"},
        {"Login successful.", NULL},
        {"Choice: ", "7\n"}
    };
    static const struct dialog_step add_steps[] = {
        {"Choice: ", "2\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-master-password-42\n"},
        {"Login successful.", NULL},
        {"Choice: ", "2\n"},
        {"No credentials.", NULL},
        {"Choice: ", "1\n"},
        {"Label: ", "Example\"},{\"event\":\"forged\n"},
        {"Credential username: ", "dummy-user\n"},
        {"Credential password: ", "dummy-credential-secret-73\n"},
        {"Notes (optional): ", "dummy notes\n"},
        {"Credential added.", NULL},
        {"Choice: ", "6\n"},
        {"Vault locked.", NULL},
        {"Choice: ", "3\n"}
    };
    static const struct dialog_step list_steps[] = {
        {"Choice: ", "2\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-master-password-42\n"},
        {"Login successful.", NULL},
        {"Choice: ", "2\n"},
        {"Label: Example\"},{\"event\":\"forged | Username: dummy-user", NULL},
        {"Choice: ", "7\n"}
    };
    static const struct dialog_step failed_vault_steps[] = {
        {"Choice: ", "2\n"},
        {"Username: ", "Alice\n"},
        {"Master password: ", "dummy-master-password-42\n"},
        {"Login failed.", NULL},
        {"Choice: ", "3\n"}
    };
    char home_template[TEST_PATH_BYTES];
    char vault_path[TEST_PATH_BYTES];
    char audit_path[TEST_PATH_BYTES];
    char *home;
    struct transcript transcript;
    struct stat vault_status;
    unsigned char *vault_data = NULL;
    unsigned char *after_failure = NULL;
    unsigned char *audit_data = NULL;
    size_t vault_length = 0;
    size_t after_failure_length = 0;
    size_t audit_length = 0;
    char record_id[TEST_RECORD_ID_BYTES * 2 + 2] = {0};
    char oversized_label[131];
    struct timespec throttle_start = {0};
    struct timespec throttle_end = {0};
    const char *program;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PROGRAM\n", argv[0]);
        return 1;
    }
    program = argv[1];
    home = make_temporary_home(home_template);
    CHECK(home != NULL);
    if (home == NULL) {
        return 1;
    }

    CHECK(run_dialog(program, home, oversized_steps,
                     sizeof(oversized_steps) / sizeof(oversized_steps[0]),
                     &transcript));
    test_embedded_nul(program, home);
    CHECK(run_dialog(program, home, mismatch_steps,
                     sizeof(mismatch_steps) / sizeof(mismatch_steps[0]),
                     &transcript));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)mismatch_password,
                          sizeof(mismatch_password) - 1));
    CHECK(run_dialog(program, home, short_password_steps,
                     sizeof(short_password_steps) /
                         sizeof(short_password_steps[0]),
                     &transcript));
    CHECK(run_dialog(program, home, register_steps,
                     sizeof(register_steps) / sizeof(register_steps[0]),
                     &transcript));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)master_password,
                          sizeof(master_password) - 1));
    CHECK(find_vault(home, vault_path));
    CHECK(stat(vault_path, &vault_status) == 0);
    CHECK(S_ISREG(vault_status.st_mode));
    CHECK((vault_status.st_mode & 07777) == 0600);

    CHECK(clock_gettime(CLOCK_MONOTONIC, &throttle_start) == 0);
    CHECK(run_dialog(program, home, wrong_password_steps,
                     sizeof(wrong_password_steps) /
                         sizeof(wrong_password_steps[0]),
                     &transcript));
    CHECK(clock_gettime(CLOCK_MONOTONIC, &throttle_end) == 0);
    CHECK(elapsed_milliseconds(&throttle_start, &throttle_end) >= 1400);
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)wrong_password,
                          sizeof(wrong_password) - 1));

    memset(oversized_label, 'A', sizeof(oversized_label) - 2);
    oversized_label[sizeof(oversized_label) - 2] = '\n';
    oversized_label[sizeof(oversized_label) - 1] = '\0';
    {
        const struct dialog_step failed_add_steps[] = {
            {"Choice: ", "2\n"},
            {"Username: ", "Alice\n"},
            {"Master password: ", "dummy-master-password-42\n"},
            {"Login successful.", NULL},
            {"Choice: ", "1\n"},
            {"Label: ", oversized_label},
            {"Input too long.", NULL},
            {"Choice: ", "7\n"}
        };

        CHECK(run_dialog(program, home, failed_add_steps,
                         sizeof(failed_add_steps) /
                             sizeof(failed_add_steps[0]),
                         &transcript));
    }

    CHECK(run_dialog(program, home, add_steps,
                     sizeof(add_steps) / sizeof(add_steps[0]), &transcript));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)master_password,
                          sizeof(master_password) - 1));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)credential_password,
                          sizeof(credential_password) - 1));

    CHECK(run_dialog(program, home, list_steps,
                     sizeof(list_steps) / sizeof(list_steps[0]), &transcript));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)master_password,
                          sizeof(master_password) - 1));
    CHECK(!contains_bytes(transcript.data, transcript.length,
                          (const unsigned char *)credential_password,
                          sizeof(credential_password) - 1));
    CHECK(extract_record_id(&transcript, record_id));

    if (record_id[0] != '\0') {
        static const char missing_id[] =
            "00000000000000000000000000000000\n";
        const struct dialog_step view_steps[] = {
            {"Choice: ", "2\n"},
            {"Username: ", "Alice\n"},
            {"Master password: ", "dummy-master-password-42\n"},
            {"Login successful.", NULL},
            {"Choice: ", "3\n"},
            {"Record ID: ", "bad-id\n"},
            {"Invalid record ID.", NULL},
            {"Choice: ", "3\n"},
            {"Record ID: ", missing_id},
            {"Credential not found.", NULL},
            {"Choice: ", "4\n"},
            {"Record ID: ", missing_id},
            {"Credential not found.", NULL},
            {"Choice: ", "5\n"},
            {"Record ID: ", missing_id},
            {"Credential not found.", NULL},
            {"Choice: ", "3\n"},
            {"Record ID: ", record_id},
            {"Label: Example\"},{\"event\":\"forged", NULL},
            {"Username: dummy-user", NULL},
            {"Notes: dummy notes", NULL},
            {"Password: hidden", NULL},
            {"Warning: revealed passwords may remain visible in terminal "
             "output.", NULL},
            {"Type yes to reveal password: ", "no\n"},
            {"Password remains hidden.", NULL},
            {"Choice: ", "7\n"}
        };

        CHECK(run_dialog(program, home, view_steps,
                         sizeof(view_steps) / sizeof(view_steps[0]),
                         &transcript));
        CHECK(!contains_bytes(transcript.data, transcript.length,
                              (const unsigned char *)credential_password,
                              sizeof(credential_password) - 1));

        {
            const struct dialog_step failed_update_steps[] = {
                {"Choice: ", "2\n"},
                {"Username: ", "Alice\n"},
                {"Master password: ", "dummy-master-password-42\n"},
                {"Login successful.", NULL},
                {"Choice: ", "4\n"},
                {"Record ID: ", record_id},
                {"New label: ", oversized_label},
                {"Input too long.", NULL},
                {"Choice: ", "2\n"},
                {"Label: Example\"},{\"event\":\"forged | Username: dummy-user", NULL},
                {"Choice: ", "7\n"}
            };

            CHECK(run_dialog(program, home, failed_update_steps,
                             sizeof(failed_update_steps) /
                                 sizeof(failed_update_steps[0]),
                             &transcript));
        }
        {
            const struct dialog_step update_steps[] = {
                {"Choice: ", "2\n"},
                {"Username: ", "Alice\n"},
                {"Master password: ", "dummy-master-password-42\n"},
                {"Login successful.", NULL},
                {"Choice: ", "4\n"},
                {"Record ID: ", record_id},
                {"New label: ", "Updated Service\n"},
                {"New credential username: ", "updated-user\n"},
                {"New credential password: ",
                 "updated-dummy-secret-91\n"},
                {"New notes (optional): ", "updated notes\n"},
                {"Credential updated.", NULL},
                {"Choice: ", "6\n"},
                {"Vault locked.", NULL},
                {"Choice: ", "3\n"}
            };

            CHECK(run_dialog(program, home, update_steps,
                             sizeof(update_steps) / sizeof(update_steps[0]),
                             &transcript));
            CHECK(!contains_bytes(transcript.data, transcript.length,
                                  (const unsigned char *)updated_password,
                                  sizeof(updated_password) - 1));
        }
        {
            const struct dialog_step persisted_update_steps[] = {
                {"Choice: ", "2\n"},
                {"Username: ", "Alice\n"},
                {"Master password: ", "dummy-master-password-42\n"},
                {"Login successful.", NULL},
                {"Choice: ", "2\n"},
                {"Label: Updated Service | Username: updated-user", NULL},
                {"Choice: ", "3\n"},
                {"Record ID: ", record_id},
                {"Notes: updated notes", NULL},
                {"Password: hidden", NULL},
                {"Warning: revealed passwords may remain visible in terminal "
                 "output.", NULL},
                {"Type yes to reveal password: ", "yes\n"},
                {"Password: updated-dummy-secret-91", NULL},
                {"Choice: ", "7\n"}
            };

            CHECK(run_dialog(program, home, persisted_update_steps,
                             sizeof(persisted_update_steps) /
                                 sizeof(persisted_update_steps[0]),
                             &transcript));
            CHECK(!contains_bytes(transcript.data, transcript.length,
                                  (const unsigned char *)credential_password,
                                  sizeof(credential_password) - 1));
            CHECK(contains_bytes(transcript.data, transcript.length,
                                 (const unsigned char *)updated_password,
                                 sizeof(updated_password) - 1));
        }
        {
            const struct dialog_step delete_steps[] = {
                {"Choice: ", "2\n"},
                {"Username: ", "Alice\n"},
                {"Master password: ", "dummy-master-password-42\n"},
                {"Login successful.", NULL},
                {"Choice: ", "5\n"},
                {"Record ID: ", record_id},
                {"Type yes to confirm deletion: ", "no\n"},
                {"Deletion cancelled.", NULL},
                {"Choice: ", "2\n"},
                {"Label: Updated Service | Username: updated-user", NULL},
                {"Choice: ", "5\n"},
                {"Record ID: ", record_id},
                {"Type yes to confirm deletion: ", "yes\n"},
                {"Credential deleted.", NULL},
                {"Choice: ", "6\n"},
                {"Vault locked.", NULL},
                {"Choice: ", "3\n"}
            };
            static const struct dialog_step persisted_delete_steps[] = {
                {"Choice: ", "2\n"},
                {"Username: ", "Alice\n"},
                {"Master password: ", "dummy-master-password-42\n"},
                {"Login successful.", NULL},
                {"Choice: ", "2\n"},
                {"No credentials.", NULL},
                {"Choice: ", "7\n"}
            };

            CHECK(run_dialog(program, home, delete_steps,
                             sizeof(delete_steps) / sizeof(delete_steps[0]),
                             &transcript));
            CHECK(run_dialog(program, home, persisted_delete_steps,
                             sizeof(persisted_delete_steps) /
                                 sizeof(persisted_delete_steps[0]),
                             &transcript));
            CHECK(!contains_bytes(transcript.data, transcript.length,
                                  (const unsigned char *)updated_password,
                                  sizeof(updated_password) - 1));
        }
    }

    CHECK(make_path(audit_path, home, ".securepm/audit.log"));
    CHECK(chmod(audit_path, 0400) == 0);
    {
        static const struct dialog_step audit_failure_steps[] = {
            {"Choice: ", "2\n"},
            {"Username: ", "Alice\n"},
            {"Master password: ", "dummy-master-password-42\n"},
            {"Warning: security audit event could not be recorded.", NULL},
            {"Login successful.", NULL},
            {"Choice: ", "2\n"},
            {"No credentials.", NULL},
            {"Choice: ", "7\n"}
        };

        CHECK(run_dialog(program, home, audit_failure_steps,
                         sizeof(audit_failure_steps) /
                             sizeof(audit_failure_steps[0]),
                         &transcript));
    }
    CHECK(chmod(audit_path, 0600) == 0);

    vault_data = read_file(vault_path, &vault_length);
    CHECK(vault_data != NULL && vault_length != 0);
    if (vault_data != NULL && vault_length != 0) {
        CHECK(!contains_bytes(vault_data, vault_length,
                              (const unsigned char *)credential_password,
                              sizeof(credential_password) - 1));
        vault_data[vault_length - 1] ^= 1;
        CHECK(overwrite_file(vault_path, vault_data, vault_length));
        CHECK(run_dialog(program, home, failed_vault_steps,
                         sizeof(failed_vault_steps) /
                             sizeof(failed_vault_steps[0]),
                         &transcript));
        after_failure = read_file(vault_path, &after_failure_length);
        CHECK(after_failure != NULL);
        CHECK(after_failure_length == vault_length);
        if (after_failure != NULL && after_failure_length == vault_length) {
            CHECK(memcmp(after_failure, vault_data, vault_length) == 0);
        }
        free(after_failure);
        after_failure = NULL;
        CHECK(unlink(vault_path) == 0);
        CHECK(run_dialog(program, home, failed_vault_steps,
                         sizeof(failed_vault_steps) /
                             sizeof(failed_vault_steps[0]),
                         &transcript));
        CHECK(lstat(vault_path, &vault_status) != 0 && errno == ENOENT);
    }
    free(vault_data);
    test_interrupted_secret(program, home);
    test_eof_at_secret(program, home);
    audit_data = read_file(audit_path, &audit_length);
    CHECK(audit_data != NULL && audit_length != 0);
    if (audit_data != NULL) {
        static const char *const required_events[] = {
            "\"event\":\"user_registration\",\"outcome\":\"success\"",
            "\"event\":\"user_registration\",\"outcome\":\"failure\"",
            "\"event\":\"login\",\"outcome\":\"success\"",
            "\"event\":\"login\",\"outcome\":\"failure\"",
            "\"event\":\"vault_load\",\"outcome\":\"failure\"",
            "\"event\":\"credential_create\",\"outcome\":\"success\"",
            "\"event\":\"credential_create\",\"outcome\":\"failure\"",
            "\"event\":\"credential_update\",\"outcome\":\"success\"",
            "\"event\":\"credential_update\",\"outcome\":\"failure\"",
            "\"event\":\"credential_delete\",\"outcome\":\"success\"",
            "\"event\":\"credential_delete\",\"outcome\":\"failure\"",
            "\"event\":\"credential_delete\",\"outcome\":\"cancelled\"",
            "\"event\":\"password_reveal\",\"outcome\":\"success\"",
            "\"event\":\"password_reveal\",\"outcome\":\"cancelled\"",
            "\"event\":\"session_lock\",\"outcome\":\"success\""
        };
        static const char *const forbidden_values[] = {
            master_password, wrong_password, credential_password,
            updated_password, "Alice", "dummy-user", "updated-user",
            "dummy notes", "updated notes", "\"event\":\"forged"
        };

        for (size_t index = 0;
             index < sizeof(required_events) / sizeof(required_events[0]);
             ++index) {
            CHECK(count_text(audit_data, audit_length,
                             required_events[index]) != 0);
        }
        for (size_t index = 0;
             index < sizeof(forbidden_values) / sizeof(forbidden_values[0]);
             ++index) {
            CHECK(!contains_bytes(audit_data, audit_length,
                                  (const unsigned char *)forbidden_values[index],
                                  strlen(forbidden_values[index])));
        }
        if (record_id[0] != '\0') {
            CHECK(!contains_bytes(audit_data, audit_length,
                                  (const unsigned char *)record_id,
                                  TEST_RECORD_ID_BYTES * 2));
        }
    }
    free(audit_data);
    CHECK(remove_tree(home));
    test_registration_vault_failure(program);

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u interactive CLI checks\n",
                failures, checks);
        return 1;
    }
    printf("PASS: %u interactive CLI checks\n", checks);
    return 0;
}
