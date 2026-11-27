#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "clipboard.h"
#include "credentials.h"
#include "crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* The transport never places credential bytes in argv or the environment. */
static int send_secret(int fd, const unsigned char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
#ifdef __APPLE__
        ssize_t n = send(fd, data + sent, length - sent, 0);
#else
        ssize_t n = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
#endif
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int wait_for_helper(pid_t pid)
{
    struct timespec start, now;
    const struct timespec delay = {0, 10000000L};
    int status;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        goto stop;
    }
    for (;;) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (result < 0 && errno != EINTR) {
            return 0;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 5) {
            break;
        }
        (void)nanosleep(&delay, NULL);
    }
stop:
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return 0;
}

enum helper_operation { HELPER_COPY, HELPER_READ, HELPER_CLEAR };

/* Absolute paths in production; the test binary uses only its dummy helper. */
static char **helper_args(enum helper_operation operation)
{
#ifdef SECUREPM_CLIPBOARD_TEST
    static char *copy[] = {"./build/test_clipboard_sink", "copy", NULL};
    static char *readback[] = {"./build/test_clipboard_sink", "read", NULL};
    static char *clear[] = {"./build/test_clipboard_sink", "clear", NULL};
    return operation == HELPER_COPY ? copy : operation == HELPER_READ ? readback : clear;
#elif defined(__APPLE__)
    static char *copy[] = {"/usr/bin/pbcopy", NULL};
    static char *readback[] = {"/usr/bin/pbpaste", "-Prefer", "txt", NULL};
    return operation == HELPER_READ ? readback : copy;
#else
    static char *wayland[] = {"/usr/bin/wl-copy", "--type", "text/plain", NULL};
    static char *wayland_read[] = {"/usr/bin/wl-paste", "--no-newline", "--type", "text/plain", NULL};
    static char *wayland_clear[] = {"/usr/bin/wl-copy", "--clear", NULL};
    static char *x11[] = {"/usr/bin/xclip", "-selection", "clipboard", "-in", NULL};
    static char *x11_read[] = {"/usr/bin/xclip", "-selection", "clipboard", "-out", NULL};
    if (getenv("WAYLAND_DISPLAY") != NULL && access(wayland[0], X_OK) == 0 &&
        access(wayland_read[0], X_OK) == 0) {
        return operation == HELPER_COPY ? wayland : operation == HELPER_READ ? wayland_read : wayland_clear;
    }
    if (getenv("DISPLAY") != NULL && access(x11[0], X_OK) == 0) {
        return operation == HELPER_READ ? x11_read : x11;
    }
    return NULL;
#endif
}

static int helper_write(char **args, const unsigned char *password, size_t length)
{
    int sockets[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int initialized = 0;
    int sent, success = 0;
    if (args == NULL) return 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return 0;
    }
    if (sockets[0] <= STDERR_FILENO || sockets[1] <= STDERR_FILENO ||
        fcntl(sockets[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(sockets[1], F_SETFD, FD_CLOEXEC) < 0) {
        goto cleanup;
    }
#ifdef __APPLE__
    {
        int enabled = 1;
        if (setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE,
                       &enabled, sizeof(enabled)) != 0) {
            goto cleanup;
        }
    }
#endif
    if (posix_spawn_file_actions_init(&actions) != 0) {
        goto cleanup;
    }
    initialized = 1;
    if (posix_spawn_file_actions_adddup2(&actions, sockets[1], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&actions, sockets[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, sockets[1]) != 0 ||
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) != 0 ||
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) != 0 ||
        posix_spawn(&pid, args[0], &actions, NULL, args, environ) != 0) {
        goto cleanup;
    }
    close(sockets[1]);
    sockets[1] = -1;
    /* At most 1024 bytes are written into the local socket. */
    sent = send_secret(sockets[0], password, length);
    (void)shutdown(sockets[0], SHUT_WR);
    close(sockets[0]);
    sockets[0] = -1;
    success = wait_for_helper(pid) && sent;
cleanup:
    if (initialized) {
        posix_spawn_file_actions_destroy(&actions);
    }
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    return success;
}

/* Never read an unbounded clipboard into process memory or print its contents. */
static int helper_read(unsigned char *data, size_t capacity, size_t *length)
{
    int fds[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    int initialized = 0, success = 0, status;
    pid_t pid = -1, spawned;
    size_t used = 0;
    struct timespec start, now;
    char **args = helper_args(HELPER_READ);
    if (args == NULL || clock_gettime(CLOCK_MONOTONIC, &start) != 0 ||
        pipe(fds) != 0) return 0;
    if (fds[0] <= STDERR_FILENO || fds[1] <= STDERR_FILENO ||
        fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(fds[1], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0 ||
        posix_spawn_file_actions_init(&actions) != 0) goto cleanup;
    initialized = 1;
    if (posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&actions, fds[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, fds[1]) != 0 ||
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) != 0 ||
        posix_spawn(&spawned, args[0], &actions, NULL, args, environ) != 0) goto cleanup;
    pid = spawned;
    close(fds[1]);
    fds[1] = -1;
    for (;;) {
        struct pollfd descriptor = {fds[0], POLLIN, 0};
        ssize_t n;
        int result;
        int64_t elapsed;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) break;
        elapsed = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                  (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= 2000 || used == capacity) break;
        result = poll(&descriptor, 1, (int)(2000 - elapsed));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) break;
        n = read(fds[0], data + used, capacity - used);
        if (n > 0) used += (size_t)n;
        else if (n == 0) {
            success = wait_for_helper(pid);
            pid = -1;
            break;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) break;
    }
cleanup:
    if (pid > 0) {
        (void)kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }
    if (initialized) posix_spawn_file_actions_destroy(&actions);
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    if (success) *length = used;
    return success;
}

#ifdef SECUREPM_CLIPBOARD_TEST
#define CLIPBOARD_LIFETIME_SECONDS 2
#else
#define CLIPBOARD_LIFETIME_SECONDS 30
#endif

static struct {
    unsigned char key[32];
    unsigned char tag[32];
    size_t length;
    struct timespec deadline;
    int pending;
} clipboard_state;

static int clipboard_tag(const unsigned char *data, size_t length,
                         unsigned char tag[32])
{
    unsigned int tag_length = 0;
    return HMAC(EVP_sha256(), clipboard_state.key, sizeof(clipboard_state.key),
                data, length, tag, &tag_length) != NULL && tag_length == 32;
}

void clipboard_clear(void)
{
    unsigned char data[CREDENTIALS_PASSWORD_MAX_BYTES + 1] = {0};
    unsigned char tag[32] = {0};
    size_t length = 0;
    int matching = 0, read_ok;
    if (!clipboard_state.pending) return;
    read_ok = helper_read(data, sizeof(data), &length);
    if (read_ok &&
        length == clipboard_state.length && clipboard_tag(data, length, tag)) {
        matching = CRYPTO_memcmp(tag, clipboard_state.tag, sizeof(tag)) == 0;
    }
    OPENSSL_cleanse(data, sizeof(data));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(&clipboard_state, sizeof(clipboard_state));
    if (!read_ok || (matching && !helper_write(helper_args(HELPER_CLEAR), (const unsigned char *)"", 0))) {
        fputs("Warning: clipboard could not be cleared. Clear it manually.\n", stderr);
    }
}

/* -1 means no deadline; 0 means the pending value has expired. */
int clipboard_poll_timeout(void)
{
    struct timespec now;
    int64_t nanoseconds;
    if (!clipboard_state.pending) return -1;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    nanoseconds = (int64_t)(clipboard_state.deadline.tv_sec - now.tv_sec) * 1000000000 +
                  clipboard_state.deadline.tv_nsec - now.tv_nsec;
    if (nanoseconds <= 0) return 0;
    if (nanoseconds > (int64_t)CLIPBOARD_LIFETIME_SECONDS * 1000000000)
        return CLIPBOARD_LIFETIME_SECONDS * 1000;
    return (int)((nanoseconds + 999999) / 1000000);
}

void clipboard_service(void)
{
    if (clipboard_poll_timeout() == 0) clipboard_clear();
}

int clipboard_copy(const unsigned char *password, size_t length)
{
    if (password == NULL || length == 0 || length > CREDENTIALS_PASSWORD_MAX_BYTES ||
        memchr(password, 0, length) != NULL) return 0;
    clipboard_clear();
    if (!crypto_random(clipboard_state.key, sizeof(clipboard_state.key)) ||
        !clipboard_tag(password, length, clipboard_state.tag) ||
        clock_gettime(CLOCK_MONOTONIC, &clipboard_state.deadline) != 0 ||
        !helper_write(helper_args(HELPER_COPY), password, length)) {
        OPENSSL_cleanse(&clipboard_state, sizeof(clipboard_state));
        return 0;
    }
    clipboard_state.deadline.tv_sec += CLIPBOARD_LIFETIME_SECONDS;
    clipboard_state.length = length;
    clipboard_state.pending = 1;
    return 1;
}
