#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif
#include "clipboard.h"
#include "credentials.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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

int clipboard_copy(const unsigned char *password, size_t length)
{
    int sockets[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int initialized = 0;
    int sent, success = 0;
#ifdef SECUREPM_CLIPBOARD_TEST
    char *args[] = {"./build/test_clipboard_sink", NULL};
#elif defined(__APPLE__)
    char *args[] = {"/usr/bin/pbcopy", NULL};
#else
    char *wayland[] = {"/usr/bin/wl-copy", "--type", "text/plain", NULL};
    char *x11[] = {"/usr/bin/xclip", "-selection", "clipboard", "-in", NULL};
    char **args = NULL;
    if (getenv("WAYLAND_DISPLAY") != NULL && access(wayland[0], X_OK) == 0) {
        args = wayland;
    } else if (getenv("DISPLAY") != NULL && access(x11[0], X_OK) == 0) {
        args = x11;
    }
    if (args == NULL) {
        return 0;
    }
#endif
    if (password == NULL || length > CREDENTIALS_PASSWORD_MAX_BYTES ||
        memchr(password, 0, length) != NULL) {
        return 0;
    }
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
