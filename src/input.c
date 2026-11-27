#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "input.h"
#include "clipboard.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <openssl/crypto.h>

static volatile sig_atomic_t interrupted_signal;
static struct termios application_terminal;
static struct termios secret_terminal;
static int application_terminal_fd = -1;
static int secret_terminal_fd = -1;
static int application_terminal_saved;
static int secret_terminal_saved;
static int signal_pipe[2] = {-1, -1};
static volatile sig_atomic_t signal_pipe_write_fd = -1;
static int cleanup_registered;

static void handle_signal(int signal_number)
{
    int saved_errno = errno;
    int wakeup_fd = (int)signal_pipe_write_fd;
    unsigned char byte = (unsigned char)signal_number;

    interrupted_signal = signal_number;
    if (wakeup_fd >= 0) {
        (void)write(wakeup_fd, &byte, 1);
    }
    errno = saved_errno;
}

static void close_signal_pipe(void)
{
    signal_pipe_write_fd = -1;
    if (signal_pipe[0] >= 0) {
        (void)close(signal_pipe[0]);
        signal_pipe[0] = -1;
    }
    if (signal_pipe[1] >= 0) {
        (void)close(signal_pipe[1]);
        signal_pipe[1] = -1;
    }
}

static int set_pipe_flags(int descriptor)
{
    int descriptor_flags = fcntl(descriptor, F_GETFD);
    int status_flags = fcntl(descriptor, F_GETFL);

    return descriptor_flags >= 0 && status_flags >= 0 &&
           fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0 &&
           fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) == 0;
}

static void drain_signal_pipe(void)
{
    unsigned char bytes[32];

    if (signal_pipe[0] < 0) {
        return;
    }
    while (read(signal_pipe[0], bytes, sizeof(bytes)) > 0) {
    }
}

static int initialize_signal_pipe(void)
{
    if (signal_pipe[0] >= 0 && signal_pipe[1] >= 0) {
        drain_signal_pipe();
        return 1;
    }
    if (pipe(signal_pipe) != 0 || !set_pipe_flags(signal_pipe[0]) ||
        !set_pipe_flags(signal_pipe[1])) {
        close_signal_pipe();
        return 0;
    }
    signal_pipe_write_fd = signal_pipe[1];
    return 1;
}

static int install_handler(int signal_number)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    if (sigemptyset(&action.sa_mask) != 0) {
        return 0;
    }
    return sigaction(signal_number, &action, NULL) == 0;
}

int input_initialize(void)
{
    struct termios controlled;

    interrupted_signal = 0;
    if (!initialize_signal_pipe() ||
        (!cleanup_registered && atexit(input_cleanup) != 0) ||
        !install_handler(SIGINT) ||
        !install_handler(SIGTERM) ||
        !install_handler(SIGHUP) ||
        !install_handler(SIGQUIT) ||
        !install_handler(SIGTSTP)) {
        return 0;
    }
    cleanup_registered = 1;
    if (isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &application_terminal) != 0) {
            return 0;
        }
        controlled = application_terminal;
        controlled.c_iflag &= (tcflag_t)~(IXON | IXOFF);
#ifdef IXANY
        controlled.c_iflag &= (tcflag_t)~IXANY;
#endif
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &controlled) != 0) {
            return 0;
        }
        application_terminal_fd = STDIN_FILENO;
        application_terminal_saved = 1;
    }
    return 1;
}

static int restore_secret_terminal(void)
{
    int result;

    if (secret_terminal_saved) {
        do {
            result = tcsetattr(secret_terminal_fd, TCSAFLUSH,
                               &secret_terminal);
        } while (result != 0 && errno == EINTR);
        if (result == 0) {
            secret_terminal_saved = 0;
            secret_terminal_fd = -1;
        }
        return result == 0;
    }
    return 1;
}

static int restore_application_terminal(void)
{
    int result;

    if (!application_terminal_saved) {
        return 1;
    }
    do {
        result = tcsetattr(application_terminal_fd, TCSAFLUSH,
                           &application_terminal);
    } while (result != 0 && errno == EINTR);
    if (result == 0) {
        application_terminal_saved = 0;
        application_terminal_fd = -1;
    }
    return result == 0;
}

void input_cleanup(void)
{
    (void)restore_secret_terminal();
    (void)restore_application_terminal();
    close_signal_pipe();
}

static void clear_input(char *buffer, size_t capacity, size_t *length)
{
    if (length != NULL) {
        *length = 0;
    }
    if (buffer != NULL && capacity != 0 && capacity <= INT_MAX) {
        OPENSSL_cleanse(buffer, capacity);
    }
}

static int valid_input_arguments(const char *prompt, const char *buffer,
                                 size_t capacity, const size_t *length)
{
    return prompt != NULL && buffer != NULL && capacity >= 2 &&
           capacity <= INT_MAX && length != NULL;
}

static int wait_for_input(void)
{
    struct pollfd descriptors[2];

    descriptors[0].fd = STDIN_FILENO;
    descriptors[0].events = POLLIN;
    descriptors[1].fd = signal_pipe[0];
    descriptors[1].events = POLLIN;
    while (1) {
        int result;

        if (interrupted_signal != 0) {
            return 0;
        }
        descriptors[0].revents = 0;
        descriptors[1].revents = 0;
        clipboard_service();
        result = poll(descriptors, 2, clipboard_poll_timeout());
        if (result < 0) {
            int saved_errno = errno;
            clipboard_service();
            errno = saved_errno;
        } else {
            clipboard_service();
        }
        if (result == 0) continue;
        if (result < 0) {
            if (errno == EINTR) {
                if (interrupted_signal != 0) {
                    return 0;
                }
                continue;
            }
            return -1;
        }
        if ((descriptors[1].revents & POLLIN) != 0) {
            drain_signal_pipe();
        }
        if (interrupted_signal != 0) {
            return 0;
        }
        if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            return 1;
        }
        if ((descriptors[0].revents & POLLNVAL) != 0 ||
            (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            errno = EBADF;
            return -1;
        }
    }
}

static int read_line(const char *prompt, char *buffer, size_t capacity,
                     size_t *length)
{
    size_t used = 0;
    int invalid = 0;
    int too_long = 0;
    int received_input = 0;

    clear_input(buffer, capacity, length);
    if (!valid_input_arguments(prompt, buffer, capacity, length)) {
        errno = EINVAL;
        return INPUT_READ_ERROR;
    }
    if (interrupted_signal != 0) {
        return INPUT_READ_INTERRUPTED;
    }
    if (fputs(prompt, stdout) == EOF || fflush(stdout) == EOF) {
        return INPUT_READ_ERROR;
    }
    while (1) {
        unsigned char byte;
        ssize_t count;
        int wait_result;

        wait_result = wait_for_input();
        if (wait_result <= 0) {
            clear_input(buffer, capacity, length);
            return wait_result == 0 ? INPUT_READ_INTERRUPTED :
                                      INPUT_READ_ERROR;
        }
        count = read(STDIN_FILENO, &byte, 1);
        if (interrupted_signal != 0) {
            clear_input(buffer, capacity, length);
            return INPUT_READ_INTERRUPTED;
        }
        if (count == 0) {
            if (!received_input) {
                return INPUT_READ_EOF;
            }
            break;
        }
        if (count < 0) {
            if (errno == EINTR && interrupted_signal == 0) {
                continue;
            }
            clear_input(buffer, capacity, length);
            return interrupted_signal != 0 ? INPUT_READ_INTERRUPTED :
                                             INPUT_READ_ERROR;
        }
        received_input = 1;
        if (byte == '\n') {
            break;
        }
        if (byte == '\0') {
            invalid = 1;
            continue;
        }
        if (used < capacity - 1) {
            buffer[used++] = (char)(unsigned char)byte;
        } else {
            too_long = 1;
        }
    }
    if (used != 0 && buffer[used - 1] == '\r') {
        --used;
    }
    buffer[used] = '\0';
    if (invalid || too_long) {
        clear_input(buffer, capacity, length);
        return invalid ? INPUT_READ_INVALID : INPUT_READ_TOO_LONG;
    }
    if (interrupted_signal != 0) {
        clear_input(buffer, capacity, length);
        return INPUT_READ_INTERRUPTED;
    }
    *length = used;
    return INPUT_READ_OK;
}

int input_read_line(const char *prompt, char *buffer, size_t capacity,
                    size_t *length)
{
    return read_line(prompt, buffer, capacity, length);
}

int input_read_secret(const char *prompt, char *buffer, size_t capacity,
                      size_t *length)
{
    struct termios hidden;
    int result;
    int restore_result;

    clear_input(buffer, capacity, length);
    if (!valid_input_arguments(prompt, buffer, capacity, length)) {
        errno = EINVAL;
        return INPUT_READ_ERROR;
    }
    if (!isatty(STDIN_FILENO) ||
        tcgetattr(STDIN_FILENO, &secret_terminal) != 0) {
        errno = ENOTTY;
        return INPUT_READ_ERROR;
    }
    hidden = secret_terminal;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    secret_terminal_fd = STDIN_FILENO;
    secret_terminal_saved = 1;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        secret_terminal_saved = 0;
        secret_terminal_fd = -1;
        return INPUT_READ_ERROR;
    }
    result = read_line(prompt, buffer, capacity, length);
    restore_result = restore_secret_terminal();
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    if (!restore_result && result == INPUT_READ_OK) {
        clear_input(buffer, capacity, length);
        return INPUT_READ_ERROR;
    }
    return result;
}

int input_discard_pending(void)
{
    int result;

    if (!isatty(STDIN_FILENO) || interrupted_signal != 0) {
        errno = interrupted_signal != 0 ? EINTR : ENOTTY;
        return 0;
    }
    do {
        result = tcflush(STDIN_FILENO, TCIFLUSH);
    } while (result != 0 && errno == EINTR && interrupted_signal == 0);
    return result == 0;
}

int input_interrupted_signal(void)
{
    return (int)interrupted_signal;
}
