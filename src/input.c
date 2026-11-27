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
#include <time.h>
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
static int session_timeout_seconds;
static int session_timed_out;
static struct timespec prompt_start;

void input_session_begin(void)
{
    session_timeout_seconds = 300;
    session_timed_out = 0;
#ifdef SECUREPM_INPUT_TEST
    const char *test_timeout = getenv("SECUREPM_TEST_IDLE_SECONDS");
    if (test_timeout != NULL && strcmp(test_timeout, "2") == 0) {
        session_timeout_seconds = 2;
    }
#endif
}

int input_session_end(void)
{
    int expired = session_timed_out;
    session_timeout_seconds = 0;
    session_timed_out = 0;
    return expired;
}

/* Activity is a submitted line, not individual keystrokes. Each
 * authenticated prompt has a fixed deadline. */
static int session_poll_timeout(void)
{
    struct timespec now;
    time_t seconds;
    long milliseconds;

    if (session_timeout_seconds == 0) return -1;
    if (session_timed_out || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < prompt_start.tv_sec) {
        session_timed_out = 1;
        return 0;
    }
    seconds = now.tv_sec - prompt_start.tv_sec;
    if (seconds > session_timeout_seconds) {
        session_timed_out = 1;
        return 0;
    }
    milliseconds = (long)(session_timeout_seconds - seconds) * 1000L +
                   (prompt_start.tv_nsec - now.tv_nsec) / 1000000L;
    if (milliseconds <= 0) {
        session_timed_out = 1;
        return 0;
    }
    return (int)milliseconds;
}

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
        int timeout;
        int clipboard_timeout;
        int poll_errno = 0;

        if (interrupted_signal != 0) {
            return 0;
        }
        descriptors[0].revents = 0;
        descriptors[1].revents = 0;
        clipboard_service();
        timeout = session_poll_timeout();
        if (session_timed_out) return 0;
        clipboard_timeout = clipboard_poll_timeout();
        if (clipboard_timeout >= 0 && (timeout < 0 || clipboard_timeout < timeout)) {
            timeout = clipboard_timeout;
        }
        result = poll(descriptors, 2, timeout);
        if (result < 0) {
            poll_errno = errno;
        }
        clipboard_service();
        if (session_poll_timeout() == 0) return 0;
        if (result == 0) continue;
        if (result < 0) {
            errno = poll_errno;
            if (poll_errno == EINTR) {
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
                     size_t *length, const struct termios *editing)
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
    if (session_timeout_seconds != 0 &&
        clock_gettime(CLOCK_MONOTONIC, &prompt_start) != 0) {
        session_timed_out = 1;
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
        /* Noncanonical input avoids silent truncation by the terminal's
         * canonical queue (notably on macOS). Keep the configured editing
         * characters while letting the kernel deliver interrupt signals. */
        if (editing != NULL) {
            if (editing->c_cc[VEOF] != _POSIX_VDISABLE &&
                byte == editing->c_cc[VEOF]) {
                clear_input(buffer, capacity, length);
                return INPUT_READ_EOF;
            }
            if (editing->c_cc[VKILL] != _POSIX_VDISABLE &&
                byte == editing->c_cc[VKILL]) {
                clear_input(buffer, capacity, length);
                used = 0;
                invalid = 0;
                too_long = 0;
                received_input = 0;
                continue;
            }
            if (editing->c_cc[VERASE] != _POSIX_VDISABLE &&
                byte == editing->c_cc[VERASE]) {
                /* Once oversized or invalid, reject the line unless the
                 * user explicitly clears it. Remove a UTF-8 code point
                 * rather than leaving a partial multibyte character. */
                if (used != 0 && !too_long && !invalid) {
                    size_t end = used;
                    do {
                        --used;
                    } while (used != 0 &&
                             ((unsigned char)buffer[used] & 0xc0U) == 0x80U);
                    OPENSSL_cleanse(buffer + used, end - used);
                }
                continue;
            }
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

static int read_terminal_line(const char *prompt, char *buffer,
                              size_t capacity, size_t *length, int secret)
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
    hidden.c_lflag &= (tcflag_t)~(ICANON | IEXTEN);
    if (secret) {
        hidden.c_lflag &= (tcflag_t)~(ECHO | ECHONL);
    }
    hidden.c_cc[VMIN] = 1;
    hidden.c_cc[VTIME] = 0;
    secret_terminal_fd = STDIN_FILENO;
    secret_terminal_saved = 1;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        secret_terminal_saved = 0;
        secret_terminal_fd = -1;
        return INPUT_READ_ERROR;
    }
    result = read_line(prompt, buffer, capacity, length, &secret_terminal);
    restore_result = restore_secret_terminal();
    if (secret || result == INPUT_READ_EOF || result == INPUT_READ_INTERRUPTED) {
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
    }
    if (!restore_result && result == INPUT_READ_OK) {
        clear_input(buffer, capacity, length);
        return INPUT_READ_ERROR;
    }
    return result;
}

int input_read_line(const char *prompt, char *buffer, size_t capacity,
                    size_t *length)
{
    /* Long public fields (notes) need the same untruncated byte input as
     * passwords. Short public fields retain normal terminal line editing. */
    if (capacity > 1024 && isatty(STDIN_FILENO)) {
        return read_terminal_line(prompt, buffer, capacity, length, 0);
    }
    return read_line(prompt, buffer, capacity, length, NULL);
}

int input_read_secret(const char *prompt, char *buffer, size_t capacity,
                      size_t *length)
{
    return read_terminal_line(prompt, buffer, capacity, length, 1);
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
