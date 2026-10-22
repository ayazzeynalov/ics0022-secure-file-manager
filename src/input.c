#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "input.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted_signal;
static struct termios saved_terminal;
static int terminal_fd = -1;
static int terminal_saved;

static void handle_signal(int signal_number)
{
    interrupted_signal = signal_number;
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
    interrupted_signal = 0;
    if (atexit(input_cleanup) != 0 ||
        !install_handler(SIGINT) ||
        !install_handler(SIGTERM) ||
        !install_handler(SIGHUP) ||
        !install_handler(SIGQUIT)) {
        return 0;
    }
    return 1;
}

static int restore_terminal(void)
{
    int result;

    if (terminal_saved) {
        do {
            result = tcsetattr(terminal_fd, TCSANOW, &saved_terminal);
        } while (result != 0 && errno == EINTR);
        if (result == 0) {
            terminal_saved = 0;
            terminal_fd = -1;
        }
        return result == 0;
    }
    return 1;
}

void input_cleanup(void)
{
    (void)restore_terminal();
}

static int discard_remainder(void)
{
    int byte;

    do {
        errno = 0;
        byte = fgetc(stdin);
        if (byte == EOF && ferror(stdin) && errno == EINTR) {
            clearerr(stdin);
            return INPUT_READ_INTERRUPTED;
        }
    } while (byte != '\n' && byte != EOF);
    return interrupted_signal == 0 ? INPUT_READ_TOO_LONG :
                                     INPUT_READ_INTERRUPTED;
}

static int read_line(const char *prompt, char *buffer, size_t capacity,
                     size_t *length)
{
    size_t used;
    int next;

    if (prompt == NULL || buffer == NULL || capacity < 2 || length == NULL ||
        capacity > INT_MAX) {
        errno = EINVAL;
        return INPUT_READ_ERROR;
    }
    buffer[0] = '\0';
    *length = 0;
    if (interrupted_signal != 0) {
        return INPUT_READ_INTERRUPTED;
    }
    if (fputs(prompt, stdout) == EOF || fflush(stdout) == EOF) {
        return INPUT_READ_ERROR;
    }
    errno = 0;
    if (fgets(buffer, (int)capacity, stdin) == NULL) {
        if (interrupted_signal != 0 || (ferror(stdin) && errno == EINTR)) {
            clearerr(stdin);
            return INPUT_READ_INTERRUPTED;
        }
        return feof(stdin) ? INPUT_READ_EOF : INPUT_READ_ERROR;
    }
    used = strlen(buffer);
    if (used != 0 && buffer[used - 1] == '\n') {
        buffer[--used] = '\0';
        if (used != 0 && buffer[used - 1] == '\r') {
            buffer[--used] = '\0';
        }
        *length = used;
        return INPUT_READ_OK;
    }
    if (used < capacity - 1) {
        *length = used;
        return INPUT_READ_OK;
    }
    errno = 0;
    next = fgetc(stdin);
    if (next == '\n' || next == EOF) {
        if (next == EOF && ferror(stdin)) {
            if (errno == EINTR || interrupted_signal != 0) {
                clearerr(stdin);
                return INPUT_READ_INTERRUPTED;
            }
            return INPUT_READ_ERROR;
        }
        *length = used;
        return INPUT_READ_OK;
    }
    return discard_remainder();
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

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &saved_terminal) != 0) {
        errno = ENOTTY;
        return INPUT_READ_ERROR;
    }
    hidden = saved_terminal;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    terminal_fd = STDIN_FILENO;
    terminal_saved = 1;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        terminal_saved = 0;
        terminal_fd = -1;
        return INPUT_READ_ERROR;
    }
    result = read_line(prompt, buffer, capacity, length);
    restore_result = restore_terminal();
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
    if (!restore_result && result == INPUT_READ_OK) {
        return INPUT_READ_ERROR;
    }
    return result;
}

int input_interrupted_signal(void)
{
    return (int)interrupted_signal;
}
