#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "input.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        ++failures; \
        fprintf(stderr, "FAIL %s:%d: %s\n", \
                __FILE__, __LINE__, #condition); \
    } \
} while (0)

static int all_zero(const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;

    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] != 0) {
            return 0;
        }
    }
    return 1;
}

static int replace_stdin(const unsigned char *data, size_t data_length,
                         int *saved_stdin)
{
    int descriptors[2] = {-1, -1};
    size_t offset = 0;

    *saved_stdin = dup(STDIN_FILENO);
    if (*saved_stdin < 0 || pipe(descriptors) != 0) {
        return 0;
    }
    while (offset < data_length) {
        ssize_t written = write(descriptors[1], data + offset,
                                data_length - offset);

        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            close(descriptors[0]);
            close(descriptors[1]);
            return 0;
        }
    }
    if (close(descriptors[1]) != 0 ||
        dup2(descriptors[0], STDIN_FILENO) < 0) {
        close(descriptors[0]);
        return 0;
    }
    close(descriptors[0]);
    return 1;
}

static int restore_stdin(int saved_stdin)
{
    int result = dup2(saved_stdin, STDIN_FILENO);

    close(saved_stdin);
    return result >= 0;
}

static void check_line_failure_clears(const unsigned char *input,
                                      size_t input_length,
                                      int expected_result)
{
    char buffer[5];
    size_t length = 99;
    int saved_stdin = -1;

    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(replace_stdin(input, input_length, &saved_stdin));
    if (saved_stdin < 0) {
        return;
    }
    CHECK(input_read_line("", buffer, sizeof(buffer), &length) ==
          expected_result);
    CHECK(length == 0);
    CHECK(all_zero(buffer, sizeof(buffer)));
    CHECK(restore_stdin(saved_stdin));
}

static void test_failed_line_reads(void)
{
    static const unsigned char too_long[] = "abcde\n";
    static const unsigned char embedded_nul[] = {'a', 0, 'b', '\n'};

    check_line_failure_clears(too_long, sizeof(too_long) - 1,
                              INPUT_READ_TOO_LONG);
    check_line_failure_clears(embedded_nul, sizeof(embedded_nul),
                              INPUT_READ_INVALID);
    check_line_failure_clears(NULL, 0, INPUT_READ_EOF);
}

static void check_successful_line(const unsigned char *input,
                                  size_t input_length,
                                  const char *expected, size_t expected_length)
{
    char buffer[5];
    size_t length = 99;
    int saved_stdin = -1;

    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(replace_stdin(input, input_length, &saved_stdin));
    if (saved_stdin < 0) {
        return;
    }
    CHECK(input_read_line("", buffer, sizeof(buffer), &length) ==
          INPUT_READ_OK);
    CHECK(length == expected_length);
    CHECK(memcmp(buffer, expected, expected_length) == 0);
    CHECK(buffer[expected_length] == '\0');
    CHECK(restore_stdin(saved_stdin));
}

static void test_successful_line_boundaries(void)
{
    static const unsigned char maximum[] = "abcd\n";
    static const unsigned char empty[] = "\n";
    static const unsigned char crlf[] = "abc\r\n";
    static const unsigned char partial_eof[] = "xy";

    check_successful_line(maximum, sizeof(maximum) - 1, "abcd", 4);
    check_successful_line(empty, sizeof(empty) - 1, "", 0);
    check_successful_line(crlf, sizeof(crlf) - 1, "abc", 3);
    check_successful_line(partial_eof, sizeof(partial_eof) - 1, "xy", 2);
}

static void test_descriptor_error_clears(void)
{
    char buffer[8];
    size_t length = 99;
    int saved_stdin = dup(STDIN_FILENO);

    CHECK(saved_stdin >= 0);
    if (saved_stdin < 0) {
        return;
    }
    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(close(STDIN_FILENO) == 0);
    CHECK(input_read_line("", buffer, sizeof(buffer), &length) ==
          INPUT_READ_ERROR);
    CHECK(length == 0);
    CHECK(all_zero(buffer, sizeof(buffer)));
    CHECK(restore_stdin(saved_stdin));
}

static void test_nonterminal_secret_failure(void)
{
    char buffer[16];
    size_t length = 99;
    int saved_stdin = -1;

    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(replace_stdin(NULL, 0, &saved_stdin));
    if (saved_stdin < 0) {
        return;
    }
    CHECK(input_read_secret("", buffer, sizeof(buffer), &length) ==
          INPUT_READ_ERROR);
    CHECK(length == 0);
    CHECK(all_zero(buffer, sizeof(buffer)));
    CHECK(restore_stdin(saved_stdin));
}

static void test_invalid_arguments_clear(void)
{
    char buffer[8];
    size_t length = 99;

    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(input_read_line(NULL, buffer, sizeof(buffer), &length) ==
          INPUT_READ_ERROR);
    CHECK(length == 0);
    CHECK(all_zero(buffer, sizeof(buffer)));
}

static void test_interruption_clears(void)
{
    char buffer[8];
    size_t length = 99;

    memset(buffer, 0xa5, sizeof(buffer));
    CHECK(input_initialize());
    CHECK(raise(SIGINT) == 0);
    CHECK(input_read_line("", buffer, sizeof(buffer), &length) ==
          INPUT_READ_INTERRUPTED);
    CHECK(length == 0);
    CHECK(all_zero(buffer, sizeof(buffer)));
}

int main(void)
{
    test_failed_line_reads();
    test_successful_line_boundaries();
    test_descriptor_error_clears();
    test_nonterminal_secret_failure();
    test_invalid_arguments_clear();
    test_interruption_clears();

    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u input checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u input checks\n", checks);
    return 0;
}
