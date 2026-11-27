/* Test-only helper: simulated clipboard for dummy bytes, never the OS clipboard. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    const char *expected = getenv("SECUREPM_TEST_CLIPBOARD_EXPECTED");
    const char *path = getenv("SECUREPM_TEST_CLIPBOARD_FILE");
    unsigned char data[1025];
    size_t used = 0;
    FILE *stream;
    if (argc != 2 || expected == NULL) return 1;
    if (strcmp(argv[1], "read") == 0) {
        if (path == NULL) return fputs(expected, stdout) == EOF;
        stream = fopen(path, "rb");
        if (stream == NULL) return 1;
        used = fread(data, 1, sizeof(data), stream);
        int ok = !ferror(stream) && fwrite(data, 1, used, stdout) == used;
        if (fclose(stream) != 0) ok = 0;
        return !ok;
    }
    if (strcmp(argv[1], "clear") == 0) {
        if (path == NULL) return 0;
        stream = fopen(path, "wb");
        return stream == NULL || fclose(stream) != 0;
    }
    if (strcmp(argv[1], "copy") != 0) return 1;
    while (used < sizeof(data)) {
        ssize_t n = read(STDIN_FILENO, data + used, sizeof(data) - used);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        used += (size_t)n;
    }
    if (used >= sizeof(data) || used != strlen(expected) ||
        memcmp(data, expected, used) != 0) return 1;
    if (path == NULL) return 0;
    stream = fopen(path, "wb");
    if (stream == NULL) return 1;
    int ok = fwrite(data, 1, used, stream) == used;
    if (fclose(stream) != 0) ok = 0;
    return !ok;
}
