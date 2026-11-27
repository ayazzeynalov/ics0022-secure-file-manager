/* Test-only helper: checks dummy bytes from stdin without using a clipboard. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void)
{
    const char *expected = getenv("SECUREPM_TEST_CLIPBOARD_EXPECTED");
    unsigned char data[1025];
    size_t used = 0;
    if (expected == NULL) return 1;
    while (used < sizeof(data)) {
        ssize_t n = read(STDIN_FILENO, data + used, sizeof(data) - used);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        used += (size_t)n;
    }
    return used < sizeof(data) && used == strlen(expected) &&
           memcmp(data, expected, used) == 0 ? 0 : 1;
}
