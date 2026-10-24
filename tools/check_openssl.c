#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>

#if OPENSSL_VERSION_MAJOR != 3
#error "securepm requires OpenSSL 3.x headers"
#endif

int main(void)
{
    if (OPENSSL_version_major() != 3) {
        fputs("securepm requires OpenSSL 3.x libraries\n", stderr);
        return 1;
    }

    return 0;
}
