#include "auth.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

static unsigned int checks;
static unsigned int failures;

#define CHECK(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static int all_value(const unsigned char *buffer, size_t length,
                     unsigned char value)
{
    for (size_t i = 0; i < length; ++i) {
        if (buffer[i] != value) {
            return 0;
        }
    }
    return 1;
}

static void test_verifier(void)
{
    unsigned char key[CRYPTO_KEY_BYTES];
    unsigned char wrong_key[CRYPTO_KEY_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES] = {0};
    const unsigned char expected[AUTH_VERIFIER_BYTES] = {
        0xab,0x91,0x34,0x03,0x84,0x34,0x88,0x9a,
        0xa6,0x93,0xd6,0xec,0xe3,0x67,0x99,0x8d,
        0xc5,0xe2,0xaa,0xd4,0x8f,0x1c,0xf4,0x7b,
        0xe5,0x2e,0xaf,0xf7,0xf6,0xeb,0x2b,0x02
    };

    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)i;
    }
    memcpy(wrong_key, key, sizeof(key));
    wrong_key[0] ^= 1;

    CHECK(auth_create_verifier(key, sizeof(key),
                               verifier, sizeof(verifier)) == 1);
    CHECK(memcmp(verifier, expected, sizeof(expected)) == 0);
    CHECK(auth_verify_verifier(key, sizeof(key),
                               verifier, sizeof(verifier)) == 1);
    CHECK(auth_verify_verifier(wrong_key, sizeof(wrong_key),
                               verifier, sizeof(verifier)) == 0);
    verifier[0] ^= 1;
    CHECK(auth_verify_verifier(key, sizeof(key),
                               verifier, sizeof(verifier)) == 0);
    verifier[0] ^= 1;

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(wrong_key, sizeof(wrong_key));
    OPENSSL_cleanse(verifier, sizeof(verifier));
}

static void test_verifier_invalid_inputs(void)
{
    unsigned char key[CRYPTO_KEY_BYTES] = {0};
    unsigned char verifier[AUTH_VERIFIER_BYTES];

    memset(verifier, 0xa5, sizeof(verifier));
    CHECK(auth_create_verifier(NULL, sizeof(key),
                               verifier, sizeof(verifier)) == 0);
    CHECK(auth_create_verifier(key, sizeof(key) - 1,
                               verifier, sizeof(verifier)) == 0);
    CHECK(auth_create_verifier(key, sizeof(key), NULL, sizeof(verifier)) == 0);
    CHECK(auth_create_verifier(key, sizeof(key),
                               verifier, sizeof(verifier) - 1) == 0);
    CHECK(auth_create_verifier(key, sizeof(key), key, sizeof(key)) == 0);
    CHECK(all_value(verifier, sizeof(verifier), 0xa5));
    CHECK(auth_verify_verifier(NULL, sizeof(key),
                               verifier, sizeof(verifier)) == 0);
    CHECK(auth_verify_verifier(key, sizeof(key) - 1,
                               verifier, sizeof(verifier)) == 0);
    CHECK(auth_verify_verifier(key, sizeof(key), NULL, sizeof(verifier)) == 0);
    CHECK(auth_verify_verifier(key, sizeof(key),
                               verifier, sizeof(verifier) - 1) == 0);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(verifier, sizeof(verifier));
}

struct wrapped_fixture {
    unsigned char kek[CRYPTO_KEY_BYTES];
    unsigned char user_id[8];
    unsigned char vmk[AUTH_VMK_BYTES];
    unsigned char wrapped[AUTH_WRAPPED_VMK_BYTES];
    unsigned char nonce[AUTH_VMK_NONCE_BYTES];
    unsigned char tag[AUTH_VMK_TAG_BYTES];
};

static int create_wrapped_fixture(struct wrapped_fixture *fixture)
{
    for (size_t i = 0; i < sizeof(fixture->kek); ++i) {
        fixture->kek[i] = (unsigned char)(0x80 + i);
    }
    for (size_t i = 0; i < sizeof(fixture->user_id); ++i) {
        fixture->user_id[i] = (unsigned char)(i + 1);
    }
    return auth_generate_wrapped_vmk(fixture->kek, sizeof(fixture->kek),
                                     fixture->user_id, sizeof(fixture->user_id),
                                     AUTH_VMK_FORMAT_VERSION,
                                     fixture->vmk, sizeof(fixture->vmk),
                                     fixture->wrapped, sizeof(fixture->wrapped),
                                     fixture->nonce, sizeof(fixture->nonce),
                                     fixture->tag, sizeof(fixture->tag));
}

static void clear_wrapped_fixture(struct wrapped_fixture *fixture)
{
    OPENSSL_cleanse(fixture, sizeof(*fixture));
}

static void test_vmk_wrap_round_trip_and_aad(void)
{
    struct wrapped_fixture fixture = {0};
    unsigned char unwrapped[AUTH_VMK_BYTES] = {0};
    unsigned char direct[AUTH_VMK_BYTES] = {0};
    const unsigned char exact_aad[] = {
        's','e','c','u','r','e','p','m',':','v','m','k','-','w','r','a','p',
        0x00,0x00,0x00,0x01,
        0x00,0x08,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
    };
    size_t direct_length = 0;

    CHECK(create_wrapped_fixture(&fixture) == 1);
    CHECK(auth_unwrap_vmk(fixture.kek, sizeof(fixture.kek),
                          fixture.user_id, sizeof(fixture.user_id),
                          AUTH_VMK_FORMAT_VERSION,
                          fixture.wrapped, sizeof(fixture.wrapped),
                          fixture.nonce, sizeof(fixture.nonce),
                          fixture.tag, sizeof(fixture.tag),
                          unwrapped, sizeof(unwrapped)) == 1);
    CHECK(memcmp(unwrapped, fixture.vmk, sizeof(unwrapped)) == 0);

    /* Pin the documented binary AAD encoding independently of auth.c. */
    CHECK(crypto_aes256_gcm_decrypt(fixture.kek, sizeof(fixture.kek),
                                    fixture.wrapped, sizeof(fixture.wrapped),
                                    exact_aad, sizeof(exact_aad),
                                    fixture.nonce, sizeof(fixture.nonce),
                                    fixture.tag, sizeof(fixture.tag),
                                    direct, sizeof(direct),
                                    &direct_length) == 1);
    CHECK(direct_length == AUTH_VMK_BYTES);
    CHECK(memcmp(direct, fixture.vmk, sizeof(direct)) == 0);

    OPENSSL_cleanse(unwrapped, sizeof(unwrapped));
    OPENSSL_cleanse(direct, sizeof(direct));
    clear_wrapped_fixture(&fixture);
}

static void expect_unwrap_failure(const struct wrapped_fixture *fixture,
                                  const unsigned char *kek,
                                  const unsigned char *user_id,
                                  uint32_t format_version,
                                  const unsigned char *wrapped,
                                  const unsigned char *tag)
{
    unsigned char output[AUTH_VMK_BYTES];

    memset(output, 0xa5, sizeof(output));
    CHECK(auth_unwrap_vmk(kek, AUTH_VMK_BYTES,
                          user_id, sizeof(fixture->user_id), format_version,
                          wrapped, AUTH_WRAPPED_VMK_BYTES,
                          fixture->nonce, sizeof(fixture->nonce),
                          tag, AUTH_VMK_TAG_BYTES,
                          output, sizeof(output)) == 0);
    CHECK(all_value(output, sizeof(output), 0xa5));
    OPENSSL_cleanse(output, sizeof(output));
}

static void test_vmk_authentication_failures(void)
{
    struct wrapped_fixture fixture = {0};
    unsigned char wrong_kek[CRYPTO_KEY_BYTES];
    unsigned char wrong_user_id[sizeof(fixture.user_id)];

    CHECK(create_wrapped_fixture(&fixture) == 1);
    memcpy(wrong_kek, fixture.kek, sizeof(wrong_kek));
    wrong_kek[0] ^= 1;
    expect_unwrap_failure(&fixture, wrong_kek, fixture.user_id,
                          AUTH_VMK_FORMAT_VERSION, fixture.wrapped, fixture.tag);

    fixture.wrapped[0] ^= 1;
    expect_unwrap_failure(&fixture, fixture.kek, fixture.user_id,
                          AUTH_VMK_FORMAT_VERSION, fixture.wrapped, fixture.tag);
    fixture.wrapped[0] ^= 1;

    fixture.tag[0] ^= 1;
    expect_unwrap_failure(&fixture, fixture.kek, fixture.user_id,
                          AUTH_VMK_FORMAT_VERSION, fixture.wrapped, fixture.tag);
    fixture.tag[0] ^= 1;

    memcpy(wrong_user_id, fixture.user_id, sizeof(wrong_user_id));
    wrong_user_id[0] ^= 1;
    expect_unwrap_failure(&fixture, fixture.kek, wrong_user_id,
                          AUTH_VMK_FORMAT_VERSION, fixture.wrapped, fixture.tag);
    expect_unwrap_failure(&fixture, fixture.kek, fixture.user_id,
                          AUTH_VMK_FORMAT_VERSION + 1,
                          fixture.wrapped, fixture.tag);

    OPENSSL_cleanse(wrong_kek, sizeof(wrong_kek));
    OPENSSL_cleanse(wrong_user_id, sizeof(wrong_user_id));
    clear_wrapped_fixture(&fixture);
}

static void test_vmk_invalid_inputs(void)
{
    struct wrapped_fixture fixture = {0};
    unsigned char oversized_user_id[AUTH_USER_ID_MAX_BYTES + 1] = {0};
    unsigned char output[AUTH_VMK_BYTES];

    CHECK(create_wrapped_fixture(&fixture) == 1);
    memset(output, 0xa5, sizeof(output));

#define BAD_WRAP(k, kl, uid, ul, ver, vmk, vc, wrapped, wc, nonce, nc, tag, tc) \
    CHECK(auth_generate_wrapped_vmk(k, kl, uid, ul, ver, vmk, vc, wrapped, wc, \
                                    nonce, nc, tag, tc) == 0)
    BAD_WRAP(NULL, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 31, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, NULL, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 0, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, oversized_user_id, sizeof(oversized_user_id), 1,
             output, 32, fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 2, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, NULL, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 31,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             NULL, 32, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 31, fixture.nonce, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, NULL, 12, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 11, fixture.tag, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, NULL, 16);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1, output, 32,
             fixture.wrapped, 32, fixture.nonce, 12, fixture.tag, 15);
    BAD_WRAP(fixture.kek, 32, fixture.user_id, 8, 1,
             fixture.wrapped, 32, fixture.wrapped, 32,
             fixture.nonce, 12, fixture.tag, 16);
#undef BAD_WRAP
    CHECK(all_value(output, sizeof(output), 0xa5));

#define BAD_UNWRAP(k, kl, uid, ul, ver, wrapped, wl, nonce, nl, tag, tl, vmk, vc) \
    CHECK(auth_unwrap_vmk(k, kl, uid, ul, ver, wrapped, wl, nonce, nl, tag, tl, \
                          vmk, vc) == 0)
    BAD_UNWRAP(NULL, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 31, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, NULL, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 0, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, NULL, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 31,
               fixture.nonce, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               NULL, 12, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 11, fixture.tag, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, NULL, 16, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 15, output, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, NULL, 32);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, output, 31);
    BAD_UNWRAP(fixture.kek, 32, fixture.user_id, 8, 1, fixture.wrapped, 32,
               fixture.nonce, 12, fixture.tag, 16, fixture.wrapped, 32);
#undef BAD_UNWRAP
    CHECK(all_value(output, sizeof(output), 0xa5));

    OPENSSL_cleanse(oversized_user_id, sizeof(oversized_user_id));
    OPENSSL_cleanse(output, sizeof(output));
    clear_wrapped_fixture(&fixture);
}

int main(void)
{
    test_verifier();
    test_verifier_invalid_inputs();
    test_vmk_wrap_round_trip_and_aad();
    test_vmk_authentication_failures();
    test_vmk_invalid_inputs();
    if (failures != 0) {
        fprintf(stderr, "FAIL: %u of %u auth checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u auth checks\n", checks);
    return 0;
}
