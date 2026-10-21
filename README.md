# ICS0022 Secure Password Manager

Semester project for **ICS0022 Secure Programming**.

I originally selected the Secure File Manager project, but changed to **Secure Password Manager** for Checkpoint 1.

## Current stage

The **Checkpoint 1: threat model and architecture** design is preserved while preparing for **Checkpoint 2: core implementation**.
The interface remains a CLI skeleton. The crypto module provides random bytes, scrypt root-key derivation, HKDF-SHA256 key separation, and AES-256-GCM authenticated encryption. The authentication module provides master-password verifier primitives and VMK protection. The storage module provides secure directory initialization, bounded reads, and atomic file replacement. The user database module persists validated authentication metadata for multiple users. Registration, encrypted vault serialization, and login sessions are not implemented yet.

The supplied Password Manager checkpoint requirements call for working vault storage, credentials encrypted at rest, master-password verification before unlocking, an interface that never prints plaintext passwords, clean-machine build instructions, incremental commits, and a short progress note. These functional requirements remain pending; this setup is not a completed Checkpoint 2 submission. The File Manager encryption/decryption commands in the same sheet apply to the other project.

## Project scope

The password manager will:

- use a master password to unlock a user's vault;
- store credentials only in encrypted form;
- allow adding, retrieving, updating and deleting credentials;
- keep passwords out of logs and command-line arguments;
- validate all user input;
- enforce per-user ownership of stored records.

The interface will be a local command-line application written in C17 using OpenSSL 3.x and POSIX APIs.

## Planned design

```text
User
  |
  v
CLI / input validation
  |
  v
User management / authentication
  |
  v
Vault manager
  |------> Crypto module
  |------> Storage
  |
  +------> Audit log
```

Each user will have a separate encrypted vault file.

Planned storage:

```text
~/.securepm/
├── users.db
├── audit.log
└── vaults/
    └── <user-id>.vault
```

## Security decisions

- **Master password:** entered interactively with terminal echo disabled. It will not be stored in plaintext.
- **Password KDF:** scrypt through OpenSSL with a per-user random salt. Salt and KDF parameters will be stored with the user record; cost parameters will be benchmarked before authentication is finalized.
- **Key separation:** HKDF-SHA256 with distinct contexts for the authentication key and key-encryption key (KEK). A verifier derived from the authentication key will be stored separately in `users.db`.
- **Vault encryption:** AES-256-GCM with a fresh 12-byte nonce for each encryption and a 16-byte authentication tag. Randomness will come from OpenSSL `RAND_bytes()`; failed authentication-tag verification must reject the vault.
- **Vault key:** a random 256-bit Vault Master Key (VMK), protected by the password-derived KEK.
- **Cryptographic APIs:** use established OpenSSL APIs, not custom cryptographic algorithms. Passwords and encryption keys must never be hardcoded.
- **File permissions:** application directories will use `0700` and files `0600`. Vault filenames will use application-generated user IDs, not usernames or credential labels. Filesystem operations must guard against path traversal and symlink redirection.
- **Vault updates:** write encrypted temporary files and replace the previous vault only after a successful write; never write plaintext temporary files. Keep local vault data out of version control.
- **Input and ownership:** validate lengths, counts, formats, and size calculations before allocation or copying; check return values and enforce ownership on every protected record operation.
- **Memory:** password/key buffers will be cleared after use.
- **Errors/logging:** user-facing errors will be generic. Structured logs will use an allow-list of non-secret event fields and never contain passwords, encryption keys, or credential contents.

The main threats considered for Checkpoint 1 are:

- guessing or leaking the master password;
- stealing or modifying the encrypted vault;
- sensitive data remaining in memory;
- malicious or oversized input through the CLI.

More detailed threat-model notes are included in the Checkpoint 1 submission.

## Cryptographic module

`src/crypto.h` defines the public API. Functions return `1` on success and `0` on failure; they do not print secrets or errors. `crypto_random()` uses OpenSSL `RAND_bytes()` and accepts nonempty buffers up to `INT_MAX` bytes. Future registration must generate a fresh `CRYPTO_SALT_BYTES` (16-byte) salt for each user; the user database persists supplied salts, but user creation is not implemented.

`crypto_derive_root()` takes an explicit password byte length, a 16-byte salt, and a `crypto_scrypt_params` structure, and produces exactly 32 bytes. `crypto_scrypt_defaults` specifies **N=32768, r=8, p=1, max_memory=67108864 bytes (64 MiB)**. Passwords are bounded to 1–1024 bytes without truncation. Supported parameter bounds are power-of-two N from 2 to 32768, r from 1 to 8, p=1, and a positive memory limit no larger than 64 MiB. OpenSSL rejects settings whose memory requirements exceed that limit. Smaller costs are supported for tests and future compatibility; version 1 user records require the production defaults exactly.

`crypto_derive_keys()` produces a `crypto_keys` structure containing a 32-byte authentication key and a 32-byte KEK. It uses HKDF-SHA256 extract-and-expand with no additional HKDF salt and these exact ASCII context labels, excluding their terminating NUL bytes:

- Authentication key: `securepm:v1:auth`
- Key Encryption Key: `securepm:v1:kek`

The labels are versioned derivation inputs; changing them changes the keys. `crypto_hkdf_sha256()` exposes the underlying primitive for reuse and reference-vector testing, with input buffers limited to 1024 bytes each and output limited to 1–8160 bytes.

Callers must supply valid buffers of the declared sizes, keep outputs separate from inputs, and clear passwords, returned root keys, and separated keys with `OPENSSL_cleanse()` when no longer needed. The module clears its intermediate secret buffers on success and failure and frees OpenSSL contexts. Failed derivations clear valid-sized output buffers; invalid output pointers or lengths are rejected without writing. It does not implement locked memory or protection against privileged process inspection.

`crypto_aes256_gcm_encrypt()` uses a 32-byte key, generates a fresh 12-byte nonce with `crypto_random()`, supports optional AAD, and returns ciphertext plus a 16-byte authentication tag. `crypto_aes256_gcm_decrypt()` accepts the same parameters and releases plaintext only after the tag is verified. Authentication failure leaves the caller's plaintext buffer untouched and reports a zero output length. Empty plaintext is supported. Input and output buffers must be distinct, message and AAD lengths are limited to `INT_MAX`, and ciphertext has the same length as plaintext. Nonce uniqueness depends on OpenSSL's random generator succeeding; no nonce state is persisted by this module.

## Authentication and VMK protection

`src/auth.h` defines reusable primitives; it does not implement users, login sessions, or persistence. `auth_create_verifier()` computes a 32-byte HMAC-SHA256 using the 32-byte authentication key and the exact ASCII message `securepm:auth-verifier:v1`, excluding its terminating NUL. `auth_verify_verifier()` recalculates it and compares all 32 bytes with OpenSSL `CRYPTO_memcmp()`. This verifier permits offline password guesses if authentication metadata is stolen; resistance depends on the preceding per-user scrypt derivation and the strength of the master password.

`auth_generate_wrapped_vmk()` generates a random 32-byte VMK and protects it with the 32-byte KEK through the existing AES-256-GCM API. It returns the VMK for immediate in-memory vault use together with a 32-byte wrapped VMK, 12-byte nonce, and 16-byte tag. `auth_unwrap_vmk()` publishes the VMK only after GCM authentication succeeds. Callers must never persist the plaintext VMK and must clear it when the vault locks.

VMK wrapping authenticates this exact binary AAD sequence, with no NUL terminator or padding:

1. 17 ASCII bytes: `securepm:vmk-wrap`
2. Format version as a 4-byte unsigned big-endian integer; the only supported value is currently `1`.
3. User-ID length as a 2-byte unsigned big-endian integer.
4. The application-generated user-ID bytes, with a current allowed length of 1–255 bytes.

Thus the AAD length is `23 + user_id_length`. The user database persists the format version and exact user ID alongside the wrapped VMK, nonce, and tag. Future login code must reconstruct this sequence byte-for-byte. Modifying the version or user ID causes unwrapping to fail.

## Filesystem storage

`src/storage.h` provides a crypto-independent storage context for the application root and vault directory. `storage_init()` opens the absolute `HOME` path one component at a time without following symlinks, verifies that `HOME` belongs to the effective user, and creates or validates `~/.securepm/` and `~/.securepm/vaults/` with mode `0700`. Existing directories with the wrong owner, type, or permissions are rejected.

`storage_read_file()` performs bounded reads and distinguishes a missing file from an unsafe object or I/O error. `storage_atomic_write()` writes at most 16 MiB to a same-directory temporary file created exclusively with mode `0600`, flushes and closes it, revalidates any destination, renames it atomically, and synchronizes the directory. Existing files must be regular files owned by the effective user with exact mode `0600` and one hard link. Files are addressed relative to retained directory descriptors with `openat()` and related APIs; public filenames are limited to 1–128 ASCII bytes, must start with an alphanumeric character, and may otherwise contain only alphanumerics, `.`, `_`, and `-`. This prevents path separators and traversal components. Future vault code must use application-generated user IDs for filenames and pass only metadata or already-encrypted vault bytes to this module.

On macOS, file flushing uses `F_FULLFSYNC` when supported and falls back to `fsync()`. Some macOS filesystems do not support directory `fsync()`; `EINVAL` and `ENOTSUP` are treated as the platform's best available behavior. Linux uses `fsync()` for files and directories. The module checks POSIX mode bits and ownership but does not inspect platform-specific ACLs, extended attributes, or network-filesystem atomicity guarantees.

## User database

`src/user_db.h` provides an in-memory database of at most 256 users with load, find, add, and save operations. A missing `users.db` loads as an empty database; an existing malformed file is an error. Usernames are 1–64 visible ASCII bytes and are compared exactly and case-sensitively. Both usernames and 16-byte application-generated user IDs must be unique. Version 1 records accept only `crypto_scrypt_defaults`.

The binary format does not serialize C structures. It starts with the 8 ASCII bytes `SPMUSRDB`, followed by a 32-bit file version and 32-bit record count. Each record contains a 32-bit record/VMK-wrap format version, a 16-bit username length and the username bytes, then the 16-byte user ID, 16-byte scrypt salt, four 64-bit scrypt parameters (`N`, `r`, `p`, and memory limit), 32-byte authentication verifier, 32-byte wrapped VMK, 12-byte nonce, and 16-byte tag. Every integer is unsigned big-endian. The parser rejects unsupported versions or parameter profiles, invalid lengths, duplicates, truncation, trailing data, and counts above 256 before publishing the loaded database.

The database intentionally contains password-verification material and an encrypted VMK, but no master password, derived key, KEK, or plaintext VMK. File permissions prevent access by other users; the format does not add a separate whole-file authentication code, so an attacker who can already write files as the account owner can cause denial of service or alter metadata. VMK ciphertext integrity remains enforced by its GCM tag when later unwrapped.

## Planned interface

```text
$ ./securepm

1. Create user
2. Login
3. Exit

After login:

add
list
show <record-id>
copy <record-id>
update <record-id>
delete <record-id>
lock
help
exit
```

Stored passwords will not be printed in cleartext.
The planned `show` command must mask or omit passwords. Any future `copy` implementation must preserve the no-plaintext-output rule.

## Build

Requirements: a C17 compiler, Make, OpenSSL 3.x development headers/libraries, and a POSIX shell. `pkg-config` is recommended for dependency discovery.

On macOS with Homebrew:

```bash
xcode-select --install # if the command-line tools are not installed
brew install openssl@3 pkg-config
```

On Debian/Ubuntu with OpenSSL 3.x packages:

```bash
sudo apt install build-essential pkg-config libssl-dev
```

From the repository root:

```bash
make clean && make
./securepm --help
make test
```

The build uses `pkg-config` for `libcrypto`, then a Homebrew OpenSSL prefix if available, or the compiler's default search paths. For a custom installation, set `OPENSSL_CFLAGS` and `OPENSSL_LIBS`, for example:

```bash
make OPENSSL_CFLAGS='-I/opt/openssl/include' OPENSSL_LIBS='-L/opt/openssl/lib -lcrypto'
```

An OpenSSL probe checks both headers and the loaded library for major version 3. Missing or incompatible dependencies fail the build; cryptography is not silently disabled. Clean before changing compilers or dependency flags. Standard `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, and `LDLIBS` are also supported; C17 is always enabled.

The smoke test checks seven CLI cases: `--help`, `-h`, no arguments, an unknown option, extra arguments, an unimplemented command, and an empty argument. It checks output and exit status, not vault security or authentication.

`make test` also runs unit tests for deterministic scrypt derivation, salt separation, HKDF key separation and repeatability, AES-GCM round trips and authentication failures, verifier creation and checking, VMK protection and AAD binding, secure filesystem behavior, and user database parsing and persistence. Storage and database tests use isolated temporary `HOME` directories. Database tests cover multiple records, uniqueness, reopen persistence, permissions, fixed-endian encoding, malformed inputs, unsupported versions and scrypt profiles, truncation, and trailing data. HKDF is checked against [RFC 5869 Appendix A, cases 1 and 3](https://www.rfc-editor.org/rfc/rfc5869#appendix-A), and AES-GCM decryption uses a published AES-256-GCM known-answer vector. Tests use dummy data and never print key bytes. Production-cost scrypt is exercised; only input-boundary tests use smaller costs. These tests do not constitute a security audit or a benchmark of password-guessing resistance.

Clean build files:

```bash
make clean
```

## Repository structure

```text
.
├── README.md
├── Makefile
├── .gitignore
├── src/
│   ├── main.c              # program entry point
│   ├── cli.c               # help and argument dispatch
│   ├── cli.h
│   ├── auth.c              # verifier and VMK protection primitives
│   ├── auth.h
│   ├── crypto.c            # randomness and key derivation
│   ├── crypto.h
│   ├── storage.c           # secure filesystem operations
│   ├── storage.h
│   ├── user_db.c           # versioned user metadata persistence
│   └── user_db.h
├── tools/
│   └── check_openssl.c     # build dependency/version probe
└── tests/
    ├── smoke.sh           # CLI integration smoke test
    ├── test_auth.c        # authentication and VMK unit tests
    ├── test_crypto.c      # cryptographic unit tests
    ├── test_storage.c     # storage unit tests
    └── test_user_db.c     # user database unit tests
```

Objects and generated header dependencies go in the ignored `build/` directory. The executable remains `securepm`.

Add implementation/header pairs under `src/` as each feature is developed:

| Module | Responsibility |
| --- | --- |
| `input.c` / `input.h` | Bounded interactive input and terminal echo control |
| `serialization.c` / `serialization.h` | Vault encoding, decoding, and format validation |
| `vault.c` / `vault.h` | Credential operations and coordination of storage and cryptography |

These are planned boundaries, not implemented APIs. Further unit tests and integration tests will live under `tests/` alongside the current tests. No empty module implementations are included.
