# ICS0022 Secure Password Manager

Semester project for **ICS0022 Secure Programming**.

I originally selected the Secure File Manager project, but changed to **Secure Password Manager** for Checkpoint 1.

## Current stage

The **Checkpoint 1: threat model and architecture** design is preserved while preparing for **Checkpoint 2: core implementation**.
The interface remains a CLI skeleton. A separate crypto module now provides random bytes, scrypt root-key derivation, and HKDF-SHA256 key separation, with unit tests. Encrypted vault storage and authentication are not implemented yet.

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

## Key derivation module

`src/crypto.h` defines the public API. Functions return `1` on success and `0` on failure; they do not print secrets or errors. `crypto_random()` uses OpenSSL `RAND_bytes()` and accepts nonempty buffers up to `INT_MAX` bytes. Generate a fresh `CRYPTO_SALT_BYTES` (16-byte) salt for each future user record; user creation and salt persistence are not implemented.

`crypto_derive_root()` takes an explicit password byte length, a 16-byte salt, and a `crypto_scrypt_params` structure, and produces exactly 32 bytes. `crypto_scrypt_defaults` specifies **N=32768, r=8, p=1, max_memory=67108864 bytes (64 MiB)**. Passwords are bounded to 1–1024 bytes without truncation. Supported parameter bounds are power-of-two N from 2 to 32768, r from 1 to 8, p=1, and a positive memory limit no larger than 64 MiB. OpenSSL rejects settings whose memory requirements exceed that limit. Smaller costs are supported for tests and future compatibility; new user records must use the production defaults. A future metadata loader must enforce its accepted cost profile as well as these resource bounds.

`crypto_derive_keys()` produces a `crypto_keys` structure containing a 32-byte authentication key and a 32-byte KEK. It uses HKDF-SHA256 extract-and-expand with no additional HKDF salt and these exact ASCII context labels, excluding their terminating NUL bytes:

- Authentication key: `securepm:v1:auth`
- Key Encryption Key: `securepm:v1:kek`

The labels are versioned derivation inputs; changing them changes the keys. `crypto_hkdf_sha256()` exposes the underlying primitive for reuse and reference-vector testing, with input buffers limited to 1024 bytes each and output limited to 1–8160 bytes.

Callers must supply valid buffers of the declared sizes, keep outputs separate from inputs, and clear passwords, returned root keys, and separated keys with `OPENSSL_cleanse()` when no longer needed. The module clears its intermediate secret buffers on success and failure and frees OpenSSL contexts. Failed derivations clear valid-sized output buffers; invalid output pointers or lengths are rejected without writing. It does not implement locked memory or protection against privileged process inspection.

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

`make test` also runs cryptographic unit tests for deterministic scrypt derivation, salt separation, HKDF key separation and repeatability, buffer boundaries, invalid inputs, and failure cleanup. HKDF is checked against [RFC 5869 Appendix A, cases 1 and 3](https://www.rfc-editor.org/rfc/rfc5869#appendix-A). Tests use dummy data and never print key bytes. Production-cost scrypt is exercised; only input-boundary tests use smaller costs. These tests do not constitute a security audit or a benchmark of password-guessing resistance.

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
│   ├── crypto.c            # randomness and key derivation
│   └── crypto.h
├── tools/
│   └── check_openssl.c     # build dependency/version probe
└── tests/
    ├── smoke.sh           # CLI integration smoke test
    └── test_crypto.c      # cryptographic unit tests
```

Objects and generated header dependencies go in the ignored `build/` directory. The executable remains `securepm`.

Add implementation/header pairs under `src/` as each feature is developed:

| Module | Responsibility |
| --- | --- |
| `input.c` / `input.h` | Bounded interactive input and terminal echo control |
| `storage.c` / `storage.h` | Vault file I/O, permissions, and safe replacement |
| `serialization.c` / `serialization.h` | Vault encoding, decoding, and format validation |
| `auth.c` / `auth.h` | User authentication and unlocked-session lifetime |
| `vault.c` / `vault.h` | Credential operations and coordination of storage and cryptography |

These are planned boundaries, not implemented APIs. Authenticated encryption will later extend the existing crypto module. Further unit tests and integration tests will live under `tests/` alongside the current tests. No empty module implementations are included.
