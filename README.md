# ICS0022 Secure Password Manager

Semester project for **ICS0022 Secure Programming**.

I originally selected the Secure File Manager project, but changed to **Secure Password Manager** for Checkpoint 1.

## Current stage

The **Checkpoint 1: threat model and architecture** design is preserved while preparing for **Checkpoint 2: core implementation**.
The program still contains only a CLI skeleton. Initial setup separates CLI dispatch from the entry point, adds OpenSSL dependency checks, and tests the existing help and argument handling. Encrypted vault storage and authentication are not implemented yet.

The supplied Password Manager checkpoint requirements call for working vault storage, credentials encrypted at rest, master-password verification before unlocking, an interface that never prints plaintext passwords, clean-machine build instructions, incremental commits, and a short progress note. These functional requirements remain pending; this setup is not a completed Checkpoint 2 submission. The File Manager encryption/decryption commands in the same sheet apply to the other project.

## Project scope

The password manager will:

- use a master password to unlock a user's vault;
- store credentials only in encrypted form;
- allow adding, retrieving, updating and deleting credentials;
- keep passwords out of logs and command-line arguments;
- validate all user input;
- enforce per-user ownership of stored records.

The interface will be a local command-line application written in C.

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
- **Password KDF:** planned to use scrypt through OpenSSL.
- **Key separation:** HKDF-SHA256 with distinct purpose-specific contexts.
- **Vault encryption:** AES-256-GCM.
- **Vault key:** a random 256-bit Vault Master Key (VMK), protected by a key derived from the master password.
- **File permissions:** private application directories/files will use restrictive permissions.
- **Memory:** password/key buffers will be cleared after use.
- **Errors/logging:** user-facing errors will be generic and logs will not contain secrets.

The main threats considered for Checkpoint 1 are:

- guessing or leaking the master password;
- stealing or modifying the encrypted vault;
- sensitive data remaining in memory;
- malicious or oversized input through the CLI.

More detailed threat-model notes are included in the Checkpoint 1 submission.

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
├── AGENTS.md
├── src/
│   ├── main.c              # program entry point
│   ├── cli.c               # help and argument dispatch
│   └── cli.h
├── tools/
│   └── check_openssl.c     # build dependency/version probe
└── tests/
    └── smoke.sh           # CLI integration smoke test
```

Objects and generated header dependencies go in the ignored `build/` directory. The executable remains `securepm`.

Add implementation/header pairs under `src/` as each feature is developed:

| Module | Responsibility |
| --- | --- |
| `crypto.c` / `crypto.h` | OpenSSL KDF, key separation, randomness, and authenticated encryption |
| `input.c` / `input.h` | Bounded interactive input and terminal echo control |
| `storage.c` / `storage.h` | Vault file I/O, permissions, and safe replacement |
| `serialization.c` / `serialization.h` | Vault encoding, decoding, and format validation |
| `auth.c` / `auth.h` | User authentication and unlocked-session lifetime |
| `vault.c` / `vault.h` | Credential operations and coordination of storage and cryptography |

These are planned boundaries, not implemented APIs. Unit tests for individual modules and integration tests for complete workflows will live under `tests/` alongside the existing smoke test. No empty module implementations are included.
