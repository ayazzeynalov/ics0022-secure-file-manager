# ICS0022 Secure Password Manager

This is the Checkpoint 2 implementation of a local password manager for the
ICS0022 Secure Programming course. It is written in C17 and uses OpenSSL 3.x
and POSIX APIs.

## Implemented features

The current command-line application supports:

- creating multiple local users;
- logging in with a master password;
- creating an encrypted empty vault during registration;
- adding credentials with a label, username, password, and optional notes;
- listing credential record IDs, labels, and usernames without displaying
  passwords;
- locking the active session; and
- loading the same encrypted vault after restarting the program.

User metadata is stored in `~/.securepm/users.db`. Each user has a separate
vault under `~/.securepm/vaults/`, named from the application's random 16-byte
user ID rather than the username. The user database, vault, and credential
payload use versioned binary formats with explicit lengths and big-endian
integers. Raw C structures are not written to disk.

`users.db` contains the username, user ID, scrypt salt and parameters,
authentication verifier, and encrypted Vault Master Key (VMK). Credential
records are serialized and then encrypted before they are passed to the
filesystem storage layer. Master passwords, derived keys, plaintext VMKs, and
plaintext credential payloads are not persisted.

## Interactive use

Run the program without arguments in a terminal:

```text
$ ./securepm

Secure Password Manager:
1. Create user
2. Login
3. Exit
```

Registration asks for a username and master password. A new master password
must be 12–1024 bytes and must be entered twice. Both entries are read with
terminal echo disabled. After the entries match, the account metadata is
created and an encrypted empty credential vault is initialized. Existing valid
accounts with shorter passwords remain unlockable for compatibility.

Login verifies the master password, unwraps the user's VMK, and decrypts the
existing vault. A missing, malformed, or unauthenticated vault causes login to
fail and is not silently replaced.

After login, the menu provides:

```text
Vault menu:
1. Add credential
2. List credentials
3. Lock
4. Exit
```

Adding a credential rewrites the encrypted vault atomically. Listing displays
only the record ID, label, and username. Passwords are never accepted as
command-line arguments or displayed by the list operation. Run
`./securepm --help` for the command summary.

## Security decisions

- **Password derivation:** OpenSSL scrypt derives a 32-byte root key from the
  master password and a random 16-byte per-user salt. New records use
  `N=32768`, `r=8`, `p=1`, with a 64 MiB memory limit.
- **Key separation:** HKDF-SHA256 derives separate authentication and Key
  Encryption Keys from the root key. A random 32-byte VMK is encrypted under
  the Key Encryption Key.
- **Authenticated encryption:** AES-256-GCM protects wrapped VMKs and vault
  payloads. Each encryption uses a fresh random 12-byte nonce and a 16-byte
  authentication tag. User and format metadata are bound as authenticated
  additional data.
- **Filesystem storage:** `~/.securepm/` and its `vaults/` directory use mode
  `0700`; files use mode `0600`. Storage uses directory file descriptors,
  `openat()`, `O_NOFOLLOW`, ownership and hard-link checks, exclusive temporary
  files, checked writes, synchronization, and atomic replacement.
- **Input validation:** terminal input is bounded and rejects oversized input
  and embedded NUL bytes. Binary formats validate lengths, counts, versions,
  integer conversions, truncation, trailing data, and maximum sizes before
  copying or allocating.
- **Secret handling:** password input uses disabled terminal echo, and terminal
  settings are restored after normal input, EOF, errors, or handled signals.
  Password-derived keys, plaintext payloads, credential collections, and
  session VMKs are cleared with OpenSSL cleanup functions when released.
- **Concurrent access:** stable `0600` lock files serialize user registration
  and each vault's complete read-modify-write session. Data files continue to
  use atomic replacement.
- **Registration recovery:** a pending marker allows an interrupted account
  creation to resume only after the same master password is authenticated.
- **Login throttling:** failures in one interactive process take at least 0.5,
  1, then 2 seconds, with later failures capped at 2 seconds. A successful
  authentication resets the delay.

Authentication failures use a generic CLI message. The program relies on
OpenSSL primitives and does not implement cryptographic algorithms itself.

## Build and run

The build requires a C17 compiler, Make, a POSIX environment, and OpenSSL 3.x
development headers and libraries. `pkg-config` is recommended.

On macOS with Homebrew:

```bash
xcode-select --install  # if Command Line Tools are not installed
brew install openssl@3 pkg-config
```

On Debian or Ubuntu with OpenSSL 3.x packages:

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

Build, check the help text, run interactively, and run the tests from the
repository root:

```bash
make clean && make
./securepm --help
./securepm
make test
```

The Makefile first uses `pkg-config` to locate `libcrypto`, then checks for a
Homebrew OpenSSL installation on macOS, and otherwise uses the compiler's
default search paths. A build-time probe rejects OpenSSL versions other than
major version 3. Custom paths can be supplied explicitly:

```bash
make OPENSSL_CFLAGS='-I/opt/openssl/include' \
     OPENSSL_LIBS='-L/opt/openssl/lib -lcrypto'
```

The application and full test suite pass on macOS and Ubuntu 24.04.5 ARM64.
The Linux run used GCC 13.3.0 and OpenSSL 3.0.13.

## Tests

`make test` runs:

- command-line argument smoke tests;
- cryptographic unit and reference-vector tests for randomness, scrypt, HKDF,
  and AES-256-GCM;
- authentication-verifier and VMK-wrapping tests;
- POSIX storage and file-permission tests;
- user database, account, vault, and credential serialization tests; and
- pseudo-terminal integration tests for registration, hidden input, login,
  credential persistence, malformed vault handling, bounded input, and terminal
  restoration.

Filesystem tests use isolated temporary `HOME` directories and dummy secrets.
The test suite covers authentication failures, malformed and truncated files,
atomic replacement, secure cleanup, and restart persistence. It is not a
security audit or a benchmark of password-guessing resistance.

## Remaining limitations and planned work

Checkpoint 2 does not yet provide credential retrieval, update, or deletion.
It also has no structured audit logging, password generation, or clipboard
integration. These features are planned after the current checkpoint.

Login throttling applies only within one running process. It cannot prevent a
new process from starting fresh or slow offline attacks against stolen
authentication metadata.

Sensitive buffers are cleared when released, but memory is not locked against
swapping and cannot be protected from a privileged process. The encrypted
vault format authenticates its contents but does not prevent deletion or
rollback to an older valid vault.
