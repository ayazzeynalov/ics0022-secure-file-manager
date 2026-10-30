# ICS0022 Secure Password Manager

This is a local password manager for the ICS0022 Secure Programming course. It
is written in C17 and uses OpenSSL 3.x and POSIX APIs.

## Implemented features

The current command-line application supports:

- creating multiple local users;
- logging in with a master password;
- creating an encrypted empty vault during registration;
- adding credentials with a label, username, password, and optional notes;
- listing credential record IDs, labels, and usernames without displaying
  passwords;
- viewing a credential by record ID, with its password hidden unless the user
  acknowledges a terminal-output warning and explicitly requests reveal;
- updating and deleting credentials by record ID;
- locking the active session;
- recording minimized structured security audit events; and
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
3. View credential details
4. Update credential
5. Delete credential
6. Lock
7. Exit
```

Adding, updating, or deleting a credential rewrites the encrypted vault
atomically while the user's vault lock is held. Viewing displays the record ID,
label, username, and notes, but keeps the password hidden unless the user types
`yes` after a warning that terminal output may remain visible. Listing never
displays passwords. Passwords are never accepted as command-line arguments. Run
`./securepm --help` for the command summary.

## Per-user access control

Application accounts are isolated by authentication, session state, separate
Vault Master Keys, and separate encrypted vault files. Successful login unwraps
only the selected account's VMK and issues an in-process session capability
cryptographically bound to that account's user ID and VMK. Vault and CLI entry
points reject locked, modified, or fabricated session structures; locking or a
failed subsequent login clears the user ID, VMK, and capability.

Each vault filename is derived from its account's random 16-byte user ID. The
same user ID, format version, and ciphertext length are authenticated as
AES-256-GCM additional data, while each account has an independently generated
VMK. Substituting another account's valid vault, changing authenticated metadata,
or using the wrong session therefore fails authentication without publishing
plaintext. Per-user lock filenames serialize each account's read-modify-write
operations independently.

After vault authentication, CRUD and password-reveal lookups operate only on
the current session's decrypted credential collection. Record IDs are not
global references: knowing an ID from another vault does not grant access, and
there is no cross-vault credential lookup. The lower-level credential collection
module only transforms memory supplied by its trusted caller; the CLI and vault
layers are the authorization boundary that controls which collection can be
obtained and persisted.

This is application-level isolation between password-manager accounts, not a
separate operating-system privilege boundary. All encrypted vaults belong to
the same OS user under `~/.securepm`. Mode `0700` directories and `0600` files
restrict other OS users, but cannot stop a malicious process already running as
the same OS user from copying, deleting, replacing, or rolling back files, or
from inspecting this process's memory. The in-process session capability guards
against accidental or fabricated internal API use; it is not a sandbox against
malicious code executing inside the password-manager process.

## Security audit log

Security events are appended to `~/.securepm/audit.log` as one JSON object per
line. Records have a fixed schema and use UTC RFC 3339 timestamps:

```json
{"timestamp":"2026-10-29T12:34:56Z","event":"login","outcome":"success"}
```

Event names are fixed in the program and cover user registration, login, vault
load, credential creation/update/deletion, confirmed or cancelled password
reveal, and session lock. Outcomes are limited to `success`, `failure`, and
`cancelled`. A modifying operation is recorded as successful only after the
encrypted vault has been durably replaced.

Audit records deliberately contain no user or account identifier, password,
key, VMK, label, credential username, notes, record ID, verifier, salt,
encrypted material, or other caller-controlled text. This prevents untrusted
input from changing the JSON structure and minimizes disclosure if the log is
read. The tradeoff is that events cannot be correlated to a particular account
when multiple local accounts are active.

The log and its stable append lock use mode `0600` inside the existing `0700`
storage directory. Append opens reject symlinks, non-regular files, unexpected
ownership or mode, and files with multiple hard links. A per-file advisory lock
serializes processes; writes use `O_APPEND`, retry interruptions, handle short
writes, synchronize completed records, and stop before the log exceeds 1 MiB.

Audit logging is best effort for this educational local application. If an
event cannot be recorded, the CLI prints a generic warning but does not change,
roll back, or overwrite the result or error state of the primary authentication
or vault operation. The log has no automatic rotation: after the 1 MiB bound is
reached, events fail visibly until the user securely archives or removes the
log. The log is not cryptographically authenticated or tamper-evident, and a
crash or power loss can leave an incomplete final line despite runtime handling
of ordinary partial-write errors.

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
- **Secret handling:** password input uses disabled terminal echo and unbuffered
  descriptor reads. Failed input buffers are cleared immediately, and unread
  terminal input is flushed when terminal settings are restored after normal
  input, EOF, errors, or handled signals. Password-derived keys, plaintext
  payloads, credential collections, and session VMKs are cleared with OpenSSL
  cleanup functions when released.
- **Concurrent access:** stable `0600` lock files serialize user registration
  and each vault's complete read-modify-write session. Data files continue to
  use atomic replacement.
- **Audit/error handling:** fixed-enum JSON Lines events contain no identifiers
  or sensitive fields. Audit append failures produce a generic warning without
  changing the primary operation, while authentication and vault-load failures
  retain generic user-facing messages.
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
- structured audit schema, minimization, append, fault, and concurrency tests;
- two-account access-control, session-capability, cross-record, vault
  substitution, tampering, and restart-isolation tests;
- user database, account, vault, and credential serialization tests; and
- pseudo-terminal integration tests for registration, hidden input, login,
  credential retrieval, update and deletion, malformed vault handling, bounded
  input, terminal restoration, audit event coverage, log injection resistance,
  and audit-write failure handling.

Filesystem tests use isolated temporary `HOME` directories and dummy secrets.
The test suite covers authentication failures, malformed and truncated files,
atomic replacement, secure cleanup, and restart persistence. It is not a
security audit or a benchmark of password-guessing resistance.

## Remaining limitations and planned work

Stored passwords are available to the authenticated process and can be revealed
in terminal output after explicit confirmation; the application does not yet
provide a reviewed clipboard mechanism or password generation.

The audit log intentionally has no account identifiers, tamper-evident chain,
automatic rotation, or protection against modification by the same operating
system account. Its 1 MiB bound limits resource consumption but requires manual
archival or removal when full.

Per-user cryptographic authentication rejects a substituted vault, but cannot
prevent the same OS user from deleting a vault or rolling back both account
metadata and a vault to an older mutually valid state. A privileged debugger,
in-process code execution, or another process with the same user's memory-access
rights is outside the application-account isolation boundary.

Login throttling applies only within one running process. It cannot prevent a
new process from starting fresh or slow offline attacks against stolen
authentication metadata.

Sensitive buffers are cleared when released, but memory is not locked against
swapping and cannot be protected from a privileged process. The encrypted
vault format authenticates its contents but does not prevent deletion or
rollback to an older valid vault.
