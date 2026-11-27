# ICS0022 Secure Password Manager

This is a local password manager for the ICS0022 Secure Programming course. It
is written in C17 and uses OpenSSL 3.x and POSIX APIs.

## Project status

Final-project implementation extends the Checkpoint 3 code with
clipboard-only password retrieval and operation-scoped credential decryption.

The application supports user authentication, encrypted credential
storage, credential management, per-user access control, and
structured security logging.

The macOS build with OpenSSL 3.5.9 passed 3,705 functional checks and
3,042 checks in a separate Clang IntegerSanitizer run. Additional regression
suites cover rollback, clipboard expiration, session timeout, authentication
revalidation, audit rotation, input boundaries and recovery. The production
clipboard was tested on macOS; Linux automated tests use an isolated test
backend, not a graphical session.

The remaining limitations are documented below.

## Implemented features

The current command-line application supports:

- creating multiple local users;
- logging in with a master password;
- creating an encrypted empty vault during registration;
- adding credentials with a label, username, password, and optional notes;
- listing credential record IDs, labels, and usernames without displaying
  passwords;
- viewing a credential by record ID, with its password hidden unless the user
  explicitly confirms copying it to the system clipboard;
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
label, username, and notes, and always keeps the password hidden in terminal
output. Type `yes` at the confirmation prompt to copy it to the system
clipboard. Paste it into the intended application and clear the clipboard
after use. The application attempts to clear unchanged clipboard text after
30 seconds, or sooner on session lock or normal exit. Other applications and
clipboard history tools may read or retain it. Listing never displays
passwords. Passwords are never accepted as command-line arguments. Run
`./securepm --help` for the command summary.

On macOS, retrieval uses `/usr/bin/pbcopy`. On Linux, it requires a graphical
Wayland session with `/usr/bin/wl-copy` and `/usr/bin/wl-paste`, or an X11
session with `/usr/bin/xclip`.
The helper receives password bytes through a local socket, not command-line
arguments or a shell. Without a supported helper, copying fails with a generic
message; there is no cleartext terminal fallback. The actual graphical Linux
clipboard has not been validated in the current test environment.

The interactive process handles `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`, and
`SIGTSTP` by notifying the normal input path and then performing ordinary
session, vault-lock, secret-buffer, and terminal cleanup. In particular,
Ctrl+Z terminates the session instead of suspending an unlocked vault. Terminal
software flow control is disabled while the application is running so that
Ctrl+S cannot leave output apparently frozen, and the original terminal state
is restored at exit. Password echo is restored on recoverable secret-input exit
paths. Copy and deletion confirmations discard input that was already queued
before the confirmation prompt, so a pasted sequence cannot supply its own
future `yes` response.

An authenticated session retains the VMK and a keyed HMAC-SHA256 snapshot
of the expected serialized vault payload. The snapshot key is independently
randomized for each login and cleared on session exit. The credential
collection is decrypted and checked on demand, then explicitly cleared before
returning to the vault menu. The collection can remain in memory during an
interactive operation, including its confirmation prompt. Before copying a
password, the vault is revalidated. Updates use an exact compare-before-replace
operation on the encrypted file; successful changes refresh the expected
snapshot. A missing, corrupted or externally changed vault causes an operation
to fail or the session to lock. A valid older payload is rejected during an
active session; rollback across separate logins is not prevented.

## Per-user access control

Application accounts are isolated by authentication, session state, separate
Vault Master Keys, and separate encrypted vault files. Successful login unwraps
only the selected account's VMK and issues an in-process session capability
cryptographically bound to that account's user ID, VMK and record digest. Vault and CLI entry
points reject locked, modified, or fabricated session structures; locking or a
failed subsequent login clears the user ID, VMK, and capability.

Each vault filename is derived from its account's random 16-byte user ID. The
same user ID, format version, and ciphertext length are authenticated as
AES-256-GCM additional data, while each account has an independently generated
VMK. Substituting another account's valid vault, changing authenticated metadata,
or using the wrong session therefore fails authentication without publishing
plaintext. Per-user lock filenames serialize each account's read-modify-write
operations independently.

After vault authentication, CRUD and password-copy lookups operate only on
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
{"timestamp":"2026-10-29T12:34:56Z","event":"login","outcome":"success","actor_id":"00112233445566778899aabbccddeeff"}
```

Event names are fixed in the program and cover user registration, login, vault
load, credential creation/update/deletion, password copy attempts with recorded outcomes, and session lock. Outcomes are limited to `success`, `failure`, and
`cancelled`. A modifying operation is recorded as successful only after the
encrypted vault has been durably replaced.

Audit records contain an internal random 128-bit account ID encoded as hex
for authenticated actions, or JSON `null` when no identity was authenticated.
They do not contain usernames, passwords, keys, credential fields, verifier,
salt or arbitrary caller-controlled text. The identifier allows correlation of
an account's activity without exposing its username.

The log and its stable locks use mode `0600` in the private `0700` directory.
Append rejects unsafe files and uses synchronized, bounded writes. An outer
advisory lock serializes append and rotation between cooperating instances.
At the 1 MiB limit, the previous log is durably copied to `audit.log.1` before
atomically replacing the current log with the new event. Only one archive is
retained: at most 2 MiB of completed log files, excluding temporary writes.
An interrupted rotation can leave duplicate history; external modifications,
unsafe files or I/O errors can prevent rotation. Audit failures produce a
warning without undoing the primary operation. Logs are not tamper-evident.

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
  files, checked writes, synchronization, and atomic replacement. On macOS,
  storage also rejects private directories and files carrying an extended ACL,
  because an ACL can grant access that is not represented by the ordinary mode
  bits. Linux retains the mode/ownership checks and does not depend on macOS ACL
  APIs.
- **Input validation:** terminal input is bounded and rejects oversized input
  and embedded NUL bytes. Binary formats validate lengths, counts, versions,
  integer conversions, truncation, trailing data, and maximum sizes before
  copying or allocating.
- **Secret handling:** password input uses disabled terminal echo and unbuffered
  descriptor reads. Failed input buffers are cleared immediately, and unread
  terminal input is flushed when terminal settings are restored after normal
  input, EOF, errors, or handled signals. Password-derived keys, plaintext
  payloads, credential collections, and session VMKs are cleared with OpenSSL
  cleanup functions when released. The master password is cleared after
  authentication or registration, and the collection is cleared between menu
  operations.
- **Concurrent access:** stable `0600` lock files serialize user registration
  and each vault's complete read-modify-write session. Data files continue to
  use atomic replacement. Storage retains descriptors for `HOME`, the private
  root, and the vault directory and verifies that their current pathnames still
  identify the same directories. After acquiring or before relying on a lock,
  the lock descriptor must still identify the file at the expected pathname.
  Atomic replacement also verifies that the destination has not changed while
  the temporary file is written.
- **Audit/error handling:** fixed-enum JSON Lines events contain a pseudonymous actor ID
  when authenticated, but no usernames or secret fields. Audit append failures produce a generic warning without
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
brew install openssl@3.5 pkg-config
```

On Debian or Ubuntu with OpenSSL 3.x packages:

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

On Windows, use an Ubuntu distribution under WSL2 and run the Debian/Ubuntu
commands above inside that environment. Native Win32 builds are not supported;
the application depends on POSIX terminals, signals, pseudo-terminals, file
descriptors, permissions, and locking.

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

For Linux graphical clipboard retrieval, install `wl-clipboard` on Wayland or
`xclip` on X11 as appropriate. Python 3 is needed for additional integration tests. Linux automated tests
cover command-line behavior, not the native graphical clipboard.

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
  input, real terminal-generated signals, flow-control behavior, terminal
  restoration, queued confirmation input, failed credential persistence, audit
  event coverage, log injection resistance, and audit-write failure handling.

Run the complete portable regression suite from the repository root:

```bash
make test-all
```

On Linux, `make test-memory` optionally inspects only the test child process
heap and stack for a randomly generated dummy credential. It first verifies
that the marker can be observed while an operation is pending, then checks
that it is absent after adding, listing and locking. No raw memory is saved.
The experiment requires permission to read the child via `/proc`; it is not
a proof of erasure from all mappings or other processes.

For a Clang sanitizer build on Linux:

```bash
make clean
make CC=clang CFLAGS="-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" test test-snapshot
```

For credential-parser fuzzing with Clang/libFuzzer, run from the repository root:

```bash
mkdir -p build/fuzz-corpus
cp tests/fuzz_corpus/* build/fuzz-corpus/
clang -std=c17 -g -O1 -fsanitize=fuzzer,address,undefined -Isrc \
  tests/fuzz_credentials.c src/credentials.c src/crypto.c src/vault.c \
  src/account.c src/user_db.c src/storage.c src/auth.c -lcrypto \
  -o build/fuzz_credentials
./build/fuzz_credentials -runs=10000 -max_len=4096 build/fuzz-corpus
```

Filesystem tests use isolated temporary `HOME` directories and dummy secrets.
The test suite covers authentication failures, malformed and truncated files,
atomic replacement, secure cleanup, and restart persistence. It is not a
security audit or a benchmark of password-guessing resistance.

## Remaining limitations and planned work

Stored passwords are available to the authenticated process during an
operation and can be copied to the operating system clipboard after explicit
confirmation. Clipboard contents are outside the encrypted vault and may
remain accessible to other applications. Automatic expiry is best-effort: a
keyed HMAC checks that the current text matches the copied password without
retaining a plaintext copy. Clipboard read and clear are separate operations;
a concurrent clipboard change, helper failure, clipboard history, process
termination or system suspension can defeat cleanup. The timer is serviced
while waiting for input; blocking operations can delay it. There is no password
generator. The test backend is built separately and is
not part of the production executable.

Audit logs use pseudonymous account IDs and bounded rotation but are not
cryptographically authenticated. The same OS account can modify or delete
logs; older archives are intentionally discarded when rotating.

At startup the application sets both soft and hard `RLIMIT_CORE` to zero
and refuses to start if that fails. This reduces ordinary core-file exposure,
not privileged debugger access, OS-specific crash reporting or piped Linux
core handlers.

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
vault format authenticates its contents. The session snapshot detects changed
plaintext within a session, but cannot prevent deletion or rollback across
separate logins.

`SIGKILL` and `SIGSTOP` cannot be caught, so the process cannot guarantee
terminal restoration, explicit memory clearing, or lock-release cleanup after
those signals. The operating system releases process-owned descriptors and
advisory locks when a killed process exits, but `SIGSTOP` can leave an unlocked
session and its lock suspended until the process is continued or terminated.
The terminal hardening also cannot prevent privileged memory inspection,
swapping, crash-dump copies, or copies introduced by the compiler or runtime.

The pathname and compare-before-replace checks reduce accidental and
cooperative-process lost updates, but they cannot create an operating-system
security boundary against a malicious process running as the same OS user.
Such a process can continuously race pathname checks, replace files immediately
after validation, or stop the password manager between validation and rename.
Preventing that class of attack requires a stronger OS privilege boundary or a
trusted external storage service. The CLI revalidates the authenticated account record from `users.db` before
credential operations, before copying or committing changes, and after each
operation. The session capability binds a SHA-256 digest of the canonical
account record to the user ID and VMK. Missing, malformed or changed account
metadata causes rejection and session locking when detected. Registration of
another account does not invalidate an unchanged account record. This is
operation-boundary validation, not continuous monitoring or an atomic transaction
across both files; transient changes between checks may not be detected.

Authenticated prompts have a five-minute deadline measured with a monotonic
clock. Submitting a line (not individual
keystrokes) advances to the next prompt. Passwords and long notes use
noncanonical terminal input to avoid the OS canonical line length limit.
Backspace and line kill are handled by the reader; an oversized line must
be cleared or submitted and rejected. EOF cancels these prompts. Password
echo stays disabled. For long notes the terminal may display editing keys
differently than in canonical mode. Timeout cancels an unfinished operation,
clears the session and clipboard (best effort), releases the vault lock and returns
to the login menu. This is not a hard deadline during computation, a blocked
system call or process suspension. Run `make test-idle` for an accelerated
integration test; the two-second override is available only in the test binary.

Clipboard lifecycle regression: `make test-clipboard` (isolated dummy clipboard,
2-second test-only expiry; production uses 30 seconds).
On macOS, optionally verify the native clipboard using
`python3 -B tests/test_clipboard_macos.py --overwrite-clipboard` after building.
This deliberately replaces the current clipboard with dummy data; do not use
it while the test runs. No real vault is used.

### Additional recovery checks

`make test-recovery` injects a partial temporary-file write followed by
`ENOSPC` in the test build only, measures twenty invalid login attempts and
checks recovery from a matching backup of `users.db` and the encrypted vault.
No actual disk is filled. Backups must be made while all instances are closed
and kept in private storage; restore matching database and vault files only
while the application is closed. Keep directories at mode 0700 and data
files at mode 0600. The test uses synthetic accounts and a mock clipboard.
The login delay is process-local, not a persistent lockout.


## Reproducible Linux build and CI

The Dockerfile builds on Debian 13 and runs as an unprivileged user. From
this directory, if Docker is installed:

```bash
docker build -t securepm-course .
docker run --rm -it securepm-course
```

This disposable container is for demonstrating registration, login and local
storage; it has no host clipboard connection. Copying passwords requires a
supported graphical session outside the default headless container. Do not
use real credentials in the disposable demo. The GitHub Actions workflow
runs `make test-all` on Linux and macOS with a separate sanitizer job. Native
macOS clipboard checks remain manual/opt-in because they modify the real
clipboard.

## Secret scan review

Gitleaks 8.30.1 reported one historical `generic-api-key` finding in
`tests/test_cli.c` at commit `35381a328a5a72479ba80842be3131f3c16d5edf`,
line 931. Manual review confirmed it is a synthetic credential used in a
cross-account test, not a service API key. `.gitleaksignore` contains only
that exact finding fingerprint. No entire test directory or rule is excluded.
The current source scan reported no findings before the final packaging step.
