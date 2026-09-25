# ICS0022 Secure Password Manager — Checkpoint 1

**Course:** ICS0022 Secure Programming  
**Student:** Ayaz Zeynalov  
**Checkpoint:** 1 — Threat Model and Architecture  
**Implementation:** C17, OpenSSL 3.x, POSIX APIs  

> **Project change:** Changed project from **Secure File Encryption and Management System** to **Secure Password Manager**.

## 1. Scope and current status

The project is a local command-line password manager. Each application user has an encrypted vault containing credential records. A master password is used to authenticate the user and unlock the vault. Stored passwords are never written to disk in plaintext and are never printed in cleartext by the interface.

Checkpoint 1 is a design checkpoint. The repository contains the planned architecture, threat model, cryptographic and vault-format decisions, a Makefile, and a small buildable CLI skeleton. Authentication, encryption, and vault operations are intentionally left for Checkpoint 2.

### In scope

- master-password authentication;
- encrypted credential storage;
- add, list, retrieve, update, and delete credential records;
- per-user ownership on every record operation;
- secure memory handling for passwords and keys;
- strict input and length validation;
- safe local file handling;
- structured audit logging without secrets;
- generic user-facing security errors.

### Out of scope

- network access, remote synchronization, or a web service;
- browser extensions;
- password sharing between users;
- recovery of a forgotten master password;
- protection from a compromised OS kernel, root/administrator, or a debugger with permission to read this process;
- guaranteed physical erasure from SSD snapshots, backups, or copy-on-write storage.

## 2. Security objectives and assets

The main assets are:

- master password;
- Vault Master Key (VMK) and other derived keys;
- stored credentials (service, username, password, notes);
- encrypted vault files;
- authentication metadata in `users.db`;
- per-user ownership metadata;
- audit log.

The security objectives are:

- **Confidentiality:** credential plaintext must only be available after successful authentication.
- **Integrity:** unauthorized modification of a vault must be detected.
- **Authentication:** a user must prove knowledge of the correct master password before a vault is unlocked.
- **Authorization:** authentication does not give access to every vault; ownership is checked on every protected operation.
- **Availability / fail-secure behavior:** malformed, truncated, or tampered data must cause a controlled failure rather than a crash or unsafe fallback.

## 3. Architecture

```text
                         +----------------------+
                         |   User / Terminal    |
                         +----------+-----------+
                                    |
                       untrusted input / hidden
                       master-password prompt
                                    |
                                    v
+------------------------------------------------------------------+
|                    APPLICATION PROCESS                           |
|                                                                  |
|  +-------------+     +----------------+     +-----------------+  |
|  | Interactive | --> | Input          | --> | User Management |  |
|  | CLI         |     | Validation     |     | / Authentication|  |
|  +-------------+     +----------------+     +--------+--------+  |
|                                                     |            |
|                                            authenticated session |
|                                                     v            |
|                                           +---------+----------+ |
|                                           | Vault Manager      | |
|                                           +----+----------+----+ |
|                                                |          |      |
|                                      +---------+--+   +---+----+ |
|                                      | Crypto     |   | Audit  | |
|                                      | Module     |   | Logger | |
|                                      +---------+--+   +---+----+ |
+------------------------------------------------|----------|------+
                                                 |          |
                                     ciphertext  |          | events
                                                 v          v
+------------------------------------------------------------------+
|                         STORAGE                                  |
|   users.db        vaults/<user-id>.vault        audit.log        |
+------------------------------------------------------------------+
```

### Components and data flow

**Interactive CLI**  
Provides a small session-based interface. The master password is read interactively with terminal echo disabled. It is never accepted through command-line arguments or environment variables.

**Input validation**  
Validates command syntax, usernames, labels, field lengths, record identifiers, and serialized length fields. The design uses allow-lists and explicit upper bounds instead of trying to remove a list of "bad" characters.

**User management / authentication**  
Loads non-secret authentication metadata for the selected user, derives key material from the entered master password, verifies the stored authentication verifier in constant time, and creates an authenticated in-memory session.

**Vault manager**  
Implements add/list/show/copy/update/delete operations and checks ownership before every protected operation.

**Crypto module**  
Uses OpenSSL high-level APIs only. No custom cryptographic primitive will be implemented.

**Storage layer**  
Stores non-secret authentication metadata and one encrypted vault per application user. Internal vault filenames are generated by the application, not from usernames or credential labels.

**Audit logger**  
Records security-relevant events and outcomes without recording passwords, credentials, encryption keys, or decrypted vault data.

## 4. Trust boundaries and secure defaults

1. **Terminal -> application:** every command and text field is untrusted input.
2. **Authenticated user -> protected records:** authentication and authorization are separate; every protected operation checks the current owner/session.
3. **Application -> filesystem:** filesystem objects may be replaced or redirected, so sensitive I/O should use descriptor-based checks and restrictive permissions.
4. **Process memory -> persistent storage:** plaintext master passwords, VMK, KEK, and decrypted credentials must never cross this boundary.

The application follows fail-safe defaults: authentication failure, RNG failure, invalid permissions, invalid vault structure, failed GCM authentication, or unexpected I/O causes the operation to fail rather than continue with reduced security.

## 5. Master password and key hierarchy

The master password is never stored. The initial key design is:

```text
Master password
      |
      v
scrypt(password, per-user salt, versioned parameters)
      |
      v
32-byte root key
      |
      +------------------------+
      |                        |
      v                        v
HKDF("securepm/auth")      HKDF("securepm/kek")
      |                        |
      v                        v
   K_auth                     KEK
      |                        |
      v                        v
authentication verifier   unwrap/wrap random VMK
                               |
                               v
                         256-bit random VMK
                               |
                               v
                         AES-256-GCM vault
```

### Password KDF

The planned password KDF is **scrypt** through OpenSSL. Parameters are stored with the user record so they can be changed later. The initial implementation will use an OWASP-style memory-hard configuration and benchmark it on the clean target environment before the parameters are frozen.

Using separate HKDF contexts for authentication and key encryption keeps the two purposes cryptographically separated even though they originate from the same password-derived root key.

### Authentication verifier

A verifier derived from `K_auth` is stored in `users.db`. On login the program recomputes the verifier and compares it with a constant-time comparison such as `CRYPTO_memcmp()`. Unknown-user and wrong-password failures use the same generic user-facing message.

### Vault Master Key

The **VMK** is a random 256-bit key generated with OpenSSL CSPRNG. It encrypts the credential vault. The VMK is encrypted (wrapped) under the password-derived KEK and is not stored in plaintext.

This design allows a future master-password change to re-wrap the VMK instead of decrypting and re-encrypting every credential record.

## 6. Vault encryption and format

### Cryptographic scheme

- vault encryption: **AES-256-GCM**;
- VMK: 32 bytes;
- nonce: fresh random 12-byte value for every vault encryption;
- authentication tag: 16 bytes;
- randomness: OpenSSL `RAND_bytes()`, with return values checked;
- relevant non-secret header fields are authenticated as AAD;
- GCM authentication must succeed before decrypted data is accepted.

A nonce is never intentionally reused with the same VMK.

### Planned vault file

```text
MAGIC / format version
cipher identifier
user_id
generation
nonce
ciphertext_length
ciphertext
GCM authentication tag
```

The encrypted plaintext contains length-prefixed credential records:

```text
record_count

record:
    record_id
    label_length
    username_length
    password_length
    notes_length
    label
    username
    password
    notes
```

All counts and lengths are checked before arithmetic, allocation, or copying. Truncated files, impossible lengths, integer overflow, unknown versions, and inconsistent record sizes are rejected.

## 7. Persistent storage

Planned layout:

```text
~/.securepm/                    0700
├── users.db                    0600
├── audit.log                   0600
└── vaults/                     0700
    └── <random-user-id>.vault  0600
```

The process will use a restrictive `umask(077)` while creating private data.

Usernames and credential labels are data, not internal filesystem paths. Application-generated user IDs are used for vault filenames.

Vault updates are planned as an atomic replacement:

```text
encrypt new vault in memory
        |
        v
create private unpredictable temporary ciphertext file
        |
        v
write -> fsync -> close
        |
        v
atomic rename over the previous vault
```

No plaintext temporary vault file is needed. Security-sensitive opens will prefer `open()/openat()`, `O_CLOEXEC`, `O_EXCL`, `O_NOFOLLOW` where available, and post-open `fstat()` checks to reduce symlink and TOCTOU risks.

## 8. Planned CLI

The application is session based so the master password is not repeatedly exposed through command-line arguments.

```text
$ ./securepm

1. Create user
2. Login
3. Exit

Username: ayaz
Master password: ********

securepm> add
securepm> list
securepm> show <record-id>
securepm> copy <record-id>
securepm> update <record-id>
securepm> delete <record-id>
securepm> lock
securepm> help
securepm> exit
```

`show` displays non-secret metadata and masks the stored password. `copy` is planned as the password-retrieval mechanism so the interface does not print stored passwords in cleartext. Clipboard lifetime/clearing will be treated as an implementation and testing concern because clipboard contents are another temporary secret.

## 9. Threat model

| ID | Required area | Threat | Intended mitigation | Planned verification |
|---|---|---|---|---|
| T01 | Master password | Password leaks through shell history or process list | Hidden interactive prompt; never accept secrets in `argv`, environment variables, config files, or logs | Inspect shell history and `ps` while logging in |
| T02 | Master password | Offline guessing after theft of `users.db` | Unique random salt + memory-hard scrypt + versioned work parameters | Inspect stored auth record; benchmark KDF |
| T03 | Master password | Username enumeration through different login errors | Same generic user-facing failure for unknown user and wrong password | Compare failure messages |
| T04 | Vault at rest | Attacker steals the vault file | AES-256-GCM under a random VMK; restrictive filesystem permissions | `strings`/hex inspection must not expose credentials |
| T05 | Vault at rest | Ciphertext/header is modified or truncated | GCM tag verification, authenticated header fields, strict format parser, fail closed | Flip/truncate bytes and verify unlock fails safely |
| T06 | Vault at rest | GCM nonce reuse | Fresh 96-bit random nonce on every encryption; checked RNG result | Save repeatedly and compare nonces |
| T07 | Vault in memory | Passwords or keys remain in memory after use | Mutable secret buffers, short lifetime, centralized cleanup, `OPENSSL_cleanse`/secure clear before free | Unit tests around cleanup paths; sanitizer runs |
| T08 | Vault in memory | Crash/error path skips secret cleanup | Single cleanup path for sensitive functions; no plaintext temp vault | Force errors and review cleanup paths |
| T09 | Interface | Oversized/off-by-one/null-termination input corrupts memory | Explicit field limits, checked arithmetic, bounded reads, explicit lengths, safe termination | Test empty, MAX-1, MAX, MAX+1 and very large input |
| T10 | Interface | Format-string input reads/writes process memory | Never use user-controlled data as a format string; compile with format warnings | Inputs such as `%x%x%n` are treated only as data |
| T11 | Access control | User accesses another user's records/vault | Stable user ID + ownership check on every protected operation | Create two users and attempt cross-user access |
| T12 | File I/O | Path traversal, symlink, hard-link, or TOCTOU redirects internal storage | Internal filenames not user-controlled; private directory; descriptor-based validation; atomic operations | Traversal/symlink/race-oriented negative tests |
| T13 | Logging | Secrets appear in audit logs or errors | Allow-list of log fields; generic user-facing errors; never pass secret buffers to logger | Search logs for test passwords and key material |
| T14 | Interface | Clipboard exposes a retrieved password longer than necessary | Copy only on explicit request; planned short clipboard lifetime/clear; never log copied data | Clipboard behavior tested separately |
| T15 | Availability | Malformed serialized lengths cause overflow, huge allocation, or crash | Validate length/count before arithmetic and allocation; global vault/field limits | Malformed-vault and boundary tests; fuzz parser |

### Residual risks

- A root/administrator attacker or debugger able to inspect this process can read live secrets.
- Weak master passwords remain guessable even with a strong KDF.
- Clipboard managers may retain copied passwords outside this application's control.
- Rollback to an older but otherwise valid encrypted vault is not fully prevented by the initial design.
- Physical erasure from SSD snapshots/backups is outside the application's guarantees.

## 10. Secure coding rules used by this project

The implementation will follow the concepts covered in the course materials:

- **Week 1 — secure SDLC:** security requirements and threat modelling are done before implementing the crypto/storage code; later checkpoints add security testing and code review.
- **Week 1 — authentication vs authorization:** login verifies identity; every record operation separately checks ownership.
- **Week 1 — CIA / fail securely / defense in depth:** encryption, integrity checking, access control, filesystem permissions, validation, and testing are separate layers.
- **Week 2 — economy of mechanism:** local CLI, one crypto library, one encrypted vault per user; no network service or unnecessary framework.
- **Week 2 — fail-safe defaults:** deny access and reject data whenever authentication, parsing, RNG, integrity, or I/O validation fails.
- **Week 2 — complete mediation:** authorization is checked on every protected record operation.
- **Week 2 — least privilege:** private `0700/0600` storage and no unnecessary elevated privileges.
- **Week 2 — threat modelling / misuse cases:** assets and attack scenarios are converted into mitigations and later negative tests.
- **Week 3 — secure file I/O:** internal paths are application controlled; symlink, traversal, race, temporary-file, and TOCTOU behavior are considered explicitly.
- **Week 4 — strings and input validation:** explicit size limits, checked arithmetic, correct null termination, and boundary testing prevent common C string mistakes.
- **Week 4 — format strings:** user-controlled strings are always passed as data, e.g. `printf("%s", value)`, never as the format string itself.

Examples of functions/patterns to avoid with untrusted data include unbounded `strcpy`, `strcat`, `sprintf`, `gets`, and `printf(variable)`. Bounded operations are still checked for truncation and null-termination edge cases rather than assumed safe automatically.

## 11. Logging and error handling

Planned structured audit events include:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
VAULT_UNLOCKED
VAULT_LOCKED
ENTRY_CREATED
ENTRY_UPDATED
ENTRY_DELETED
VAULT_INTEGRITY_FAILURE
```

Example non-secret fields:

```text
timestamp=<UTC> event=<event> user=<internal-id-or-unknown> source=local outcome=<success|failure>
```

The audit log must never contain a master password, stored credential password, root key, K_auth, KEK, VMK, decrypted vault content, or clipboard content.

## 12. Implementation choice and repository structure

### Why C17

C exposes the memory, buffer, string, and file-I/O concerns studied in the course and allows sensitive buffers to be explicitly managed and cleared.

### Why OpenSSL 3.x

OpenSSL provides established implementations for CSPRNG, scrypt, HKDF, HMAC, constant-time comparison helpers, and AES-GCM. The project uses high-level OpenSSL APIs rather than implementing cryptographic primitives.

### Planned repository structure

```text
.
├── README.md
├── Checkpoint_1.md
├── Makefile
├── .gitignore
├── include/
│   ├── auth.h
│   ├── crypto.h
│   ├── input.h
│   ├── secure_mem.h
│   ├── storage.h
│   ├── vault.h
│   └── audit.h
├── src/
│   ├── main.c
│   ├── auth.c
│   ├── crypto.c
│   ├── input.c
│   ├── secure_mem.c
│   ├── storage.c
│   ├── vault.c
│   └── audit.c
└── tests/
```

Only the minimal CLI skeleton is required to exist at Checkpoint 1. Modules are added incrementally in later checkpoints rather than filled with fake implementations.

## 13. Build and run

Current Checkpoint 1 skeleton:

```bash
make
./securepm --help
```

Development build with sanitizers:

```bash
make debug
```

Cleanup:

```bash
make clean
```

The Makefile enables strict warnings. The debug target enables AddressSanitizer and UndefinedBehaviorSanitizer so memory and undefined-behavior defects can be found during implementation.

## 14. Checkpoint roadmap

### Checkpoint 1 — current

- architecture and data flow;
- master-password/key hierarchy;
- vault format and cryptographic scheme;
- threat model covering master password, vault at rest, vault in memory, and interface;
- README and initialized buildable repository.

### Checkpoint 2

- create-user/login and master-password verification;
- basic encrypted vault storage;
- add/list/show/copy/update/delete operations;
- credentials encrypted at rest;
- interface never prints stored passwords in cleartext;
- clean-machine build/run instructions and incremental commits.

### Checkpoint 3

- secure-memory handling audit;
- full validation/sanitization on all fields;
- structured logging and secure generic errors;
- ownership enforcement on every record operation;
- unit/integration/negative tests;
- malformed-vault and boundary tests;
- ASan/UBSan and static-analysis review;
- draft final report.

## 15. Adversarial demonstration checklist

The project will be prepared for a reviewer to actively try unsafe inputs even though this is not treated as a separate documented Checkpoint 1 requirement. Before the final presentation I plan to verify at least:

- wrong master password and unknown username;
- `%x%x%n` and other format-string-looking input;
- `../`, separators, control characters, and very long input;
- empty, MAX-1, MAX, and MAX+1 fields;
- modified, truncated, and malformed vault files;
- corrupted length/count fields;
- repeated vault saves use different nonces;
- symlink/path-manipulation attempts against application storage;
- cross-user record access;
- secrets absent from `users.db`, vault plaintext inspection, process arguments, and logs;
- failure/crash paths do not replace a valid vault with a partial write;
- clean build with warnings enabled;
- AddressSanitizer/UndefinedBehaviorSanitizer runs.
