# ICS0022 Secure File Manager

Semester project for **ICS0022 Secure Programming** at Tallinn University of Technology.

## Scope

This project implements a command-line **Secure File Encryption and Management System** in C. The goal is to let authenticated application users encrypt, list, decrypt, and delete their own stored files while applying secure-programming practices to authentication, cryptography, memory handling, file I/O, input validation, access control, logging, and error handling.

The project is intentionally a local CLI application. It does not expose a network service and does not implement a GUI.

## Current status

**Checkpoint 1 — threat model and architecture.**

The repository currently contains the project design, threat model, build skeleton, and a minimal executable that exposes the planned command interface. Cryptographic and authentication functionality is planned for Checkpoint 2 and is **not yet implemented**.

See [`docs/checkpoint1-design.md`](docs/checkpoint1-design.md) for the architecture, trust boundaries, assets, threat model, and planned mitigations.

## Planned security goals

- Protect stored file contents from disclosure.
- Detect modification of encrypted files before plaintext is accepted.
- Authenticate users without storing plaintext passwords.
- Enforce per-user ownership for every stored-file operation.
- Keep passwords and encryption keys out of logs and persistent plaintext storage.
- Reject unsafe file types and unsafe path operations.
- Reduce symlink, path-traversal, TOCTOU, overwrite, and permission risks.
- Use generic user-facing errors while retaining non-sensitive structured audit information.
- Avoid plaintext temporary files where possible and clear sensitive memory after use.

## Planned commands

Passwords will be entered interactively and will **never** be accepted as command-line arguments.

```text
securefm init
securefm create-user <username>
securefm encrypt <username> <source-path> <alias>
securefm decrypt <username> <alias> <output-path>
securefm list <username>
securefm delete <username> <alias>
securefm --help
```

The exact CLI may be refined during implementation, but the operations above define the intended scope.

## Planned implementation

- **Language:** C17
- **Cryptographic library:** OpenSSL 3.x EVP API
- **Target platforms:** Unix-like systems (developed on macOS; intended to remain portable to Linux)
- **Build tool:** Make
- **File handling:** POSIX file-descriptor APIs where security-sensitive behavior requires flags and post-open validation

The planned cryptographic design uses AES-256-GCM for authenticated file encryption, OpenSSL CSPRNG facilities for salts/nonces, and PBKDF2-HMAC-SHA256 for password-based derivation. Authentication and file-encryption derivation use separate salts. Parameters will be stored with the relevant metadata so that they can be upgraded later.

## Repository structure

```text
.
├── README.md
├── Makefile
├── docs/
│   └── checkpoint1-design.md
└── src/
    └── main.c
```

Additional modules and tests will be introduced incrementally as the project reaches Checkpoints 2 and 3.

## Build

A C17 compiler and `make` are sufficient for the current Checkpoint 1 skeleton.

```bash
make
```

This produces:

```text
./securefm
```

For a development build with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make debug
```

OpenSSL development headers/libraries will become a build dependency when cryptographic functionality is added in Checkpoint 2.

## Run

```bash
./securefm --help
```

At Checkpoint 1, commands other than help intentionally report that implementation is not complete yet.

## Clean

```bash
make clean
```

## Project roadmap

- **Checkpoint 1:** architecture, trust boundaries, threat model, implementation choices, README, build skeleton.
- **Checkpoint 2:** working CLI, file encryption/decryption, authentication, first-level input validation, reproducible build/run instructions.
- **Checkpoint 3:** secure memory handling, full validation/sanitization, structured logging, per-user access control, tests, near-final report.

## Course requirement mapping

The design is based on the ICS0022 Project 1 requirements. Industry readings supplied in the course (SDL/SSDLC/OWASP SAMM/DevSecOps material) are used as guidance for secure development, but they are not treated as additional mandatory product features.
