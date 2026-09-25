# ICS0022 Secure Password Manager

Semester project for **ICS0022 Secure Programming**.

I originally selected the Secure File Manager project, but changed to **Secure Password Manager** for Checkpoint 1.

## Current stage

This repository is currently at **Checkpoint 1: threat model and architecture**.  
The program only contains a small CLI skeleton for now. The encrypted vault and authentication will be implemented in the next checkpoint.

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

## Build

Current Checkpoint 1 skeleton:

```bash
make
./securepm --help
```

Debug build:

```bash
make debug
```

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
└── src/
    └── main.c
```

More source files and tests will be added when the actual vault, authentication and input-handling code is implemented.
