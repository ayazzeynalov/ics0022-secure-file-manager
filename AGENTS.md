# Development guidelines

This is the ICS0022 Secure Password Manager, despite the repository's historical
file-manager name. Preserve the Checkpoint 1 architecture documented in README.md.

- Use C17 and OpenSSL 3.x. Keep functions small, responsibilities separate, and
  filenames and identifiers descriptive. Follow the existing four-space indentation
  and brace style. Comment non-obvious behavior and security decisions.
- Keep CLI dispatch in `cli.c`; keep security-sensitive operations out of the CLI.
  Add the planned modules in README.md only when implementing their behavior.
- Validate input lengths, ranges, and formats. Check return values and handle
  errors and cleanup explicitly. Avoid unsafe string operations and unchecked sizes.
- Never print, log, or hardcode passwords or encryption keys. Never accept secrets
  in command-line arguments. Clear sensitive buffers using an appropriate secure
  clearing API when they are no longer needed.
- Use established OpenSSL APIs; never implement custom cryptographic algorithms.
  Preserve scrypt, HKDF-SHA256 key separation, AES-256-GCM, and the random 256-bit
  VMK protected by a password-derived key.
- Keep vault data out of version control. Use restrictive storage permissions.
- Add tests for implemented behavior, including invalid input and failure paths.
  Do not present scaffolding or smoke tests as proof of cryptographic security.
- Before committing, run `make clean && make`, `./securepm --help`, and `make test`;
  check compiler diagnostics and review the diff. Keep commits focused. Do not push
  to `main` or merge without explicit authorization.

The supplied checkpoint sheet defines deliverables but provides no instructor C
examples or additional coding conventions.
