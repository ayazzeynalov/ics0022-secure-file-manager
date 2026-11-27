#!/usr/bin/env python3
"""Active account revalidation with isolated synthetic vaults."""
import os
import tempfile
from pathlib import Path
from test_session_snapshot import Dialog, MASTER, SECRET, check, replace_vault


def register(d, name):
    d.answer(b'Choice: ', b'1')
    d.answer(b'Username: ', name)
    d.answer(b'Master password: ', MASTER)
    d.answer(b'Confirm master password: ', MASTER)
    d.expect(rb'User created\.')


def main():
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-auth-', dir=parent) as temp:
        home = Path(temp).resolve()
        d = Dialog(home)
        try:
            register(d, b'SnapshotUser')
            d.login()
            d.add(b'ExistingRecord')
            vault, = (home / '.securepm/vaults').glob('*.vault')
            original = vault.read_bytes()
            db = home / '.securepm/users.db'
            initial_db = db.read_bytes()
            other = Dialog(home)
            try:
                register(other, b'OtherUser')
                other.answer(b'Choice: ', b'3')
                other.finish()
            finally:
                other.close()
            current_db = db.read_bytes()
            d.answer(b'Choice: ', b'2')
            record_id = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: ExistingRecord').group(1)
            check(current_db != initial_db, 'other account registration preserves active session')
            d.expect(rb'Choice: ')
            db.unlink()
            os.write(d.fd, b'2\n')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(not db.exists() and vault.read_bytes() == original,
                  'deleted user database locks session without recreating files')
            replace_vault(db, current_db)
            d.login()
            d.expect(rb'Choice: ')
            replace_vault(db, current_db + b'X')
            os.write(d.fd, b'2\n')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(db.read_bytes() == current_db + b'X', 'malformed database rejected without overwrite')
            replace_vault(db, current_db)
            d.login()
            d.answer(b'Choice: ', b'3')
            d.answer(b'Record ID: ', record_id)
            d.expect(rb'Type yes to copy password: ')
            # First record's tag is the last 16 bytes of the original one-record DB.
            changed = bytearray(current_db)
            changed[len(initial_db) - 1] ^= 1
            replace_vault(db, changed)
            os.write(d.fd, b'yes\n')
            d.expect(rb'Password could not be copied\.')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(b'Password copied.' not in d.transcript, 'changed account record prevents clipboard copy')
            replace_vault(db, current_db)
            d.login()
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', b'UnfinishedRecord')
            d.answer(b'Credential username: ', b'dummy-user')
            d.answer(b'Credential password: ', SECRET)
            d.expect(rb'Notes \(optional\): ')
            replace_vault(db, changed)
            os.write(d.fd, b'notes\n')
            d.expect(rb'Credential could not be saved\.')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(vault.read_bytes() == original, 'changed account record prevents vault update')
            check(db.read_bytes() == changed, 'modified database not silently repaired')
            replace_vault(db, current_db)
            d.login()
            d.answer(b'Choice: ', b'2')
            d.expect(rb'Label: ExistingRecord')
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(True, 'restored database supports reauthentication; no secret output')
        finally:
            d.close()
    print('FINAL: PASS — active-session authentication tests')


if __name__ == '__main__':
    main()
