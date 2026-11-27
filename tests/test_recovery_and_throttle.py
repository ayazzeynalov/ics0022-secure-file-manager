#!/usr/bin/env python3
"""Synthetic accounts only: restart throttling and offline backup recovery."""
import argparse
import os
import shutil
import tempfile
import time
from pathlib import Path
from test_session_snapshot import Dialog, MASTER, SECRET, check
from test_session_auth import register
from test_clipboard_expiry import copy


def failed_login(d, username):
    d.answer(b'Choice: ', b'2')
    d.answer(b'Username: ', username)
    d.expect(rb'Master password: ')
    start = time.monotonic()
    os.write(d.fd, b'WrongTestPassword!\n')
    d.expect(rb'Login failed\.')
    return time.monotonic() - start


def exit_main(d):
    d.answer(b'Choice: ', b'3')
    d.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempts', type=int, default=20, choices=range(4, 21), metavar='4..20')
    args = parser.parse_args()
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-recovery-', dir=parent) as temp:
        home = Path(temp).resolve() / 'home'
        home.mkdir(mode=0o700)
        d = Dialog(home)
        try:
            register(d, b'SnapshotUser')
            d.login()
            d.add(b'BackupRecord')
            d.answer(b'Choice: ', b'6')
            exit_main(d)
        finally:
            d.close()
        root = home / '.securepm'
        vault, = (root / 'vaults').glob('*.vault')
        db = root / 'users.db'
        original = vault.read_bytes()
        backup = Path(temp) / 'backup'
        backup.mkdir(mode=0o700)
        shutil.copy2(db, backup / db.name)
        shutil.copy2(vault, backup / vault.name)
        check(all(s not in f.read_bytes() for f in backup.iterdir() for s in (MASTER, SECRET)),
              'backup files do not contain exact synthetic plaintext secrets')
        d = Dialog(home)
        try:
            delays = []
            for i in range(args.attempts):
                delays.append(failed_login(d, b'SnapshotUser'))
                print(f'Attempt {i+1}: {delays[-1]:.3f} s', flush=True)
            floors = [0.5, 1.0] + [2.0] * (args.attempts - 2)
            check(all(t >= floor - 0.05 for t, floor in zip(delays, floors)),
                  'failed login delays respect configured minimums')
            exit_main(d)
        finally:
            d.close()
        d = Dialog(home)
        try:
            elapsed = failed_login(d, b'SnapshotUser')
            print(f'First failure after restart: {elapsed:.3f} s (counter is process-local)')
            check(elapsed >= 0.45, 'first failure after restart still delayed')
            d.login()
            d.answer(b'Choice: ', b'6')
            elapsed = failed_login(d, b'NonexistentUser')
            print(f'Failure after successful login (unknown account): {elapsed:.3f} s')
            check(elapsed >= 0.45, 'unknown account receives generic delayed failure')
            exit_main(d)
        finally:
            d.close()
        check(vault.read_bytes() == original, 'failed login attempts leave vault unchanged')
        db.unlink()
        vault.unlink()
        shutil.copy2(backup / db.name, db)
        shutil.copy2(backup / vault.name, vault)
        d = Dialog(home)
        try:
            d.login()
            d.answer(b'Choice: ', b'2')
            record_id = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: BackupRecord').group(1)
            copy(d, record_id)
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(True, 'restored database and vault unlock and copy exact dummy credential')
        finally:
            d.close()
    print('FINAL: PASS — recovery and login throttling checks')


if __name__ == '__main__':
    main()
