#!/usr/bin/env python3
"""Accelerated session timeout integration with synthetic credentials."""
import os
import tempfile
import termios
from pathlib import Path
from test_session_snapshot import Dialog, MASTER, check


def main():
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-idle-', dir=parent) as temp:
        home = Path(temp).resolve()
        os.environ['SECUREPM_TEST_IDLE_SECONDS'] = '2'
        d = Dialog(home)
        try:
            d.answer(b'Choice: ', b'1')
            d.answer(b'Username: ', b'SnapshotUser')
            d.answer(b'Master password: ', MASTER)
            d.answer(b'Confirm master password: ', MASTER)
            d.expect(rb'User created\.')
            d.login()
            d.add(b'ExistingRecord')
            vault, = (home / '.securepm/vaults').glob('*.vault')
            original = vault.read_bytes()
            d.expect(rb'Session timed out\. Vault locked\.')
            d.expect(rb'Secure Password Manager:')
            check(True, 'idle menu locks session')
            # Login again verifies that the previous lock was released.
            d.login()
            check(True, 'reauthentication after timeout succeeds')
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', b'UnfinishedRecord')
            d.answer(b'Credential username: ', b'dummy-user')
            d.expect(rb'Credential password: ')
            os.write(d.fd, b'partial-secret-not-submitted')
            d.expect(rb'Session timed out\. Vault locked\.')
            d.expect(rb'Secure Password Manager:')
            check(bool(termios.tcgetattr(d.fd)[3] & termios.ECHO), 'terminal echo restored')
            check(vault.read_bytes() == original, 'unfinished add leaves vault unchanged')
            d.login()
            d.answer(b'Choice: ', b'2')
            d.expect(rb'Label: ExistingRecord')
            check(True, 'existing record remains accessible after reauthentication')
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(b'partial-secret-not-submitted' not in d.transcript, 'partial secret absent from terminal')
        finally:
            d.close()
            os.environ.pop('SECUREPM_TEST_IDLE_SECONDS', None)
    print('FINAL: PASS — idle timeout regression tests')


if __name__ == '__main__':
    main()
