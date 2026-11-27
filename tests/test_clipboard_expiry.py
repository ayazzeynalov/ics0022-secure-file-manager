#!/usr/bin/env python3
"""Clipboard lifecycle integration with a dummy clipboard in a private temp directory."""
import os
import tempfile
import time
from pathlib import Path
from test_session_snapshot import Dialog, MASTER, SECRET, check


def wait_for_value(path, expected, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists() and path.read_bytes() == expected:
            return True
        time.sleep(0.05)
    return False


def copy(d, record_id):
    d.answer(b'Choice: ', b'3')
    d.answer(b'Record ID: ', record_id)
    d.answer(b'Type yes to copy password: ', b'yes')
    d.expect(rb'Password copied\.')


def main():
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-clipboard-', dir=parent) as temp:
        home = Path(temp).resolve()
        path = home / 'dummy-clipboard'
        os.environ['SECUREPM_TEST_CLIPBOARD_FILE'] = str(path)
        d = Dialog(home)
        try:
            d.answer(b'Choice: ', b'1')
            d.answer(b'Username: ', b'SnapshotUser')
            d.answer(b'Master password: ', MASTER)
            d.answer(b'Confirm master password: ', MASTER)
            d.expect(rb'User created\.')
            d.login()
            d.add(b'ClipboardRecord')
            d.answer(b'Choice: ', b'2')
            record_id = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: ClipboardRecord').group(1)
            copy(d, record_id)
            check(path.read_bytes() == SECRET, 'dummy clipboard receives exact bytes')
            check(wait_for_value(path, b''), 'clipboard expires while waiting at the menu')
            copy(d, record_id)
            path.write_bytes(b'new unrelated text')
            time.sleep(3)
            check(path.read_bytes() == b'new unrelated text', 'replacement clipboard survives expiry')
            copy(d, record_id)
            d.answer(b'Choice: ', b'6')
            d.expect(rb'Vault locked\.')
            check(wait_for_value(path, b''), 'clipboard cleared on session lock')
            d.login()
            copy(d, record_id)
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(path.read_bytes() == b'', 'clipboard cleared on exit')
            check(SECRET not in d.transcript and MASTER not in d.transcript,
                  'dummy secrets absent from terminal transcript')
        finally:
            d.close()
            os.environ.pop('SECUREPM_TEST_CLIPBOARD_FILE', None)
    print('FINAL: PASS — clipboard lifecycle tests')


if __name__ == '__main__':
    main()
