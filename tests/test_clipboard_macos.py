#!/usr/bin/env python3
"""Opt-in native macOS clipboard test. Overwrites clipboard with dummy data only."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import test_session_snapshot as snapshot
from test_session_snapshot import Dialog, MASTER, SECRET, check
from test_clipboard_expiry import copy

OTHER = b'SecurePM unrelated dummy clipboard text'


def read_clipboard():
    return subprocess.run(['/usr/bin/pbpaste', '-Prefer', 'txt'],
                          capture_output=True, check=True, timeout=5).stdout


def write_clipboard(data):
    subprocess.run(['/usr/bin/pbcopy'], input=data, check=True, timeout=5)


def main():
    if sys.platform != 'darwin' or sys.argv[1:] != ['--overwrite-clipboard']:
        raise SystemExit('macOS only; pass --overwrite-clipboard to opt in.')
    snapshot.PROGRAM = Path('securepm').resolve()
    if not snapshot.PROGRAM.is_file():
        raise SystemExit('Run from repository root after make.')
    with tempfile.TemporaryDirectory(prefix='securepm-native-clipboard-',
                                     dir='/private/tmp') as temp:
        d = Dialog(Path(temp).resolve())
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
            check(read_clipboard() == SECRET, 'native clipboard receives exact dummy bytes')
            deadline = time.monotonic() + 38
            print('Checking production expiry (30 seconds); do not use the clipboard.', flush=True)
            while time.monotonic() < deadline and read_clipboard() == SECRET:
                time.sleep(0.5)
            check(read_clipboard() == b'', 'native clipboard clears after timeout')
            copy(d, record_id)
            write_clipboard(OTHER)
            d.answer(b'Choice: ', b'6')
            d.expect(rb'Vault locked\.')
            d.expect(rb'Choice: ')
            check(read_clipboard() == OTHER, 'unrelated clipboard survives lock')
            # Login prompt was consumed above; send choice directly.
            os.write(d.fd, b'2\n')
            d.answer(b'Username: ', b'SnapshotUser')
            d.answer(b'Master password: ', MASTER)
            d.expect(rb'Login successful\.')
            copy(d, record_id)
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(read_clipboard() == b'', 'native clipboard clears on exit')
            check(SECRET not in d.transcript and MASTER not in d.transcript,
                  'dummy secrets absent from terminal transcript')
        finally:
            d.close()
            # Do not overwrite any unrelated user content if the test fails.
            if read_clipboard() in (SECRET, OTHER):
                write_clipboard(b'')
    print('FINAL: PASS — native macOS clipboard lifecycle')


if __name__ == '__main__':
    main()
