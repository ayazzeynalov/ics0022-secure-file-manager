#!/usr/bin/env python3
"""Exercise byte limits, UTF-8 roundtrip and literal format strings."""
import os
import tempfile
import termios
from pathlib import Path
import test_session_snapshot as snapshot
from test_session_snapshot import Dialog, check
from test_session_auth import register
from test_clipboard_expiry import copy


def main():
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-input-', dir=parent) as tmp:
        home = Path(tmp).resolve()
        path = home / 'dummy-clipboard'
        os.environ['SECUREPM_TEST_CLIPBOARD_FILE'] = str(path)
        snapshot.SECRET = ('əõ€🔑' * 93 + 'x').encode('utf-8')  # 1024 bytes
        assert len(snapshot.SECRET) == 1024
        d = Dialog(home)
        try:
            register(d, b'SnapshotUser')
            d.login()
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', 'õ'.encode() * 64 + b'x')
            d.expect(rb'Input too long\.')
            check(True, '129-byte multibyte label rejected')
            label = b'Format_%s_%x_%n_%p'
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', label)
            d.answer(b'Credential username: ', b'dummy-user')
            d.expect(rb'Credential password: ')
            flags = termios.tcgetattr(d.fd)[3]
            check(not flags & (termios.ICANON | termios.ECHO),
                  'password prompt bypasses canonical limit with echo disabled')
            os.write(d.fd, snapshot.SECRET + b'x\n')
            d.expect(rb'Input too long\.')
            check(True, '1025-byte password rejected')
            d.add(label)
            d.answer(b'Choice: ', b'2')
            rid = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: Format_%s_%x_%n_%p').group(1)
            check(True, 'format specifiers printed literally')
            copy(d, rid)
            check(path.read_bytes() == snapshot.SECRET, '1024-byte UTF-8 password copied exactly')
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', b'OversizedNotes')
            d.answer(b'Credential username: ', b'dummy-user')
            d.answer(b'Credential password: ', snapshot.SECRET)
            d.answer(b'Notes (optional): ', b'n' * 1025)
            d.expect(rb'Input too long\.')
            check(True, '1025-byte notes rejected')
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', 'õ'.encode() * 64)
            d.answer(b'Credential username: ', b'dummy-user')
            d.answer(b'Credential password: ', snapshot.SECRET)
            d.answer(b'Notes (optional): ', b'n' * 1024)
            d.expect(rb'Credential added\.')
            d.answer(b'Choice: ', b'2')
            notes_id = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: ' + rb'\\xc3\\xb5' * 64).group(1)
            check(True, '128-byte UTF-8 label accepted and safely escaped')
            d.answer(b'Choice: ', b'3')
            d.answer(b'Record ID: ', notes_id)
            d.expect(rb'Notes: ' + b'n' * 1024 + rb'\r?\n')
            check(True, '1024-byte notes stored exactly')
            d.answer(b'Type yes to copy password: ', b'no')
            d.answer(b'Choice: ', b'7')
            d.finish()
            check(path.read_bytes() == b'', 'clipboard cleared on exit')
        finally:
            d.close()
            os.environ.pop('SECUREPM_TEST_CLIPBOARD_FILE', None)
    print('FINAL: PASS — input boundary tests')


if __name__ == '__main__':
    main()
