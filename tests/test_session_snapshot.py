#!/usr/bin/env python3
"""Regression tests for in-session vault rollback; synthetic data only."""
import errno
import os
import pty
import re
import select
import signal
import subprocess
import tempfile
import time
from pathlib import Path

MASTER = b'SnapshotMaster2026!'
SECRET = b'SnapshotDummySecret123'
PROGRAM = Path('build/securepm_test').resolve()


class Dialog:
    def __init__(self, home):
        self.buffer = b''
        self.transcript = bytearray()
        self.reaped = False
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                env = dict(os.environ, HOME=str(home),
                           SECUREPM_TEST_CLIPBOARD_EXPECTED=SECRET.decode())
                os.execve(str(PROGRAM), [str(PROGRAM)], env)
            finally:
                os._exit(127)

    def read(self, timeout):
        if not select.select([self.fd], [], [], max(0, timeout))[0]:
            return None
        try:
            data = os.read(self.fd, 8192)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            return b''
        self.transcript.extend(data)
        return data

    def expect(self, pattern):
        deadline = time.monotonic() + 30
        while True:
            match = re.search(pattern, self.buffer)
            if match:
                self.buffer = self.buffer[match.end():]
                return match
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f'Timeout waiting for {pattern!r}')
            data = self.read(remaining)
            if data is None or not data:
                raise RuntimeError(f'No output waiting for {pattern!r}')
            self.buffer += data

    def answer(self, prompt, value):
        self.expect(re.escape(prompt))
        os.write(self.fd, value + b'\n')

    def finish(self):
        deadline = time.monotonic() + 15
        pty_open = True
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.reaped = True
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    raise RuntimeError(f'Unexpected exit status: {status}')
                if MASTER in self.transcript or SECRET in self.transcript:
                    raise RuntimeError('Test secret appeared in terminal transcript')
                return
            if pty_open:
                data = self.read(0.1)
                if data == b'':
                    pty_open = False
            else:
                time.sleep(0.05)
        raise RuntimeError('Application did not exit')

    def close(self):
        if not self.reaped:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(self.pid, 0)
        os.close(self.fd)

    def login(self):
        self.answer(b'Choice: ', b'2')
        self.answer(b'Username: ', b'SnapshotUser')
        self.answer(b'Master password: ', MASTER)
        self.expect(rb'Login successful\.')

    def add(self, label):
        self.answer(b'Choice: ', b'1')
        self.answer(b'Label: ', label)
        self.answer(b'Credential username: ', b'dummy-user')
        self.answer(b'Credential password: ', SECRET)
        self.answer(b'Notes (optional): ', b'dummy notes')
        self.expect(rb'Credential added\.')


def replace_vault(path, data):
    fd, name = tempfile.mkstemp(prefix='snapshot-test-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def check(condition, name):
    if not condition:
        raise RuntimeError('FAIL: ' + name)
    print('PASS: ' + name, flush=True)


def main():
    if not PROGRAM.is_file() or not Path('build/test_clipboard_sink').is_file():
        raise SystemExit('Run from repository root after make test.')
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-snapshot-', dir=parent) as temp:
        home = Path(temp).resolve()
        d = Dialog(home)
        try:
            d.answer(b'Choice: ', b'1')
            d.answer(b'Username: ', b'SnapshotUser')
            d.answer(b'Master password: ', MASTER)
            d.answer(b'Confirm master password: ', MASTER)
            d.expect(rb'User created\.')
            d.login()
            d.add(b'FirstRecord')
            vaults = list((home / '.securepm/vaults').glob('*.vault'))
            check(len(vaults) == 1, 'one isolated vault created')
            vault = vaults[0]
            older = vault.read_bytes()
            d.add(b'SecondRecord')
            newer = vault.read_bytes()
            check(older != newer, 'two different valid encrypted snapshots')
            d.answer(b'Choice: ', b'2')
            first_id = d.expect(rb'ID: ([0-9a-f]{32}) \| Label: FirstRecord').group(1)
            d.expect(rb'Label: SecondRecord')
            check(True, 'legitimate changes accepted between operations')
            d.expect(rb'Choice: ')
            replace_vault(vault, older)
            os.write(d.fd, b'2\n')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(True, 'valid older vault rejected during active session')
            d.answer(b'Choice: ', b'3')
            d.finish()
            check(vault.read_bytes() == older, 'rollback not silently overwritten')
        finally:
            d.close()

        replace_vault(vault, newer)
        d = Dialog(home)
        try:
            d.login()
            d.answer(b'Choice: ', b'3')
            d.answer(b'Record ID: ', first_id)
            d.expect(rb'Type yes to copy password: ')
            replace_vault(vault, older)
            os.write(d.fd, b'yes\n')
            d.expect(rb'Password could not be copied\.')
            check(True, 'vault replacement during confirmation prevents copy')
            d.answer(b'Choice: ', b'2')
            d.expect(rb'Vault is unavailable\. Session locked\.')
            check(True, 'subsequent operation locks changed vault')
            d.answer(b'Choice: ', b'3')
            d.finish()
            check(vault.read_bytes() == older, 'copy failure does not alter vault')
            check(b'Password copied.' not in d.transcript, 'no successful copy after substitution')
            check(True, 'test secrets absent from terminal output')
        finally:
            d.close()
    print('FINAL: PASS — session snapshot regression tests', flush=True)


if __name__ == '__main__':
    main()
