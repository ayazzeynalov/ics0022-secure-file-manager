#!/usr/bin/env python3
"""Check attribution, rotation and secret minimization in a disposable HOME."""
import json
import re
import tempfile
from pathlib import Path
from test_session_snapshot import Dialog, MASTER, SECRET, check, replace_vault
from test_session_auth import register


def main():
    parent = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'
    with tempfile.TemporaryDirectory(prefix='securepm-audit-', dir=parent) as tmp:
        home = Path(tmp).resolve()
        d = Dialog(home)
        try:
            register(d, b'SnapshotUser')
            register(d, b'OtherUser')
            d.answer(b'Choice: ', b'2')
            d.answer(b'Username: ', b'OtherUser')
            d.answer(b'Master password: ', b'WrongDummyPassword123')
            d.expect(rb'Login failed\.')
            d.login()
            d.add(b'PrivateLabel')
            d.answer(b'Choice: ', b'6')
            d.expect(rb'Vault locked\.')
            log = home / '.securepm/audit.log'
            raw = log.read_bytes()
            rows = [json.loads(line) for line in raw.splitlines()]
            ids = [r['actor_id'] for r in rows if r['event'] == 'user_registration' and r['outcome'] == 'success']
            check(len(ids) == 2 and ids[0] != ids[1] and all(re.fullmatch('[0-9a-f]{32}', i) for i in ids), 'distinct account IDs recorded')
            check(any(r['event'] == 'login' and r['outcome'] == 'failure' and r['actor_id'] is None for r in rows), 'failed authentication has no claimed actor')
            for event in ('login', 'vault_load', 'credential_create', 'session_lock'):
                check(any(r['event'] == event and r['outcome'] == 'success' and r['actor_id'] == ids[0] for r in rows), event + ' attributed to authenticated account')
            check(all(x not in raw for x in (MASTER, SECRET, b'PrivateLabel', b'SnapshotUser', b'OtherUser', b'WrongDummyPassword123')), 'no secret or username in audit log')
            # Fill with complete synthetic JSON records, not arbitrary junk.
            limit = 1024 * 1024
            line = raw.splitlines(keepends=True)[0]
            filled = line * (limit // len(line))
            # Guarantee the next record cannot fit.
            filled += b' ' * (limit - len(filled))
            replace_vault(log, filled)
            d.login()
            archive = log.with_name('audit.log.1')
            check(archive.read_bytes() == filled, 'full log archived without changing its bytes')
            check(0 < log.stat().st_size <= limit and archive.stat().st_size <= limit, 'both logs within configured limit')
            check(log.stat().st_mode & 0o777 == 0o600 and archive.stat().st_mode & 0o777 == 0o600, 'both logs have mode 0600')
            second = filled.replace(b'"success"', b'"failure"')
            check(len(second) == limit and second != filled, 'second synthetic full log differs')
            replace_vault(log, second)
            d.answer(b'Choice: ', b'6')
            d.expect(rb'Vault locked\.')
            check(archive.read_bytes() == second and log.stat().st_size < limit,
                  'second rotation replaces only the previous archive')
            # Refuse an unsafe archive destination instead of overwriting it.
            sentinel = home / 'outside-sentinel'
            sentinel.write_bytes(b'outside sentinel')
            archive.unlink()
            archive.symlink_to(sentinel)
            replace_vault(log, filled)
            d.login()
            check(log.read_bytes() == filled and archive.is_symlink() and
                  sentinel.read_bytes() == b'outside sentinel',
                  'unsafe archive leaves active log and symlink target unchanged')
            archive.unlink()
            d.answer(b'Choice: ', b'7')
            d.finish()
        finally:
            d.close()
    print('FINAL: PASS — audit attribution and rotation')


if __name__ == '__main__':
    main()
