#!/usr/bin/env python3
"""Linux-only observation of synthetic data in the test child's heap/stack."""
import os
import sys
import tempfile
from pathlib import Path

import test_session_snapshot as ts
from test_session_auth import register


def count_marker(pid, marker):
    count = 0
    regions = set()
    with open(f'/proc/{pid}/maps') as maps, open(f'/proc/{pid}/mem', 'rb', buffering=0) as mem:
        for line in maps:
            fields = line.split()
            if fields[-1] not in ('[heap]', '[stack]'):
                continue
            lo, hi = (int(value, 16) for value in fields[0].split('-'))
            if hi - lo > 64 * 1024 * 1024:
                raise RuntimeError('Memory region exceeds inspection limit')
            mem.seek(lo)
            data = mem.read(hi - lo)
            if len(data) != hi - lo:
                raise RuntimeError('Incomplete memory read')
            count += data.count(marker)
            regions.add(fields[-1])
    if regions != {'[heap]', '[stack]'}:
        raise RuntimeError('Expected heap and stack mappings not found')
    return count


def main():
    if sys.platform != 'linux':
        raise SystemExit('Linux /proc is required for this optional experiment.')
    ts.PROGRAM = Path('securepm').resolve()
    marker = b'UniqueMemoryProbe-' + os.urandom(16).hex().encode()
    with tempfile.TemporaryDirectory(prefix='securepm-memory-') as home:
        d = ts.Dialog(Path(home))
        try:
            register(d, b'SnapshotUser')
            d.login()
            d.answer(b'Choice: ', b'1')
            d.answer(b'Label: ', b'MemoryProbe')
            d.answer(b'Credential username: ', b'dummy')
            d.answer(b'Credential password: ', marker)
            d.expect(rb'Notes \(optional\): ')
            ts.check(count_marker(d.pid, marker) > 0, 'positive control: dummy credential observed during operation')
            os.write(d.fd, b'notes\n')
            d.expect(rb'Credential added\.')
            d.expect(rb'Choice: ')
            ts.check(count_marker(d.pid, marker) == 0, 'dummy credential absent from heap/stack after add')
            os.write(d.fd, b'2\n')
            d.expect(rb'Label: MemoryProbe')
            d.expect(rb'Choice: ')
            ts.check(count_marker(d.pid, marker) == 0, 'dummy credential absent from heap/stack after list')
            os.write(d.fd, b'6\n')
            d.expect(rb'Vault locked\.')
            d.expect(rb'Choice: ')
            ts.check(count_marker(d.pid, marker) == 0, 'dummy credential absent from heap/stack after lock')
            os.write(d.fd, b'3\n')
            d.finish()
            ts.check(marker not in d.transcript, 'dummy credential absent from terminal transcript')
        finally:
            d.close()
    print('FINAL: PASS — scoped Linux memory observation')


if __name__ == '__main__':
    main()
