#!/usr/bin/env python3
"""Apple fsck/readback and subsequent writes to actual portable recovery output."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from encrypted_output import disk_hash
from hfs_header_growth import attach
from image_mutation import writable_copy
from image_repacking import Commands, files, version
from verify_preservation import require


def compare(actual, expected):
    observed = {entry['path']: entry for entry in actual['entries']}
    wanted = {entry['path']: entry for entry in expected['entries']}
    require(set(observed) == set(wanted), 'recovered namespace')
    for path, entry in wanted.items():
        for key in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                    'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if key in entry:
                require(observed[path].get(key) == entry[key], f'{path} {key}: {observed[path].get(key)} != {entry[key]}')


def check(image, expected, work, command, modify=False):
    mount = work / (image.stem + '-mount')
    mount.mkdir()
    device = attach(image, command, readonly=not modify, writable=modify)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        command('diskutil', 'mount', *([] if modify else ['readOnly']),
                '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
        compare(files(mount / 'Fixture'), expected)
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
        if modify:
            # Exercise live journaling, allocation and shared-inode contents
            # after Go recovery, without using a Go writer for expectations.
            (mount / 'Fixture/alias').write_bytes(b'Native write after journal recovery\n')
            require((mount / 'Fixture/retained').read_bytes() == (mount / 'Fixture/alias').read_bytes(),
                    'native continuation retains hard-link identity')
            directory = mount / 'Fixture/native-after-recovery'
            directory.mkdir()
            for index in range(48):
                (directory / str(index)).write_bytes(bytes(8193))
            for index in range(0, 48, 2):
                (directory / str(index)).unlink()
            (directory / 'reuse').write_bytes(bytes(65537))
    finally:
        command('hdiutil', 'detach', device)


def verify(expected_major, references, outputs, diagnostics):
    require_disposable_host()
    version(expected_major)
    manifest = json.loads((references / 'recovery.json').read_text())
    require(manifest['complete'] and manifest['major'] == expected_major and len(manifest['cases']) == 4,
            'complete recovery reference corpus')
    diagnostics.mkdir(parents=True)
    command = Commands(diagnostics / 'commands.json')
    names = set()
    with tempfile.TemporaryDirectory(prefix='verify-hfs-recovery-') as temporary:
        work = Path(temporary)
        for case in manifest['cases']:
            for format_name in ('UDRO', 'UDZO'):
                name = case['id'] + '-' + format_name + '.dmg'
                image = outputs / name
                names.add(name)
                before = sha256(image)
                check(image, case['recovered']['files'], work, command)
                require(sha256(image) == before, 'native readback changed portable evidence')
                if format_name == 'UDRO':
                    raw = work / (case['id'] + '-continued.raw')
                    writable_copy(image, raw, command, disk_hash)
                    check(raw, case['recovered']['files'], work, command, modify=True)
                    device = attach(raw, command, readonly=True)
                    try:
                        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
                    finally:
                        command('hdiutil', 'detach', device)
                # Portable mutation after recovery has its own actual output.
                # Only the shared inode's mode and ctime change.
            edited = outputs / (case['id'] + '-edited.dmg')
            names.add(edited.name)
            expected = json.loads(json.dumps(case['recovered']['files']))
            for entry in expected['entries']:
                if entry['path'] in ('Fixture/retained', 'Fixture/alias'):
                    entry['mode'] = entry['mode'] & ~0o7777 | 0o600
                    entry['changeNS'] = 1749283750 * 1000000000
            check(edited, expected, work, command)
    require({path.name for path in outputs.glob('*.dmg')} == names, 'exact portable output inventory')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--diagnostics', type=Path, required=True)
    arguments = parser.parse_args()
    verify(arguments.expected_major, arguments.references, arguments.outputs, arguments.diagnostics)
