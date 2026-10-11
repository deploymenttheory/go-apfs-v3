#!/usr/bin/env python3
"""Independent native qualification of portable edits to existing HFS images."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from hfs_editing import STAMP, read_journal
from hfs_header_growth import Commands, attach, read_headers
from image_repacking import files, version
from image_mutation import writable_copy
from verify_preservation import require


def compare(actual, expected, phase):
    observed = {entry['path']: entry for entry in actual['entries']}
    want = {entry['path']: entry for entry in expected['entries']}
    require(set(observed) == set(want), 'existing paths preserved')
    changed = {'Fixture/alias', 'Fixture/fragmented-data', 'Fixture/small',
               'Fixture/inline-compressed', 'Fixture/resource-compressed'}
    if phase == 'final':
        changed |= {'Fixture/fragmented-resource', 'Fixture/empty', 'Fixture/independent'}
    for path, entry in want.items():
        got = observed[path]
        entry = dict(entry)
        if path in changed:
            entry['changeNS'] = STAMP * 1000000000
        for key in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                    'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if key in entry:
                require(got.get(key) == entry[key], f'{path} {key}: {got.get(key)} != {entry[key]}')


def native_hash(image, command):
    from encrypted_output import disk_hash
    return disk_hash(image, command)


def check_raw(raw, expected, phase, command, work, modify=False, journal=None):
    before = sha256(raw)
    if journal is not None:
        observed = read_journal(raw)
        require(observed is not None, 'journaling retained')
        for key in ('infoBlock', 'offset', 'size', 'sha256', 'infoSHA256'):
            require(observed[key] == journal[key], 'journal storage preserved: ' + key)
    device = attach(raw, command, readonly=not modify, writable=modify)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        headers = read_headers(raw, raw.stat().st_size)
        require(headers['primary']['forks'] == headers['alternate']['forks'], 'both headers agree')
        mount = work / 'mount'
        mount.mkdir()
        command('diskutil', 'mount', *([] if modify else ['readOnly']), '-mountOptions',
                'owners,noatime', '-mountPoint', mount, device)
        compare(files(mount / 'Fixture'), expected, phase)
        if journal is not None:
            for name, file in journal['backingFiles'].items():
                st = os.lstat(mount / name)
                require(st.st_ino == file['object'] and st.st_size == file['size'], 'journal backing identity')
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
        if modify:
            with (mount / 'Fixture/alias').open('ab') as stream:
                stream.write(b'native continuation\n')
                stream.flush()
                os.fsync(stream.fileno())
            require((mount / 'Fixture/fragmented-data').read_bytes() == (mount / 'Fixture/alias').read_bytes(),
                    'native writes retain shared inode')
            # Native tree growth, deletion and allocation reuse after Go edits.
            directory = mount / 'Fixture/native-created'
            directory.mkdir()
            for i in range(96):
                (directory / (f'{i:03d}-' + 'x' * 100)).write_bytes(bytes(8193))
            for i in range(0, 96, 2):
                (directory / (f'{i:03d}-' + 'x' * 100)).unlink()
            (directory / 'reused').write_bytes(bytes(65537))
    finally:
        command('hdiutil', 'detach', device)
    if journal is not None:
        observed = read_journal(raw)
        require(observed is not None and observed['start'] == observed['end'], 'journaling survives native unmount')
        if modify:
            require(observed['sha256'] != journal['sha256'], 'native continuation actually updates journal')
    if not modify:
        require(sha256(raw) == before, 'native read-only verification changed raw copy')
    shutil.rmtree(work / 'mount')


def verify(corpus, outputs, continuation, expected_major, journaled=False):
    require_disposable_host()
    version(expected_major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'hfs-editing-{expected_major}.diagnostics.json')
    with tempfile.TemporaryDirectory(prefix='hfs-edit-readback-') as tmp:
        work = Path(tmp)
        count = 0
        for manifest_path in sorted(corpus.glob('macos-*/manifest.json')):
            manifest = json.loads(manifest_path.read_text())
            require(manifest['contract'] == ('journaled-hfs-file-edits' if journaled else 'existing-hfs-file-edits'),
                    'native corpus journal profile')
            for case in manifest['cases']:
                for phase in ('peak', 'final'):
                    for format_name in ('UDRO', 'UDZO'):
                        relative = Path(manifest_path.parent.name, case['id'], phase + '-' + format_name + '.dmg')
                        images = [outputs / (('hfs-journaled-edits-' if journaled else 'hfs-edits-') + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        require(all(image.is_file() for image in images), 'every portable host supplies edited images')
                        require(len({sha256(image) for image in images}) == 1, 'host-independent deterministic image bytes')
                        image = images[0]
                        source_hash = sha256(image)
                        command('hdiutil', 'verify', image)
                        raw = work / 'output.raw'
                        writable_copy(image, raw, command, native_hash)
                        check_raw(raw, case['states'][phase]['files'], phase, command, work, journal=case['before'].get('journal'))
                        if phase == 'final' and format_name == 'UDZO':
                            check_raw(raw, case['states'][phase]['files'], phase, command, work, modify=True, journal=case['before'].get('journal'))
                            device = attach(raw, command, readonly=True)
                            try:
                                command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
                                mount = work / 'remount'
                                mount.mkdir()
                                command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
                                require((mount / 'Fixture/alias').read_bytes().endswith(b'native continuation\n'), 'native append survives remount')
                                require(len(list((mount / 'Fixture/native-created').iterdir())) == 49, 'native allocation/tree edits survive remount')
                                command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
                            finally:
                                command('hdiutil', 'detach', device)
                            shutil.rmtree(work / 'remount')
                            shutil.copyfile(raw, continuation / (manifest_path.parent.name + '-' + case['id'] + '.raw'))
                        raw.unlink()
                        require(sha256(image) == source_hash, 'native verification changed portable output')
                        count += 1
        require(count == 24, 'complete native edit readback inventory')


def verify_continued(directory, expected_major, journaled=False):
    require_disposable_host()
    version(expected_major)
    command = Commands(directory / f'continued-{expected_major}.diagnostics.json')
    images = list(directory.glob('*.dmg'))
    require(len(images) == 6, 'complete Go/native/Go continuation inventory')
    with tempfile.TemporaryDirectory(prefix='continued-hfs-readback-') as tmp:
        work = Path(tmp)
        for image in images:
            raw = work / 'continued.raw'
            writable_copy(image, raw, command, native_hash)
            require((read_journal(raw) is not None) == journaled, 'Go re-edit retains journal profile')
            device = attach(raw, command, readonly=True)
            try:
                command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
                mount = work / 'mount'
                mount.mkdir()
                command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
                from hfs_editing import payload
                require((mount / 'Fixture/alias').read_bytes() == payload('continued-go', 8193), 'Go re-edit survives Apple readback')
                require((mount / 'Fixture/fragmented-data').read_bytes() == (mount / 'Fixture/alias').read_bytes(), 'continued alias identity')
                require(len(list((mount / 'Fixture/native-created').iterdir())) == 49, 'native-created entries preserved by Go re-edit')
                command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
            finally:
                command('hdiutil', 'detach', device)
            shutil.rmtree(work / 'mount')
            raw.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--outputs', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--continued', type=Path)
    parser.add_argument('--journaled', action='store_true')
    args = parser.parse_args()
    if args.continued:
        verify_continued(args.continued, args.expected_major, args.journaled)
    else:
        verify(args.corpus, args.outputs, args.continuation, args.expected_major, args.journaled)
