#!/usr/bin/env python3
"""Check every portable DMG with Apple tools and independent mounted observations.

Expected values come only from native source captures. Native inode numbers may
change during construction; the path-to-inode relationship must remain bijective.
Every output image is checked without repair and attached read-only. No Go runs.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import tempfile

from capture import observe_files, native_xattrs, sha256
from preservation import digest_values
from verify_preservation import require
from metadata_edits import birth_ns


def built_devices(attached, apfs, command):
    entries = [e for e in attached['system-entities'] if 'dev-entry' in e]
    if not apfs:
        require(len(entries) == 1, 'one bare HFS volume')
        return entries[0]['dev-entry'], entries[0]['dev-entry']
    volumes = [e['dev-entry'] for e in entries if e.get('volume-kind') == 'apfs']
    require(len(volumes) == 1, 'one APFS volume')
    details = plistlib.loads(command('diskutil', 'info', '-plist', volumes[0]))
    stores = details['APFSPhysicalStores']
    require(len(stores) == 1, 'one APFS physical store')
    device = '/dev/' + stores[0]['APFSPhysicalStore']
    require(device in [e['dev-entry'] for e in entries], 'physical store belongs to attached image')
    return device, volumes[0]


def verify(image, expected, sensitive, command, apfs=False, empty=False):
    before = sha256(image)
    image_info = plistlib.loads(command('hdiutil', 'imageinfo', '-plist', image))
    require(image_info['Format'] == image.stem, 'requested DMG encoding')
    command('hdiutil', 'verify', image)
    attached = plistlib.loads(command('hdiutil', 'attach', '-readonly', '-nomount', '-plist', image))
    device = attached['system-entities'][0]['dev-entry']
    temporary = tempfile.TemporaryDirectory(prefix="apfs-build-readback-")
    try:
        device, volume = built_devices(attached, apfs, command)
        if apfs:
            command('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '-n', device.replace('/dev/disk', '/dev/rdisk'))
        else:
            command('/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        mount = Path(temporary.name) / "mount"
        mount.mkdir()
        command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, volume)
        info = plistlib.loads(command('diskutil', 'info', '-plist', volume))
        require(info['VolumeName'] == 'Example', 'volume name')
        require(info['TotalSize'] == (64 if empty else 160 if sensitive else 8) * 1024 * 1024, 'volume capacity')
        require(('case-sensitive' in info['FilesystemName'].lower()) == sensitive, 'case policy')
        require(info['FilesystemType'] == ('apfs' if apfs else 'hfs'), 'filesystem kind')
        require(not info['WritableVolume'] and os.statvfs(mount).f_flag & os.ST_RDONLY, 'read-only native mount')
        # Capture the root under the same logical spelling as the input tree.
        actual = observe_files(mount)
        for entry in actual['entries']:
            entry['path'] = 'Fixture' + entry['path'][len(mount.name):]
        want = {e['path']: e for e in expected['entries']}
        got = {e['path']: e for e in actual['entries']}
        require(set(got) == set(want), f'exact directory tree: missing={set(want)-set(got)}, extra={set(got)-set(want)}')
        raw = {e['object']: e['attributes'] for e in expected['rawAttributes']}
        forward, reverse = {}, {}
        for path, entry in want.items():
            result = got[path]
            for key in ('mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS', 'changeNS', 'accessNS', 'attributes'):
                require(result[key] == entry[key], f'{image.name}: {path}: {key}: {result[key]} != {entry[key]}')
            if not stat.S_ISDIR(entry['mode']):
                for key in ('size', 'links', 'sha256', 'target'):
                    require(result.get(key) == entry.get(key), f'{path}: {key}')
            old, new = entry['object'], result['object']
            require(forward.setdefault(old, new) == new and reverse.setdefault(new, old) == old, f'{path}: link identity')
            source = mount if path == 'Fixture' else mount / path.removeprefix('Fixture/')
            require(birth_ns(source) == entry['birthNS'], f'{path}: exact birth nanoseconds')
            require(digest_values(native_xattrs(source, 0x21)) == raw[old], f'{path}: raw attributes/forks')
        if apfs and not empty:
            require(len(expected.get('lookups', [])) == 53, 'native name lookup inventory')
            for query in expected['lookups']:
                source = mount / query['path'].removeprefix('Fixture/')
                try:
                    actual_id = source.lstat().st_ino
                except FileNotFoundError:
                    actual_id = 0
                require(actual_id == (forward[query['object']] if query['object'] else 0), f'native lookup: {query["path"]}')
        if not empty:
            command('codesign', '--verify', '--deep', '--strict', mount / 'Example.app')
    finally:
        try:
            command('hdiutil', 'detach', device)
        finally:
            temporary.cleanup()
    require(sha256(image) == before, 'native readback modified output image')
    if apfs:
        verify_native_allocation(image, command, empty)
        require(sha256(image) == before, 'native allocation changed the original image')
    return before, len(want)


def verify_native_allocation(image, command, empty=False):
    """Apple writes only a disposable shadow, then checks and remounts that state."""
    with tempfile.TemporaryDirectory(prefix='apfs-build-allocation-') as work:
        work = Path(work)
        mount = work / 'mount'; mount.mkdir()
        shadow = work / 'writes.shadow'
        def mount_image(readonly=False):
            result = plistlib.loads(command('hdiutil', 'attach', '-plist', '-nobrowse', '-owners', 'off',
                                            *(['-readonly'] if readonly else []), '-shadow', shadow,
                                            '-mountpoint', mount, image))
            return built_devices(result, True, command)[0]
        device = mount_image()
        payload = bytes(range(256)) * 2048
        try:
            root = mount / 'native-allocation'; root.mkdir()
            original = root / 'grow'
            original.write_bytes(payload)
            os.link(original, root / 'alias')
            with original.open('ab') as stream:
                stream.write(payload)
                stream.flush(); os.fsync(stream.fileno())
            original.rename(root / 'renamed')
            require((root / 'alias').read_bytes() == payload * 2, 'native hard-link growth')
            (root / 'alias').unlink()
            for i in range(96):
                (root / f'entry-{i:03}').write_bytes(payload[:4096])
            for i in range(0, 96, 2):
                (root / f'entry-{i:03}').unlink()
            # Reuse space freed by both data and tree records.
            (root / 'reused').write_bytes(payload)
        finally:
            command('hdiutil', 'detach', device)
        # Check the shadow's new checkpoint while unmounted, before final readback.
        attached = plistlib.loads(command('hdiutil', 'attach', '-readonly', '-nomount', '-plist', '-shadow', shadow, image))
        device, _ = built_devices(attached, True, command)
        try:
            command('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '-n', device.replace('/dev/disk', '/dev/rdisk'))
        finally:
            command('hdiutil', 'detach', device)
        device = mount_image(readonly=True)
        try:
            root = mount / 'native-allocation'
            require((root / 'renamed').read_bytes() == payload * 2, 'native growth survives remount')
            require((root / 'reused').read_bytes() == payload, 'native reuse survives remount')
            require(not (root / 'alias').exists(), 'native unlink survives remount')
            for i in range(96):
                path = root / f'entry-{i:03}'
                require(path.read_bytes() == payload[:4096] if i % 2 else not path.exists(), 'native create/delete survives remount')
            if not empty:
                command('codesign', '--verify', '--deep', '--strict', mount / 'Example.app')
        finally:
            command('hdiutil', 'detach', device)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, choices=[15, 26, 27], required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    args = parser.parse_args()
    require(platform.system() == 'Darwin', 'Apple verification requires macOS')
    require(int(subprocess.check_output(['sw_vers', '-productVersion'], text=True).split('.')[0]) == args.expected_major, 'wrong macOS verifier')
    transcript = []
    args.outputs.mkdir(parents=True, exist_ok=True)
    def command(*argv):
        print('verify:', *map(str, argv), flush=True)
        record = {'argv': list(map(str, argv)), 'status': 'started'}
        transcript.append(record)
        def save():
            (args.outputs / f'image-building-{args.expected_major}.diagnostics.json').write_text(json.dumps(transcript, indent=2) + '\n')
        save()
        try:
            r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
        except BaseException as error:
            record.update(status='failed', error=str(error)); save(); raise
        record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace')); save()
        require(r.returncode == 0, f'command failed: {argv}: {r.stdout.decode(errors="replace")} {r.stderr.decode(errors="replace")}')
        return r.stdout
    total = 0
    for major in args.producers.split(','):
        corpus = args.corpus / f'macos-{major}'
        manifest = json.loads((corpus / 'manifest.json').read_text())
        require(manifest['schema'] == 1 and manifest['scenario'] == 'image-building', 'corpus schema')
        require(manifest['producer']['version'].split('.')[0] == major, 'source macOS version')
        require({c['id'] for c in manifest['cases']} == {'image-building/' + name for name in ('apfs', 'apfs-case-sensitive', 'hfsplus', 'hfsx')}, 'case inventory')
        for case in manifest['cases']:
            require(sha256(corpus / case['image']) == case['sha256'], 'source image digest')
            require(sha256(corpus / case['files']) == case['filesSHA256'], 'native observation digest')
            expected = json.loads((corpus / case['files']).read_text())
            case_id = case['id'].split('/')[1]
            for encoding in ('UDRO', 'UDZO'):
                digests = []
                for consumer in args.consumers.split(','):
                    image = args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id / (encoding + '.dmg')
                    digest, entries = verify(image, expected, case['expected']['caseSensitive'], command, case['expected']['filesystem'] == 'APFS')
                    digests.append(digest); total += entries
                require(len(set(digests)) == 1, f'{case_id}/{encoding}: hosts produced different image bytes')
            if case_id == 'apfs':
                entry = next(e for e in expected['entries'] if e['path'] == 'Fixture/empty-build-root')
                empty = {'entries': [dict(entry, path='Fixture')],
                         'rawAttributes': [a for a in expected['rawAttributes'] if a['object'] == entry['object']]}
                digests = []
                for consumer in args.consumers.split(','):
                    image = args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id / 'empty/UDZO.dmg'
                    digest, entries = verify(image, empty, False, command, True, True)
                    digests.append(digest); total += entries
                require(len(set(digests)) == 1, 'empty APFS: hosts produced different image bytes')
    print(f'Apple image checks, filesystem checks, exact mounted readback and signature verification passed: {total} entries.')


if __name__ == '__main__':
    main()
