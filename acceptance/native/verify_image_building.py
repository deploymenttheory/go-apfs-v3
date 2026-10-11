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
import container_building as containers
import encrypted_output
import compression_output
import image_capacity
from image_outputs import verify_identical_outputs


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


def verify_capacity(size, sensitive, empty):
    if empty or sensitive:
        require(size == (64 if empty else 160) * 1024 * 1024, 'requested volume capacity')
    else:
        # This profile deliberately exercises automatic sizing. Added ordinary
        # input bytes can grow it beyond the shared 8 MiB minimum.
        require(8 * 1024 * 1024 <= size <= 1 << 40 and size % 4096 == 0, 'automatic volume capacity')


def verify(image, expected, sensitive, command, apfs=False, empty=False, file_compression=None):
    containers.require_disposable_host()
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
        verify_capacity(info['TotalSize'], sensitive, empty)
        require(('case-sensitive' in info['FilesystemName'].lower()) == sensitive, 'case policy')
        require(info['FilesystemType'] == ('apfs' if apfs else 'hfs'), 'filesystem kind')
        require(not info['WritableVolume'] and os.statvfs(mount).f_flag & os.ST_RDONLY, 'read-only native mount')
        entries = verify_mounted(mount, expected, command, empty, 53 if apfs and not empty else 0, file_compression)
    finally:
        try:
            command('hdiutil', 'detach', device)
        finally:
            temporary.cleanup()
    require(sha256(image) == before, 'native readback modified output image')
    if apfs or file_compression:
        verify_native_allocation(image, command, empty, apfs, file_compression)
        require(sha256(image) == before, 'native allocation changed the original image')
    return before, entries


def verify_mounted(mount, expected, command, empty=False, lookup_count=0, file_compression=None):
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
            if file_compression and key in ('flags','attributes') and stat.S_ISREG(entry['mode']):
                continue
            require(result[key] == entry[key], f'{mount}: {path}: {key}: {result[key]} != {entry[key]}')
        if not stat.S_ISDIR(entry['mode']):
            for key in ('size', 'links', 'sha256', 'target'):
                require(result.get(key) == entry.get(key), f'{path}: {key}')
        old, new = entry['object'], result['object']
        require(forward.setdefault(old, new) == new and reverse.setdefault(new, old) == old, f'{path}: link identity')
        source = mount if path == 'Fixture' else mount / path.removeprefix('Fixture/')
        require(birth_ns(source) == entry['birthNS'], f'{path}: exact birth nanoseconds')
        if file_compression and stat.S_ISREG(entry['mode']):
            compression_output.verify(source, entry, result, raw[old], file_compression)
        else:
            require(digest_values(native_xattrs(source, 0x21)) == raw[old], f'{path}: raw attributes/forks')
    if lookup_count:
        require(len(expected.get('lookups', [])) == lookup_count, 'native name lookup inventory')
        for query in expected['lookups']:
            source = mount / query['path'].removeprefix('Fixture/')
            try:
                actual_id = source.lstat().st_ino
            except FileNotFoundError:
                actual_id = 0
            require(actual_id == (forward[query['object']] if query['object'] else 0), f'native lookup: {query["path"]}')
    if not empty:
        command('codesign', '--verify', '--deep', '--strict', mount / 'Example.app')
    return len(want)


def verify_native_allocation(image, command, empty=False, apfs=True, file_compression=None):
    """Apple writes only a disposable shadow, then checks and remounts that state."""
    containers.require_disposable_host()
    with tempfile.TemporaryDirectory(prefix='apfs-build-allocation-') as work:
        work = Path(work)
        mount = work / 'mount'; mount.mkdir()
        shadow = work / 'writes.shadow'
        def mount_image(readonly=False):
            result = plistlib.loads(command('hdiutil', 'attach', '-plist', '-nobrowse', '-owners', 'off',
                                            *(['-readonly'] if readonly else []), '-shadow', shadow,
                                            '-mountpoint', mount, image))
            return built_devices(result, apfs, command)[0]
        device = mount_image()
        payload = bytes(range(256)) * 2048
        compression_payload = None
        try:
            if file_compression:
                compression_payload = compression_output.mutate(mount)
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
        device, _ = built_devices(attached, apfs, command)
        try:
            if apfs:
                command('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '-n', device.replace('/dev/disk', '/dev/rdisk'))
            else:
                command('/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        finally:
            command('hdiutil', 'detach', device)
        device = mount_image(readonly=True)
        try:
            if compression_payload:
                compression_output.verify_mutated(mount, compression_payload)
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


def verify_container(image, expected, case_id, command):
    containers.require_disposable_host()
    before = sha256(image)
    require(plistlib.loads(command('hdiutil', 'imageinfo', '-plist', image))['Format'] == image.stem,
            'requested container encoding')
    command('hdiutil', 'verify', image)
    total = 0
    with tempfile.TemporaryDirectory(prefix='apfs-container-readback-') as temporary:
        device, physical, inventory = containers.attached(image, command, readonly=True)
        try:
            containers.check_filesystem(physical, command)
            require(inventory['CapacityCeiling'] == expected['size'], 'shared container capacity')
            require(inventory['APFSContainerUUID'] == expected['containerUUID'], 'container UUID')
            require(len(inventory['Volumes']) == len(expected['volumes']), 'exact volume count')
            groups = plistlib.loads(command('diskutil', 'apfs', 'listVolumeGroups', '-plist',
                                           inventory['ContainerReference']))['Containers'][0].get('VolumeGroups', [])
            require(len(groups) == (1 if case_id == 'group' else 0), 'exact group count')
            for wanted in expected['volumes']:
                matches = [v for v in inventory['Volumes'] if v['APFSVolumeUUID'] == wanted['uuid']]
                require(len(matches) == 1, 'unique volume identity')
                volume = matches[0]
                for field, key in (('Name', 'name'), ('Roles', 'roles'), ('CapacityReserve', 'reserve'), ('CapacityQuota', 'quota')):
                    require(volume[field] == wanted[key], f'{wanted["name"]}: {key}')
                group = next((g['APFSVolumeGroupUUID'] for g in groups
                              if any(v['DeviceIdentifier'] == volume['DeviceIdentifier'] for v in g['Volumes'])), '')
                require(group == wanted['group'], 'native group membership')
                directory = Path(temporary) / wanted['name']
                containers.mount(volume, directory, command, readonly=True)
                info = plistlib.loads(command('diskutil', 'info', '-plist', volume['DeviceIdentifier']))
                require(('case-sensitive' in info['FilesystemName'].lower()) == wanted['sensitive'], 'per-volume case policy')
                require(not info['WritableVolume'] and os.statvfs(directory).f_flag & os.ST_RDONLY, 'read-only container mount')
                total += verify_mounted(directory, wanted['files'], command, wanted['empty'], 3)
        finally:
            command('hdiutil', 'detach', device)
    allocation = containers.native_allocation(image, case_id, command)
    require(allocation['independentWritesAndReuse'] == expected['allocation']['independentWritesAndReuse'] is True,
            'native independent writes and reuse')
    if case_id == 'shared':
        for control, maximum in (('quota', 16*containers.MIB), ('reserve', 64*containers.MIB)):
            # Physical allocation depends on metadata history. Both the native
            # reference and the fresh build must enforce the bounded policy.
            for result in (allocation, expected['allocation']):
                require(0 < result[control]['writtenBytes'] < maximum, 'native bounded space enforcement')
                require(result[control]['errno'] in (containers.errno.EDQUOT, containers.errno.ENOSPC), 'native space error')
    require(sha256(image) == before, 'container verification changed source image')
    return before, total



def verify_containers(corpus, outputs, major, consumers, command):
    corpus = corpus / 'containers'
    manifest = json.loads((corpus / 'manifest.json').read_text())
    require(manifest['schema'] == 1 and manifest['scenario'] == 'image-building/containers', 'container corpus schema')
    require(manifest['producer']['version'].split('.')[0] == major, 'container producer version')
    require(len(manifest['cases']) == 2 and {c['id'] for c in manifest['cases']} == {'shared', 'group'}, 'container cases')
    total = 0
    for case in manifest['cases']:
        for name, digest in (('image', 'sha256'), ('observation', 'observationSHA256'),
                             ('groups', 'groupsSHA256'), ('inventory', 'inventorySHA256')):
            require(sha256(corpus / case[name]) == case[digest], 'container reference digest')
        expected = json.loads((corpus / case['observation']).read_text())
        for encoding in ('UDRO', 'UDZO'):
            images = [outputs / f'image-building-{consumer}' / f'macos-{major}' / 'containers' / case['id'] / (encoding + '.dmg')
                      for consumer in consumers]
            total += verify_identical_outputs(images, lambda image: verify_container(image, expected, case['id'], command))
            bits = encrypted_output.BUILD_PROFILES.get((case['id'], encoding))
            if bits:
                encrypted_output.verify(images, bits, command)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, choices=[15, 26, 27], required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    args = parser.parse_args()
    containers.require_disposable_host()
    require(platform.system() == 'Darwin', 'Apple verification requires macOS')
    require(int(subprocess.check_output(['sw_vers', '-productVersion'], text=True).split('.')[0]) == args.expected_major, 'wrong macOS verifier')
    transcript = []
    args.outputs.mkdir(parents=True, exist_ok=True)
    def command(*argv, fixture_input=None, expected_success=True):
        print('verify:', *map(str, argv), flush=True)
        record = {'argv': list(map(str, argv)), 'status': 'started', 'expectedSuccess': expected_success}
        transcript.append(record)
        def save():
            (args.outputs / f'image-building-{args.expected_major}.diagnostics.json').write_text(json.dumps(transcript, indent=2) + '\n')
        save()
        try:
            r = subprocess.run(list(map(str, argv)), input=fixture_input, capture_output=True, timeout=120)
        except BaseException as error:
            record.update(status='failed', error=str(error)); save(); raise
        record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace')); save()
        require(expected_success is None or (r.returncode == 0) == expected_success, f'command failed: {argv}: {r.stdout.decode(errors="replace")} {r.stderr.decode(errors="replace")}')
        if expected_success is None and r.returncode:
            return None
        return r.stdout
    image_capacity.compare(args.corpus, args.outputs, command, args.expected_major)
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
                images = [args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id / (encoding + '.dmg')
                          for consumer in args.consumers.split(',')]
                total += verify_identical_outputs(images, lambda image: verify(image, expected, case['expected']['caseSensitive'], command, case['expected']['filesystem'] == 'APFS'))
                bits = encrypted_output.BUILD_PROFILES.get((case_id, encoding))
                if bits:
                    encrypted_output.verify(images, bits, command)
            for policy in ('zlib', 'none'):
                encoding = 'UDZO' if case['expected']['caseSensitive'] else 'UDRO'
                images = [args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id /
                          'file-compression' / policy / (encoding + '.dmg') for consumer in args.consumers.split(',')]
                total += verify_identical_outputs(images, lambda image: verify(image, expected,
                    case['expected']['caseSensitive'], command, case['expected']['filesystem'] == 'APFS',
                    file_compression=policy))
            if case_id == 'apfs':
                entry = next(e for e in expected['entries'] if e['path'] == 'Fixture/empty-build-root')
                empty = {'entries': [dict(entry, path='Fixture')],
                         'rawAttributes': [a for a in expected['rawAttributes'] if a['object'] == entry['object']]}
                images = [args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id / 'empty/UDZO.dmg'
                          for consumer in args.consumers.split(',')]
                total += verify_identical_outputs(images, lambda image: verify(image, empty, False, command, True, True))
        total += verify_containers(corpus, args.outputs, major, args.consumers.split(','), command)
    print(f'Apple image checks, filesystem checks, exact mounted readback and signature verification passed: {total} entries.')


if __name__ == '__main__':
    main()
