#!/usr/bin/env python3
"""Apple references for larger and multiple-volume offline image editing.

The filesystem, before/after observations and checker results come from Apple.
This collector never runs Go and never constructs filesystem records.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile

from capture import sha256
from container_building import attached, check_filesystem, require_disposable_host
from hfs_header_growth import retain_file
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, version
from verify_preservation import require

SOURCES = ('phase5_capture.py', 'capture.py', 'container_building.py',
           'hfs_header_growth.py', 'image_mutation.py', 'image_repacking.py',
           'image_building.py', 'file_compression.py', 'verify_preservation.py',
           'preservation.py', 'metadata_edits.py', 'content_replacement.py',
           'snapshot_reading.py', 'apfs_editing.py')
PROFILES = (
    ('apfs-large', 1536 << 20, 'APFS', False),
    ('apfs-case-sensitive-large', 1536 << 20, 'APFSX', False),
    ('apfs-volumes', 768 << 20, 'APFS', True),
    ('apfs-case-sensitive-volumes', 768 << 20, 'APFSX', True),
)


def mounted(volume, path, command, readonly=False):
    require_disposable_host()
    path.mkdir()
    command('diskutil', 'mount', *(['readOnly'] if readonly else []),
            '-mountOptions', 'owners,noatime', '-mountPoint', path,
            volume['DeviceIdentifier'])


def create(root, command):
    # Darwin metadata bindings remain behind the disposable VM guard.
    from file_compression import RESOURCE, xattr
    from image_building import create_signed_app
    root.mkdir()
    (root / 'data').write_bytes(b'Original linked contents\n')
    os.link(root / 'data', root / 'alias')
    os.symlink('data', root / 'symlink')
    xattr(root / 'data', RESOURCE, b'Independent resource fork\x00\xff')
    xattr(root / 'data', 'org.go-apfs.retained', b'Opaque metadata\x00\xff')
    (root / 'mode').write_bytes(b'Permissions\n')
    os.chmod(root / 'mode', 0o644)
    create_signed_app(root, command)


def edit(root, command):
    from file_compression import xattr
    from metadata_edits import set_metadata
    data = (bytes(range(256)) * 257)[:65537]
    (root / 'alias').write_bytes(data)
    set_metadata(root / 'alias', {
        'modifyTime': {'value': '2025-06-07T08:09:10.000000000Z'}}, command)
    os.chmod(root / 'mode', 0o755)
    xattr(root / 'data', 'org.go-apfs.created', b'New attribute\x00\xff')
    (root / 'created').mkdir()
    (root / 'created/nested').write_bytes(b'New nested contents\n')
    (root / 'mode').rename(root / 'renamed')
    os.link(root / 'data', root / 'another-alias')


def observe(image, work, command, label):
    from image_repacking import files
    original = sha256(image)
    native = raw_command(command, image)
    cleanup, physical, inventory = attached(image, native, readonly=True)
    try:
        check_filesystem(physical, native)
        result = []
        for volume in inventory['Volumes']:
            path = work / (label + '-' + volume['Name'])
            mounted(volume, path, native, readonly=True)
            observed = files(path / 'Fixture')
            native('codesign', '--verify', '--deep', '--strict',
                   path / 'Fixture/Example.app')
            result.append({
                'name': volume['Name'], 'uuid': volume['APFSVolumeUUID'],
                'reserveBytes': volume.get('CapacityReserve', 0),
                'quotaBytes': volume.get('CapacityQuota', 0),
                'files': observed, 'checkerStatus': 0, 'signatureStatus': 0})
        return result
    finally:
        native('hdiutil', 'detach', cleanup)
        require(sha256(image) == original, 'native read-only observation changed source')


def capture_case(case_id, capacity, native_fs, multiple, work, output, command):
    image = work / (case_id + '.dmg')
    # diskutil accepts APFSX; hdiutil requires the filesystem display name.
    hdiutil_fs = 'Case-sensitive APFS' if native_fs == 'APFSX' else native_fs
    command('hdiutil', 'create', '-size', str(capacity), '-layout', 'NONE',
            '-fs', hdiutil_fs, '-volname', 'Primary', image)
    cleanup, _, inventory = attached(image, command)
    try:
        if multiple:
            command('diskutil', 'apfs', 'addVolume', inventory['ContainerReference'],
                    native_fs, 'Secondary', '-reserve', str(32 << 20),
                    '-quota', str(64 << 20), '-nomount')
            inventory = plistlib.loads(command(
                'diskutil', 'apfs', 'list', '-plist',
                inventory['ContainerReference']))['Containers'][0]
        for volume in inventory['Volumes']:
            path = work / (case_id + '-create-' + volume['Name'])
            mounted(volume, path, command)
            create(path / 'Fixture', command)
    finally:
        command('hdiutil', 'detach', cleanup)
    source = work / (case_id + '-source.raw')
    copy_disk(image, source, command)
    before = observe(source, work, command, case_id + '-before')
    retained_source = retain_file(source, output / (case_id + '-source.raw.gz'))
    edited = work / (case_id + '-after.raw')
    shutil.copyfile(source, edited)
    native = raw_command(command, edited)
    cleanup, _, inventory = attached(edited, native)
    target_name = 'Secondary' if multiple else 'Primary'
    try:
        volume = next(v for v in inventory['Volumes'] if v['Name'] == target_name)
        path = work / (case_id + '-native-edit')
        mounted(volume, path, native)
        edit(path / 'Fixture', native)
    finally:
        native('hdiutil', 'detach', cleanup)
    after = observe(edited, work, command, case_id + '-after')
    retained_after = retain_file(edited, output / (case_id + '-after.raw.gz'))
    require(sha256(source) == retained_source['uncompressedSHA256'],
            'native edit changed original evidence')
    return {'id': case_id, 'source': retained_source,
            'nativeAfter': retained_after, 'before': before, 'after': after,
            'targetVolume': target_name, 'capacityBytes': capacity,
            'operations': ['replace-through-alias', 'chmod', 'xattr-create',
                           'mkdir', 'create-file', 'rename', 'hard-link-create']}


def capture(major, output):
    require_disposable_host()
    producer = version(major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    for profile in PROFILES:
        # Keep large decoded images for only one case at a time.
        with tempfile.TemporaryDirectory(prefix='phase5-reference-') as tmp:
            cases.append(capture_case(*profile, Path(tmp), output, command))
        (output / 'capture-progress.json').write_text(json.dumps({
            'major': major, 'complete': False, 'cases': cases}, indent=2) + '\n')
    producer['tools'] = {name: sha256(Path(name)) for name in (
        '/usr/bin/hdiutil', '/usr/sbin/diskutil',
        '/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs')}
    producer['sources'] = {name: sha256(Path(__file__).with_name(name))
                           for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'contract': 'phase5-offline-editing', 'major': major,
                'producer': producer, 'cases': cases,
                'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
