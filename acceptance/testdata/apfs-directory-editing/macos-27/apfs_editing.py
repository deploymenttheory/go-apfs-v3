#!/usr/bin/env python3
"""Independent existing-APFS file edits, produced only on disposable macOS VMs.

Apple formats every source and records every expected state. No Go code supplies
the images, observations, checker outcomes or subsequent native modifications.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from capture import native_extents, sha256
from container_building import attached, check_filesystem, require_disposable_host
import file_compression as compression
from hfs_header_growth import retain_file
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, files, version
from verify_preservation import require

STAMP = 1749283750
CAPACITY = 128 << 20
SOURCES = ('apfs_editing.py', 'capture.py', 'container_building.py', 'file_compression.py',
           'hfs_header_growth.py', 'image_repacking.py', 'image_building.py',
           'image_mutation.py', 'verify_preservation.py', 'metadata_edits.py',
           'content_replacement.py', 'preservation.py')
PEAK = (('alias', 'grow', 20 << 20, False), ('small', 'small', 7000, False),
        ('inline-compressed', 'inline', 7000, False),
        ('resource-compressed', 'resource', 100000, False))
FINAL = (('fragmented-data', 'shrink', 513, False),
         ('fragmented-resource', 'fork', 131073, True), ('empty', 'empty', 0, False),
         ('independent', 'independent', 65537, False))


def mount(volume, directory, command, readonly=False):
    require_disposable_host()
    directory.mkdir()
    command('diskutil', 'mount', *(['readOnly'] if readonly else []),
            '-mountOptions', 'owners,noatime', '-mountPoint', directory, volume['DeviceIdentifier'])


def payload(label, size):
    pattern = bytes(range(256)) + label.encode() + b'\n'
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def write_payload(path, label, size):
    # Preserve pattern alignment across streaming writes.
    unit = bytes(range(256)) + label.encode() + b'\n'
    with open(path, 'wb') as stream:
        off = 0
        while off < size:
            take = min(size - off, 128 << 10)
            start = off % len(unit)
            data = (unit * ((start + take + len(unit) - 1) // len(unit)))[start:start + take]
            require(stream.write(data) == take, 'complete native payload write')
            off += take
        stream.flush()
        os.fsync(stream.fileno())


def create(root, command):
    from image_building import create_signed_app
    root.mkdir()
    for name in ('small', 'empty', 'independent', 'fragmented-data', 'fragmented-resource'):
        (root / name).write_bytes(b'existing data\n')
    compression.xattr(root / 'independent', compression.RESOURCE, b'Independent fork\x00\xff')
    compression.xattr(root / 'independent', 'org.go-apfs.retained', b'Opaque retained metadata\x00\xff')
    compression.install(root / 'inline-compressed', 3, compression.plain(1200),
                        payload=compression.encode(3, compression.plain(1200)))
    plain = compression.plain(65553)
    compression.install(root / 'resource-compressed', 4, plain,
                        blocks=[compression.encode(4, plain[i:i + 65536]) for i in range(0, len(plain), 65536)])
    os.link(root / 'fragmented-data', root / 'alias')
    os.symlink('fragmented-data', root / 'symlink')
    (root / 'Unicode-\u00e9').write_bytes(b'Native name lookup\n')
    create_signed_app(root, command)
    guards = root / 'guards'
    guards.mkdir()
    # Interleave durable native allocations, then remove guards. Capture actual
    # extent geometry; no assumed allocator sequence supplies an expectation.
    for n in range(32):
        write_payload(guards / str(n), 'guard', 128 << 10)
        with (root / 'fragmented-data').open('ab') as stream:
            stream.write(payload('original', 128 << 10)); stream.flush(); os.fsync(stream.fileno())
        with open(str(root / 'fragmented-resource') + '/..namedfork/rsrc', 'ab') as stream:
            stream.write(payload('original-fork', 128 << 10)); stream.flush(); os.fsync(stream.fileno())
    for guard in guards.iterdir():
        guard.unlink()
    (root / 'empty').write_bytes(b'')


def apply_native(root, phase, command):
    from metadata_edits import set_metadata
    for name, label, size, resource in PEAK if phase == 'peak' else FINAL:
        path = root / name
        write_payload(str(path) + ('/..namedfork/rsrc' if resource else ''), label, size)
        set_metadata(path, {'modifyTime': {'value': '2025-06-07T08:09:10.000000000Z'}}, command)
    if phase == 'peak':
        os.chmod(root / 'small', 0o755)


def observe(image, work, command):
    require_disposable_host()
    before = sha256(image)
    native = raw_command(command, image)
    cleanup, physical, inventory = attached(image, native, readonly=True)
    try:
        require(len(inventory['Volumes']) == 1, 'single-volume APFS edit profile')
        check_filesystem(physical, native)
        directory = work / ('read-' + image.stem)
        mount(inventory['Volumes'][0], directory, native, readonly=True)
        observed = files(directory / 'Fixture')
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
        ranges = {name: native_extents(str(directory / 'Fixture' / name) +
                  ('/..namedfork/rsrc' if name == 'fragmented-resource' else ''))
                  for name in ('fragmented-data', 'fragmented-resource')}
        return {'files': observed, 'nativeExtents': ranges, 'checkerStatus': 0,
                'volumeUUID': inventory['Volumes'][0]['APFSVolumeUUID']}
    finally:
        native('hdiutil', 'detach', cleanup)
        require(sha256(image) == before, 'read-only observation changed image')


def capture(expected_major, output):
    require_disposable_host()
    producer = version(expected_major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    with tempfile.TemporaryDirectory(prefix='apfs-existing-edits-') as tmp:
        work = Path(tmp)
        for filesystem, native_fs in (('apfs', 'APFS'), ('apfs-case-sensitive', 'Case-sensitive APFS')):
            dmg = work / (filesystem + '.dmg')
            command('hdiutil', 'create', '-size', str(CAPACITY), '-layout', 'NONE',
                    '-fs', native_fs, '-volname', 'Existing', dmg)
            cleanup, _, inventory = attached(dmg, command)
            try:
                directory = work / (filesystem + '-write')
                mount(inventory['Volumes'][0], directory, command)
                create(directory / 'Fixture', command)
            finally:
                command('hdiutil', 'detach', cleanup)
            image = work / (filesystem + '-source.raw')
            copy_disk(dmg, image, command)
            before = observe(image, work, command)
            source = retain_file(image, output / (filesystem + '-source.raw.gz'))
            case = {'id': filesystem, 'source': source, 'before': before, 'states': {}}
            for phase in ('peak', 'final'):
                edited = work / (filesystem + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                native = raw_command(command, edited)
                cleanup, _, inventory = attached(edited, native)
                try:
                    directory = work / (filesystem + '-' + phase + '-write')
                    mount(inventory['Volumes'][0], directory, native)
                    apply_native(directory / 'Fixture', phase, native)
                finally:
                    native('hdiutil', 'detach', cleanup)
                state = observe(edited, work, command)
                state['archive'] = retain_file(edited, output / (filesystem + '-' + phase + '.raw.gz'))
                case['states'][phase] = state
                image = edited
            cases.append(case)
    producer['tools'] = {path: sha256(Path(path)) for path in
                         ('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '/usr/bin/hdiutil')}
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'major': expected_major, 'producer': producer, 'cases': cases,
                'contract': 'existing-apfs-file-edits', 'modificationSeconds': STAMP,
                'capacityBytes': CAPACITY, 'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
