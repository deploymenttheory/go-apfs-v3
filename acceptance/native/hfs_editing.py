#!/usr/bin/env python3
"""Apple-created fragmented HFS write controls; native operations only on VMs.

This family proves edits of existing identities rather than fresh construction.
Sources, native before/after states, checker verdicts and exact scripts are kept.
Go never participates in fixture production or supplies native expectations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile

from capture import native_extents
from container_building import require_disposable_host
import file_compression as compression
from hfs_header_growth import Commands, attach, read_headers, retain_file
from image_repacking import files, version
from verify_preservation import require

CAPACITY = 64 << 20
STAMP = 1749283750  # 2025-06-07T08:09:10Z; explicit offline modification policy.
SOURCES = ('hfs_editing.py', 'capture.py', 'container_building.py', 'file_compression.py',
           'hfs_header_growth.py', 'image_repacking.py', 'image_building.py',
           'verify_preservation.py')
PEAK = (('alias', 'grow', 20 << 20, False), ('small', 'small', 7000, False),
        ('inline-compressed', 'inline', 7000, False),
        ('resource-compressed', 'resource', 100000, False))
FINAL = (('fragmented-data', 'shrink', 513, False),
         ('fragmented-resource', 'fork', 131073, True), ('empty', 'empty', 0, False),
         ('independent', 'independent', 65537, False))


def payload(label, size):
    pattern = bytes(range(256)) + label.encode() + b'\n'
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def write_payload(path, label, size):
    with open(path, 'wb') as stream:
        pattern = payload(label, size)
        for off in range(0, size, 128 << 10):
            stream.write(pattern[off:off + (128 << 10)])
        stream.flush()
        os.fsync(stream.fileno())


def create(root, command):
    # Import native metadata bindings only after the disposable-host guard.
    from image_building import create_signed_app
    root.mkdir()
    for name in ('small', 'empty', 'independent', 'fragmented-data', 'fragmented-resource'):
        (root / name).write_bytes(b'existing data\n')
    compression.xattr(root / 'independent', compression.RESOURCE, b'Independent fork\x00\xff')
    compression.xattr(root / 'independent', 'org.go-apfs.retained', b'Opaque retained metadata\x00\xff')
    compression.install(root / 'inline-compressed', 3, compression.plain(1200),
                        payload=compression.encode(3, compression.plain(1200)))
    compression.xattr(root / 'inline-compressed', compression.RESOURCE, b'Independent inline fork')
    data = compression.plain(65537)
    compression.install(root / 'resource-compressed', 4, data,
                        blocks=[compression.encode(4, data[off:off+65536]) for off in range(0, len(data), 65536)])
    create_signed_app(root, command)
    os.link(root / 'fragmented-data', root / 'alias')
    os.symlink('fragmented-data', root / 'symlink')
    guards = root.parent / 'allocation-guards'
    guards.mkdir()
    count = 0
    while os.statvfs(root).f_bavail * os.statvfs(root).f_frsize > 1 << 20:
        require(count < 2048, 'bounded fragmentation guard count')
        (guards / str(count)).write_bytes(bytes(32 << 10))
        count += 1
    for n in range(0, count, 2):
        (guards / str(n)).unlink()
    write_payload(root / 'fragmented-data', 'original', 8 << 20)
    write_payload(str(root / 'fragmented-resource') + '/..namedfork/rsrc', 'original-fork', 8 << 20)
    for name, fork in (('fragmented-data', False), ('fragmented-resource', True)):
        ranges = native_extents(str(root / name) + ('/..namedfork/rsrc' if fork else ''))
        require(len(ranges) > 8, f'{name} requires native overflow records')


def apply_native(root, phase):
    for name, label, size, resource in PEAK if phase == 'peak' else FINAL:
        path = root / name
        access = path.stat().st_atime_ns
        write_payload(str(path) + ('/..namedfork/rsrc' if resource else ''), label, size)
        os.utime(path, ns=(access, STAMP * 1000000000))
    if phase == 'peak':
        os.chmod(root / 'small', 0o755)


def observe(image, work, command):
    mount = work / ('read-' + image.stem)
    device = attach(image, command, readonly=True)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        headers = read_headers(image, CAPACITY)
        with image.open('rb') as stream:
            stream.seek(headers['primary']['forks']['extents']['extents'][0][0] * 4096)
            tree = stream.read(512)
        headers['extentsTree'] = {'nodeSize': struct.unpack_from('>H', tree, 32)[0],
                                  'totalNodes': struct.unpack_from('>I', tree, 36)[0]}
        mount.mkdir()
        command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
        observed = files(mount / 'Fixture')
        observed['rawAttributes'] = [{'object': item['object'], 'attributes': item['rawAttributes']}
                                     for item in observed['entries']]
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
        ranges = {name: native_extents(str(mount / 'Fixture' / name) +
                  ('/..namedfork/rsrc' if name == 'fragmented-resource' else ''))
                  for name in ('fragmented-data', 'fragmented-resource')}
        return {'files': observed, 'headers': headers, 'nativeExtents': ranges, 'checkerStatus': 0}
    finally:
        command('hdiutil', 'detach', device)


def capture(expected_major, output):
    require_disposable_host()
    producer = version(expected_major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    with tempfile.TemporaryDirectory(prefix='hfs-existing-edits-') as tmp:
        work = Path(tmp)
        for filesystem in ('hfsplus', 'hfsx'):
            image = work / (filesystem + '-source.raw')
            with image.open('xb') as stream:
                stream.truncate(CAPACITY)
            device = attach(image, command, writable=True)
            try:
                command('sudo', '/sbin/newfs_hfs', *(['-s'] if filesystem == 'hfsx' else []),
                        '-b', '4096', '-n', 'c=4096,e=1024,a=4096',
                        '-c', 'c=8,e=1,a=8,d=1,r=1', '-I', 'c=10,e=1,a=10',
                        '-v', 'Existing', device.replace('/dev/disk', '/dev/rdisk'))
                mount = work / (filesystem + '-write')
                mount.mkdir()
                command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
                create(mount / 'Fixture', command)
            finally:
                command('hdiutil', 'detach', device)
            before = observe(image, work, command)
            source = retain_file(image, output / (filesystem + '-source.raw.gz'))
            case = {'id': filesystem, 'source': source, 'before': before, 'states': {}}
            for phase in ('peak', 'final'):
                edited = work / (filesystem + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                device = attach(edited, command, writable=True)
                try:
                    mount = work / (filesystem + '-' + phase + '-write')
                    mount.mkdir()
                    command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
                    apply_native(mount / 'Fixture', phase)
                finally:
                    command('hdiutil', 'detach', device)
                state = observe(edited, work, command)
                state['archive'] = retain_file(edited, output / (filesystem + '-' + phase + '.raw.gz'))
                case['states'][phase] = state
                image = edited
            cases.append(case)
    producer['tools'] = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                         for path in ('/sbin/newfs_hfs', '/sbin/fsck_hfs', '/usr/bin/hdiutil')}
    producer['sources'] = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                           for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'major': expected_major, 'producer': producer, 'cases': cases,
                'contract': 'existing-hfs-file-edits', 'modificationSeconds': STAMP,
                'capacityBytes': CAPACITY,
                'commandsSHA256': hashlib.sha256((output / 'commands.json').read_bytes()).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
