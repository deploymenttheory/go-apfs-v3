#!/usr/bin/env python3
"""Apple-created fragmented HFS write controls; native operations only on VMs.

This family proves edits of existing identities rather than fresh construction.
Sources, native before/after states, checker verdicts and exact scripts are kept.
Go never participates in fixture production or supplies native expectations.
"""
import argparse
import errno
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
           'verify_preservation.py', 'metadata_edits.py', 'content_replacement.py')
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
    pressure = None
    # Actual allocation, not cached statfs availability, defines exhaustion.
    # Keep the native ENOSPC outcome; remove the incomplete guard before holes.
    while count < 2048:
        path = guards / str(count)
        try:
            with path.open('wb') as stream:
                stream.write(bytes(32 << 10))
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as failure:
            if failure.errno != errno.ENOSPC:
                raise
            pressure = {'errno': failure.errno, 'completeGuardFiles': count,
                        'reportedAvailableBytes': os.statvfs(root).f_bavail * os.statvfs(root).f_frsize}
            path.unlink(missing_ok=True)
            break
        count += 1
    require(pressure is not None, 'bounded guard workload must reach actual ENOSPC')
    for n in range(0, count, 2):
        (guards / str(n)).unlink()
    write_payload(root / 'fragmented-data', 'original', 8 << 20)
    write_payload(str(root / 'fragmented-resource') + '/..namedfork/rsrc', 'original-fork', 8 << 20)
    for name, fork in (('fragmented-data', False), ('fragmented-resource', True)):
        ranges = native_extents(str(root / name) + ('/..namedfork/rsrc' if fork else ''))
        require(len(ranges) > 8, f'{name} requires native overflow records')
    return pressure


def apply_native(root, phase, command):
    from metadata_edits import set_metadata
    for name, label, size, resource in PEAK if phase == 'peak' else FINAL:
        path = root / name
        write_payload(str(path) + ('/..namedfork/rsrc' if resource else ''), label, size)
        # Supply birth/access explicitly, matching the preservation policy.
        # hfs_vnop_setattr otherwise clamps HFS+ birth to an older new mtime.
        set_metadata(path, {'modifyTime': {'value': '2025-06-07T08:09:10.000000000Z'}}, command)
    if phase == 'peak':
        os.chmod(root / 'small', 0o755)


def journal_backing_files(stream, volume):
    """Observe raw native CNIDs: mounted pathname lookup hides journal files.

    Root records precede later parents in the catalog. This bounded observer
    reads their leaf chain through the header's inline catalog extents only;
    it is a capture tool, not another general filesystem implementation.
    """
    block_size = struct.unpack_from('>I', volume, 40)[0]
    extents = [struct.unpack_from('>II', volume, 288 + n * 8) for n in range(8)]
    def read_fork(offset, size):
        result = bytearray()
        for start, count in extents:
            length = count * block_size
            if offset >= length:
                offset -= length
                continue
            take = min(size - len(result), length - offset)
            stream.seek(start * block_size + offset)
            result.extend(stream.read(take))
            offset = 0
            if len(result) == size:
                return bytes(result)
        raise ValueError('capture catalog root outside inline extents')
    header = read_fork(0, 512)
    node_size, leaf = struct.unpack_from('>H', header, 32)[0], struct.unpack_from('>I', header, 24)[0]
    result, seen = {}, set()
    while leaf:
        require(leaf not in seen and len(seen) < 64, 'bounded journal catalog observation')
        seen.add(leaf)
        node = read_fork(leaf * node_size, node_size)
        require(node[8] == 255, 'native catalog leaf')
        for n in range(struct.unpack_from('>H', node, 10)[0]):
            off = struct.unpack_from('>H', node, node_size - 2 * (n + 1))[0]
            key_size, parent, name_size = struct.unpack_from('>HIH', node, off)
            if parent > 2:
                require(len(result) == 2, 'both native journal backing files observed')
                return result
            name = node[off + 8:off + 8 + 2 * name_size].decode('utf-16-be')
            if parent == 2 and name in ('.journal', '.journal_info_block'):
                value = off + 2 + key_size
                require(struct.unpack_from('>H', node, value)[0] == 2, 'journal catalog file')
                result[name] = {'object': struct.unpack_from('>I', node, value + 8)[0],
                                'size': struct.unpack_from('>Q', node, value + 88)[0]}
        leaf = struct.unpack_from('>I', node)[0]
    require(len(result) == 2, 'native journal backing inventory')
    return result


def read_journal(image):
    """File-only observations of native journal bytes, independent of Go."""
    with image.open('rb') as stream:
        stream.seek(1024)
        volume = stream.read(512)
        if not struct.unpack_from('>I', volume, 4)[0] & 0x2000:
            return None
        block_size, info_block = struct.unpack_from('>I', volume, 40)[0], struct.unpack_from('>I', volume, 12)[0]
        require(0 < info_block < image.stat().st_size // block_size, 'native journal info location')
        stream.seek(info_block * block_size)
        info = stream.read(block_size)
        flags, offset, size = struct.unpack_from('>I', info)[0], *struct.unpack_from('>QQ', info, 36)
        require(flags == 1 and 0 < size <= image.stat().st_size - offset, 'initialized internal journal')
        stream.seek(offset)
        header = stream.read(48)
        order = '<' if header[:4] == b'xLNJ' else '>'
        magic, endian, start, end, stored_size, list_size, checksum, header_size, sequence = struct.unpack(order + 'IIQQQIIII', header)
        require(magic == 0x4a4e4c78 and endian == 0x12345678 and stored_size == size and start == end,
                'clean native journal header')
        stream.seek(offset)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            data = stream.read(min(remaining, 128 << 10))
            require(bool(data), 'complete journal bytes')
            digest.update(data)
            remaining -= len(data)
        return {'infoBlock': info_block, 'flags': flags, 'offset': offset, 'size': size,
                'start': start, 'end': end, 'headerSize': header_size, 'blockListSize': list_size,
                'checksum': checksum, 'sequence': sequence, 'byteOrder': order,
                'sha256': digest.hexdigest(), 'infoSHA256': hashlib.sha256(info).hexdigest(),
                'backingFiles': journal_backing_files(stream, volume)}


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
        result = {'files': observed, 'headers': headers, 'nativeExtents': ranges, 'checkerStatus': 0}
        journal = read_journal(image)
        if journal is not None:
            result['journal'] = journal
        return result
    finally:
        command('hdiutil', 'detach', device)


def capture(expected_major, output, journaled=False):
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
                        *(['-J', '1m'] if journaled else []),
                        '-b', '4096', '-n', 'c=4096,e=1024,a=4096',
                        '-c', 'c=8,e=1,a=8,d=1,r=1', '-I', 'c=10,e=1,a=10',
                        '-v', 'Existing', device.replace('/dev/disk', '/dev/rdisk'))
                mount = work / (filesystem + '-write')
                mount.mkdir()
                command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
                pressure = create(mount / 'Fixture', command)
            finally:
                command('hdiutil', 'detach', device)
            before = observe(image, work, command)
            require(('journal' in before) == journaled, 'requested journal profile captured')
            source = retain_file(image, output / (filesystem + '-source.raw.gz'))
            case = {'id': filesystem, 'source': source, 'before': before, 'states': {},
                    'allocationPressure': pressure}
            for phase in ('peak', 'final'):
                edited = work / (filesystem + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                device = attach(edited, command, writable=True)
                try:
                    mount = work / (filesystem + '-' + phase + '-write')
                    mount.mkdir()
                    command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
                    apply_native(mount / 'Fixture', phase, command)
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
                'contract': 'journaled-hfs-file-edits' if journaled else 'existing-hfs-file-edits', 'modificationSeconds': STAMP,
                'capacityBytes': CAPACITY,
                'commandsSHA256': hashlib.sha256((output / 'commands.json').read_bytes()).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--journaled', action='store_true')
    args = parser.parse_args()
    capture(args.expected_major, args.output, args.journaled)
