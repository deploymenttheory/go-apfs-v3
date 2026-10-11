#!/usr/bin/env python3
"""Retain matched Apple/Go HFS catalog-growth controls on disposable macOS VMs.

Go supplies only explicitly labelled construction controls. Apple formats the
independent controls and supplies all checker and mounted-readback verdicts.
Every disk snapshot is streamed from the native device, never a Go decoder.
"""
import argparse
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_repacking import files, version
from verify_preservation import require

CAPACITIES = (10936320, 16777216)
SOURCES = ('hfs_header_growth.py', 'capture.py', 'container_building.py',
           'image_repacking.py', 'verify_preservation.py')
FORKS = {'allocation': 112, 'extents': 192, 'catalog': 272, 'attributes': 352, 'startup': 432}


class Commands:
    def __init__(self, path):
        self.path = path
        self.records = []

    def __call__(self, *argv, expected_success=True):
        record = {'argv': list(map(str, argv)), 'status': 'started'}
        self.records.append(record)
        self.save()
        print('HFS growth:', *record['argv'], flush=True)
        try:
            result = subprocess.run(record['argv'], capture_output=True, timeout=120)
            record.update(status=result.returncode, stdout=result.stdout.decode(errors='replace'),
                          stderr=result.stderr.decode(errors='replace'))
        except BaseException as error:
            record.update(status='failed', error=str(error))
            raise
        finally:
            self.save()
        if expected_success is not None:
            require((result.returncode == 0) == expected_success, f'native command: {record}')
        return result.stdout

    def save(self):
        self.path.write_text(json.dumps(self.records, indent=2) + '\n')


def geometry(device):
    # _IOR('d', 24/25/77, uint32_t/uint64_t), from Apple's SDK sys/disk.h.
    # Record logical AND physical sizes: HFS rounds alternate-header I/O to
    # physical boundaries, which may differ between direct and shadow devices.
    result = {}
    with open(device, 'rb', buffering=0) as source:
        for name, number, fmt in (('logicalBlockSize', 24, 'I'), ('blockCount', 25, 'Q'),
                                  ('physicalBlockSize', 77, 'I')):
            data = bytearray(struct.calcsize(fmt))
            fcntl.ioctl(source.fileno(), 0x40000000 | len(data) << 16 | ord('d') << 8 | number, data)
            result[name] = struct.unpack('=' + fmt, data)[0]
    result['deviceBytes'] = result['logicalBlockSize'] * result['blockCount']
    return result


def decode_header(raw):
    require(len(raw) == 512 and raw[:2] in (b'H+', b'HX'), 'HFS volume header')
    result = {'signature': raw[:2].decode(), 'attributes': struct.unpack_from('>I', raw, 4)[0],
              'lastMountedVersion': raw[8:12].decode(errors='replace')}
    for name, offset in (('files', 32), ('directories', 36), ('blockSize', 40),
                         ('totalBlocks', 44), ('freeBlocks', 48)):
        result[name] = struct.unpack_from('>I', raw, offset)[0]
    result['forks'] = {}
    for name, offset in FORKS.items():
        size, clump, blocks = struct.unpack_from('>QII', raw, offset)
        extents = [list(struct.unpack_from('>II', raw, offset + 16 + i * 8)) for i in range(8)]
        result['forks'][name] = {'logicalSize': size, 'clumpSize': clump,
                                'totalBlocks': blocks, 'extents': extents}
    return result


def read_headers(device, size):
    with open(device, 'rb', buffering=0) as source:
        source.seek(1024)
        primary = decode_header(source.read(512))
        require(primary['blockSize'] * primary['totalBlocks'] == size, 'bare volume/device equality')
        source.seek(size - 1024)
        alternate = decode_header(source.read(512))
        fork = primary['forks']['catalog']
        source.seek(fork['extents'][0][0] * primary['blockSize'])
        tree = source.read(106)
        require(len(tree) == 106 and tree[8] == 1, 'catalog B-tree header')
        catalog = {'nodeSize': struct.unpack_from('>H', tree, 32)[0],
                   'totalNodes': struct.unpack_from('>I', tree, 36)[0],
                   'freeNodes': struct.unpack_from('>I', tree, 40)[0],
                   'clumpSize': struct.unpack_from('>I', tree, 46)[0]}
    return {'primary': primary, 'alternate': alternate, 'catalog': catalog}


def attach(image, command, shadow=None, mount=None, readonly=False):
    options = ['-shadow', shadow] if shadow else []
    if image.suffix == '.raw':
        options += ['-imagekey', 'diskimage-class=CRawDiskImage']
    options += ['-nomount', '-noautofsck']
    if not mount or readonly:
        options += ['-readonly']
    data = plistlib.loads(command('hdiutil', 'attach', '-plist', *options, image))
    devices = [e['dev-entry'] for e in data['system-entities'] if 'dev-entry' in e]
    require(len(devices) == 1, 'one bare HFS device')
    if mount:
        try:
            command('diskutil', 'mount', *(['readOnly'] if readonly else []),
                    '-mountOptions', 'noowners,noatime', '-mountPoint', mount, devices[0])
        except BaseException:
            command('hdiutil', 'detach', devices[0])
            raise
    return devices[0]


def snapshot(image, output, command, shadow=None):
    device = attach(image, command, shadow=shadow)
    raw = device.replace('/dev/disk', '/dev/rdisk')
    try:
        native = geometry(raw)
        state = read_headers(raw, native['deviceBytes'])
        digest = hashlib.sha256()
        # A gzip snapshot retains unused sectors, both headers and every extent.
        with open(raw, 'rb', buffering=0) as source, output.open('xb') as stored:
            with gzip.GzipFile(filename='', mode='wb', fileobj=stored, mtime=0) as compressed:
                remaining = native['deviceBytes']
                while remaining:
                    data = source.read(min(1 << 20, remaining))
                    require(data, 'short native snapshot')
                    digest.update(data)
                    compressed.write(data)
                    remaining -= len(data)
        command('/sbin/fsck_hfs', '-dfn', raw, expected_success=None)
        checker = command.records[-1].copy()
        return {'image': output.name, 'imageSHA256': sha256(output),
                'diskSHA256': digest.hexdigest(), 'geometry': native,
                'headers': state, 'checker': checker}
    finally:
        command('hdiutil', 'detach', device)


def create_apple(image, capacity, sensitive, initial, command):
    # The control is freshly formatted by Apple, not a rewrap/conversion of Go.
    with image.open('xb') as stream:
        stream.truncate(capacity)
    data = plistlib.loads(command('hdiutil', 'attach', '-nomount', '-plist',
                                 '-imagekey', 'diskimage-class=CRawDiskImage', image))
    device = data['system-entities'][0]['dev-entry']
    try:
        command('sudo', '/sbin/newfs_hfs', *(['-s'] if sensitive else []),
                '-b', '4096', '-n', 'c=4096,e=4096,a=4096',
                '-c', 'c=8,e=8,a=8,d=1,r=1',
                '-I', ','.join(f'{key}={initial[name]["totalBlocks"]}'
                              for key, name in (('c', 'catalog'), ('e', 'extents'), ('a', 'attributes'))),
                '-v', 'Growth', device.replace('/dev/disk', '/dev/rdisk'))
    finally:
        command('hdiutil', 'detach', device)


def workload(mount):
    root = mount / 'native-allocation'
    root.mkdir()
    payload = bytes(range(256)) * 2048
    original = root / 'grow'
    original.write_bytes(payload)
    os.setxattr(original, 'org.go-apfs.header-growth', b'catalog growth keeps attributes')
    os.setxattr(original, 'com.apple.ResourceFork', b'independent growth-control resource fork')
    os.link(original, root / 'alias')
    with original.open('ab') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    original.rename(root / 'renamed')
    require((root / 'alias').read_bytes() == payload * 2, 'native hard-link growth')
    (root / 'alias').unlink()
    # 512 long names force catalog allocation beyond the matched small initial
    # fork; confirm growth from retained structures, never infer it from counts.
    for i in range(512):
        (root / f'entry-{i:03}-{"catalog-growth-" * 6}').write_bytes(payload[:4096])
    for i in range(0, 512, 2):
        (root / f'entry-{i:03}-{"catalog-growth-" * 6}').unlink()
    (root / 'reused').write_bytes(payload)
    os.sync()
    return files(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, choices=[15, 26, 27], required=True)
    parser.add_argument('--go-images', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_disposable_host()
    producer = version(args.expected_major)
    require(not args.output.exists(), 'refuse to replace retained corpus')
    args.output.mkdir(parents=True)
    command = Commands(args.output / 'commands.json')
    source_dir = Path(__file__).parent
    sources = []
    for name in SOURCES:
        shutil.copyfile(source_dir / name, args.output / name)
        sources.append({'source': name, 'sha256': sha256(args.output / name)})
    producer.update(sources=sources, run=os.environ.get('GITHUB_RUN_ID', ''),
                    revision=os.environ.get('GITHUB_SHA', ''))
    # Retain exact shipped tool bytes' hashes, SDK ioctl definitions and versions.
    producer['tools'] = {path: sha256(path) for path in ('/sbin/newfs_hfs', '/sbin/fsck_hfs', '/usr/bin/hdiutil')}
    producer['uname'] = command('uname', '-a').decode().strip()
    disk_images = plistlib.loads(command('hdiutil', 'info', '-plist'))
    producer['diskImagesVersion'] = {key: value for key, value in disk_images.items() if key != 'images'}
    sdk = Path(command('xcrun', '--show-sdk-path').decode().strip())
    producer['sdkDiskHeaderSHA256'] = sha256(sdk / 'usr/include/sys/disk.h')
    result = {'schema': 1, 'scenario': 'hfs-header-growth', 'producer': producer, 'cases': []}
    def save():
        (args.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    save()
    with tempfile.TemporaryDirectory(prefix='apfs-hfs-growth-') as work:
        work = Path(work)
        for profile in ('hfsplus', 'hfsx'):
            for capacity in CAPACITIES:
                go = args.go_images / f'{profile}-{capacity}.dmg'
                before_go = snapshot(go, args.output / f'{profile}-{capacity}-go-before.raw.gz', command)
                require(before_go['checker']['status'] == 0, 'Go control initially passes native checker')
                initial = before_go['headers']['primary']['forks']
                apple_raw = work / f'{profile}-{capacity}-apple.raw'
                create_apple(apple_raw, capacity, profile == 'hfsx', initial, command)
                # Both shadow controls use UDRO: raw-vs-UDIF driver selection
                # would otherwise confound the Apple/Go construction comparison.
                apple = work / f'{profile}-{capacity}-apple.dmg'
                command('hdiutil', 'convert', apple_raw, '-format', 'UDRO', '-o', apple)
                before_apple = snapshot(apple, args.output / f'{profile}-{capacity}-apple-before.raw.gz', command)
                require(before_apple['checker']['status'] == 0, 'Apple control initially passes native checker')
                for before in (before_go, before_apple):
                    require(before['geometry']['deviceBytes'] == capacity, 'matched capacity')
                    require(before['headers']['primary']['blockSize'] == 4096, 'matched allocation blocks')
                    require(before['headers']['catalog']['nodeSize'] == 4096, 'matched catalog nodes')
                    require(before['headers']['primary']['attributes'] & 0x2000 == 0, 'matched nonjournaled profile')
                    for name in ('catalog', 'extents', 'attributes'):
                        fork = before['headers']['primary']['forks'][name]
                        require(fork['totalBlocks'] == initial[name]['totalBlocks'] and fork['clumpSize'] == 32768,
                                'matched system-fork initial and clump sizes')
                for origin, source, before in (('go', go, before_go), ('apple', apple, before_apple)):
                    source_digest = sha256(source)
                    for route in ('direct', 'shadow'):
                        case_id = f'{profile}-{capacity}-{origin}-{route}'
                        private = work / f'{case_id}.raw'
                        # Direct controls start with the very same retained bytes.
                        if route == 'direct':
                            with gzip.open(args.output / before['image'], 'rb') as inp, private.open('xb') as out:
                                shutil.copyfileobj(inp, out, 1 << 20)
                            require(sha256(private) == before['diskSHA256'], 'exact direct-copy admission')
                        image = private if route == 'direct' else source
                        shadow = work / f'{case_id}.shadow' if route == 'shadow' else None
                        admitted = snapshot(image, args.output / f'{case_id}-admitted.raw.gz', command, shadow)
                        require(admitted['diskSHA256'] == before['diskSHA256'], 'native route sector equality')
                        mount = work / f'{case_id}-mount'
                        mount.mkdir()
                        device = attach(image, command, shadow, mount)
                        try:
                            mounted_geometry = geometry(device.replace('/dev/disk', '/dev/rdisk'))
                            observations = workload(mount)
                        finally:
                            command('hdiutil', 'detach', device)
                        after = snapshot(image, args.output / f'{case_id}-after.raw.gz', command, shadow)
                        require(after['headers']['primary']['forks']['catalog']['totalBlocks'] > initial['catalog']['totalBlocks'],
                                'catalog actually grew')
                        require(sha256(source) == source_digest, 'native writes preserved original source')
                        case = {'id': case_id, 'origin': origin, 'route': route, 'filesystem': profile,
                                'capacity': capacity, 'sourceImageSHA256': source_digest,
                                'before': before, 'admitted': admitted, 'mountedGeometry': mounted_geometry,
                                'after': after, 'files': observations}
                        result['cases'].append(case)
                        save()
                        device = attach(image, command, shadow, mount, readonly=True)
                        try:
                            case['readbackFiles'] = files(mount / 'native-allocation')
                            require(case['readbackFiles'] == observations, 'native contents/metadata survive remount')
                        finally:
                            command('hdiutil', 'detach', device)
                        save()
                        # Record failures as evidence. They remain explicit native
                        # checker failures and cannot qualify a mutation route.
                        print('HFS growth verdict:', case_id, after['checker']['status'], flush=True)
    require(len(result['cases']) == 16, 'complete matched growth inventory')
    result['complete'] = True
    save()


if __name__ == '__main__':
    main()
