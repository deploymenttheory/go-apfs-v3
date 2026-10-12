#!/usr/bin/env python3
"""Capture actual Apple HFS journal write windows on disposable macOS VMs.

APFS clonefile captures the backing file while Apple changes HFS metadata. We
never manufacture pending cursors or journal payloads. Apple recovers a separate
copy; the original clone and every native verdict remain available for analysis.
No Go code participates in producing these references.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
import threading
import time

from container_building import require_disposable_host
from hfs_header_growth import attach, retain_file
from image_repacking import Commands, files, version
from verify_preservation import require

CAPACITY = 64 << 20


def checksum(data):
    value = 0
    for byte in data:
        value = ((value << 8) ^ (value + byte)) & 0xffffffff
    return (~value) & 0xffffffff


def pending_changes(image, state):
    """Measure unapplied committed native metadata; no recovery is performed.

    Checking only nonempty cursors would accept journals whose home writes have
    already completed. Walk the declared range, check every payload and compare
    the latest recorded bytes with their home sectors. Apple's replay-only
    result remains the independent expected output, including any tail records.
    """
    data = image.read_bytes()
    size, header_size = state['size'], state['headerSize']
    base, order = state['offset'], state['byteOrder']

    def advance(offset, count):
        return header_size + (offset + count - header_size) % (size - header_size)

    def read(offset, count):
        first = min(count, size - offset)
        return data[base + offset:base + offset + first] + data[base + header_size:base + header_size + count - first]

    position, consumed = state['start'], 0
    latest = {}
    while position != state['end'] and consumed < size - header_size:
        raw = bytearray(read(position, state['blockListSize']))
        maximum, count, used, stored, flags = struct.unpack_from(order + 'HHIII', raw)
        raw[8:12] = bytes(4)
        if checksum(raw[:32]) != stored or not (1 <= count <= maximum <= len(raw) // 16 - 1):
            return 0
        if used < len(raw) or used > size - header_size - consumed:
            return 0
        offset, actual = advance(position, len(raw)), len(raw)
        for index in range(1, count):
            number, length, stored = struct.unpack_from(order + 'qII', raw, 16 + index * 16)
            if not length or length % 512 or length > used - actual:
                return 0
            payload = read(offset, length)
            if number != -1:
                if number < 0 or number * header_size + length > len(data) or (flags & 1 and stored and checksum(payload) != stored):
                    return 0
                for part in range(0, length, 512):
                    latest[number * header_size + part] = payload[part:part + 512]
            offset, actual = advance(offset, length), actual + length
        if actual != used:
            return 0
        consumed, position = consumed + used, advance(position, used)
    if position != state['end']:
        return 0
    return sum(data[offset:offset + 512] != value for offset, value in latest.items())


def journal(image):
    """File-only geometry observation; does not interpret/replay transactions."""
    with image.open('rb') as stream:
        stream.seek(1024)
        volume = stream.read(512)
        require(volume[:2] in (b'H+', b'HX'), 'native HFS volume')
        block_size = struct.unpack_from('>I', volume, 40)[0]
        info_block = struct.unpack_from('>I', volume, 12)[0]
        stream.seek(info_block * block_size)
        info = stream.read(180)
        flags = struct.unpack_from('>I', info)[0]
        offset, size = struct.unpack_from('>QQ', info, 36)
        require(flags == 1 and size <= image.stat().st_size - offset, 'native internal journal')
        stream.seek(offset)
        raw = stream.read(48)
    order = '<' if raw[:4] == b'xLNJ' else '>'
    magic, endian, start, end, stored_size, list_size, checksum, header_size, sequence = struct.unpack(order + 'IIQQQIIII', raw)
    require(magic == 0x4a4e4c78 and endian == 0x12345678 and stored_size == size, 'native journal header')
    return {'offset': offset, 'size': size, 'start': start, 'end': end,
            'blockListSize': list_size, 'headerSize': header_size, 'sequence': sequence,
            'checksum': checksum, 'byteOrder': order, 'attributes': struct.unpack_from('>I', volume, 4)[0]}


def clone_file(source, target):
    require_disposable_host()
    # Native APFS clonefile makes one backing-file point-in-time copy. The
    # source HFS mount keeps running, exactly as if its storage had disappeared
    # at that instant. Native recovery, not the capture, judges consistency.
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    call = library.clonefile
    call.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
    call.restype = ctypes.c_int
    if call(os.fsencode(source), os.fsencode(target), 0):
        raise OSError(ctypes.get_errno(), 'clonefile', str(target))


def churn(root, stop, errors):
    try:
        from file_compression import xattr
        generation = 0
        while not stop.is_set():
            for index in range(256):
                if stop.is_set():
                    break
                path = root / f'entry-{index}'
                os.chmod(path, 0o600 | (generation & 0o77))
                xattr(path, 'org.go-apfs.journal', struct.pack('>QI', generation, index))
            generation += 1
    except BaseException as error:
        errors.append(str(error))
        stop.set()


def recover(image, work, output, name, helper, command):
    device = attach(image, command, writable=True)
    mount = work / (image.stem + '-recovered')
    mount.mkdir()
    try:
        command('sudo', '--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT', helper,
                device.replace('/dev/disk', '/dev/rdisk'))
        replay = retain_file(image, output / (name + '-apple-replay.raw.gz'))
        replay_journal = journal(image)
        require(replay_journal['start'] == replay_journal['end'], 'native replay emptied journal')
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
        observed = files(mount / 'Fixture')
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
    finally:
        command('hdiutil', 'detach', device)
    # Check independently after unmount, without recovery or repair.
    device = attach(image, command, readonly=True)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
    finally:
        command('hdiutil', 'detach', device)
    return {'files': observed, 'journal': journal(image), 'checkerStatus': 0,
            'replayArchive': replay, 'replayJournal': replay_journal}


def capture(expected_major, output):
    require_disposable_host()
    producer = version(expected_major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    diagnostics = []
    with tempfile.TemporaryDirectory(prefix='hfs-journal-recovery-') as temporary:
        work = Path(temporary)
        helper = work / 'hfs-replay'
        command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror',
                Path(__file__).with_name('hfs_replay.c'), '-o', helper)
        for filesystem in ('hfsplus', 'hfsx'):
            image = work / (filesystem + '-live.raw')
            with image.open('xb') as stream:
                stream.truncate(CAPACITY)
            # Apple's documented -nokernel forces an image-owned helper. It
            # can be paused without freezing any unrelated filesystem/device.
            attachment = plistlib.loads(command('hdiutil', 'attach', '-nokernel', '-nomount', '-noautofsck',
                                                '-imagekey', 'diskimage-class=CRawDiskImage', '-plist', image))
            devices = [item['dev-entry'] for item in attachment['system-entities'] if 'dev-entry' in item]
            require(len(devices) == 1, 'owned bare HFS image device')
            device = devices[0]
            mount = work / (filesystem + '-live')
            mount.mkdir()
            snapshots = {}
            stop, errors = threading.Event(), []
            worker = None
            try:
                command('sudo', '/sbin/newfs_hfs', *(['-s'] if filesystem == 'hfsx' else []),
                        '-J', '1m', '-b', '4096', '-v', 'Recovery', device.replace('/dev/disk', '/dev/rdisk'))
                command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
                root = mount / 'Fixture'
                root.mkdir()
                from image_building import create_signed_app
                from file_compression import xattr, RESOURCE
                create_signed_app(root, command)
                (root / 'retained').write_bytes(b'Journal recovery preserves file contents.\n')
                xattr(root / 'retained', RESOURCE, b'Independent resource fork\x00\xff')
                os.link(root / 'retained', root / 'alias')
                os.symlink('retained', root / 'link')
                for index in range(256):
                    (root / f'entry-{index}').touch()
                    xattr(root / f'entry-{index}', 'org.go-apfs.journal', struct.pack('>QI', 0, index))
                command('sync')
                inventory = plistlib.loads(command('hdiutil', 'info', '-plist'))
                (output / (filesystem + '-diskimages-info.json')).write_text(json.dumps(inventory, indent=2) + '\n')
                worker = threading.Thread(target=churn, args=(root, stop, errors))
                worker.start()
                deadline = time.monotonic() + 60
                attempt = 0
                while time.monotonic() < deadline and len(snapshots) < 2:
                    candidate = work / (filesystem + f'-candidate-{attempt}.raw')
                    clone_file(image, candidate)
                    state = journal(candidate)
                    shape = 'wrapped' if state['start'] > state['end'] else 'linear'
                    changes = pending_changes(candidate, state) if state['start'] != state['end'] and shape not in snapshots else 0
                    if changes:
                        snapshots[shape] = candidate
                        retain_file(candidate, output / (filesystem + '-' + shape + '-interrupted.raw.gz'))
                        diagnostics.append({'filesystem': filesystem, 'attempt': attempt, 'journal': state,
                                            'unappliedSectors': changes})
                        print('Captured pending native journal:', filesystem, shape, state, flush=True)
                    else:
                        candidate.unlink()
                    attempt += 1
                    time.sleep(0.005)
                require(not errors, f'native metadata workload: {errors}')
            finally:
                stop.set()
                if worker:
                    worker.join(timeout=10)
                    require(not worker.is_alive(), 'bounded native workload shutdown')
                command('hdiutil', 'detach', device)
                (output / 'capture-diagnostics.json').write_text(json.dumps(diagnostics, indent=2) + '\n')
            require(len(snapshots) == 2, f'pending linear and wrapped journals: {filesystem}')
            for shape, source in sorted(snapshots.items()):
                name = filesystem + '-' + shape
                from capture import sha256
                original = {'image': name + '-interrupted.raw.gz',
                            'sha256': sha256(output / (name + '-interrupted.raw.gz')),
                            'uncompressedSHA256': sha256(source), 'uncompressedBytes': source.stat().st_size}
                recovered = work / (name + '-apple.raw')
                shutil.copyfile(source, recovered)
                before = journal(source)
                native = recover(recovered, work, output, name, helper, command)
                native['archive'] = retain_file(recovered, output / (name + '-apple.raw.gz'))
                cases.append({'id': name, 'source': original, 'journal': before, 'recovered': native})
                (output / 'recovery.json').write_text(json.dumps({'producer': producer, 'cases': cases}, indent=2) + '\n')
    producer['tools'] = {str(path): hashlib.sha256(Path(path).read_bytes()).hexdigest()
                         for path in ('/sbin/newfs_hfs', '/sbin/fsck_hfs', '/usr/bin/hdiutil', '/usr/sbin/diskutil')}
    scripts = ('hfs_journal_recovery.py', 'hfs_replay.c', 'hfs_header_growth.py', 'image_repacking.py',
               'container_building.py', 'image_building.py', 'file_compression.py', 'capture.py')
    script_output = output / 'scripts'
    script_output.mkdir()
    for name in scripts:
        shutil.copyfile(Path(__file__).with_name(name), script_output / name)
    (output / 'recovery.json').write_text(json.dumps({'producer': producer, 'cases': cases}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    arguments = parser.parse_args()
    capture(arguments.expected_major, arguments.output)
