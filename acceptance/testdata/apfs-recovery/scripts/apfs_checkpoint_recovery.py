#!/usr/bin/env python3
"""Retain actual Apple checkpoint write windows on disposable macOS VMs.

An image-owned helper is briefly paused; no checkpoint records are manufactured.
Apple fsck supplies the selected XID, then a read-only native mount supplies the
complete file observation. Original bytes are retained before either operation.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import tempfile
import threading
import time

from apfs_editing import mount
from capture import sha256
from container_building import attached, require_disposable_host
from hfs_header_growth import retain_file
from hfs_journal_recovery import image_helper
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, files, version
from verify_preservation import require

CAPACITY = 128 << 20
MODES = ('data', 'mapping', 'committed', 'wrapped')
SOURCES = ('apfs_checkpoint_recovery.py', 'apfs_capture.c', 'apfs_editing.py',
           'capture.py', 'container_building.py', 'hfs_header_growth.py',
           'hfs_journal_recovery.py', 'image_mutation.py', 'image_repacking.py',
           'image_building.py', 'file_compression.py', 'verify_preservation.py')


def checksum_valid(data):
    if len(data) < 32 or len(data) % 4:
        return False
    a = b = 0
    for (value,) in struct.iter_unpack('<I', data[8:]):
        a = (a + value) % 0xffffffff
        b = (b + a) % 0xffffffff
    x = 0xffffffff - (a + b) % 0xffffffff
    y = 0xffffffff - (a + x) % 0xffffffff
    return struct.unpack_from('<Q', data)[0] == (y << 32 | x)


def checkpoints(image):
    """File-only observation for acquisition diagnostics, never the oracle."""
    with image.open('rb') as stream:
        zero = stream.read(4096)
        require(zero[32:36] == b'NXSB' and checksum_valid(zero), 'native block-zero geometry')
        count, data_count = struct.unpack_from('<II', zero, 104)
        base, data_base = struct.unpack_from('<QQ', zero, 112)
        require(0 < count <= 256 and 0 < data_count <= 4096, 'bounded native checkpoint rings')
        states = []
        for index in range(count):
            stream.seek((base + index) * 4096)
            raw = stream.read(4096)
            if raw[32:36] != b'NXSB' or not checksum_valid(raw):
                continue
            next_desc, next_data, desc_index, desc_length, data_index, data_length = struct.unpack_from('<6I', raw, 128)
            states.append({'xid': struct.unpack_from('<Q', raw, 16)[0],
                           'address': base + index, 'descriptorIndex': desc_index,
                           'descriptorLength': desc_length, 'dataIndex': data_index,
                           'dataLength': data_length, 'nextDescriptor': next_desc, 'nextData': next_data})
        require(states, 'native descriptor superblocks')
        latest = max(states, key=lambda state: state['xid'])
        future = {}
        for label, address in (('mapping', base + latest['nextDescriptor']),
                               ('data', data_base + latest['nextData'])):
            stream.seek(address * 4096)
            raw = stream.read(4096)
            xid = struct.unpack_from('<Q', raw, 16)[0]
            if checksum_valid(raw) and xid > latest['xid']:
                future[label] = {'address': address, 'xid': xid, 'type': struct.unpack_from('<I', raw, 24)[0]}
    return {'blockZeroXID': struct.unpack_from('<Q', zero, 16)[0],
            'descriptorBase': base, 'descriptorBlocks': count,
            'dataBase': data_base, 'dataBlocks': data_count,
            'latest': latest, 'candidates': sorted(states, key=lambda state: -state['xid']), 'future': future}


def create(root, command):
    from image_building import create_signed_app
    from file_compression import xattr, RESOURCE
    root.mkdir()
    create_signed_app(root, command)
    (root / 'retained').write_bytes(b'Checkpoint recovery preserves identity.\n')
    xattr(root / 'retained', RESOURCE, b'Independent resource fork\x00\xff')
    xattr(root / 'retained', 'org.go-apfs.retained', b'Opaque metadata\x00\xff')
    os.link(root / 'retained', root / 'alias')
    os.symlink('retained', root / 'link')
    for index in range(256):
        (root / f'entry-{index}').write_bytes(b'Initial committed contents\n')
        xattr(root / f'entry-{index}', 'org.go-apfs.checkpoint', struct.pack('>QI', 0, index))


def churn(root, stop, errors):
    from file_compression import xattr
    try:
        generation = 1
        while not stop.is_set():
            for index in range(256):
                if stop.is_set():
                    break
                path = root / f'entry-{index}'
                os.chmod(path, 0o600 | (generation & 0o77))
                xattr(path, 'org.go-apfs.checkpoint', struct.pack('>QI', generation, index))
            descriptor = os.open(root / 'entry-0', os.O_RDONLY)
            try:
                # F_FULLFSYNC is SDK sys/fcntl.h value 51. This requests Apple's
                # complete native commit, rather than assuming sync timing.
                fcntl.fcntl(descriptor, 51)
            finally:
                os.close(descriptor)
            generation += 1
    except BaseException as error:
        errors.append(str(error))
        stop.set()


def apple_state(image, work, command):
    before = sha256(image)
    native = raw_command(command, image)
    cleanup, physical, inventory = attached(image, native, readonly=True)
    directory = work / (image.stem + '-read')
    try:
        verdict = native('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs',
                         '-n', physical.replace('/dev/disk', '/dev/rdisk')).decode()
        matches = re.findall(r'Checking the checkpoint with transaction ID (\d+)', verdict)
        require(len(matches) == 1, 'Apple checker identifies exactly one selected checkpoint')
        require(len(inventory['Volumes']) == 1, 'single native recovery volume')
        mount(inventory['Volumes'][0], directory, native, readonly=True)
        observed = files(directory / 'Fixture')
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
        return {'selectedXID': int(matches[0]), 'checkerStatus': 0,
                'volumeUUID': inventory['Volumes'][0]['APFSVolumeUUID'], 'files': observed}
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory, ignore_errors=True)
        require(sha256(image) == before, 'Apple read-only selection changed original evidence')


def damage_controls(source, filesystem, work, output, command):
    """Explicitly derived corruption controls, distinct from genuine captures.

    Flip one checksum byte in the newest map or mapped object. An independently
    checked Apple control disables that damaged checkpoint's descriptor, leaving
    the earlier Apple-created filesystem structures unchanged. This establishes
    the complete earlier state without pretending the damaged disk was produced
    by interruption, or that fsck performs the same fallback as the kernel.
    """
    state = checkpoints(source)
    latest = state['latest']
    mapping = state['descriptorBase'] + latest['descriptorIndex']
    with source.open('rb') as stream:
        stream.seek(mapping * 4096 + 40 + 32)
        object_address = struct.unpack('<Q', stream.read(8))[0]
    cases = []
    for shape, address in (('bad-mapping', mapping), ('bad-object', object_address)):
        name = filesystem + '-' + shape
        damaged = work / (name + '-interrupted.raw')
        shutil.copyfile(source, damaged)
        with damaged.open('r+b') as stream:
            stream.seek(address * 4096)
            before = stream.read(1)[0]
            stream.seek(address * 4096)
            stream.write(bytes([before ^ 1]))
        archive = retain_file(damaged, output / (name + '-interrupted.raw.gz'))
        control = work / (name + '-apple-control.raw')
        shutil.copyfile(damaged, control)
        with control.open('r+b') as stream:
            stream.seek(latest['address'] * 4096)
            stream.write(bytes(4096))
        native = apple_state(control, work, command)
        require(native['selectedXID'] < latest['xid'], 'Apple independently checks an earlier complete checkpoint')
        native['controlArchive'] = retain_file(control, output / (name + '-apple-control.raw.gz'))
        cases.append({'id': name, 'source': archive, 'checkpoint': checkpoints(damaged), 'native': native,
                      'damage': {'parentSHA256': sha256(source), 'offset': address * 4096,
                                 'before': before, 'after': before ^ 1,
                                 'disabledControlDescriptor': latest['address']}})
    return cases


def capture(expected_major, output):
    require_disposable_host()
    producer = version(expected_major)
    producer['run'] = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    producer['revision'] = os.environ['GITHUB_SHA']
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases, diagnostics = [], []
    with tempfile.TemporaryDirectory(prefix='apfs-checkpoint-recovery-') as temporary:
        work = Path(temporary)
        capture_helper = work / 'apfs-capture'
        command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror', Path(__file__).with_name('apfs_capture.c'), '-o', capture_helper)
        for filesystem, native_fs in (('apfs', 'APFS'), ('apfs-case-sensitive', 'Case-sensitive APFS')):
            dmg, image = work / (filesystem + '.dmg'), work / (filesystem + '-live.raw')
            command('hdiutil', 'create', '-size', str(CAPACITY), '-layout', 'NONE', '-fs', native_fs, '-volname', 'Recovery', dmg)
            cleanup, _, inventory = attached(dmg, command)
            initial = work / (filesystem + '-initial')
            try:
                mount(inventory['Volumes'][0], initial, command)
                create(initial / 'Fixture', command)
            finally:
                command('hdiutil', 'detach', cleanup)
            copy_disk(dmg, image, command)
            def owned(*argv, **kwargs):
                if tuple(map(str, argv[:2])) == ('hdiutil', 'attach'):
                    argv = (*argv[:2], '-nokernel', '-noautofsck', *argv[2:])
                return command(*argv, **kwargs)
            native = raw_command(owned, image)
            cleanup, physical, inventory = attached(image, native)
            directory = work / (filesystem + '-live')
            stop, errors = threading.Event(), []
            worker = None
            snapshots = {}
            try:
                mount(inventory['Volumes'][0], directory, native)
                images = plistlib.loads(command('hdiutil', 'info', '-plist'))
                (output / (filesystem + '-diskimages-info.json')).write_text(json.dumps(images, indent=2) + '\n')
                identifier = image_helper(images, image, physical)
                worker = threading.Thread(target=churn, args=(directory / 'Fixture', stop, errors))
                worker.start()
                deadline, attempt = time.monotonic() + 120, 0
                for mode in MODES:
                    while time.monotonic() < deadline:
                        candidate = work / (filesystem + f'-candidate-{attempt}.raw')
                        window = json.loads(command('sudo', '--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT',
                                                    capture_helper, image, identifier, candidate, mode))
                        state = checkpoints(candidate)
                        accepted = (mode in state['future']) if mode in ('data', 'mapping') else state['latest']['xid'] == window['observedXID']
                        if mode == 'committed':
                            accepted = accepted and state['latest']['xid'] > state['blockZeroXID']
                        if mode == 'wrapped':
                            accepted = accepted and state['latest']['dataIndex'] < window['previousDataIndex']
                        diagnostics.append({'filesystem': filesystem, 'attempt': attempt, 'window': window, 'state': state, 'accepted': accepted})
                        attempt += 1
                        if accepted:
                            snapshots[mode] = candidate
                            retain_file(candidate, output / (filesystem + '-' + mode + '-interrupted.raw.gz'))
                            print('Captured native checkpoint:', filesystem, mode, state['latest'], flush=True)
                            break
                        candidate.unlink()
                    require(mode in snapshots, f'actual Apple checkpoint window: {filesystem} {mode}')
                require(not errors, f'native metadata workload: {errors}')
            finally:
                stop.set()
                if worker:
                    worker.join(timeout=10)
                    require(not worker.is_alive(), 'bounded native workload shutdown')
                command('hdiutil', 'detach', cleanup)
                (output / 'capture-diagnostics.json').write_text(json.dumps(diagnostics, indent=2) + '\n')
            for mode, source in snapshots.items():
                name = filesystem + '-' + mode
                archive = {'image': name + '-interrupted.raw.gz',
                           'sha256': sha256(output / (name + '-interrupted.raw.gz')),
                           'uncompressedSHA256': sha256(source), 'uncompressedBytes': source.stat().st_size}
                native_state = apple_state(source, work, command)
                cases.append({'id': name, 'source': archive, 'checkpoint': checkpoints(source), 'native': native_state})
                (output / 'recovery.json').write_text(json.dumps({'producer': producer, 'cases': cases}, indent=2) + '\n')
            cases.extend(damage_controls(snapshots['committed'], filesystem, work, output, command))
    producer['tools'] = {name: sha256(Path(name)) for name in
                         ('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '/usr/bin/hdiutil', '/usr/sbin/diskutil')}
    scripts = output / 'scripts'
    scripts.mkdir()
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), scripts / name)
    producer['sources'] = {name: sha256(scripts / name) for name in SOURCES}
    manifest = {'schema': 1, 'scenario': 'apfs-checkpoint-recovery', 'major': expected_major,
                'complete': True, 'producer': producer, 'cases': cases,
                'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'recovery.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    capture(arguments.expected_major, arguments.output)
