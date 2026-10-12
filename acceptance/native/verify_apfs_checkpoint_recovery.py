#!/usr/bin/env python3
"""Apple qualification of actual portable checkpoint recovery and torn commits."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from apfs_editing import mount
from capture import sha256
from container_building import attached, check_filesystem, require_disposable_host
from encrypted_output import disk_hash
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from verify_hfs_recovery import compare
from verify_preservation import require

STAMP = 1749283750
CONTINUED = b'Native write after checkpoint recovery\n'


def check(image, expected, work, command, modify=False, continued=False):
    before = sha256(image)
    native = raw_command(command, image) if image.suffix == '.raw' else command
    cleanup, physical, inventory = attached(image, native, readonly=not modify)
    directory = work / 'mount'
    try:
        check_filesystem(physical, native)
        require(len(inventory['Volumes']) == 1, 'single recovery volume')
        mount(inventory['Volumes'][0], directory, native, readonly=not modify)
        root = directory / 'Fixture'
        if expected is not None:
            compare(files(root), expected)
        native('codesign', '--verify', '--deep', '--strict', root / 'Example.app')
        if modify:
            with (root / 'alias').open('wb') as stream:
                stream.write(CONTINUED)
                stream.flush()
                os.fsync(stream.fileno())
            require((root / 'retained').read_bytes() == CONTINUED, 'native writes retain shared inode')
            created = root / 'native-after-recovery'
            created.mkdir()
            for index in range(48):
                (created / str(index)).write_bytes(bytes(8193))
            for index in range(0, 48, 2):
                (created / str(index)).unlink()
            (created / 'reuse').write_bytes(bytes(65537))
        if continued:
            require((root / 'retained').read_bytes() == (root / 'alias').read_bytes() == CONTINUED,
                    'native continuation persists through remount')
            require(len(list((root / 'native-after-recovery').iterdir())) == 25,
                    'native allocation, unlink and reuse persist through remount')
            require((root / 'native-after-recovery/reuse').read_bytes() == bytes(65537), 'native reused contents')
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory, ignore_errors=True)
    if not modify:
        require(sha256(image) == before, 'read-only verification changed image bytes')


def changed_observation(original, mode=None, payload=None):
    result = json.loads(json.dumps(original))
    for entry in result['entries']:
        if entry['path'] in ('Fixture/retained', 'Fixture/alias'):
            if mode is not None:
                entry['mode'] = entry['mode'] & ~0o7777 | mode
            if payload is not None:
                entry['size'], entry['sha256'] = payload['payloadSize'], payload['payloadSHA256']
                entry['modifyNS'] = STAMP * 1000000000
            entry['changeNS'] = STAMP * 1000000000
    return result


def verify(expected_major, references, outputs, diagnostics):
    require_disposable_host()
    version(expected_major)
    manifest = json.loads((references / 'recovery.json').read_text())
    require(manifest['complete'] and manifest['major'] == expected_major and len(manifest['cases']) == 12,
            'complete independent checkpoint corpus')
    diagnostics.mkdir(parents=True)
    command = Commands(diagnostics / 'commands.json')
    expected_names = set()
    with tempfile.TemporaryDirectory(prefix='verify-apfs-checkpoints-') as temporary:
        work = Path(temporary)
        for case in manifest['cases']:
            for format_name in ('UDRO', 'UDZO'):
                image = outputs / (case['id'] + '-' + format_name + '.dmg')
                expected_names.add(image.name)
                command('hdiutil', 'verify', image)
                check(image, case['native']['files'], work, command)
                if format_name == 'UDRO':
                    raw = work / 'continued.raw'
                    writable_copy(image, raw, command, disk_hash)
                    check(raw, case['native']['files'], work, command, modify=True)
                    check(raw, None, work, command, continued=True)
                    raw.unlink()
            edited = outputs / (case['id'] + '-edited.dmg')
            expected_names.add(edited.name)
            check(edited, changed_observation(case['native']['files'], mode=0o600), work, command)
        faults = json.loads((outputs / 'faults.json').read_text())
        original = next(case for case in manifest['cases'] if case['id'] == 'apfs-committed')
        expected_system = {'recovered-Linux': 'linux', 'recovered-Windows': 'windows', 'recovered-macOS': 'darwin'}[outputs.parent.name]
        require(faults['schema'] == 1 and faults['scenario'] == 'interrupted-Go-commits'
                and faults['producer']['system'] == expected_system and faults['source'] == original['id']
                and faults['sourceSHA256'] == original['source']['uncompressedSHA256']
                and faults['modifySeconds'] == STAMP and len(faults['cases']) == 6, 'Go interrupted-commit provenance')
        seen = set()
        for fault in faults['cases']:
            stage = fault['stage']
            require(stage not in seen and stage in ('data', 'metadata', 'ephemeral', 'mapping', 'superblock', 'block-zero')
                    and fault['partialBytes'] == 7 and fault['trace'][-1]['stage'] == stage,
                    'actual torn write at each named publication boundary')
            seen.add(stage)
            require(fault['modified'] == (stage == 'block-zero'), 'only fully published new checkpoints expose new data')
            image = outputs / fault['output']
            expected_names.add(image.name)
            require(sha256(image) == fault['outputSHA256'], 'actual portable fault recovery output digest')
            digest, count = hashlib.sha256(), 0
            with gzip.open(outputs / f'fault-{stage}-interrupted.raw.gz', 'rb') as stream:
                while data := stream.read(128 << 10):
                    count += len(data)
                    require(count <= 128 << 20, 'bounded actual interrupted Go input')
                    digest.update(data)
            require(count == 128 << 20 and digest.hexdigest() == fault['inputSHA256'], 'retained actual torn input digest')
            observation = changed_observation(original['native']['files'], payload=faults) if fault['modified'] else original['native']['files']
            check(image, observation, work, command)
            raw = work / 'fault-continued.raw'
            writable_copy(image, raw, command, disk_hash)
            check(raw, observation, work, command, modify=True)
            check(raw, None, work, command, continued=True)
            raw.unlink()
    require({path.name for path in outputs.glob('*.dmg')} == expected_names, 'exact portable recovery output inventory')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--diagnostics', type=Path, required=True)
    arguments = parser.parse_args()
    verify(arguments.expected_major, arguments.references, arguments.outputs, arguments.diagnostics)
