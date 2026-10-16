#!/usr/bin/env python3
"""Apple qualification of portable APFS edits and subsequent native allocation."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from apfs_editing import attached, mount, check_filesystem, payload
from capture import sha256
from container_building import require_disposable_host
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from verify_hfs_editing import compare, native_hash
from verify_preservation import require


def check_raw(raw, expected, phase, command, work, modify=False):
    before = sha256(raw)
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native, readonly=not modify)
    directory = work / 'mount'
    try:
        check_filesystem(physical, native)
        mount(inventory['Volumes'][0], directory, native, readonly=not modify)
        if expected is not None:
            compare(files(directory / 'Fixture'), expected, phase)
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
        if modify:
            with (directory / 'Fixture/alias').open('ab') as stream:
                stream.write(b'native continuation\n'); stream.flush(); os.fsync(stream.fileno())
            require((directory / 'Fixture/alias').read_bytes() == (directory / 'Fixture/fragmented-data').read_bytes(),
                    'native writes preserve hard-link identity')
            created = directory / 'Fixture/native-created'
            created.mkdir()
            for n in range(96):
                (created / (f'{n:03}-' + 'x' * 100)).write_bytes(bytes(8193))
            for n in range(0, 96, 2):
                (created / (f'{n:03}-' + 'x' * 100)).unlink()
            (created / 'reused').write_bytes(bytes(65537))
    finally:
        native('hdiutil', 'detach', cleanup)
    shutil.rmtree(directory)
    if not modify:
        require(sha256(raw) == before, 'native observation changed portable raw copy')


def verify(corpus, outputs, continuation, expected_major):
    require_disposable_host()
    version(expected_major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'apfs-editing-{expected_major}.diagnostics.json')
    count = 0
    from qualification_cases import image_verification
    input_id = 'apfs-editing'
    evidence = image_verification(corpus, outputs, input_id, 'apfs-edits-',
        ['macos-{source}/{case}/peak-UDRO.dmg', 'macos-{source}/{case}/peak-UDZO.dmg', 'macos-{source}/{case}/final-UDRO.dmg', 'macos-{source}/{case}/final-UDZO.dmg'], 'apfs_editing', expected_major,
        manifest='manifest.json', continued=lambda name: name.endswith('/final-UDZO.dmg'))
    with tempfile.TemporaryDirectory(prefix='apfs-edit-readback-') as tmp:
        work = Path(tmp)
        for manifest_path in sorted(corpus.glob('macos-*/manifest.json')):
            manifest = json.loads(manifest_path.read_text())
            require(manifest['contract'] == 'existing-apfs-file-edits', 'APFS edit corpus contract')
            for case in manifest['cases']:
                for phase in ('peak', 'final'):
                    for format_name in ('UDRO', 'UDZO'):
                        relative = Path(manifest_path.parent.name, case['id'], phase + '-' + format_name + '.dmg')
                        images = [outputs / ('apfs-edits-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        with evidence.case(images):
                            require(all(image.is_file() for image in images), 'every portable host supplies APFS edits')
                            require(len({sha256(image) for image in images}) == 1, 'byte-identical APFS edits across hosts')
                            image, raw = images[0], work / 'output.raw'
                            before = sha256(image)
                            command('hdiutil', 'verify', image)
                            writable_copy(image, raw, command, native_hash)
                            check_raw(raw, case['states'][phase]['files'], phase, command, work)
                            if phase == 'final' and format_name == 'UDZO':
                                check_raw(raw, case['states'][phase]['files'], phase, command, work, modify=True)
                                check_raw(raw, None, phase, command, work)
                                shutil.copyfile(raw, continuation / (manifest_path.parent.name + '-' + case['id'] + '.raw'))
                            raw.unlink()
                            require(sha256(image) == before, 'native check changed portable image')
                            count += 1
    require(count == 24, 'complete APFS readback inventory')
    evidence.finish()


def verify_continued(directory, expected_major):
    require_disposable_host()
    version(expected_major)
    command = Commands(directory / f'apfs-continued-{expected_major}.diagnostics.json')
    images = sorted(directory.glob('*.dmg'))
    require(len(images) == 6, 'complete Go/native/Go APFS continuation inventory')
    from qualification_cases import continuation_verification
    evidence = continuation_verification(directory, 'apfs', 'apfs_editing-continued', expected_major,
        metadata=False, raw_suffix=False)
    with tempfile.TemporaryDirectory(prefix='apfs-continued-readback-') as tmp:
        work = Path(tmp)
        for image in images:
            with evidence.case([image]):
                raw = work / 'continued.raw'
                writable_copy(image, raw, command, native_hash)
                native = raw_command(command, raw)
                cleanup, physical, inventory = attached(raw, native, readonly=True)
                directory = work / 'mount'
                try:
                    check_filesystem(physical, native)
                    mount(inventory['Volumes'][0], directory, native, readonly=True)
                    require((directory / 'Fixture/alias').read_bytes() == payload('continued-go', 8193),
                            'Go re-edit survives native remount')
                    require((directory / 'Fixture/alias').read_bytes() == (directory / 'Fixture/fragmented-data').read_bytes(),
                            'continued hard-link contents')
                    require(len(list((directory / 'Fixture/native-created').iterdir())) == 49,
                            'native directory/allocation changes survive Go re-edit')
                    native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
                finally:
                    native('hdiutil', 'detach', cleanup)
                shutil.rmtree(directory)
                raw.unlink()
    evidence.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--outputs', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--continued', type=Path)
    args = parser.parse_args()
    if args.continued:
        verify_continued(args.continued, args.expected_major)
    else:
        verify(args.corpus, args.outputs, args.continuation, args.expected_major)
