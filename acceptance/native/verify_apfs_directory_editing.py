#!/usr/bin/env python3
"""Apple qualification of APFS directory edits from every portable producer."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from apfs_editing import attached, mount, check_filesystem, payload
from capture import sha256
from container_building import require_disposable_host
from directory_edits import compare as compare_directory
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from verify_hfs_editing import native_hash
from verify_preservation import require


def compare(actual, expected, before):
    moved = {'Fixture/Catalog/Forked': 'Fixture/independent',
             'Fixture/Catalog/linked': 'Fixture/alias', 'Fixture/small': '',
             'Fixture/Catalog/symlink': 'Fixture/symlink',
             'Fixture/Catalog/dir-link': 'Fixture/dir-link'}
    compare_directory(actual, expected, before, moved,
                      lambda path: path in ('Fixture', 'Fixture/small', 'Fixture/third') or path.startswith('Fixture/Catalog'))


def check(raw, case, phase, command, work, modify=False):
    digest = sha256(raw)
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native, readonly=not modify)
    directory = work / 'mount'
    try:
        check_filesystem(physical, native)
        mount(inventory['Volumes'][0], directory, native, readonly=not modify)
        compare(files(directory / 'Fixture'), case['states'][phase]['files'], case['before']['files'])
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
        if modify:
            created = directory / 'Fixture/Catalog/native-created'
            created.mkdir()
            for n in range(96):
                (created / (f'{n:03d}-' + 'n' * 100)).write_bytes(bytes(8193))
            for n in range(0, 96, 2):
                (created / (f'{n:03d}-' + 'n' * 100)).unlink()
            (created / 'reused').write_bytes(bytes(65537))
            # A native hard link after Go repaired the primary/sibling records
            # proves that Apple's driver can extend and shrink that link set.
            native('/bin/ln', directory / 'Fixture/third', created / 'native-link')
            native('/bin/rm', created / 'native-link')
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)
    if not modify:
        require(sha256(raw) == digest, 'native read-only check changed portable bytes')


def verify(corpus, outputs, continuation, major):
    require_disposable_host()
    version(major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'apfs-directories-{major}.diagnostics.json')
    count = 0
    with tempfile.TemporaryDirectory(prefix='apfs-directory-readback-') as tmp:
        work = Path(tmp)
        for path in sorted(corpus.glob('macos-*/manifest.json')):
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == 'existing-apfs-directory-edits', 'native APFS directory corpus')
            for case in manifest['cases']:
                for phase in ('catalog', 'catalog-final'):
                    for format_name in ('UDRO', 'UDZO'):
                        relative = Path(path.parent.name, case['id'], phase + '-' + format_name + '.dmg')
                        images = [outputs / ('apfs-directories-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        require(all(image.is_file() for image in images), 'all portable directory outputs present')
                        require(len({sha256(image) for image in images}) == 1, 'byte-identical APFS directory outputs across hosts')
                        image, raw = images[0], work / 'output.raw'
                        digest = sha256(image)
                        command('hdiutil', 'verify', image)
                        writable_copy(image, raw, command, native_hash)
                        check(raw, case, phase, command, work)
                        if phase == 'catalog-final' and format_name == 'UDZO':
                            check(raw, case, phase, command, work, modify=True)
                            # Check the resulting allocation/tree with Apple's
                            # checker before supplying it to the next Go edit.
                            cleanup, physical, _ = attached(raw, raw_command(command, raw), readonly=True)
                            try:
                                check_filesystem(physical, raw_command(command, raw))
                            finally:
                                command('hdiutil', 'detach', cleanup)
                            shutil.copyfile(raw, continuation / (path.parent.name + '-' + case['id'] + '.raw'))
                        raw.unlink()
                        require(sha256(image) == digest, 'portable image changed during native verification')
                        count += 1
    require(count == 24, 'complete directory readback inventory')


def verify_continued(directory, major):
    require_disposable_host()
    version(major)
    command = Commands(directory / f'apfs-directory-continued-{major}.diagnostics.json')
    images = list(directory.glob('*.dmg'))
    require(len(images) == 6, 'complete Go/native/Go directory continuation inventory')
    with tempfile.TemporaryDirectory(prefix='apfs-directory-continued-') as tmp:
        work = Path(tmp)
        for image in images:
            raw = work / 'continued.raw'
            writable_copy(image, raw, command, native_hash)
            native = raw_command(command, raw)
            cleanup, physical, inventory = attached(raw, native, readonly=True)
            directory = work / 'mount'
            try:
                check_filesystem(physical, native)
                mount(inventory['Volumes'][0], directory, native, readonly=True)
                root = directory / 'Fixture'
                require((root / 'Catalog/continued-go/renamed').read_bytes() == payload('continued-catalog', 8193), 'continued Go create/move bytes')
                require(not (root / 'Catalog/native-created').exists(), 'Go recursive removal survives native remount')
                require(not (root / 'third').exists(), 'last hard link removed by Go')
                require((root / 'guards').is_dir(), 'symlink removal never traverses its target')
                require(len(list((root / 'Catalog/other/Moved').iterdir())) == 47, 'namespace preserved across continued edits')
                native('codesign', '--verify', '--deep', '--strict', root / 'Example.app')
            finally:
                native('hdiutil', 'detach', cleanup)
                shutil.rmtree(directory)
            raw.unlink()


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
