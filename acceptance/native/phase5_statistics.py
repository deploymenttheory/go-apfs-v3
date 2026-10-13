#!/usr/bin/env python3
"""Apple directory-stat transitions across origins, hard links and storage.

Original images after each native operation preserve the hidden records for
file-only analysis. Public apfs.util -S independently reports their effects.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import attached, require_disposable_host
from hfs_header_growth import retain_file
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, version
from phase5_capture import APFS_UTIL, STATS_PROFILES, SOURCES as BASE_SOURCES, create, mounted, observe

SOURCES = ('phase5_statistics.py', *BASE_SOURCES)


def apply(root, operation, command):
    require_disposable_host()
    op, path = operation['op'], root / operation['path']
    if op == 'create':
        path.write_bytes(bytes(operation['size']))
    elif op == 'chmod':
        os.chmod(path, int(operation['mode'], 8))
    elif op == 'xattr':
        from file_compression import xattr
        xattr(path, 'org.go-apfs.statistics', b'Native metadata transition')
    elif op == 'link':
        os.link(path, root / operation['destination'])
    elif op == 'rename':
        path.rename(root / operation['destination'])
    elif op == 'unlink':
        path.unlink()
    elif op == 'mkdir':
        path.mkdir()
    elif op == 'rmdir':
        path.rmdir()
    elif op == 'compressed':
        from file_compression import encode, install, plain
        data = plain(operation['size'])
        install(path, 3, data, payload=encode(3, data))
    else:
        raise ValueError(op)


OPERATIONS = (
    {'op': 'create', 'path': 'new', 'size': 5000},
    {'op': 'chmod', 'path': 'new', 'mode': '0600'},
    {'op': 'xattr', 'path': 'new'},
    {'op': 'link', 'path': 'new', 'destination': 'new-alias'},
    {'op': 'link', 'path': 'new', 'destination': 'nested-origin/new-alias'},
    {'op': 'unlink', 'path': 'new'},
    {'op': 'rename', 'path': 'new-alias', 'destination': '../Untracked/moved'},
    {'op': 'unlink', 'path': 'nested-origin/new-alias'},
    {'op': 'mkdir', 'path': 'subtree'},
    {'op': 'create', 'path': 'subtree/data', 'size': 8193},
    {'op': 'rename', 'path': 'subtree', 'destination': 'nested-origin/subtree'},
    {'op': 'rename', 'path': 'nested-origin/subtree', 'destination': '../Untracked/subtree'},
    {'op': 'rename', 'path': '../Untracked/subtree', 'destination': 'subtree'},
    {'op': 'compressed', 'path': 'compressed', 'size': 1200},
    {'op': 'unlink', 'path': 'compressed'},
    {'op': 'rename', 'path': 'nested-origin', 'destination': '../Untracked/origin'},
    {'op': 'rename', 'path': '../Untracked/origin', 'destination': 'nested-origin'},
    {'op': 'unlink', 'path': 'nested-origin/child/data'},
    {'op': 'rmdir', 'path': 'nested-origin/child'},
    {'op': 'unlink', 'path': 'nested-origin/cross-directory-alias'},
    {'op': 'rmdir', 'path': 'nested-origin'},
)


def capture(major, output):
    require_disposable_host()
    producer = version(major)
    producer.update(revision=os.environ['GITHUB_SHA'], run=os.environ['GITHUB_RUN_ID'])
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    for case_id, capacity, native_fs, _ in STATS_PROFILES:
        with tempfile.TemporaryDirectory(prefix='phase5-statistics-') as tmp:
            work = Path(tmp)
            dmg = work / 'source.dmg'
            command('hdiutil', 'create', '-size', str(capacity), '-layout', 'NONE',
                    '-fs', 'Case-sensitive APFS' if native_fs == 'APFSX' else native_fs,
                    '-volname', 'Primary', dmg)
            cleanup, _, inventory = attached(dmg, command)
            try:
                directory = work / 'create'
                mounted(inventory['Volumes'][0], directory, command)
                create(directory / 'Fixture', command, True)
                command('sudo', 'mkdir', directory / 'Untracked')
                command('sudo', 'chown', f'{os.getuid()}:{os.getgid()}', directory / 'Untracked')
            finally:
                command('hdiutil', 'detach', cleanup)
            source = work / 'source.raw'
            copy_disk(dmg, source, command)
            before = observe(source, work, command, 'before', True)
            saved = retain_file(source, output / (case_id + '-source.raw.gz'))
            edited = work / 'edited.raw'
            shutil.copyfile(source, edited)
            states = []
            for index, operation in enumerate(OPERATIONS):
                native = raw_command(command, edited)
                cleanup, _, inventory = attached(edited, native)
                try:
                    directory = work / f'edit-{index}'
                    mounted(inventory['Volumes'][0], directory, native)
                    apply(directory / 'Fixture', operation, native)
                finally:
                    native('hdiutil', 'detach', cleanup)
                state = observe(edited, work, command, f'after-{index}', True)
                archive = retain_file(edited, output / f'{case_id}-after-{index:02d}.raw.gz')
                states.append({'operation': operation, 'volumes': state, 'archive': archive})
            cases.append({'id': case_id, 'source': saved, 'before': before, 'states': states})
    producer['tools'] = {name: sha256(Path(name)) for name in (
        '/usr/bin/hdiutil', '/usr/sbin/diskutil', APFS_UTIL,
        '/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs')}
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'contract': 'phase5-statistics-transitions', 'major': major,
                'producer': producer, 'cases': cases, 'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
