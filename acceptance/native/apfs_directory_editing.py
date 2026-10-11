#!/usr/bin/env python3
"""Apple create/rename/unlink evidence; run only on disposable macOS VMs.

This extends the APFS editing family. Native commands supply every expectation;
the Go writer is not involved in source creation or expected observations.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from apfs_editing import CAPACITY, STAMP, SOURCES, create, mount, payload
from capture import sha256
from container_building import attached, check_filesystem, require_disposable_host
from hfs_header_growth import retain_file
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, files, version

COUNT = 96


def filename(number):
    return f'{number:03d}-' + 'x' * 100


def apply(root, phase, command, host):
    from metadata_edits import set_metadata
    catalog = root / 'Catalog'
    if phase == 'catalog':
        host.write_bytes(payload('catalog', 8193))
        os.chmod(host, 0o644)
        command('/bin/mkdir', '-p', '-m', '0750', catalog / 'A/B')
        command('/bin/mkdir', catalog / 'other', catalog / 'obsolete')
        for number in range(COUNT):
            command('/bin/cp', host, catalog / 'A/B' / filename(number))
        command('/bin/cp', host, catalog / 'obsolete/child')
        command('/bin/cp', host, catalog / 'caf\u00e9:resource')
        command('/bin/mv', root / 'independent', catalog / 'forked')
        command('/bin/mv', catalog / 'forked', catalog / 'Forked')
        command('/bin/mv', catalog / 'A/B', catalog / 'other/Moved')
        command('/bin/mv', catalog / 'other/Moved' / filename(1), root / 'small')
        command('/bin/mv', root / 'alias', catalog / 'linked')
        command('/bin/rm', root / 'fragmented-data')
        command('/bin/mv', root / 'symlink', catalog)
        command('/bin/mv', root / 'dir-link', catalog)
        command('/bin/rm', '-r', catalog / 'obsolete')
        command('/bin/chmod', '0751', catalog / 'other')
        changed = [catalog, catalog / 'A', catalog / 'other', catalog / 'other/Moved',
                   catalog / 'caf\u00e9:resource', root / 'small', *list((catalog / 'other/Moved').iterdir())]
    else:
        command('/bin/rm', catalog / 'linked', root / 'third', root / 'inline-compressed', root / 'resource-compressed')
        command('/bin/rm', '-r', catalog / 'symlink', catalog / 'dir-link')
        for number in range(0, COUNT, 2):
            command('/bin/rm', catalog / 'other/Moved' / filename(number))
        command('/bin/rm', '-r', catalog / 'A')
        command('/bin/mkdir', catalog / 'reused')
        command('/bin/cp', host, catalog / 'reused/contents')
        changed = [catalog / 'reused', catalog / 'reused/contents']
    # The documented offline creation clock is explicit. Normalize native
    # birth/mtime/atime for new objects, retaining the observed native ctime.
    time = {'value': '2025-06-07T08:09:10.000000000Z'}
    for path in changed:
        set_metadata(path, {'birthTime': time, 'modifyTime': time, 'accessTime': time}, command)


def observe(image, work, command):
    require_disposable_host()
    before = sha256(image)
    native = raw_command(command, image)
    cleanup, physical, inventory = attached(image, native, readonly=True)
    try:
        check_filesystem(physical, native)
        directory = work / ('read-' + image.stem)
        mount(inventory['Volumes'][0], directory, native, readonly=True)
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
        return {'files': files(directory / 'Fixture'), 'checkerStatus': 0,
                'volumeUUID': inventory['Volumes'][0]['APFSVolumeUUID']}
    finally:
        native('hdiutil', 'detach', cleanup)
        if sha256(image) != before:
            raise RuntimeError('read-only directory observation changed image')


def capture(major, output):
    require_disposable_host()
    producer = version(major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    with tempfile.TemporaryDirectory(prefix='apfs-directory-edits-') as tmp:
        work = Path(tmp)
        for filesystem, native_fs in (('apfs', 'APFS'), ('apfs-case-sensitive', 'Case-sensitive APFS')):
            dmg = work / (filesystem + '.dmg')
            command('hdiutil', 'create', '-size', str(CAPACITY), '-layout', 'NONE', '-fs', native_fs, '-volname', 'Existing', dmg)
            cleanup, _, inventory = attached(dmg, command)
            try:
                directory = work / (filesystem + '-write')
                mount(inventory['Volumes'][0], directory, command)
                create(directory / 'Fixture', command)
                os.link(directory / 'Fixture/alias', directory / 'Fixture/third')
                os.symlink('guards', directory / 'Fixture/dir-link')
            finally:
                command('hdiutil', 'detach', cleanup)
            image = work / (filesystem + '-source.raw')
            copy_disk(dmg, image, command)
            case = {'id': filesystem, 'source': retain_file(image, output / (filesystem + '-source.raw.gz')),
                    'before': observe(image, work, command), 'states': {}}
            host = work / 'catalog-payload'
            for phase in ('catalog', 'catalog-final'):
                edited = work / (filesystem + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                native = raw_command(command, edited)
                cleanup, _, inventory = attached(edited, native)
                try:
                    directory = work / (filesystem + '-' + phase + '-write')
                    mount(inventory['Volumes'][0], directory, native)
                    apply(directory / 'Fixture', phase, native, host)
                finally:
                    native('hdiutil', 'detach', cleanup)
                state = observe(edited, work, command)
                state['archive'] = retain_file(edited, output / (filesystem + '-' + phase + '.raw.gz'))
                case['states'][phase] = state
                image = edited
            cases.append(case)
    producer['tools'] = {path: sha256(Path(path)) for path in
                         ('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '/usr/bin/hdiutil',
                          '/bin/cp', '/bin/mv', '/bin/rm', '/bin/mkdir', '/bin/chmod')}
    sources = (*SOURCES, Path(__file__).name)
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in sources}
    for name in sources:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'major': major, 'producer': producer, 'cases': cases,
                'contract': 'existing-apfs-directory-edits', 'modificationSeconds': STAMP,
                'capacityBytes': CAPACITY, 'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
