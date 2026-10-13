#!/usr/bin/env python3
"""Independent Apple debug-format, initialization and HFS tree-growth controls."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from build_hfs_reference import build
from capture import sha256
from container_building import require_disposable_host
from hfs_header_growth import attach, read_headers, retain_file
from image_repacking import Commands, files, version
from verify_preservation import require

CAPACITY = 96 << 20
SOURCES = ('phase5_hfs_capture.py', 'build_hfs_reference.py', 'capture.py',
           'container_building.py', 'hfs_header_growth.py', 'image_repacking.py',
           'image_building.py', 'image_mutation.py', 'file_compression.py',
           'verify_preservation.py', 'preservation.py', 'metadata_edits.py',
           'content_replacement.py', 'snapshot_reading.py')


def check(device, command):
    require_disposable_host()
    command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))


def mount(device, path, command, readonly=False):
    require_disposable_host()
    path.mkdir()
    command('diskutil', 'mount', *(['readOnly'] if readonly else []),
            '-mountOptions', 'owners,noatime', '-mountPoint', path, device)


def observe(image, work, command, label):
    require_disposable_host()
    original = sha256(image)
    device = attach(image, command, readonly=True)
    try:
        check(device, command)
        headers = read_headers(image, CAPACITY)
        path = work / label
        mount(device, path, command, readonly=True)
        values = files(path / 'Fixture') if (path / 'Fixture').exists() else {'entries': []}
        return {'headers': headers, 'files': values, 'checkerStatus': 0}
    finally:
        command('hdiutil', 'detach', device)
        require(sha256(image) == original, 'HFS observation changed source')


def format_image(image, binary, command, sensitive, journaled, growth):
    require_disposable_host()
    with image.open('xb') as stream:
        stream.truncate(CAPACITY)
    device = attach(image, command, writable=True)
    try:
        args = ['-s'] if sensitive else []
        if journaled:
            args += ['-J']
        args += ['-U', str(os.getuid()), '-G', str(os.getgid())]
        if growth:
            # 6144 1024-byte catalog nodes exactly fill the header map.
            # Native insertion and subsequent Go insertion must cross that map.
            args += ['-n', 'c=1024', '-I', 'c=1536', '-c', 'c=1536']
        else:
            args += ['-I', 'a=0']
        command('sudo', binary, *args, '-v', 'Phase5',
                device.replace('/dev/disk', '/dev/rdisk'))
        if journaled:
            # The source formatter leaves a new journal marked for initialization.
            # Ask Apple's checker to prepare it before any read-only observation;
            # retain the actual commands and journal state, never synthesize it.
            command('sudo', '/sbin/fsck_hfs', '-fy',
                    device.replace('/dev/disk', '/dev/rdisk'))
        check(device, command)
    finally:
        command('hdiutil', 'detach', device)


def tree_names(start, stop):
    for number in range(start, stop):
        yield f'{number:05}-' + 'long-name-' * 18


def capture_case(case_id, sensitive, journaled, growth, binary, work, output, command):
    require_disposable_host()
    source = work / (case_id + '-source.raw')
    format_image(source, binary, command, sensitive, journaled, growth)
    (output / (case_id + '-format-headers.json')).write_text(json.dumps(
        read_headers(source, CAPACITY), indent=2) + '\n')
    # Retain original formatter bytes even if a subsequent native mount fails.
    retain_file(source, output / (case_id + '-formatted.raw.gz'))
    if growth:
        device = attach(source, command, writable=True)
        try:
            path = work / 'populate'
            mount(device, path, command)
            root = path / 'Fixture'
            root.mkdir()
            for name in tree_names(0, 1000):
                (root / name).write_bytes(b'')
        finally:
            command('hdiutil', 'detach', device)
    before = observe(source, work, command, 'before')
    if not growth:
        require(before['headers']['primary']['forks']['attributes']['logicalSize'] == 0,
                'original Apple debug image must have no attributes file')
    saved_source = retain_file(source, output / source.name.replace('.raw', '.raw.gz'))
    after = work / (case_id + '-after.raw')
    shutil.copyfile(source, after)
    device = attach(after, command, writable=True)
    try:
        path = work / 'write'
        mount(device, path, command)
        root = path / 'Fixture'
        if growth:
            for name in tree_names(1000, 4000):
                (root / name).write_bytes(b'')
        else:
            from file_compression import xattr
            root.mkdir()
            (root / 'data').write_bytes(b'First ordinary contents\n')
            xattr(root / 'data', 'org.go-apfs.first', b'First native attribute\x00\xff')
            os.link(root / 'data', root / 'alias')
    finally:
        command('hdiutil', 'detach', device)
    final = observe(after, work, command, 'after')
    if growth:
        require(final['headers']['catalog']['totalNodes'] > 6144,
                'native controls must actually grow beyond the initial node map')
    else:
        require(final['headers']['primary']['forks']['attributes']['logicalSize'] > 0,
                'Apple kernel must initialize the absent attributes file')
    saved_after = retain_file(after, output / after.name.replace('.raw', '.raw.gz'))
    require(sha256(source) == saved_source['uncompressedSHA256'], 'original HFS evidence changed')
    return {'id': case_id, 'source': saved_source, 'nativeAfter': saved_after,
            'before': before, 'after': final, 'sensitive': sensitive,
            'journaled': journaled, 'growth': growth,
            'operation': 'catalog-node-map-growth' if growth else 'first-attribute-initialization'}


def capture(major, output):
    require_disposable_host()
    producer = version(major)
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    with tempfile.TemporaryDirectory(prefix='phase5-hfs-') as tmp:
        work = Path(tmp)
        binary, formatter = build(work / 'formatter', command)
        producer['formatter'] = formatter
        for sensitive, label in ((False, 'hfsplus'), (True, 'hfsx')):
            for journaled in (False, True):
                case_id = label + ('-journaled' if journaled else '') + '-first-attribute'
                with tempfile.TemporaryDirectory(dir=work) as case_tmp:
                    cases.append(capture_case(case_id, sensitive, journaled, False,
                                              binary, Path(case_tmp), output, command))
                (output / 'capture-progress.json').write_text(json.dumps({
                    'major': major, 'complete': False, 'cases': cases}, indent=2) + '\n')
            with tempfile.TemporaryDirectory(dir=work) as case_tmp:
                cases.append(capture_case(label + '-catalog-map-growth', sensitive, False,
                                          True, binary, Path(case_tmp), output, command))
    producer['tools'] = {name: sha256(Path(name)) for name in ('/sbin/fsck_hfs', '/usr/bin/hdiutil')}
    source_paths = [Path(__file__).with_name(name) for name in SOURCES]
    source_paths += sorted((Path(__file__).parent / 'reference/hfs').rglob('*'))
    producer['sources'] = {}
    for path in source_paths:
        if not path.is_file():
            continue
        name = str(path.relative_to(Path(__file__).parent))
        producer['sources'][name] = sha256(path)
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    manifest = {'schema': 1, 'contract': 'phase5-hfs-allocation', 'major': major,
                'producer': producer, 'cases': cases,
                'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    capture(args.expected_major, args.output)
