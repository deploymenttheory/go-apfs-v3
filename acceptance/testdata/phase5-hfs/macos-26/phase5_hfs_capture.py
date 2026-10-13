#!/usr/bin/env python3
"""Independent Apple debug-format, initialization and HFS tree-growth controls."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import tempfile

from build_hfs_reference import build
from capture import sha256
from container_building import require_disposable_host
from hfs_header_growth import attach, read_headers, retain_file
from hfs_editing import read_journal
from image_repacking import Commands, files, version
from verify_preservation import require

CAPACITY = 96 << 20
GROWTH_CAPACITY = 512 << 20
MAP_CAPACITY = (4096 - 256) * 8
GROWTH_FILES = 120000
SOURCES = ('phase5_hfs_capture.py', 'build_hfs_reference.py', 'capture.py',
           'container_building.py', 'hfs_header_growth.py', 'image_repacking.py',
           'image_building.py', 'image_mutation.py', 'file_compression.py',
           'verify_preservation.py', 'preservation.py', 'metadata_edits.py',
           'content_replacement.py', 'snapshot_reading.py', 'hfs_editing.py')


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
        headers = read_headers(image, image.stat().st_size)
        path = work / label
        mount(device, path, command, readonly=True)
        values = files(path / 'Fixture') if (path / 'Fixture').exists() else {'entries': []}
        return {'headers': headers, 'files': values, 'checkerStatus': 0,
                'journal': read_journal(image)}
    finally:
        command('hdiutil', 'detach', device)
        require(sha256(image) == original, 'HFS observation changed source')


def format_image(image, binary, command, sensitive, journaled, growth):
    require_disposable_host()
    with image.open('xb') as stream:
        stream.truncate(GROWTH_CAPACITY if growth else CAPACITY)
    device = attach(image, command, writable=True)
    try:
        args = ['-s'] if sensitive else []
        if journaled:
            args += ['-J']
        args += ['-U', str(os.getuid()), '-G', str(os.getgid())]
        if growth:
            # Apple's formatter requires catalog nodes >=4096 bytes. These
            # 30720 nodes exactly fill its header map (120 MiB catalog file).
            # Native insertion and subsequent Go insertion must cross that map.
            args += ['-n', 'c=4096', '-I', 'c=30720', '-c', 'c=4096']
        else:
            args += ['-I', 'a=0']
        command('sudo', binary, *args, '-v', 'Phase5',
                device.replace('/dev/disk', '/dev/rdisk'))
        if journaled:
            # hfs_vfsutils.c:hfs_early_journal_init checks journal_is_clean on
            # read-only mounts BEFORE handling kJIJournalNeedInitMask. fsck_hfs
            # does not initialize the formatter's zero journal. Let the kernel
            # initialize it through a first ordinary writable mount/unmount.
            # hfs_xattr_init also creates the attributes tree on this mount.
            # This journaled control therefore covers the initialized native
            # profile, while nonjournaled controls prove absent-tree creation.
            path = image.parent / 'initialize-journal'
            path.mkdir()
            command('sudo', '/sbin/mount_hfs', '-o', 'owners,noatime,nobrowse', device, path)
            # This direct mount is outside Disk Arbitration's mount bookkeeping.
            command('sudo', '/sbin/umount', path)
        if not journaled:
            check(device, command)
        # A direct writable mount may still hold the raw device just after
        # umount. Journaled images receive the same full read-only check in
        # observe after this attachment has been detached and reopened.
    finally:
        command('hdiutil', 'detach', device)


def tree_names(start, stop):
    for number in range(start, stop):
        yield f'{number:05}-' + 'long-name-' * 24


def retain_observation(value, target):
    # A map-boundary control necessarily contains many catalog records. Keep
    # independently observed metadata compressed instead of bloating manifests.
    with target.open('xb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
            for chunk in json.JSONEncoder(separators=(',', ':')).iterencode(value):
                compressed.write(chunk.encode())
    return {'image': target.name, 'sha256': sha256(target)}


def capture_case(case_id, sensitive, journaled, growth, binary, work, output, command):
    require_disposable_host()
    source = work / (case_id + '-source.raw')
    format_image(source, binary, command, sensitive, journaled, growth)
    (output / (case_id + '-format-headers.json')).write_text(json.dumps(
        read_headers(source, source.stat().st_size), indent=2) + '\n')
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
    if not growth and not journaled:
        require(before['headers']['primary']['forks']['attributes']['logicalSize'] == 0,
                'original Apple debug image must have no attributes file')
    elif journaled:
        require(before['headers']['primary']['forks']['attributes']['logicalSize'] > 0,
                'native journal initialization also initializes the attributes tree')
    saved_source = retain_file(source, output / source.name.replace('.raw', '.raw.gz'))
    after = work / (case_id + '-after.raw')
    shutil.copyfile(source, after)
    device = attach(after, command, writable=True)
    try:
        path = work / 'write'
        mount(device, path, command)
        root = path / 'Fixture'
        if growth:
            for name in tree_names(1000, GROWTH_FILES):
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
    (output / (case_id + '-allocation-observations.json')).write_text(json.dumps({
        'before': before['headers'], 'after': final['headers']}, indent=2) + '\n')
    if growth:
        require(before['headers']['catalog']['totalNodes'] == MAP_CAPACITY,
                'initial catalog exactly fits its header map')
        require(final['headers']['catalog']['totalNodes'] > MAP_CAPACITY,
                'native controls must actually grow beyond the initial node map')
    else:
        require(final['headers']['primary']['forks']['attributes']['logicalSize'] > 0,
                'Apple kernel must initialize the absent attributes file')
    saved_after = retain_file(after, output / after.name.replace('.raw', '.raw.gz'))
    if growth:
        for label, observation in (('before', before), ('after', final)):
            observation['fileArchive'] = retain_observation(
                observation.pop('files'), output / (case_id + '-' + label + '-files.json.gz'))
    require(sha256(source) == saved_source['uncompressedSHA256'], 'original HFS evidence changed')
    return {'id': case_id, 'source': saved_source, 'nativeAfter': saved_after,
            'before': before, 'after': final, 'sensitive': sensitive,
            'journaled': journaled, 'growth': growth,
            'growthFiles': GROWTH_FILES if growth else 0,
            'operation': ('catalog-node-map-growth' if growth else
                          'first-attribute-on-initialized-journal' if journaled else
                          'first-attribute-initialization')}


def capture(major, output):
    require_disposable_host()
    producer = version(major)
    producer.update(revision=os.environ['GITHUB_SHA'], run=os.environ['GITHUB_RUN_ID'])
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
