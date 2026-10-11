"""Qualify portable catalog changes and subsequent native/Go/native edits."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from container_building import require_disposable_host
from encrypted_output import sha256
from hfs_editing import STAMP, payload, read_journal
from hfs_header_growth import Commands, attach
from image_repacking import files, version
from image_mutation import writable_copy
from verify_hfs_editing import native_hash
from verify_preservation import require


def compare(actual, expected, before):
    observed = {entry['path']: entry for entry in actual['entries']}
    want = {entry['path']: entry for entry in expected['entries']}
    original = {entry['path']: entry['object'] for entry in before['entries']}
    require(set(observed) == set(want), 'catalog paths exactly match native operations')
    native_to_go, go_to_native = {}, {}
    for path, entry in want.items():
        got = observed[path]
        native_id, go_id = entry['object'], got['object']
        require(native_to_go.get(native_id, go_id) == go_id, 'native aliases remain shared')
        require(go_to_native.get(go_id, native_id) == native_id, 'distinct native identities remain distinct')
        native_to_go[native_id], go_to_native[go_id] = go_id, native_id
        source = {'Fixture/Catalog/Forked': 'Fixture/independent',
                  'Fixture/Catalog/linked': 'Fixture/alias', 'Fixture/small': ''}.get(path, path)
        if source in original:
            require(go_id == original[source], 'original CNID preserved: ' + path)
        else:
            require(go_id not in set(original.values()), 'new entries do not reuse original CNIDs')
        entry = dict(entry)
        if path in ('Fixture', 'Fixture/small') or path.startswith('Fixture/Catalog'):
            entry['changeNS'] = STAMP * 1000000000
            if entry['mode'] & 0o170000 == 0o040000:
                entry['modifyNS'] = STAMP * 1000000000
        for key in ('mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS', 'changeNS',
                    'accessNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if key in entry:
                require(got.get(key) == entry[key], f'{path} {key}: {got.get(key)} != {entry[key]}')


def check(raw, case, phase, command, work, modify=False):
    unchanged = sha256(raw)
    journal = case['before'].get('journal')
    if journal is not None:
        got = read_journal(raw)
        require(got is not None, 'catalog output remains journaled')
        for key in ('infoBlock', 'offset', 'size', 'sha256', 'infoSHA256', 'backingFiles'):
            require(got[key] == journal[key], 'catalog edits preserve journal: ' + key)
    device = attach(raw, command, readonly=not modify, writable=modify)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        mount = work / 'catalog-mount'
        mount.mkdir()
        command('diskutil', 'mount', *([] if modify else ['readOnly']), '-mountOptions',
                'owners,noatime', '-mountPoint', mount, device)
        compare(files(mount / 'Fixture'), case['states'][phase]['files'], case['before']['files'])
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
        if modify:
            directory = mount / 'Fixture/Catalog/native-created'
            directory.mkdir()
            for number in range(96):
                (directory / (f'{number:03d}-' + 'n' * 100)).write_bytes(bytes(8193))
            for number in range(0, 96, 2):
                (directory / (f'{number:03d}-' + 'n' * 100)).unlink()
            (directory / 'reused').write_bytes(bytes(65537))
    finally:
        command('hdiutil', 'detach', device)
        shutil.rmtree(work / 'catalog-mount')
    if not modify:
        require(sha256(raw) == unchanged, 'native read-only catalog verification retains bytes')
    elif journal is not None:
        got = read_journal(raw)
        require(got['start'] == got['end'] and got['sha256'] != journal['sha256'],
                'actual subsequent native journal transactions completed')


def verify(corpus, outputs, continuation, major, journaled):
    require_disposable_host()
    version(major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'hfs-catalog-{major}.diagnostics.json')
    prefix = 'hfs-journaled' if journaled else 'hfs'
    count = 0
    with tempfile.TemporaryDirectory(prefix='hfs-catalog-qualification-') as tmp:
        work = Path(tmp)
        for manifest_path in sorted(corpus.glob('macos-*/catalog-manifest.json')):
            manifest = json.loads(manifest_path.read_text())
            require(manifest['contract'] == ('journaled-hfs-catalog-edits' if journaled else 'existing-hfs-catalog-edits'), 'catalog journal profile')
            for case in manifest['cases']:
                for phase in ('catalog', 'catalog-final'):
                    relative = Path(manifest_path.parent.name, case['id'], phase + '.dmg')
                    images = [outputs / (prefix + '-catalog-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                    require(all(image.is_file() for image in images), 'every portable catalog image present')
                    require(len({sha256(image) for image in images}) == 1, 'catalog output bytes match across hosts')
                    image = images[0]
                    digest = sha256(image)
                    command('hdiutil', 'verify', image)
                    raw = work / 'catalog.raw'
                    writable_copy(image, raw, command, native_hash)
                    check(raw, case, phase, command, work)
                    if phase == 'catalog-final':
                        check(raw, case, phase, command, work, modify=True)
                        shutil.copyfile(raw, continuation / (manifest_path.parent.name + '-' + case['id'] + '.raw'))
                    raw.unlink()
                    require(sha256(image) == digest, 'portable catalog output immutable')
                    count += 1
        require(count == 12, 'complete catalog output/checker inventory')


def verify_continued(directory, major, journaled):
    require_disposable_host()
    version(major)
    command = Commands(directory / f'catalog-continued-{major}.diagnostics.json')
    images = list(directory.glob('*.dmg'))
    require(len(images) == 6, 'complete Go/native/Go catalog continuation')
    with tempfile.TemporaryDirectory(prefix='hfs-catalog-continued-') as tmp:
        work = Path(tmp)
        for image in images:
            raw = work / 'continued.raw'
            writable_copy(image, raw, command, native_hash)
            require((read_journal(raw) is not None) == journaled, 'continued catalog journal profile')
            device = attach(raw, command, readonly=True)
            try:
                command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
                mount = work / 'mount'
                mount.mkdir()
                command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
                catalog = mount / 'Fixture/Catalog'
                require((catalog / 'continued-go/renamed').read_bytes() == payload('continued-catalog', 8193), 'Go create/rename survives native remount')
                require(not (catalog / 'native-created').exists(), 'Go recursive removal survives native remount')
                require(len(list((catalog / 'other/Moved').iterdir())) == 47, 'original namespace retained across continued edits')
                command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
            finally:
                command('hdiutil', 'detach', device)
                shutil.rmtree(work / 'mount')
            raw.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--outputs', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--continued', type=Path)
    parser.add_argument('--journaled', action='store_true')
    args = parser.parse_args()
    if args.continued:
        verify_continued(args.continued, args.expected_major, args.journaled)
    else:
        verify(args.corpus, args.outputs, args.continuation, args.expected_major, args.journaled)
