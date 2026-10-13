#!/usr/bin/env python3
"""Independent Apple checks of portable ACL, set-ID and creator effects."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from phase5_permissions import mount, security
from verify_hfs_editing import native_hash
from verify_preservation import require

STAMP = 1749283750


def compare(actual, before, expected):
    observed = {e['path']: e for e in actual['entries']}
    originals = {e['path']: e for e in before['entries']}
    wanted = {e['path']: e for e in expected['entries']}
    require(set(observed) == set(wanted), 'exact permission namespace')
    original_ids = {e['object'] for e in originals.values()}
    forward, reverse = {}, {}
    for path, source in wanted.items():
        entry, got = dict(source), observed[path]
        native_id, actual_id = entry['object'], got['object']
        require(forward.setdefault(native_id, actual_id) == actual_id and
                reverse.setdefault(actual_id, native_id) == native_id, 'permission identity bijection')
        if path in originals:
            old = originals[path]
            require(actual_id == old['object'], 'original permission identity retained')
            for field in ('modifyNS', 'changeNS'):
                if entry[field] != old[field]:
                    entry[field] = STAMP * 10**9
        else:
            require(actual_id not in original_ids, 'new permission identity')
            entry['birthSeconds'] = STAMP
            entry['modifyNS'] = entry['accessNS'] = entry['changeNS'] = STAMP * 10**9
        entry['object'] = actual_id
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                      'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(got.get(field) == entry[field], f'{path} permission {field}: {got.get(field)} != {entry[field]}')


def inspect(raw, case, command, work, continued=False):
    require_disposable_host()
    digest = sha256(raw)
    native = raw_command(command, raw)
    directory = work / 'inspect'
    cleanup, volume = mount(raw, directory, native, readonly=True)
    try:
        native('diskutil', 'verifyVolume', volume)
        root = directory / 'Fixture'
        if continued:
            require((root / 'inherited/child/native-created').read_bytes() == b'Native inherited continuation\n',
                    'continued inherited creation survives remount')
            require((root / 'write-root').stat().st_mode & 0o6000 == 0,
                    'native non-root write clears portable retained set-ID')
            require(security(root / 'inherited/child/native-created')['acl'] ==
                    case['after']['security']['Fixture/inherited/child/grandchild']['acl'],
                    'native creation inherits the portable child ACL')
        else:
            actual = files(root)
            compare(actual, case['before']['files'], case['after']['files'])
            for entry in actual['entries']:
                require(security(directory / entry['path']) == case['after']['security'][entry['path']],
                        'exact Apple ACL/GUID/rights/inheritance readback: ' + entry['path'])
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)
        require(sha256(raw) == digest, 'read-only permission check changed bytes')


def continue_native(raw, command, work):
    require_disposable_host()
    native = raw_command(command, raw)
    directory = work / 'continue'
    cleanup, _ = mount(raw, directory, native)
    try:
        root = directory / 'Fixture'
        (root / 'inherited/child/native-created').write_bytes(b'Native inherited continuation\n')
        with (root / 'write-root').open('ab') as stream:
            stream.write(b'Native unprivileged continuation\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(root / 'acl-file', 0o644)
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)


def verify(corpus, outputs, major):
    require_disposable_host()
    producer = version(major)
    command = Commands(outputs / f'phase5-permissions-{major}.diagnostics.json')
    manifests = sorted(corpus.glob('macos-*/manifest.json'))
    require(len(manifests) == 3, 'all native permission source versions')
    count = 0
    with tempfile.TemporaryDirectory(prefix='phase5-permissions-readback-') as tmp:
        work = Path(tmp)
        for path in manifests:
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == 'phase5-permission-inheritance' and len(manifest['cases']) == 4,
                    'complete independent permission controls')
            for case in manifest['cases']:
                for encoding in ('UDRO', 'UDZO'):
                    relative = Path(path.parent.name, case['id'] + '-' + encoding + '.dmg')
                    images = [outputs / ('phase5-permissions-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                    require(all(image.is_file() for image in images), 'all portable permission outputs')
                    require(len({sha256(image) for image in images}) == 1, 'permission outputs identical across hosts')
                    image, raw = images[0], work / 'output.raw'
                    digest = sha256(image)
                    command('hdiutil', 'verify', image)
                    writable_copy(image, raw, command, native_hash)
                    require(raw.stat().st_size == case['source']['uncompressedBytes'], 'permission geometry retained')
                    inspect(raw, case, command, work)
                    if encoding == 'UDZO':
                        continue_native(raw, command, work)
                        inspect(raw, case, command, work, continued=True)
                    raw.unlink()
                    require(sha256(image) == digest, 'permission portable source immutable')
                    count += 1
    (outputs / f'phase5-permissions-{major}.verdict.json').write_text(json.dumps({
        'schema': 1, 'contract': 'phase5-permission-inheritance', 'producer': producer,
        'verifiedOutputs': count, 'portableHostsByteIdentical': True,
        'nativeACLAndSetIDReadback': True, 'nativeContinuedCreationAndWrites': True}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    args = parser.parse_args()
    verify(args.corpus, args.outputs, args.expected_major)
