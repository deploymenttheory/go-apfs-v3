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
from permission_inheritance import mount, security
from verify_hfs_editing import native_hash
from verify_preservation import require

STAMP = 1749283750


def compare(actual, before, expected):
    observed = {e['path']: e for e in actual['entries']}
    originals = {e['path']: e for e in before['entries']}
    wanted = {e['path']: e for e in expected['entries']}
    require(set(observed) == set(wanted), 'exact permission namespace')
    original_ids = {e['object'] for e in originals.values()}
    original_times = {field: {entry[field] for entry in originals.values()} for field in ('modifyNS', 'accessNS')}
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
                if entry[field] != old[field] and (field == 'changeNS' or
                        entry[field] > STAMP * 10**9 and entry[field] not in original_times[field]):
                    entry[field] = STAMP * 10**9
        else:
            require(actual_id not in original_ids, 'new permission identity')
            if entry['birthSeconds'] > STAMP:
                entry['birthSeconds'] = STAMP
            for field in ('modifyNS', 'accessNS'):
                if entry[field] > STAMP * 10**9 and entry[field] not in original_times[field]:
                    entry[field] = STAMP * 10**9
            entry['changeNS'] = STAMP * 10**9
        entry['object'] = actual_id
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                      'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(got.get(field) == entry[field], f'{path} permission {field}: {got.get(field)} != {entry[field]}')


def inspect(raw, case, command, work, continued=False, copies=False):
    require_disposable_host()
    digest = sha256(raw)
    native = raw_command(command, raw)
    directory = work / 'inspect'
    cleanup, volume = mount(raw, directory, native, readonly=True)
    try:
        native('diskutil', 'verifyVolume', volume)
        root = directory / 'Fixture'
        if continued:
            name = 'inherited/native-created' if copies else 'inherited/child/native-created'
            expected_acl = 'Fixture/inherited/copied' if copies else 'Fixture/inherited/child/grandchild'
            require((root / name).read_bytes() == b'Native inherited continuation\n',
                    'continued inherited creation survives remount')
            require((root / 'write-root').stat().st_mode & 0o6000 == 0,
                    'native non-root write clears portable retained set-ID')
            require(security(root / name)['acl'] ==
                    case['after']['security'][expected_acl]['acl'],
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


def continue_native(raw, command, work, copies=False):
    require_disposable_host()
    native = raw_command(command, raw)
    directory = work / 'continue'
    cleanup, _ = mount(raw, directory, native)
    try:
        root = directory / 'Fixture'
        name = 'inherited/native-created' if copies else 'inherited/child/native-created'
        (root / name).write_bytes(b'Native inherited continuation\n')
        with (root / 'write-root').open('ab') as stream:
            stream.write(b'Native unprivileged continuation\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(root / 'acl-file', 0o644)
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)


def verify(corpus, outputs, major, copies=False):
    from qualification import NativeEvidence, ReplayEvidence
    from qualification_cases import ROOT, image_targets
    require_disposable_host()
    producer = version(major)
    family = 'copy-permissions' if copies else 'permissions'
    contract = 'copy-permissions' if copies else 'permission-inheritance'
    command = Commands(outputs / f'offline-editing-{family}-{major}.diagnostics.json')
    manifests = sorted(corpus.glob('macos-*/manifest.json'))
    require(len(manifests) == 3, 'all native permission source versions')
    replay = ReplayEvidence(outputs, ROOT)
    replay.bind_input(contract, corpus)
    evidence = NativeEvidence(replay, image_targets(corpus, outputs, contract,
        'offline-editing-' + family + '-',
        [f'macos-{{source}}/{{case}}-{encoding}.dmg' for encoding in ('UDRO', 'UDZO')]),
        ROOT, outputs, 'offline-editing-' + family, major,
        continuation=lambda case, file: file['path'].endswith('-UDZO.dmg'))
    count = 0
    with tempfile.TemporaryDirectory(prefix='offline-editing-' + family + '-readback-') as tmp:
        work = Path(tmp)
        for path in manifests:
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == contract and len(manifest['cases']) == 4,
                    'complete independent permission controls')
            for case in manifest['cases']:
                for encoding in ('UDRO', 'UDZO'):
                    relative = Path(path.parent.name, case['id'] + '-' + encoding + '.dmg')
                    images = [outputs / ('offline-editing-' + family + '-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                    with evidence.case(images):
                        require(all(image.is_file() for image in images), 'all portable permission outputs')
                        require(len({sha256(image) for image in images}) == 1, 'permission outputs identical across hosts')
                        image, raw = images[0], work / 'output.raw'
                        digest = sha256(image)
                        command('hdiutil', 'verify', image)
                        writable_copy(image, raw, command, native_hash)
                        require(raw.stat().st_size == case['source']['uncompressedBytes'], 'permission geometry retained')
                        inspect(raw, case, command, work, copies=copies)
                        if encoding == 'UDZO':
                            continue_native(raw, command, work, copies=copies)
                            inspect(raw, case, command, work, continued=True, copies=copies)
                        raw.unlink()
                        require(sha256(image) == digest, 'permission portable source immutable')
                        count += 1
    (outputs / f'offline-editing-{family}-{major}.verdict.json').write_text(json.dumps({
        'schema': 1, 'contract': contract, 'producer': producer,
        'verifiedOutputs': count, 'portableHostsByteIdentical': True,
        'nativeACLAndSetIDReadback': True, 'nativeContinuedCreationAndWrites': True}, indent=2) + '\n')
    evidence.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--copies', action='store_true')
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    args = parser.parse_args()
    verify(args.corpus, args.outputs, args.expected_major, args.copies)
