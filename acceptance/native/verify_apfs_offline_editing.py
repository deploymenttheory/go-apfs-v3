#!/usr/bin/env python3
"""Apple qualification of larger and multi-volume portable APFS edits."""
import argparse
import json
import os
import re
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import attached, check_filesystem, require_disposable_host
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from apfs_geometry import APFS_UTIL, mounted
from verify_hfs_editing import native_hash
from verify_preservation import require

STAMP = 1749283750


def statistics_values(text):
    values = tuple(int(value) for value in re.findall(
        r'(?:descendants|physical size|gen-count): (\d+)', text))
    require(len(values) == 3 and all(value < 2**64 for value in values),
            'native directory statistics layout and bounds')
    return values


def compare_statistics(before, expected, actual):
    want, got = map(statistics_values, (expected, actual))
    old = statistics_values(before) if before is not None else None
    require(got[:2] == want[:2], 'exact native directory counts and allocated bytes')
    # Apple's public format requires monotonic invalidation, not a fixed stride.
    # The same fork truncation/deletion has different strides across kernels.
    require((got[2] == 0) == (want[2] == 0), 'statistics origin/inherited generation')
    if old is not None and old[2] != 0 and want[2] != 0:
        require(want[2] >= old[2] and got[2] >= old[2] and
                (want[2] == old[2]) == (got[2] == old[2]),
                'native statistics monotonic invalidation')


def original_directory_statistics(before, after, name):
    directory = next((entry for entry in after['files']['entries']
                      if entry['path'] == name), None)
    require(directory is not None and directory['mode'] & 0o170000 == 0o040000,
            'native statistics directory identity: ' + name)
    original = next((entry for entry in before['files']['entries']
                     if entry['object'] == directory['object']), None)
    if original is None:
        # A new directory has no earlier generation. Its captured after-state
        # still supplies exact counts, allocated bytes and origin/inheritance.
        return None
    text = before['directoryStatistics'].get(original['path'])
    require(text is not None, 'original statistics directory: ' + original['path'])
    return text


def compare(actual, before, expected, changed):
    observed = {e['path']: e for e in actual['entries']}
    originals = {e['path']: e for e in before['entries']}
    wanted = {e['path']: e for e in expected['entries']}
    require(set(observed) == set(wanted), 'exact native namespace')
    forward, reverse = {}, {}
    for path, source in wanted.items():
        entry, got = dict(source), observed[path]
        if not changed:
            require(got == source, f'untouched volume metadata: {path}')
            continue
        native_id, actual_id = entry['object'], got['object']
        require(forward.setdefault(native_id, actual_id) == actual_id and
                reverse.setdefault(actual_id, native_id) == native_id, 'identity bijection')
        old_path = {'Fixture/renamed': 'Fixture/mode',
                    'Fixture/another-alias': 'Fixture/data'}.get(path, path)
        if old_path in originals:
            require(actual_id == originals[old_path]['object'], 'original identity retained')
        else:
            require(actual_id not in {e['object'] for e in originals.values()}, 'new identity')
            entry['birthSeconds'] = STAMP
            entry['modifyNS'] = entry['accessNS'] = STAMP * 10**9
        entry['object'] = actual_id
        if path in ('Fixture', 'Fixture/renamed') or actual_id == originals['Fixture/data']['object'] or path.startswith('Fixture/created'):
            entry['changeNS'] = STAMP * 10**9
            if entry['mode'] & 0o170000 == 0o040000:
                entry['modifyNS'] = STAMP * 10**9
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                      'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(got.get(field) == entry[field],
                        f'{path} {field}: {got.get(field)} != {entry[field]}')


def inspect(raw, case, command, work, continued=False):
    require_disposable_host()
    digest = sha256(raw)
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native, readonly=True)
    try:
        check_filesystem(physical, native)
        require(len(inventory['Volumes']) == len(case['before']), 'all original volumes')
        for state in case['after']:
            volume = next(v for v in inventory['Volumes'] if v['APFSVolumeUUID'] == state['uuid'])
            require(volume['Name'] == state['name'], 'volume name preserved')
            for field, expected in (('CapacityReserve', state['reserveBytes']),
                                    ('CapacityQuota', state['quotaBytes'])):
                require(volume.get(field, 0) == expected, 'volume space policy')
            path = work / ('inspect-' + state['name'])
            mounted(volume, path, native, readonly=True)
            before = next(v for v in case['before'] if v['uuid'] == state['uuid'])
            target = state['name'] == case['targetVolume']
            if continued and target:
                root = path / 'Fixture'
                require((root / 'alias').read_bytes().endswith(b'native continuation\n'),
                        'continued append survives remount')
                require((root / 'alias').read_bytes() == (root / 'data').read_bytes() ==
                        (root / 'another-alias').read_bytes(), 'continued shared contents')
                require(len(list((root / 'native-created').iterdir())) == 49,
                        'native allocation, removal and reuse survive remount')
            else:
                compare(files(path / 'Fixture'), before['files'], state['files'] if target else
                        before['files'], target)
                for name, expected in state.get('directoryStatistics', {}).items():
                    actual = native(APFS_UTIL, '-S', path / name).decode(errors='strict')
                    original = original_directory_statistics(before, state, name)
                    compare_statistics(original, expected, actual)
            native('codesign', '--verify', '--deep', '--strict', path / 'Fixture/Example.app')
    finally:
        native('hdiutil', 'detach', cleanup)
    for state in case['after']:
        shutil.rmtree(work / ('inspect-' + state['name']))
    require(sha256(raw) == digest, 'read-only native check changed raw bytes')


def continue_native(raw, case, command, work):
    require_disposable_host()
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native)
    try:
        check_filesystem(physical, native)
        volume = next(v for v in inventory['Volumes'] if v['Name'] == case['targetVolume'])
        path = work / 'continue'
        mounted(volume, path, native)
        root = path / 'Fixture'
        with (root / 'alias').open('ab') as stream:
            stream.write(b'native continuation\n')
            stream.flush()
            os.fsync(stream.fileno())
        created = root / 'native-created'
        created.mkdir()
        for number in range(96):
            (created / (f'{number:03}-' + 'x' * 100)).write_bytes(bytes(8193))
        for number in range(0, 96, 2):
            (created / (f'{number:03}-' + 'x' * 100)).unlink()
        (created / 'reused').write_bytes(bytes(65537))
    finally:
        native('hdiutil', 'detach', cleanup)
    shutil.rmtree(work / 'continue')


def verify(corpus, outputs, major, statistics=False):
    from qualification import NativeEvidence, ReplayEvidence
    from qualification_cases import ROOT, image_targets
    require_disposable_host()
    producer = version(major)
    family = 'statistics' if statistics else 'apfs'
    command = Commands(outputs / f'offline-editing-{family}-{major}.diagnostics.json')
    count = 0
    paths = sorted(corpus.glob('macos-*/manifest.json'))
    require(len(paths) == 3, 'all three native source versions')
    input_id = 'apfs-directory-statistics' if statistics else 'apfs-geometry'
    patterns = ([f'macos-{{source}}/{{case}}-{encoding}.dmg' for encoding in ('UDRO', 'UDZO')]
                if statistics else [f'macos-{{source}}/{{case}}/edited-{encoding}.dmg' for encoding in ('UDRO', 'UDZO')])
    replay = ReplayEvidence(outputs, ROOT)
    replay.bind_input(input_id, corpus)
    evidence = NativeEvidence(replay, image_targets(corpus, outputs, input_id,
        'offline-editing-' + family + '-', patterns), ROOT, outputs,
        'offline-editing-' + family, major,
        continuation=lambda case, file: file['path'].endswith('-UDZO.dmg'))
    with tempfile.TemporaryDirectory(prefix='offline-editing-apfs-readback-') as tmp:
        work = Path(tmp)
        for manifest_path in paths:
            manifest = json.loads(manifest_path.read_text())
            require(manifest['contract'] == ('apfs-directory-statistics' if statistics else 'apfs-geometry-editing') and
                    len(manifest['cases']) == (2 if statistics else 4),
                    'complete offline editing APFS controls')
            for case in manifest['cases']:
                for format_name in ('UDRO', 'UDZO'):
                    relative = (Path(manifest_path.parent.name, case['id'] + '-' + format_name + '.dmg') if statistics else
                                Path(manifest_path.parent.name, case['id'], 'edited-' + format_name + '.dmg'))
                    images = [outputs / ('offline-editing-' + family + '-' + host) / relative
                              for host in ('Linux', 'Windows', 'macOS')]
                    with evidence.case(images):
                        require(all(image.is_file() for image in images), 'all portable host outputs')
                        require(len({sha256(image) for image in images}) == 1, 'reproducible across hosts')
                        image, raw = images[0], work / 'output.raw'
                        digest = sha256(image)
                        command('hdiutil', 'verify', image)
                        writable_copy(image, raw, command, native_hash)
                        require(raw.stat().st_size == case['capacityBytes'], 'original geometry retained')
                        inspect(raw, case, command, work)
                        if format_name == 'UDZO':
                            continue_native(raw, case, command, work)
                            inspect(raw, case, command, work, continued=True)
                        raw.unlink()
                        require(sha256(image) == digest, 'original portable output immutable')
                        count += 1
    require(count == (12 if statistics else 24), 'all source-version, profile and encoding combinations')
    (outputs / f'offline-editing-{family}-{major}.result.json').write_text(json.dumps({
        'producer': producer, 'verified': count, 'continuations': count // 2,
        'commandsSHA256': sha256(command.path)}, indent=2) + '\n')
    evidence.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--statistics', action='store_true')
    parser.add_argument('--expected-major', type=int, required=True)
    args = parser.parse_args()
    verify(args.corpus, args.outputs, args.expected_major, args.statistics)
