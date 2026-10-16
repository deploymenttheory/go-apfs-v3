#!/usr/bin/env python3
"""Apple checks of portable directory-stat transitions and checkpoint reuse."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile

from apfs_geometry import APFS_UTIL, mounted
from capture import sha256
from container_building import attached, check_filesystem, require_disposable_host
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, files, version
from verify_apfs_offline_editing import compare_statistics, statistics_values
from verify_hfs_editing import native_hash
from verify_preservation import require

STAMP = 1749283750


def entries(state):
    return state['files']['entries'] + state.get('outsideFiles', {}).get('entries', [])


def compare(actual, before, expected):
    originals = {entry['object']: entry for entry in entries(before)}
    observed = {entry['path']: entry for entry in actual}
    wanted = {entry['path']: entry for entry in entries(expected)}
    require(set(observed) == set(wanted), 'exact statistics transition namespace')
    forward, reverse = {}, {}
    for name, captured in wanted.items():
        entry, got = dict(captured), observed[name]
        native_id, actual_id = entry['object'], got['object']
        require(forward.setdefault(native_id, actual_id) == actual_id and
                reverse.setdefault(actual_id, native_id) == native_id,
                'statistics identity bijection')
        old = originals.get(native_id)
        if old is not None:
            require(actual_id == native_id, 'retained original statistics inode')
            if entry['changeNS'] != old['changeNS']:
                entry['changeNS'] = STAMP * 10**9
            if entry['modifyNS'] != old['modifyNS'] and entry['modifyNS'] > STAMP * 10**9:
                entry['modifyNS'] = STAMP * 10**9
        else:
            if entry['birthSeconds'] > STAMP:
                entry['birthSeconds'] = STAMP
            for field in ('modifyNS', 'accessNS'):
                if entry[field] > STAMP * 10**9:
                    entry[field] = STAMP * 10**9
            entry['changeNS'] = STAMP * 10**9
        entry['object'] = actual_id
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                      'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(got.get(field) == entry[field], f'{name} {field}: {got.get(field)} != {entry[field]}')


def inspect(raw, command, work, before, expected):
    require_disposable_host()
    digest = sha256(raw)
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native, readonly=True)
    directory = work / 'read'
    generations = {}
    try:
        check_filesystem(physical, native)
        require(len(inventory['Volumes']) == 1, 'ordinary statistics volume')
        mounted(inventory['Volumes'][0], directory, native, readonly=True)
        actual = files(directory / 'Fixture')['entries'] + files(directory / 'Untracked')['entries']
        compare(actual, before, expected)
        for name, wanted in expected['directoryStatistics'].items():
            actual = native(APFS_UTIL, '-S', directory / name).decode(errors='strict')
            previous = before['directoryStatistics'].get(name,
                'descendants: 0\nphysical size: 0\ngen-count: 0\n')
            compare_statistics(previous, wanted, actual)
            generations[name] = statistics_values(actual)
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)
    require(sha256(raw) == digest, 'native readonly transition check changed bytes')
    return generations


def continue_native(raw, command, work, previous):
    require_disposable_host()
    native = raw_command(command, raw)
    cleanup, physical, inventory = attached(raw, native)
    directory = work / 'write'
    try:
        check_filesystem(physical, native)
        mounted(inventory['Volumes'][0], directory, native)
        root = directory / 'Fixture'
        child = root / 'native-continued'
        child.mkdir()
        data = child / 'data'
        with data.open('wb') as stream:
            stream.write(bytes(65537))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(data, child / 'alias')
        data.unlink()
        allocated = (child / 'alias').stat().st_blocks * 512
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)
    cleanup, physical, inventory = attached(raw, native, readonly=True)
    directory = work / 'remount'
    try:
        check_filesystem(physical, native)
        mounted(inventory['Volumes'][0], directory, native, readonly=True)
        require((directory / 'Fixture/native-continued/alias').read_bytes() == bytes(65537),
                'native continuation contents survive remount')
        current = statistics_values(native(APFS_UTIL, '-S', directory / 'Fixture').decode())
        old = previous['Fixture']
        require(current[:2] == (old[0] + 2, old[1] + allocated) and current[2] > old[2],
                'continued native primary-inode counts, allocation and invalidation')
        native('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
    finally:
        native('hdiutil', 'detach', cleanup)
        shutil.rmtree(directory)


def verify(corpus, outputs, major):
    from qualification import NativeEvidence, ReplayEvidence
    from qualification_cases import ROOT, image_targets
    require_disposable_host()
    producer = version(major)
    command = Commands(outputs / f'offline-editing-statistics-transitions-{major}.diagnostics.json')
    paths = sorted(corpus.glob('macos-*/manifest.json'))
    require({path.parent.name for path in paths} == {'macos-15', 'macos-26', 'macos-27'},
            'every native statistics producer')
    count = continuations = 0
    input_id = 'apfs-directory-statistics-transitions'
    replay = ReplayEvidence(outputs, ROOT)
    replay.bind_input(input_id, corpus)
    evidence = NativeEvidence(replay, image_targets(corpus, outputs, input_id,
        'offline-editing-statistics-transitions-',
        [f'macos-{{source}}/{{case}}/{segment}-{encoding}.dmg'
         for segment in ('before-compression', 'final') for encoding in ('UDRO', 'UDZO')]),
        ROOT, outputs, 'offline-editing-statistics-transitions', major,
        continuation=lambda case, file: file['path'].endswith('/final-UDZO.dmg'))
    with tempfile.TemporaryDirectory(prefix='statistics-readback-') as temporary:
        work = Path(temporary)
        for path in paths:
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == 'apfs-directory-statistics-transitions' and len(manifest['cases']) == 2,
                    'complete statistics profile inventory')
            for case in manifest['cases']:
                require(len(case['states']) == 37, 'all 37 native transition controls')
                index = next(i for i, state in enumerate(case['states']) if state['operation']['op'] == 'compressed')
                # Compression construction belongs to packing. Its original Apple
                # state starts the subsequent independent deletion/move segment.
                segments = [('before-compression', case['before'][0], case['states'][index-1]['volumes'][0]),
                            ('final', case['states'][index]['volumes'][0], case['states'][-1]['volumes'][0])]
                for segment, before, expected in segments:
                    for encoding in ('UDRO', 'UDZO'):
                        relative = Path(path.parent.name, case['id'], segment + '-' + encoding + '.dmg')
                        images = [outputs / ('offline-editing-statistics-transitions-' + host) / relative
                                  for host in ('Linux', 'Windows', 'macOS')]
                        with evidence.case(images):
                            require(all(image.is_file() for image in images), 'all portable statistics outputs')
                            require(len({sha256(image) for image in images}) == 1, 'byte-identical transition outputs')
                            image, raw = images[0], work / 'output.raw'
                            digest = sha256(image)
                            command('hdiutil', 'verify', image)
                            writable_copy(image, raw, command, native_hash)
                            require(raw.stat().st_size == case['source']['uncompressedBytes'], 'original geometry')
                            generations = inspect(raw, command, work, before, expected)
                            if segment == 'final' and encoding == 'UDZO':
                                continue_native(raw, command, work, generations)
                                continuations += 1
                            raw.unlink()
                            require(sha256(image) == digest, 'portable transition image immutable')
                            count += 1
    require(count == 24 and continuations == 6, 'complete transition readback and continuation')
    (outputs / f'offline-editing-statistics-transitions-{major}.result.json').write_text(json.dumps({
        'producer': producer, 'verified': count, 'continuations': continuations,
        'commandsSHA256': sha256(command.path)}, indent=2) + '\n')
    evidence.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--expected-major', type=int, required=True)
    args = parser.parse_args()
    verify(args.corpus, args.outputs, args.expected_major)
