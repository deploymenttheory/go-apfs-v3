#!/usr/bin/env python3
"""Apple checks of absent-tree, overflow and node-map portable HFS edits."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from hfs_editing import read_journal
from hfs_header_growth import attach, read_headers
from hfs_metadata_growth import read_tree_headers
from image_mutation import writable_copy
from image_repacking import Commands, files, version
from verify_hfs_editing import native_hash
from verify_preservation import require

STAMP = 1749283750


def observation(directory, state):
    if 'fileArchive' not in state:
        return state['files']
    archive = state['fileArchive']
    path = directory / archive['image']
    require(sha256(path) == archive['sha256'], 'original native observation digest')
    with gzip.open(path, 'rb') as stream:
        data = stream.read((128 << 20) + 1)
    require(len(data) <= 128 << 20, 'bounded native observation')
    return json.loads(data)


def compare(actual, before, expected):
    got = {entry['path']: entry for entry in actual['entries']}
    old = {entry['path']: entry for entry in before['entries']}
    want = {entry['path']: entry for entry in expected['entries']}
    require(set(got) == set(want), 'exact native HFS namespace')
    forward, reverse = {}, {}
    for path, captured in want.items():
        entry, value = dict(captured), got[path]
        native_id, actual_id = entry['object'], value['object']
        require(forward.setdefault(native_id, actual_id) == actual_id and
                reverse.setdefault(actual_id, native_id) == native_id, 'native identity bijection')
        if path in old:
            require(actual_id == old[path]['object'], 'original HFS identity preserved')
            if path == 'Fixture':
                entry['modifyNS'] = entry['changeNS'] = STAMP * 10**9
        else:
            entry['birthSeconds'] = STAMP
            entry['modifyNS'] = entry['accessNS'] = entry['changeNS'] = STAMP * 10**9
        entry['object'] = actual_id
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS',
                      'accessNS', 'changeNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(value.get(field) == entry[field],
                        f'{path} {field}: {value.get(field)} != {entry[field]}')


def inspect(raw, case, command, work, before, expected, continued=False, lifecycle=None):
    require_disposable_host()
    digest = sha256(raw)
    device = attach(raw, command, readonly=True)
    path = work / 'read'
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        headers = read_headers(raw, raw.stat().st_size)
        require(headers['primary']['forks'] == headers['alternate']['forks'], 'both volume headers agree')
        if case['growth']:
            require(headers['catalog']['totalNodes'] > (4096 - 256) * 8, 'Go extended the actual node map')
        elif case.get('fragmented'):
            for name in ('catalog', 'attributes'):
                fork = headers['primary']['forks'][name]
                require(fork['totalBlocks'] > sum(e[1] for e in fork['extents']),
                        'Go metadata also exercises overflow extents: ' + name)
        else:
            require(headers['primary']['forks']['attributes']['logicalSize'] > 0, 'attributes tree initialized')
        if lifecycle is not None:
            trees = read_tree_headers(raw)
            wanted = case[lifecycle]['treeHeaders']
            # Native writable mounts may create filesystem-owned catalog and
            # security records outside Fixture. Their tree topology is not a
            # user-visible value. Both independent trees must collapse/reuse;
            # exact Fixture entries and raw attributes are checked below.
            peak = case['after']['treeHeaders']
            require(trees['catalog']['depth'] <= peak['catalog']['depth'],
                    'bounded catalog depth after deletion/reuse')
            require(trees['attributes']['depth'] < peak['attributes']['depth'] and
                    trees['attributes']['leafRecords'] <= wanted['attributes']['leafRecords'],
                    'attributes root collapse and record retirement after ' + lifecycle)
        path.mkdir()
        command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', path, device)
        if not continued:
            compare(files(path / 'Fixture'), before, expected)
        else:
            root = path / 'Fixture'
            require((root / 'native-written').read_bytes() == b'Native continuation\n', 'native writes survive remount')
            require(len(list((root / 'native-created').iterdir())) == 49, 'native growth, deletion and reuse survive remount')
    finally:
        command('hdiutil', 'detach', device)
    shutil.rmtree(path)
    require(sha256(raw) == digest, 'native read-only check changed portable raw bytes')


def continue_native(raw, command, work):
    require_disposable_host()
    device = attach(raw, command, writable=True)
    path = work / 'write'
    try:
        path.mkdir()
        command('diskutil', 'mount', '-mountOptions', 'owners,noatime', '-mountPoint', path, device)
        root = path / 'Fixture'
        with (root / 'native-written').open('wb') as stream:
            stream.write(b'Native continuation\n')
            stream.flush()
            os.fsync(stream.fileno())
        directory = root / 'native-created'
        directory.mkdir()
        for n in range(96):
            (directory / (f'{n:03}-' + 'x' * 100)).write_bytes(bytes(8193))
        for n in range(0, 96, 2):
            (directory / (f'{n:03}-' + 'x' * 100)).unlink()
        (directory / 'reused').write_bytes(bytes(65537))
    finally:
        command('hdiutil', 'detach', device)
    shutil.rmtree(path)


def verify(corpus, outputs, major, fragmented=False):
    require_disposable_host()
    producer = version(major)
    prefix = 'offline-editing-hfs-fragmented' if fragmented else 'offline-editing-hfs'
    command = Commands(outputs / f'{prefix}-{major}.diagnostics.json')
    manifests = sorted(corpus.glob('macos-*/manifest.json'))
    require({p.parent.name for p in manifests} == {'macos-15', 'macos-26', 'macos-27'}, 'all native source versions')
    count = 0
    with tempfile.TemporaryDirectory(prefix=prefix + '-readback-') as temporary:
        work = Path(temporary)
        for path in manifests:
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == ('hfs-fragmented-metadata' if fragmented else 'hfs-metadata-growth'), 'native HFS contract')
            require(len(manifest['cases']) == (2 if fragmented else 6), 'complete HFS profile inventory')
            for case in manifest['cases']:
                before = observation(path.parent, case['before'])
                stages = [('edited', case['after'])]
                if fragmented:
                    require('collapsed' in case and 'reused' in case, 'native collapse and reuse controls')
                    stages += [('collapsed', case['collapsed']), ('reused', case['reused'])]
                for stage, state in stages:
                  expected = observation(path.parent, state)
                  for encoding in ('UDRO', 'UDZO'):
                    relative = Path(path.parent.name, case['id'], stage + '-' + encoding + '.dmg')
                    images = [outputs / (prefix + '-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                    require(all(p.is_file() for p in images), 'all three portable outputs')
                    require(len({sha256(p) for p in images}) == 1, 'byte-identical across hosts')
                    image, raw = images[0], work / 'output.raw'
                    digest = sha256(image)
                    command('hdiutil', 'verify', image)
                    writable_copy(image, raw, command, native_hash)
                    require(raw.stat().st_size == case['source']['uncompressedBytes'], 'original geometry preserved')
                    journal = case['before'].get('journal')
                    if journal is not None:
                        got = read_journal(raw)
                        require(got is not None, 'original journaling retained')
                        for field in ('infoBlock', 'offset', 'size', 'sha256', 'infoSHA256', 'backingFiles'):
                            require(got[field] == journal[field], 'original journal storage: ' + field)
                    inspect(raw, case, command, work, before, expected, lifecycle=None if stage == "edited" else stage)
                    if encoding == 'UDZO' and stage == 'edited':
                        continue_native(raw, command, work)
                        inspect(raw, case, command, work, before, expected, continued=True)
                    raw.unlink()
                    require(sha256(image) == digest, 'portable completed output changed')
                    count += 1
    require(count == 36, 'all native profiles and both DMG encodings')
    (outputs / f'{prefix}-{major}.result.json').write_text(json.dumps({
        'producer': producer, 'verified': count, 'continuations': 6 if fragmented else 18,
        'commandsSHA256': sha256(command.path)}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--fragmented', action='store_true')
    args = parser.parse_args()
    verify(args.corpus, args.outputs, args.expected_major, args.fragmented)
