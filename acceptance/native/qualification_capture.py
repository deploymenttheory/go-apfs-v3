#!/usr/bin/env python3
"""Record complete Apple capture observations without changing their originals.

This gate checks each independently required native case and its returned bytes.
It does not turn an expected native refusal into a supported Go capability.
Capture records stay outside the filesystem image/observation input trees.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from qualification import (canonical, file_digest, identity, native_contract,
                           native_environment, portable_path, publish_receipt,
                           read_document, require, source_identities, verify_file)
from qualification_cases import ROOT


def snapshot(root):
    root = Path(root)
    files, total = [], 0
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'capture contains aliased input bytes')
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        portable_path(relative)
        total += path.stat().st_size
        require(len(files) < 100000 and total <= 16 << 30, 'capture exceeds corpus bounds')
        files.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': file_digest(path)})
    require(files, 'capture has no returned bytes')
    return files


def case_records(document):
    result = {}
    for key in ('cases', 'rejections', 'sectorProbes'):
        for case in document.get(key, ()):
            name = str(case['capacity']) if key == 'sectorProbes' else case['id']
            identity = key + '/' + name
            require(identity not in result, 'duplicate captured native case')
            result[identity] = case
    return result


def verify_references(root, value):
    """Check digest-bearing file references, leaving inline observations intact."""
    if isinstance(value, list):
        for item in value:
            verify_references(root, item)
    elif isinstance(value, dict):
        for key, name in value.items():
            digest = value.get(key + 'SHA256')
            if key == 'image' and not digest:
                digest = value.get('sha256')
            if isinstance(name, str) and isinstance(digest, str):
                portable_path(name)
                require(file_digest(Path(root) / name) == digest, 'captured native file digest differs: ' + name)
            if isinstance(name, (dict, list)):
                verify_references(root, name)


def capture(major, bindings, directory, source_root=ROOT):
    # The disposable-host guard runs before reading a capture or creating proof.
    environment = native_environment(major, os.sys.argv[1:])
    catalog = read_document(Path(source_root) / 'acceptance/qualification/corpus.json')
    recipes = read_document(Path(source_root) / 'acceptance/qualification/replay.json')
    entries = {entry['id']: entry for entry in catalog['entries']}
    required, inputs, outputs, originals = [], [], [], []
    current_go = False
    directory = Path(directory)
    require(not directory.exists(), 'capture proof already exists')
    for corpus_id, root in sorted(bindings.items()):
        require(corpus_id in entries, 'capture corpus is not registered')
        entry = entries[corpus_id]
        root = Path(root)
        files = snapshot(root)
        originals.extend((root, record) for record in files)
        inputs.append({'id': corpus_id, 'tree_sha256': identity(files), 'use':
                       'current-go' if any(b['capture_class'] == 'current-go-experiment' for b in entry['bindings']) else 'native-capture'})
        current_go |= inputs[-1]['use'] == 'current-go'
        manifests = sorted({test['manifest'].replace('macos-*', f'macos-{major}').rstrip('*')
                            for test in recipes['tests'] if test.get('input') == corpus_id})
        require(manifests, 'capture has no reviewed replay manifest contract')
        for manifest_name in manifests:
            document = read_document(root / manifest_name)
            producer = document['producer']
            require(producer.get('system') == 'macOS' and producer['version'] == environment['version']
                    and producer['build'] == environment['build']
                    and producer['architecture'] == environment['architecture'], 'capture belongs to another native environment')
            if inputs[-1]['use'] == 'current-go':
                revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source_root, text=True).strip()
                require(producer.get('revision') == revision, 'current-Go native experiment belongs to another revision')
            suffix = manifest_name.partition('/')[2]
            references = [c for c in entry['captures'] if c['manifest'].partition('/')[2].removesuffix('.gz') == suffix]
            require(references, 'capture manifest lacks a reviewed case contract')
            reference = next((c for c in references if c['major'] == major), references[0])
            records = case_records(document)
            require(set(records) == set(reference['cases']), 'captured native case inventory differs')
            for native_case, observation in records.items():
                verify_references((root / manifest_name).parent, observation)
                # Bind the actual case observation to its unchanged source
                # document. A successful collector process is insufficient.
                record = {'manifest': manifest_name, 'manifest_sha256': file_digest(root / manifest_name),
                          'native_case': native_case, 'observation': observation}
                name = corpus_id + '/' + identity({'manifest': manifest_name, 'case': native_case}) + '.json'
                data = canonical(record) + b'\n'
                outputs.append((name, data))
                family = entry['bindings'][0]['family']
                required.append({'family': family, 'test': 'capture/' + corpus_id + '/' + manifest_name + '/' + native_case,
                    'corpus': corpus_id, 'manifest': manifest_name, 'native_case': native_case, 'source': major,
                    'outputs': [name]})
    require(required, 'empty capture qualification')
    production = source_identities(source_root)[0] if current_go else ''
    required.sort(key=lambda c: c['test'])
    plan = {'schema': 1, 'stage': 'capture', 'contract_sha256': native_contract(source_root),
            'production_sha256': production, 'inputs': inputs, 'outputs': [],
            'environment': environment, 'cases': required, 'required_runs': [c['test'] for c in required]}
    directory.mkdir(parents=True)
    events = directory / 'events.jsonl'
    with events.open('x', encoding='utf-8') as stream:
        def emit(action, test=None):
            event = {'Action': action, 'Package': 'apple-native'}
            if test:
                event['Test'] = test
            stream.write(json.dumps(event, separators=(',', ':')) + '\n')
        emit('start')
        files = []
        by_name = dict(outputs)
        for case in required:
            emit('run', case['test'])
            name = case['outputs'][0]
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(by_name[name])
            files.append({'path': name, 'bytes': target.stat().st_size, 'sha256': file_digest(target)})
            emit('pass', case['test'])
        for root, original in originals:
            verify_file(root, original)
        emit('pass')
    return publish_receipt(plan, events, sorted(files, key=lambda f: f['path']), directory / 'receipt.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', required=True, type=int, choices=(15, 26, 27))
    parser.add_argument('--input', action='append', required=True, metavar='CORPUS=ROOT')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bindings = {}
    for binding in args.input:
        key, separator, value = binding.partition('=')
        require(separator and key and value and key not in bindings, 'invalid/duplicate capture binding')
        bindings[key] = Path(value)
    capture(args.expected_major, bindings, args.output)


if __name__ == '__main__':
    main()
