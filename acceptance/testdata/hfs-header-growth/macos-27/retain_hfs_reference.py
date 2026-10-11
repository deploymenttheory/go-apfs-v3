#!/usr/bin/env python3
"""Retain a complete native HFS capture using file-only, bounded verification.

This never invokes native tools or mounts anything. It verifies every referenced
archive and recipe, shares byte-identical archives, and keeps the original native
manifest alongside the manifest with deduplicated storage references. Existing
references cannot be overwritten. Expected native values are never regenerated.
"""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import shutil

LIMIT = 32 << 20


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def file_at(root, name, expected):
    if not name or Path(name).name != name or '/' in name or '\\' in name or name in ('.', '..'):
        raise ValueError(f'unsafe retained filename: {name}')
    path = root / name
    if not path.is_file() or path.is_symlink() or path.stat().st_size > LIMIT or digest(path) != expected:
        raise ValueError(f'missing, changed or excessive native evidence: {name}')
    return path


def verify_archive(path, expected):
    total = 0
    result = hashlib.sha256()
    with gzip.open(path, 'rb') as source:
        while chunk := source.read(1 << 20):
            total += len(chunk)
            if total > LIMIT:
                raise ValueError(f'excessive decoded archive: {path.name}')
            result.update(chunk)
    if not total or result.hexdigest() != expected:
        raise ValueError(f'changed decoded native evidence: {path.name}')


def retain(source, destination):
    raw = (source / 'manifest.json').read_bytes()
    if len(raw) > LIMIT:
        raise ValueError('excessive native manifest')
    native = json.loads(raw)
    producer = native['producer']
    major = producer['version'].split('.')[0]
    if (native.get('schema') != 1 or native.get('scenario') != 'hfs-header-growth' or
            native.get('complete') is not True or major not in ('15', '26', '27') or
            not producer.get('build') or not producer.get('run') or len(producer.get('revision', '')) != 40 or
            len(native.get('cases', [])) != 16 or len(native.get('sectorProbes', [])) != 7):
        raise ValueError('incomplete native capture/provenance')
    if destination.name != 'macos-' + major or destination.exists():
        raise ValueError('wrong destination profile or existing retained corpus')
    evidence = copy.deepcopy(native)
    copies = {}
    shared = {}
    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get('image'), str):
                expected = value.get('imageSHA256', value.get('sha256'))
                path = file_at(source, value['image'], expected)
                verify_archive(path, value.get('diskSHA256', value.get('uncompressedSHA256')))
                if expected in shared:
                    value['image'] = shared[expected]
                else:
                    shared[expected] = path.name
                    copies[path.name] = path
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(evidence)
    for recipe in producer['sources']:
        path = file_at(source, recipe['source'], recipe['sha256'])
        copies[path.name] = path
    transcript = file_at(source, 'commands.json', native['commandsSHA256'])
    copies[transcript.name] = transcript
    # Validation finishes before output creation. A failed copy lacks manifest.
    destination.mkdir(parents=True)
    for name, path in copies.items():
        shutil.copyfile(path, destination / name)
    original = destination / 'native-capture.json.gz'
    with original.open('xb') as out:
        with gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0) as compressed:
            compressed.write(raw)
    recipe = Path(__file__)
    shutil.copyfile(recipe, destination / recipe.name)
    evidence['retention'] = {
        'recipe': recipe.name, 'recipeSHA256': digest(destination / recipe.name),
        'nativeCapture': {'image': original.name, 'sha256': digest(original),
                          'uncompressedSHA256': hashlib.sha256(raw).hexdigest(), 'uncompressedBytes': len(raw)},
        'rule': 'All native cases retained; only identical compressed storage references shared.'}
    # Keep bulky exact observations compressed; the reviewable index explains
    # every control and its native outcome without a giant generated JSON diff.
    document = (json.dumps(evidence, indent=2) + '\n').encode()
    archive = destination / 'references.json.gz'
    with archive.open('xb') as out:
        with gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0) as compressed:
            compressed.write(document)
    index = {'schema': 1, 'scenario': 'hfs-header-growth-reference',
             'producer': {key: value for key, value in producer.items() if key != 'sources'},
             'evidence': {'image': archive.name, 'sha256': digest(archive),
                          'uncompressedSHA256': hashlib.sha256(document).hexdigest(),
                          'uncompressedBytes': len(document)},
             'cases': [{'id': c['id'], 'nativeCheckerStatus': c['after']['checker']['status'],
                        'catalogBlocks': {'before': c['before']['headers']['primary']['forks']['catalog']['totalBlocks'],
                                          'primaryAfter': c['after']['headers']['primary']['forks']['catalog']['totalBlocks'],
                                          'alternateAfter': c['after']['headers']['alternate']['forks']['catalog']['totalBlocks']}}
                       for c in native['cases']],
             'sectorProbes': [{'capacity': p['capacity'], 'allWritesSurvived': p['allWritesSurvived'],
                              'omittedReadOnlyOffsets': [m['offset'] for m in p['markers'] if m['reattachedSHA256'] != m['sha256']]}
                             for p in native['sectorProbes']]}
    (destination / 'manifest.json').write_text(json.dumps(index, indent=2) + '\n')
    print(f'{destination}: {len(native["cases"])} growth controls, {len(native["sectorProbes"])} sector probes; '
          f'{len(shared)} distinct archives')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    retain(args.capture, args.output)


if __name__ == '__main__':
    main()
