"""Resolve approved Apple input bytes without inheriting a filesystem verdict.

An absent pin or changed capture contract requires fresh Apple capture. Once
reuse is selected, missing or changed assets fail admission. Portable replay and
Apple verification remain fresh, including current-Go native experiments.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

from reference_sources import sources
from release_assets import fetch, read_document, require


def select(pin_path, assets, fresh=False, run=subprocess.check_output, fetcher=fetch):
    pin_path = Path(pin_path)
    if fresh or not pin_path.exists():
        require(not pin_path.is_symlink(), 'native reference pin is aliased')
        return {'reuse': False, 'reason': 'explicit fresh capture' if fresh else 'no approved reference pin'}
    pin = read_document(pin_path, 64 << 10)
    catalog = fetcher(pin, assets, os.environ.get('GITHUB_TOKEN', ''), metadata_only=True)
    manifest = read_document(catalog)
    current = run(['go', 'run', './acceptance/qualification', '-capture-contract'], text=True).strip()
    require(re.fullmatch('[a-f0-9]{64}', current), 'current capture dependency identity missing')
    if manifest['capture_contract_sha256'] != current:
        return {'reuse': False, 'reason': 'collector/helper/recipe dependency changed'}
    return {'reuse': True, 'reason': 'reviewed immutable Apple inputs',
            'pin_sha256': hashlib.sha256(pin_path.read_bytes()).hexdigest(),
            'catalog_sha256': pin['catalog']['sha256'], 'origin': manifest['origin']}


def artifact_inputs(artifact, major, mapping=None):
    require(major in (15, 26, 27), 'required native source version missing')
    selected = {name: spec for name, spec in (mapping or sources()).items()
                if spec['artifact'].format(major=major) == artifact}
    require(selected, 'unknown original capture artifact')
    return selected


def member(path):
    value = PurePosixPath(path)
    require(path and not value.is_absolute() and '\\' not in path and
            all(p not in ('', '.', '..') for p in path.split('/')), 'unsafe original reference member')
    return value


def copy_member(source, target, expected):
    require(source.is_file() and not source.is_symlink(), 'materialized native member missing/aliased')
    require(source.stat().st_size == expected['bytes'], 'materialized native member size changed')
    target.parent.mkdir(parents=True, exist_ok=True)
    digest, count = hashlib.sha256(), 0
    with source.open('rb') as original, target.open('xb') as output:
        while data := original.read(128 << 10):
            count += len(data)
            require(count <= expected['bytes'], 'materialized native member grew')
            digest.update(data)
            output.write(data)
    require(count == expected['bytes'] and digest.hexdigest() == expected['sha256'],
            'materialized native member differs from approved original bytes')


def restore(materialized, manifest, artifact, major, destination, mapping=None):
    """Invert only the explicit naming projection; preserve original file bytes."""
    selected = artifact_inputs(artifact, major, mapping)
    entries = {entry['id']: entry for entry in manifest['corpus']['entries']}
    destination = Path(destination).absolute()
    materialized = Path(materialized).resolve(strict=True)
    require(not destination.exists() and not destination.is_symlink(), 'absent artifact scratch required')
    require(not destination.is_relative_to(materialized) and not materialized.is_relative_to(destination),
            'artifact scratch must be separate from materialized input')
    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = f'macos-{major}/'
    copied = {}
    with tempfile.TemporaryDirectory(prefix='.reference-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'artifact'
        stage.mkdir()
        for name, spec in selected.items():
            require(name in entries, 'selected native reference entry missing')
            count = 0
            for expected in entries[name]['files']:
                original = member(expected['path'])
                if not str(original).startswith(prefix):
                    continue
                count += 1
                relative = member(str(original)[len(prefix):])
                target = PurePosixPath(spec['path']) / relative
                if not spec.get('source_root'):
                    target = PurePosixPath(spec['path']) / f'macos-{major}' / relative
                target = member(str(target))
                identity = (expected['bytes'], expected['sha256'])
                if str(target) in copied:
                    require(copied[str(target)] == identity, 'overlapping original reference members differ')
                    continue
                copy_member(materialized / name / Path(original), stage / Path(target), expected)
                copied[str(target)] = identity
            require(count > 0, 'required native source version has no original members')
        stage.rename(destination)
    return {'artifact': artifact, 'source_major': major, 'inputs': sorted(selected),
            'original_files': len(copied), 'original_bytes': sum(v[0] for v in copied.values())}


def materialize(pin_path, assets, artifact, major, destination, scratch, proof,
                run=subprocess.run, fetcher=fetch):
    selected = artifact_inputs(artifact, major)
    pin = read_document(pin_path, 64 << 10)
    catalog = fetcher(pin, assets, os.environ.get('GITHUB_TOKEN', ''), inputs=sorted(selected))
    manifest = read_document(catalog)
    scratch = Path(scratch).resolve(strict=True)
    destination = Path(destination).absolute()
    with tempfile.TemporaryDirectory(prefix='native-reference-', dir=scratch) as temporary:
        inputs = Path(temporary) / 'inputs'
        run(['go', 'run', './acceptance/qualification', '-materialize-references', ','.join(sorted(selected)),
             '-reference-pin', str(pin_path), '-bundle-dir', str(assets), '-input-dir', str(inputs)], check=True)
        report = restore(inputs, manifest, artifact, major, destination)
    report.update({'schema': 1, 'kind': 'approved-native-input-admission', 'assertions_executed': False,
                   'pin_sha256': hashlib.sha256(Path(pin_path).read_bytes()).hexdigest(),
                   'catalog_sha256': pin['catalog']['sha256'], 'origin': manifest['origin']})
    proof = Path(proof)
    proof.parent.mkdir(parents=True, exist_ok=True)
    with proof.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('select', 'materialize'))
    parser.add_argument('--pin', type=Path, default=Path('acceptance/qualification/references.json'))
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--artifact')
    parser.add_argument('--major', type=int)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--scratch', type=Path)
    parser.add_argument('--proof', type=Path)
    args = parser.parse_args()
    if args.action == 'select':
        report = select(args.pin, args.assets, args.fresh)
        if os.environ.get('GITHUB_OUTPUT'):
            with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
                output.write('reuse=' + str(report['reuse']).lower() + '\n')
    else:
        require(args.artifact and args.major and args.destination and args.scratch and args.proof and not args.fresh,
                'original artifact, source version, destination, scratch and admission proof required')
        report = materialize(args.pin, args.assets, args.artifact, args.major,
                             args.destination, args.scratch, args.proof)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
