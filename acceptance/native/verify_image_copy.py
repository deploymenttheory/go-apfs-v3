#!/usr/bin/env python3
"""Apple checks of portable copying, signatures and native/Go/native cycles."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_copy import operations, apply, observe, signatures
from image_metadata import metadata_files
from image_mutation import writable_copy
from image_repacking import Commands, version
from verify_hfs_editing import native_hash
from verify_image_links import Identities
from verify_image_metadata import mounted
from verify_preservation import require


def inspect(raw, kind, command, work, identities, expected):
    require_disposable_host()
    with mounted(raw, kind, command, work) as (root, native):
        identities.compare(metadata_files(root), expected)
        signatures(root, native)


def verify(corpus, outputs, continuation, major, kind, prefix):
    require_disposable_host()
    version(major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'{prefix}-copy-{major}.diagnostics.json')
    manifests = sorted(corpus.glob('macos-*/manifest.json'))
    require({p.parent.name for p in manifests} == {'macos-15', 'macos-26', 'macos-27'}, 'all three native copy sources required')
    count = 0
    with tempfile.TemporaryDirectory(prefix='copy-readback-') as temporary:
        work = Path(temporary)
        for path in manifests:
            manifest = json.loads(path.read_text())
            require(manifest['schema'] == 1 and manifest['contract'] == 'existing-' + kind + '-copy', 'native copy contract')
            expected_cases = {'apfs', 'apfs-case-sensitive'} if kind == 'apfs' else {'hfsplus', 'hfsx'}
            require(len(manifest['cases']) == 2 and {c['id'] for c in manifest['cases']} == expected_cases, 'both native name policies required')
            for case in manifest['cases']:
                for encoding in ('UDRO', 'UDZO'):
                    ids = Identities(case['before']['files'])
                    for phase in ('copy', 'copy-final'):
                        relative = Path(path.parent.name, case['id'], phase + '-' + encoding + '.dmg')
                        images = [outputs / (prefix + '-copy-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        require(all(image.is_file() for image in images), 'all host copy outputs required')
                        require(len({sha256(image) for image in images}) == 1, 'copy outputs byte-identical across hosts')
                        image, raw = images[0], work / 'output.raw'
                        digest = sha256(image)
                        command('hdiutil', 'verify', image)
                        writable_copy(image, raw, command, native_hash)
                        inspect(raw, kind, command, work, ids, case['states'][phase])
                        if phase == 'copy-final' and encoding == 'UDZO':
                            with mounted(raw, kind, command, work, writable=True) as (root, native):
                                apply(root, operations('native'), native, None)
                            before = observe(raw, kind, command, work)['files']
                            name = path.parent.name + '-' + case['id']
                            shutil.copyfile(raw, continuation / (name + '.raw'))
                            # Apple mutates a separate copy to supply expectations;
                            # no Go-generated continuation defines its own oracle.
                            control = work / 'control.raw'
                            shutil.copyfile(raw, control)
                            ops = operations('continued')
                            with mounted(control, kind, command, work, writable=True) as (root, native):
                                clocks = apply(root, ops, native, None)
                            expected = observe(control, kind, command, work)
                            expected.update(operations=ops, clockFields=clocks)
                            (continuation / (name + '.json')).write_text(json.dumps({'before': before, 'expected': expected}, indent=2) + '\n')
                            control.unlink()
                        raw.unlink()
                        require(sha256(image) == digest, 'portable copy image remains immutable')
                        count += 1
    require(count == 24, 'complete native copy readback inventory')


def verify_continued(directory, controls, major, kind, prefix):
    require_disposable_host()
    version(major)
    command = Commands(directory / f'{prefix}-copy-continued-{major}.diagnostics.json')
    cases = ('apfs', 'apfs-case-sensitive') if kind == 'apfs' else ('hfsplus', 'hfsx')
    expected_names = {f'macos-{source}-{case}.dmg' for source in (15, 26, 27) for case in cases}
    images = sorted(directory.glob('*.dmg'))
    require({p.name for p in images} == expected_names, 'all copy continuations required')
    with tempfile.TemporaryDirectory(prefix='copy-continued-') as temporary:
        work = Path(temporary)
        for image in images:
            control = json.loads((controls / (image.stem + '.json')).read_text())
            raw = work / 'continued.raw'
            digest = sha256(image)
            command('hdiutil', 'verify', image)
            writable_copy(image, raw, command, native_hash)
            inspect(raw, kind, command, work, Identities(control['before']), control['expected'])
            raw.unlink()
            require(sha256(image) == digest, 'continued copy image remains immutable')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', required=True, type=int)
    parser.add_argument('--kind', required=True, choices=('apfs', 'hfs'))
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--outputs', type=Path)
    parser.add_argument('--continuation', type=Path)
    parser.add_argument('--continued', type=Path)
    parser.add_argument('--controls', type=Path)
    args = parser.parse_args()
    if args.continued:
        verify_continued(args.continued, args.controls, args.expected_major, args.kind, args.prefix)
    else:
        verify(args.corpus, args.outputs, args.continuation, args.expected_major, args.kind, args.prefix)
