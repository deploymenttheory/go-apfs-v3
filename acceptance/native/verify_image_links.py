#!/usr/bin/env python3
"""Independent Apple readback of portable link edits and native/Go/native cycles."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_links import operations, apply, observe, FRAMEWORK
from image_metadata import metadata_files
from image_mutation import writable_copy
from image_repacking import Commands, version
from verify_hfs_editing import native_hash
from verify_image_metadata import compare as compare_metadata, mounted
from verify_preservation import require


class Identities:
    def __init__(self, before):
        self.native_to_actual = {e['object']: e['object'] for e in before['entries']}
        self.actual_to_native = dict(self.native_to_actual)

    def compare(self, actual, expected):
        got = {e['path']: e for e in actual['entries']}
        state = copy.deepcopy(expected)
        require(set(got) == {e['path'] for e in state['files']['entries']}, 'complete link namespace')
        fields = {}
        for entry in state['files']['entries']:
            native, observed = entry['object'], got[entry['path']]['object']
            require(self.native_to_actual.get(native, observed) == observed, 'original inode and alias identity retained')
            require(self.actual_to_native.get(observed, native) == native, 'distinct and retired identities remain distinct')
            self.native_to_actual[native], self.actual_to_native[observed] = observed, native
            fields[str(observed)] = state.get('clockFields', {}).get(str(native), [])
            entry['object'] = observed
        state['clockFields'] = fields
        compare_metadata(actual, state)


def inspect(raw, kind, command, work, ids, expected):
    require_disposable_host()
    with mounted(raw, kind, command, work) as (root, native):
        ids.compare(metadata_files(root), expected)
        native('codesign', '--verify', '--deep', '--strict', root / 'Example.app')
        native('codesign', '--verify', '--deep', '--strict', root / FRAMEWORK)


def verify(corpus, outputs, continuation, major, kind, prefix):
    require_disposable_host()
    version(major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'{prefix}-links-{major}.diagnostics.json')
    manifests = sorted(corpus.glob('macos-*/manifest.json'))
    require(len(manifests) == 3, 'all source versions supply link controls')
    count = 0
    from qualification_cases import image_verification
    input_id = 'apfs-link-editing' if kind == 'apfs' else ('hfs-journaled-link-editing' if prefix == 'hfs-journaled' else 'hfs-link-editing')
    evidence = image_verification(corpus, outputs, input_id, prefix + '-links-',
        ['macos-{source}/{case}/links-UDRO.dmg', 'macos-{source}/{case}/links-UDZO.dmg', 'macos-{source}/{case}/links-final-UDRO.dmg', 'macos-{source}/{case}/links-final-UDZO.dmg', 'macos-{source}/{case}/removed-UDRO.dmg', 'macos-{source}/{case}/removed-UDZO.dmg'], 'image_links', major,
        manifest='manifest.json', continued=lambda name: name.endswith('/removed-UDZO.dmg'))
    with tempfile.TemporaryDirectory(prefix='link-readback-') as temporary:
        work = Path(temporary)
        for path in manifests:
            manifest = json.loads(path.read_text())
            require(manifest['contract'] == 'existing-' + kind + '-link-edits', 'link contract')
            require(len(manifest['cases']) == 2, 'both native name policies')
            for case in manifest['cases']:
                for encoding in ('UDRO', 'UDZO'):
                    ids = Identities(case['before']['files'])
                    for phase in ('links', 'links-final', 'removed'):
                        relative = Path(path.parent.name, case['id'], phase + '-' + encoding + '.dmg')
                        images = [outputs / (prefix + '-links-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        with evidence.case(images):
                            require(all(image.is_file() for image in images), 'all portable link images supplied')
                            require(len({sha256(image) for image in images}) == 1, 'link outputs identical across hosts')
                            image, raw = images[0], work / 'output.raw'
                            digest = sha256(image)
                            command('hdiutil', 'verify', image)
                            writable_copy(image, raw, command, native_hash)
                            inspect(raw, kind, command, work, ids, case['states'][phase])
                            if phase == 'removed' and encoding == 'UDZO':
                                with mounted(raw, kind, command, work, writable=True) as (root, native):
                                    apply(root, operations('native'), native)
                                before = observe(raw, kind, command, work, signed=True)['files']
                                name = path.parent.name + '-' + case['id']
                                shutil.copyfile(raw, continuation / (name + '.raw'))
                                # A separate Apple-only copy, never a Go result,
                                # supplies the complete continuation expectation.
                                control = work / 'control.raw'
                                shutil.copyfile(raw, control)
                                ops = operations('continued')
                                with mounted(control, kind, command, work, writable=True) as (root, native):
                                    clocks = apply(root, ops, native)
                                expected = observe(control, kind, command, work, signed=True)
                                expected.update(operations=ops, clockFields=clocks)
                                (continuation / (name + '.json')).write_text(json.dumps({'before': before, 'expected': expected}, indent=2) + '\n')
                                control.unlink()
                            raw.unlink()
                            require(sha256(image) == digest, 'portable link image remains immutable')
                            count += 1
    require(count == 36, 'complete link readback inventory')
    evidence.finish()


def verify_continued(directory, controls, major, kind, prefix):
    require_disposable_host()
    version(major)
    command = Commands(directory / f'{prefix}-links-continued-{major}.diagnostics.json')
    images = sorted(directory.glob('*.dmg'))
    require(len(images) == 6, 'all native source/profile continuations present')
    from qualification_cases import continuation_verification
    evidence = continuation_verification(directory, kind, 'image_links-continued', major,
        metadata=False, raw_suffix=False)
    with tempfile.TemporaryDirectory(prefix='links-continued-') as temporary:
        work = Path(temporary)
        for image in images:
            with evidence.case([image]):
                control = json.loads((controls / (image.stem + '.json')).read_text())
                raw = work / 'continued.raw'
                writable_copy(image, raw, command, native_hash)
                inspect(raw, kind, command, work, Identities(control['before']), control['expected'])
                raw.unlink()
    evidence.finish()


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
