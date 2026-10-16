#!/usr/bin/env python3
"""Apple qualification of metadata outputs and independent native/Go/native edits."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_metadata import operations, apply_operations, metadata_files, STAMP, ATTRIBUTE
from image_mutation import raw_command, writable_copy
from image_repacking import Commands, version
from verify_hfs_editing import native_hash
from verify_preservation import require


def compare(actual, state):
    got = {e['path']: e for e in actual['entries']}
    want = {e['path']: e for e in state['files']['entries']}
    require(set(got) == set(want), 'exact metadata namespace')
    for path, entry in want.items():
        entry = dict(entry)
        for field in state.get('clockFields', {}).get(str(entry['object']), []):
            require(field in ('changeNS', 'modifyNS'), 'explicit offline clock effect')
            entry[field] = STAMP * 10**9
        for field in ('object', 'mode', 'uid', 'gid', 'flags', 'birthSeconds', 'birthNS',
                      'modifyNS', 'changeNS', 'accessNS', 'links', 'size', 'sha256', 'target', 'rawAttributes'):
            if field in entry:
                require(got[path].get(field) == entry[field], f'{path} {field}: {got[path].get(field)} != {entry[field]}')


@contextmanager
def mounted(raw, kind, command, work, writable=False):
    require_disposable_host()
    digest = sha256(raw)
    directory = work / 'metadata-mount'
    native = raw_command(command, raw)
    if kind == 'apfs':
        from apfs_editing import attached, mount, check_filesystem
        cleanup, physical, inventory = attached(raw, native, readonly=not writable)
        try:
            check_filesystem(physical, native)
            mount(inventory['Volumes'][0], directory, native, readonly=not writable)
            yield directory / 'Fixture', native
        finally:
            native('hdiutil', 'detach', cleanup)
    else:
        from hfs_header_growth import attach
        device = attach(raw, native, readonly=not writable, writable=writable)
        try:
            native('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
            directory.mkdir()
            native('diskutil', 'mount', *([] if writable else ['readOnly']),
                   '-mountOptions', 'owners,noatime', '-mountPoint', directory, device)
            yield directory / 'Fixture', native
        finally:
            native('hdiutil', 'detach', device)
    shutil.rmtree(directory)
    if not writable:
        require(sha256(raw) == digest, 'native read-only metadata check preserves raw bytes')


def inspect(raw, kind, command, work, expected=None):
    with mounted(raw, kind, command, work) as (root, native):
        observed = metadata_files(root)
        if expected is not None:
            compare(observed, expected)
        native('codesign', '--verify', '--deep', '--strict', root / 'Example.app')
        return observed


def verify(corpus, outputs, continuation, major, kind, prefix):
    require_disposable_host()
    version(major)
    continuation.mkdir(parents=True)
    command = Commands(outputs / f'{prefix}-metadata-{major}.diagnostics.json')
    count = 0
    from qualification_cases import image_verification
    input_id = 'apfs-metadata-editing' if kind == 'apfs' else ('hfs-journaled-metadata-editing' if prefix == 'hfs-journaled' else 'hfs-metadata-editing')
    evidence = image_verification(corpus, outputs, input_id, prefix + '-metadata-',
        ['macos-{source}/{case}/metadata-UDRO.dmg', 'macos-{source}/{case}/metadata-UDZO.dmg', 'macos-{source}/{case}/metadata-final-UDRO.dmg', 'macos-{source}/{case}/metadata-final-UDZO.dmg'], 'image_metadata', major,
        manifest='manifest.json', continued=lambda name: name.endswith('/metadata-final-UDZO.dmg'))
    with tempfile.TemporaryDirectory(prefix='metadata-readback-') as tmp:
        work = Path(tmp)
        manifests = sorted(corpus.glob('macos-*/manifest.json'))
        require(len(manifests) == 3, 'all source versions supply metadata controls')
        for manifest_path in manifests:
            manifest = json.loads(manifest_path.read_text())
            require(manifest['contract'] == 'existing-' + kind + '-metadata-edits', 'metadata contract')
            for case in manifest['cases']:
                for phase in ('metadata', 'metadata-final'):
                    for format_name in ('UDRO', 'UDZO'):
                        relative = Path(manifest_path.parent.name, case['id'], phase + '-' + format_name + '.dmg')
                        images = [outputs / (prefix + '-metadata-' + host) / relative for host in ('Linux', 'Windows', 'macOS')]
                        with evidence.case(images):
                            require(all(image.is_file() for image in images), 'all portable metadata images supplied')
                            require(len({sha256(image) for image in images}) == 1, 'metadata outputs identical across hosts')
                            image, raw = images[0], work / 'output.raw'
                            digest = sha256(image)
                            command('hdiutil', 'verify', image)
                            writable_copy(image, raw, command, native_hash)
                            inspect(raw, kind, command, work, case['states'][phase])
                            if phase == 'metadata-final' and format_name == 'UDZO':
                                # Kernel-created ordinary streams exercise the modern
                                # APFS ownership marker; these become real Go inputs.
                                with mounted(raw, kind, command, work, writable=True) as (root, native):
                                    apply_operations(root, [
                                        {'op': 'xattr', 'path': 'alias', 'attribute': ATTRIBUTE + '.continued', 'size': 8193},
                                        {'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE, 'size': 65537},
                                    ], native)
                                before = inspect(raw, kind, command, work)
                                name = manifest_path.parent.name + '-' + case['id']
                                shutil.copyfile(raw, continuation / (name + '.raw'))
                                # A separate Apple-only copy supplies the full expected
                                # result of the continuation. No Go output is an oracle.
                                control = work / 'control.raw'
                                shutil.copyfile(raw, control)
                                ops = operations('continued')
                                with mounted(control, kind, command, work, writable=True) as (root, native):
                                    clocks = apply_operations(root, ops, native)
                                expected = {'files': inspect(control, kind, command, work), 'operations': ops, 'clockFields': clocks}
                                (continuation / (name + '.json')).write_text(json.dumps({'before': before, 'expected': expected}, indent=2) + '\n')
                                control.unlink()
                            raw.unlink()
                            require(sha256(image) == digest, 'portable metadata image remains immutable')
                            count += 1
    require(count == (24 if kind=='apfs' else 48), 'complete metadata readback inventory')
    evidence.finish()


def verify_continued(directory, controls, major, kind, prefix):
    require_disposable_host()
    version(major)
    command = Commands(directory / f'{prefix}-metadata-continued-{major}.diagnostics.json')
    images = sorted(directory.glob('*.dmg'))
    require(len(images) == (6 if kind=='apfs' else 12), 'all source/profile continuations present')
    from qualification_cases import continuation_verification
    evidence = continuation_verification(directory, kind, 'image_metadata-continued', major,
        metadata=True, raw_suffix=False)
    with tempfile.TemporaryDirectory(prefix='metadata-continued-') as tmp:
        work = Path(tmp)
        for image in images:
            with evidence.case([image]):
                expected = json.loads((controls / (image.stem + '.json')).read_text())['expected']
                raw = work / 'continued.raw'
                writable_copy(image, raw, command, native_hash)
                inspect(raw, kind, command, work, expected)
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
