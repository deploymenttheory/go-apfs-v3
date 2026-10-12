#!/usr/bin/env python3
"""Apple link creation/lifetime observations for the existing image-edit families.

Only disposable CI VMs run native commands. Sources, signed framework material,
all expected identities and metadata come from Apple tools, independently of Go.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import time

from capture import sha256
from container_building import require_disposable_host
from image_metadata import metadata_files, STAMP
from image_repacking import Commands, version
from metadata_edits import set_metadata, set_attribute
from verify_image_metadata import mounted
from verify_preservation import require

COUNT = 32
FRAMEWORK = 'Example.framework'


def operations(phase):
    if phase == 'links':
        ops = [{'op': 'mkdir', 'path': 'Links'}, {'op': 'mkdir', 'path': 'Links/Nested'}]
        for source, destination in [('independent', 'Links/forked'), ('Links/forked', 'Links/third'),
                                    ('empty', 'Links/empty'), ('alias', 'Links/existing'),
                                    ('inline-compressed', 'Links/inline'), ('resource-compressed', 'Links/resource'),
                                    ('independent', 'Links/Nested')]:
            ops.append({'op': 'ln', 'path': source, 'destination': destination})
        for target, name in [('../independent', 'relative'), ('missing/caf\u00e9', 'dangling'),
                             ('/outside/not-present', 'absolute'), ('-target', 'dash'), ('Nested', 'directory')]:
            ops.append({'op': 'ln', 'path': target, 'destination': 'Links/' + name, 'symbolic': True})
        ops.extend([
            {'op': 'ln', 'path': '../independent', 'destination': 'replace', 'symbolic': True, 'force': True},
            {'op': 'ln', 'path': 'independent', 'destination': 'Links/empty', 'force': True},
            {'op': 'ln', 'path': 'A', 'destination': FRAMEWORK + '/Versions/Current', 'symbolic': True},
            {'op': 'ln', 'path': 'Versions/Current/Example', 'destination': FRAMEWORK + '/Example', 'symbolic': True},
            {'op': 'ln', 'path': 'Versions/Current/Resources', 'destination': FRAMEWORK + '/Resources', 'symbolic': True},
        ])
        ops.extend({'op': 'ln', 'path': 'independent', 'destination': f'Links/{n:03}-' + 'k' * 72} for n in range(COUNT))
        return ops
    if phase == 'links-final':
        ops = [
            {'op': 'write', 'path': 'Links/forked', 'size': 8193},
            {'op': 'xattr', 'path': 'Links/third', 'attribute': 'org.go-apfs.links', 'size': 4097},
            {'op': 'chmod', 'path': 'Links/third', 'mode': 0o640},
            {'op': 'rm', 'path': 'independent'},
            {'op': 'mv', 'path': 'Links/forked', 'destination': 'Links/renamed'},
            {'op': 'rm', 'path': 'Links/third'},
            {'op': 'rm', 'path': 'Links/Nested/independent'},
            {'op': 'ln', 'path': 'Links/renamed', 'destination': 'Links/dangling', 'force': True},
            {'op': 'ln', 'path': '../Links/renamed', 'destination': 'replace', 'symbolic': True, 'force': True},
            {'op': 'rm', 'path': 'Links/existing'},
            {'op': 'rm', 'path': 'Links/inline'},
            {'op': 'rm', 'path': 'Links/resource'},
        ]
        ops.extend({'op': 'rm', 'path': f'Links/{n:03}-' + 'k' * 72} for n in range(COUNT - 1))
        return ops
    if phase == 'removed':
        return [
            {'op': 'rm', 'path': 'Links/renamed'}, {'op': 'rm', 'path': 'Links/dangling'},
            {'op': 'rm', 'path': 'Links/empty'}, {'op': 'rm', 'path': f'Links/{COUNT-1:03}-' + 'k' * 72},
            {'op': 'mkdir', 'path': 'Links/reused'},
            {'op': 'ln', 'path': 'alias', 'destination': 'Links/reused/alias'},
            {'op': 'ln', 'path': 'missing-again', 'destination': 'Links/relative', 'symbolic': True, 'force': True},
        ]
    if phase == 'native':
        return [{'op': 'ln', 'path': 'alias', 'destination': 'Links/native'},
                {'op': 'ln', 'path': '../alias', 'destination': 'Links/native-symlink', 'symbolic': True}]
    if phase == 'continued':
        return [{'op': 'ln', 'path': 'Links/native', 'destination': 'Links/continued'},
                {'op': 'rm', 'path': 'Links/native'},
                {'op': 'ln', 'path': 'Links/continued', 'destination': 'Links/native-symlink', 'force': True},
                {'op': 'ln', 'path': 'missing-final', 'destination': 'Links/relative', 'symbolic': True, 'force': True},
                {'op': 'xattr', 'path': 'Links/continued', 'attribute': 'org.go-apfs.links.continued', 'size': 8193}]
    raise ValueError(phase)


def payload(size):
    pattern = bytes(range(256)) + b'link lifetime\x00\xff'
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def prepare(root, command):
    require_disposable_host()
    (root / 'replace').write_bytes(payload(65537))
    set_attribute(root / 'replace', 'org.go-apfs.links.discard', payload(8193))
    framework = root / FRAMEWORK
    resources = framework / 'Versions/A/Resources'
    resources.mkdir(parents=True)
    (resources / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'org.go-apfs.link-framework', 'CFBundleName': 'Example',
        'CFBundleExecutable': 'Example', 'CFBundlePackageType': 'FMWK', 'CFBundleVersion': '1'}))
    source = root / 'framework-source.c'
    source.write_text('int example(void) { return 42; }\n')
    command('xcrun', 'clang', '-dynamiclib', '-arch', 'arm64', '-arch', 'x86_64',
            '-mmacosx-version-min=11.0', source, '-o', framework / 'Versions/A/Example')
    source.unlink()
    for target, path in [('A', 'Versions/Current'), ('Versions/Current/Example', 'Example'),
                         ('Versions/Current/Resources', 'Resources')]:
        os.symlink(target, framework / path)
    command('codesign', '--force', '--sign', '-', '--timestamp=none', framework)
    command('codesign', '--verify', '--deep', '--strict', framework)
    # Retain Apple's signature and payload before removing only the links.
    # Recreating their exact target strings must restore a valid signed bundle.
    for path in ('Versions/Current', 'Example', 'Resources'):
        (framework / path).unlink()


def apply(root, ops, command, clocks=None):
    require_disposable_host()
    before = metadata_files(root)
    latest = max(e['changeNS'] for e in before['entries'])
    delay = latest // 10**9 + 1 - time.time()
    require(delay <= 1.1, 'link baseline clock is not in the future')
    if delay > 0:
        time.sleep(delay + 0.01)
    original = {e['object'] for e in before['entries']}
    for op in ops:
        path = root / op['path']
        verb = op['op']
        if verb == 'ln':
            flags = (['-s'] if op.get('symbolic') else ['-P']) + (['-f'] if op.get('force') else [])
            target = op['path'] if op.get('symbolic') else path
            command('/bin/ln', *flags, '--', target, root / op['destination'])
        elif verb == 'mkdir':
            command('/bin/mkdir', path)
        elif verb == 'rm':
            command('/bin/rm', path)
        elif verb == 'mv':
            command('/bin/mv', path, root / op['destination'])
        elif verb == 'write':
            path.write_bytes(payload(op['size']))
        elif verb == 'xattr':
            set_attribute(path, op['attribute'], payload(op['size']))
        elif verb == 'chmod':
            command('/bin/chmod', oct(op['mode'])[2:], path)
        else:
            raise ValueError(verb)
    after = metadata_files(root)
    explicit = {'value': '2025-06-07T08:09:10.000000000Z'}
    for entry in after['entries']:
        if entry['object'] not in original:
            set_metadata(root.parent / entry['path'], {'birthTime': explicit, 'modifyTime': explicit, 'accessTime': explicit}, command)
    after = metadata_files(root)
    old = {e['object']: e for e in before['entries']}
    clocks = {} if clocks is None else clocks
    for entry in after['entries']:
        prior = old.get(entry['object'])
        effects = clocks.setdefault(str(entry['object']), [])
        for field in ('changeNS', 'modifyNS'):
            if (prior is None and field == 'changeNS' or prior is not None and entry[field] != prior[field]) and field not in effects:
                effects.append(field)
    return clocks


def observe(raw, kind, command, work, signed=False):
    require_disposable_host()
    with mounted(raw, kind, command, work) as (root, native):
        native('codesign', '--verify', '--deep', '--strict', root / 'Example.app')
        if signed:
            native('codesign', '--verify', '--deep', '--strict', root / FRAMEWORK)
        return {'files': metadata_files(root), 'checkerStatus': 0}


def capture(references, output, kind, major):
    require_disposable_host()
    producer = version(major)
    reference = json.loads((references / 'manifest.json').read_text())
    require(reference['major'] == major, 'link source OS version')
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    from hfs_header_growth import retain_file
    cases = []
    with tempfile.TemporaryDirectory(prefix='image-links-') as temporary:
        work = Path(temporary)
        for case in reference['cases']:
            image = work / (case['id'] + '-source.raw')
            archive = references / case['source']['image']
            require(sha256(archive) == case['source']['sha256'], 'link source archive integrity')
            with gzip.open(archive, 'rb') as src, image.open('xb') as dst:
                shutil.copyfileobj(src, dst, 128 << 10)
            require(sha256(image) == case['source']['uncompressedSHA256'], 'link decoded source integrity')
            with mounted(image, kind, command, work, writable=True) as (root, native):
                prepare(root, native)
            item = {'id': case['id'], 'source': retain_file(image, output / (case['id'] + '-source.raw.gz')),
                    'before': observe(image, kind, command, work), 'states': {}}
            clocks = {}
            for phase in ('links', 'links-final', 'removed'):
                edited = work / (case['id'] + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                ops = operations(phase)
                with mounted(edited, kind, command, work, writable=True) as (root, native):
                    apply(root, ops, native, clocks)
                state = observe(edited, kind, command, work, signed=True)
                state.update(operations=ops, clockFields=json.loads(json.dumps(clocks)))
                state['archive'] = retain_file(edited, output / (case['id'] + '-' + phase + '.raw.gz'))
                item['states'][phase] = state
                image = edited
            cases.append(item)
    names = tuple(dict.fromkeys(('image_links.py', 'verify_image_metadata.py', 'verify_hfs_editing.py', 'image_metadata.py',
                                'metadata_edits.py', 'image_mutation.py', *reference['producer']['sources'])))
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in names}
    for name in names:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    producer['tools'] = dict(reference['producer']['tools'])
    producer['tools'].update({path: sha256(Path(path)) for path in ('/bin/ln', '/bin/mkdir', '/bin/mv', '/bin/rm',
                                                                '/bin/chmod', '/usr/bin/codesign', '/usr/bin/xcrun')})
    producer['referenceManifestSHA256'] = sha256(references / 'manifest.json')
    shutil.copyfile(references / 'manifest.json', output / 'reference-manifest.json')
    manifest = {'schema': 1, 'major': major, 'producer': producer, 'cases': cases,
                'contract': 'existing-' + kind + '-link-edits', 'modificationSeconds': STAMP,
                'capacityBytes': reference['capacityBytes'], 'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--references', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--kind', required=True, choices=('apfs', 'hfs'))
    parser.add_argument('--expected-major', required=True, type=int)
    args = parser.parse_args()
    capture(args.references, args.output, args.kind, args.expected_major)
