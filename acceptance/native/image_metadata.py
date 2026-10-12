#!/usr/bin/env python3
"""Independent Apple metadata edits of the existing image-edit controls.

Reuses Apple-created sources, never Go-generated images. All observations and
implicit clock effects come from the running macOS version, not a Go recipe.
"""
import argparse
import gzip
import json
import os
import plistlib
from pathlib import Path
import shutil
import struct
import tempfile

from capture import sha256
from container_building import require_disposable_host
from image_repacking import Commands, files, version
from verify_preservation import require

STAMP = 1749283750
TIME_NS = 1700000001234567891
ATTRIBUTE = 'org.go-apfs.metadata'


def operations(phase):
    if phase == 'continued':
        return [
            {'op': 'xattr-remove', 'path': 'alias', 'attribute': ATTRIBUTE + '.continued'},
            {'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE, 'size': 17},
            {'op': 'xattr', 'path': 'small', 'attribute': 'com.apple.ResourceFork', 'size': 0},
            {'op': 'chflags', 'path': 'independent', 'flags': 0},
            {'op': 'xattr', 'path': 'independent', 'attribute': 'com.apple.ResourceFork', 'size': 8193},
            {'op': 'xattr', 'path': 'independent', 'attribute': 'com.apple.ResourceFork', 'size': 17, 'seed': 42},
            {'op': 'xattr', 'path': 'independent', 'attribute': 'com.apple.ResourceFork', 'size': 0},
            {'op': 'xattr', 'path': 'fragmented-resource', 'attribute': 'com.apple.ResourceFork', 'size': 17, 'seed': 42},
            {'op': 'touch', 'path': 'symlink', 'modifyNS': TIME_NS, 'accessNS': TIME_NS + 999999999},
        ]
    if phase == 'metadata':
        result = [
            {'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE, 'size': 65537},
            {'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE + '.empty', 'size': 0},
            {'op': 'xattr', 'path': 'alias', 'attribute': ATTRIBUTE, 'size': 8193},
            {'op': 'xattr', 'path': '.', 'attribute': ATTRIBUTE, 'size': 17},
            {'op': 'xattr', 'path': 'symlink', 'attribute': ATTRIBUTE, 'size': 17},
            {'op': 'xattr', 'path': 'independent', 'attribute': 'com.apple.FinderInfo', 'finder': True},
            {'op': 'chflags', 'path': 'independent', 'flags': 0x8007},
            {'op': 'chflags', 'path': 'inline-compressed', 'flags': 0x8000},
            {'op': 'touch', 'path': 'alias', 'modifyNS': TIME_NS, 'accessNS': TIME_NS + 123456789},
            {'op': 'touch', 'path': 'symlink', 'modifyNS': TIME_NS + 999999999, 'accessNS': TIME_NS},
            {'op': 'chown', 'path': 'empty', 'uid': 60001, 'gid': 60002},
        ]
        result.extend({'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE + f'.{n:03}-' + 'k' * 72,
                       'size': 0 if n % 3 == 0 else 17} for n in range(96))
        return result
    result = [
        {'op': 'chflags', 'path': 'independent', 'flags': 0},
        {'op': 'xattr', 'path': 'small', 'attribute': ATTRIBUTE, 'size': 17},
        {'op': 'xattr-remove', 'path': 'small', 'attribute': ATTRIBUTE + '.empty'},
        {'op': 'xattr-remove', 'path': 'alias', 'attribute': ATTRIBUTE},
        {'op': 'xattr', 'path': 'independent', 'attribute': 'com.apple.FinderInfo', 'finder': True},
        {'op': 'xattr-remove', 'path': 'independent', 'attribute': 'com.apple.FinderInfo'},
        {'op': 'xattr', 'path': 'resource-compressed', 'attribute': ATTRIBUTE, 'size': 8193},
        {'op': 'xattr', 'path': '.', 'attribute': ATTRIBUTE + '.reuse', 'size': 131073},
        {'op': 'touch', 'path': 'small', 'modifyNS': TIME_NS + 10000000000, 'accessNS': TIME_NS},
    ]
    result.extend({'op': 'xattr-remove', 'path': 'small', 'attribute': ATTRIBUTE + f'.{n:03}-' + 'k' * 72}
                  for n in range(0, 96, 2))
    return result


def data(op):
    if op.get('finder'):
        # Native masks reserved FinderInfo fields on HFS and preserves their
        # existing values. Only public type/creator and the invisible bit change.
        return b'TEXTttxt' + b'\x40' + bytes(23)
    pattern = bytes((n + op.get('seed', 0)) & 255 for n in range(256)) + b'attribute bytes\x00\xff'
    size = op['size']
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def metadata_files(root):
    require_disposable_host()
    from metadata_edits import birth_ns
    observed = files(root)
    for entry in observed['entries']:
        ns = birth_ns(root.parent / entry['path'])
        entry['birthNS'], entry['birthSeconds'] = ns, ns // 10**9
    return observed


def operate(root, op, command):
    require_disposable_host()
    from metadata_edits import set_attribute, remove_attribute
    path = root / op['path']
    if op['op'] == 'xattr':
        set_attribute(path, op['attribute'], data(op))
    elif op['op'] == 'xattr-remove':
        remove_attribute(path, op['attribute'])
    elif op['op'] == 'chflags':
        # Preserve the filesystem's compressed and system flag bits.
        flags = path.lstat().st_flags & ~0x800f | op['flags']
        os.chflags(path, flags, follow_symlinks=False)
    elif op['op'] == 'touch':
        os.utime(path, ns=(op['accessNS'], op['modifyNS']), follow_symlinks=False)
    elif op['op'] == 'chown':
        command('sudo', '-n', 'chown', '-h', f"{op['uid']}:{op['gid']}", path)
    else:
        raise ValueError(op['op'])


def apply_operations(root, ops, command, clocks=None):
    require_disposable_host()
    clocks = {} if clocks is None else clocks
    for op in ops:
        path = root / op['path']
        old = path.lstat()
        operate(root, op, command)
        new = path.lstat()
        op['object'] = new.st_ino
        fields = clocks.setdefault(str(new.st_ino), [])
        if new.st_ctime_ns != old.st_ctime_ns and 'changeNS' not in fields:
            fields.append('changeNS')
        if op['op'] == 'touch':
            if 'modifyNS' in fields:
                fields.remove('modifyNS')
        elif new.st_mtime_ns != old.st_mtime_ns and 'modifyNS' not in fields:
            fields.append('modifyNS')
    return clocks


def capture(references, output, kind, major):
    require_disposable_host()
    producer = version(major)
    source_manifest = json.loads((references / 'manifest.json').read_text())
    require(source_manifest['major'] == major, 'source capture version')
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    if kind == 'apfs':
        import apfs_editing as engine
        from image_mutation import raw_command
        def mounted(image, directory):
            native = raw_command(command, image)
            cleanup, _, inventory = engine.attached(image, native)
            engine.mount(inventory['Volumes'][0], directory, native)
            return cleanup, native
    else:
        import hfs_editing as engine
        def mounted(image, directory):
            device = engine.attach(image, command, writable=True)
            directory.mkdir()
            command('diskutil', 'mount', '-mountOptions', 'owners,noatime', '-mountPoint', directory, device)
            return device, command
    cases = []
    with tempfile.TemporaryDirectory(prefix='image-metadata-') as tmp:
        work = Path(tmp)
        sources = []
        for case in source_manifest['cases']:
            image = work / (case['id'] + '-source.raw')
            archive = references / case['source']['image']
            require(sha256(archive) == case['source']['sha256'], 'immutable Apple source archive')
            with gzip.open(archive, 'rb') as src, image.open('wb') as dst:
                shutil.copyfileobj(src, dst, 128 << 10)
            require(sha256(image) == case['source']['uncompressedSHA256'], 'exact decoded source')
            sources.append((case['id'], image, False))
        if kind == 'hfs':
            from image_building import create_signed_app
            journaled = source_manifest['contract'].startswith('journaled-')
            for case_id, native_fs in (('hfsplus', 'HFS+'), ('hfsx', 'Case-sensitive HFS+')):
                case_id += '-empty-attributes'
                image = work / (case_id + '-source.raw')
                with image.open('xb') as raw:
                    raw.truncate(engine.CAPACITY)
                device = engine.attach(image, command, writable=True)
                # Reprobe the completed format before mounting: the raw device
                # was attached before newfs supplied its filesystem identity.
                # HFS selects folder-count support from the HFSX signature at
                # mount time, not just the catalog's case-sensitive comparator.
                try:
                    command('sudo', '/sbin/newfs_hfs', *(['-s'] if native_fs.startswith('Case') else []),
                            *(['-J'] if journaled else []), '-b', '4096', '-U', str(os.getuid()),
                            '-G', str(os.getgid()), '-v', 'Metadata',
                            device.replace('/dev/disk', '/dev/rdisk'))
                finally:
                    command('hdiutil', 'detach', device)
                device = engine.attach(image, command, writable=True)
                directory = work / (case_id + '-create')
                directory.mkdir()
                try:
                    command('diskutil', 'mount', '-mountOptions', 'owners,noatime', '-mountPoint', directory, device)
                    identity = plistlib.loads(command('diskutil', 'info', '-plist', directory))
                    require(('case-sensitive' in identity['FilesystemName'].lower()) == native_fs.startswith('Case'),
                            'native mounted case policy matches the formatted source')
                    root = directory / 'Fixture'
                    root.mkdir()
                    for name in ('small', 'empty', 'independent', 'fragmented-data', 'fragmented-resource'):
                        (root / name).write_bytes(b'ordinary metadata control\n')
                    with open(str(root / 'fragmented-resource') + '/..namedfork/rsrc', 'wb') as fork:
                        fork.write(b'independent resource fork\n')
                    os.link(root / 'fragmented-data', root / 'alias')
                    os.symlink('fragmented-data', root / 'symlink')
                    create_signed_app(root, command)
                finally:
                    command('hdiutil', 'detach', device)
                sources.append((case_id, image, True))
        for case_id, image, new_volume in sources:
            # Keep an Apple source even if its first checker verdict fails;
            # only a successful complete capture publishes an oracle manifest.
            source = engine.retain_file(image, output / (case_id + '-source.raw.gz'))
            before = engine.observe(image, work, command, observer=metadata_files)
            if new_volume:
                attrs = before['headers']['primary']['forks']['attributes']
                require(attrs['logicalSize'] > 0, 'initialized native attributes tree')
                # BTreeHeaderRec.leafRecords at byte 20 of the header node.
                with image.open('rb') as raw:
                    raw.seek(attrs['extents'][0][0] * 4096 + 20)
                    records = struct.unpack('>I', raw.read(4))[0]
                # Native services/signing can add their own records while the
                # fixture is populated. Keep the actual count and observations;
                # none of the tested files has an ordinary user attribute yet.
                before['initialAttributeRecords'] = records
                for entry in before['files']['entries']:
                    require(not any(name.startswith('org.go-apfs.') for name in entry['rawAttributes']),
                            'new-volume files begin without the tested attributes')
            item = {'id': case_id, 'source': source, 'before': before, 'states': {},
                    'newVolume': new_volume}
            clocks = {}
            for phase in ('metadata', 'metadata-final'):
                edited = work / (case_id + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                directory = work / (case_id + '-' + phase + '-write')
                cleanup, native = mounted(edited, directory)
                ops = operations(phase)
                if new_volume:
                    ops = [op for op in ops if not op['path'].endswith('-compressed')]
                try:
                    apply_operations(directory / 'Fixture', ops, native, clocks)
                finally:
                    native('hdiutil', 'detach', cleanup)
                state = engine.observe(edited, work, command, observer=metadata_files)
                state.update(operations=ops, clockFields=json.loads(json.dumps(clocks)))
                state['archive'] = engine.retain_file(edited, output / (case_id + '-' + phase + '.raw.gz'))
                item['states'][phase] = state
                image = edited
            cases.append(item)
    names = tuple(dict.fromkeys(('image_metadata.py', 'image_mutation.py', *engine.SOURCES)))
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in names}
    for name in names:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    producer['referenceManifestSHA256'] = sha256(references / 'manifest.json')
    producer['tools'] = source_manifest['producer']['tools']
    shutil.copyfile(references / 'manifest.json', output / 'reference-manifest.json')
    manifest = {'schema': 1, 'major': major, 'producer': producer, 'cases': cases,
                'contract': 'existing-' + kind + '-metadata-edits',
                'capacityBytes': source_manifest['capacityBytes'], 'modificationSeconds': STAMP,
                'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--references', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--kind', required=True, choices=('apfs', 'hfs'))
    parser.add_argument('--expected-major', required=True, type=int)
    args = parser.parse_args()
    capture(args.references, args.output, args.kind, args.expected_major)
