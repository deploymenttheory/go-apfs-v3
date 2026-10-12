#!/usr/bin/env python3
"""Apple cp observations for existing images; never uses Go as an oracle."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from capture import sha256
from container_building import require_disposable_host
from image_links import prepare as prepare_framework, FRAMEWORK
from image_metadata import metadata_files, STAMP
from image_repacking import Commands, version
from verify_image_metadata import mounted
from verify_preservation import require


def operations(phase):
    if phase == 'copy':
        return [
            {'sources': ['Example.app'], 'destination': 'Copies', 'archive': True},
            {'sources': [FRAMEWORK], 'destination': 'Copies', 'archive': True},
            {'sources': ['independent'], 'destination': 'Copies/forked', 'preserve': True},
            {'sources': ['inline-compressed'], 'destination': 'Copies/inline', 'preserve': True},
            {'sources': ['resource-compressed'], 'destination': 'Copies/resource', 'preserve': True},
            {'sources': ['inline-fork-compressed'], 'destination': 'Copies/inline-fork', 'preserve': True},
            {'sources': ['CopySource/'], 'destination': 'Copies/Merged', 'recursive': True},
            {'sources': ['independent'], 'destination': 'Copies/existing', 'preserve': True},
            {'sources': ['independent'], 'destination': 'Copies/no-attrs', 'noAttributes': True},
            {'sources': ['independent', 'empty'], 'destination': 'Copies/multi'},
            {'sources': ['@host-source'], 'destination': 'Copies', 'fromHost': True, 'recursive': True, 'noAttributes': True},
            {'sources': ['CopySource'], 'destination': 'Copies/preserved', 'archive': True, 'preserveLinks': True},
        ]
    if phase == 'copy-final':
        return [
            {'sources': ['CopySource/'], 'destination': 'Copies/Merged', 'archive': True},
            {'sources': ['empty'], 'destination': 'Copies/existing', 'preserve': True},
            {'sources': ['independent'], 'destination': 'Copies/no-attrs', 'noAttributes': True},
            {'sources': ['Copies/Example.app'], 'destination': 'Copies/Second.app', 'archive': True},
            # Native APFS can coalesce this existing inode's adjacent data/fork
            # ranges into one physical ownership record. Replace only its data;
            # -X keeps the independent fork and both original aliases intact.
            {'sources': ['independent'], 'destination': 'CopySource/data', 'noAttributes': True},
            {'op': 'rm', 'path': 'Copies/Example.app', 'recursive': True},
            {'op': 'mv', 'path': 'Copies/forked', 'destination': 'Copies/renamed'},
        ]
    if phase == 'native':
        return [{'sources': ['Copies/' + FRAMEWORK], 'destination': 'Copies/Native.framework', 'archive': True}]
    if phase == 'continued':
        return [{'sources': ['Copies/Native.framework'], 'destination': 'Copies/Continued.framework', 'archive': True},
                {'sources': ['empty'], 'destination': 'Copies/renamed', 'preserve': True}]
    raise ValueError(phase)


def host_source(directory):
    """Portable plain host input with no inferred macOS metadata or links."""
    directory.mkdir()
    for name in ('Nested', 'Empty'):
        (directory / name).mkdir()
    for name, data in [('payload', b'host copy\x00\xff' * 131), ('Nested/caf\u00e9', b'Unicode host copy\n'), ('zero-file', b'')]:
        (directory / name).write_bytes(data)
        os.chmod(directory / name, 0o644)
    for p in directory.rglob('*'):
        if p.is_dir():
            os.chmod(p, 0o755)
    os.chmod(directory, 0o755)


def prepare(root, command):
    require_disposable_host()
    from metadata_edits import set_attribute, set_metadata
    from file_compression import xattr, install, plain, encode, RESOURCE
    prepare_framework(root, command)
    # Install the independent fork before setting UF_COMPRESSED. Writing it to
    # an already compressed HFS file would decompress it, changing the profile.
    compressed = root / 'inline-fork-compressed'
    compressed.touch()
    xattr(compressed, RESOURCE, b'Independent compressed copy fork\x00\xff')
    install(compressed, 3, plain(1200), payload=encode(3, plain(1200)))
    for target, name in [('A', 'Versions/Current'), ('Versions/Current/Example', 'Example'),
                         ('Versions/Current/Resources', 'Resources')]:
        command('/bin/ln', '-s', '--', target, root / FRAMEWORK / name)
    for name in ('CopySource', 'CopySource/Nested', 'CopySource/Empty', 'Copies', 'Copies/Merged', 'Copies/multi'):
        (root / name).mkdir()
    data = root / 'CopySource/data'
    data.write_bytes(bytes(range(256)) * 257)
    os.chmod(data, 0o640)
    os.link(data, root / 'CopySource/alias')
    set_attribute(data, 'org.go-apfs.copy', b'copied attribute\x00\xff')
    set_attribute(data, 'com.apple.ResourceFork', b'copy fork\x00\xff' * 4099)
    (root / 'CopySource/Nested/caf\u00e9').write_bytes(b'Unicode image copy\n')
    (root / 'CopySource/._ordinary').write_bytes(b'Ordinary dot-underscore file\n')
    os.symlink('Nested/caf\u00e9', root / 'CopySource/relative')
    os.symlink('missing', root / 'CopySource/dangling')
    for n in range(12):
        (root / ('CopySource/' + f'{n:03}-' + 'n' * 64)).write_bytes(bytes([n]) * (4097 + n))
    for name in ('Copies/existing', 'Copies/no-attrs', 'Copies/Merged/kept'):
        (root / name).write_bytes(b'previous destination\n')
        set_attribute(root / name, 'org.go-apfs.copy.old', b'old destination attribute')
        set_attribute(root / name, 'com.apple.ResourceFork', b'old destination fork')
    os.link(root / 'Copies/existing', root / 'Copies/existing-alias')
    # All preservation values precede operation clocks; source inode IDs are exact.
    stamp = {'value': '2001-02-03T04:05:06.000000000Z'}
    paths = list((root / 'CopySource').rglob('*')) + [root / 'CopySource']
    paths += list((root / 'Example.app').rglob('*')) + [root / 'Example.app']
    paths += list((root / FRAMEWORK).rglob('*')) + [root / FRAMEWORK]
    paths += list((root / 'Copies').rglob('*')) + [root / 'Copies']
    # The portable construction clock is 2025. Preserved source dates must
    # precede both that clock and the native operation clock, so the filesystem
    # birth<=mtime adjustment compares the same ordered dates on both sides.
    paths += [root / name for name in ('independent', 'empty', 'inline-compressed', 'resource-compressed', 'inline-fork-compressed')]
    for p in reversed(paths):
        set_metadata(p, {'birthTime': stamp, 'modifyTime': stamp, 'accessTime': stamp}, command)


def preserve_links(source, destination, command):
    """Archive copy extension: Apple cp, ln, then native directory time restoration."""
    first = {}
    parents = set()
    for p in sorted(source.rglob('*')):
        st = p.lstat()
        if not p.is_symlink() and p.is_file() and st.st_nlink > 1:
            target = destination / p.relative_to(source)
            if st.st_ino in first:
                command('/bin/rm', target)
                command('/bin/ln', '--', first[st.st_ino], target)
                parents.add(p.parent)
            else:
                first[st.st_ino] = target
    # Link repairs happen after Apple's archive copy. Restore each affected
    # directory's copied timestamps with Apple touch, as -p specifies.
    for parent in sorted(parents, reverse=True):
        command('/usr/bin/touch', '-r', parent, destination / parent.relative_to(source))


def apply(root, ops, command, host, clocks=None):
    require_disposable_host()
    from metadata_edits import set_metadata
    before = metadata_files(root)
    delay = max(e['changeNS'] for e in before['entries']) // 10**9 + 1 - time.time()
    require(delay <= 1.1, 'copy baseline clock is not in the future')
    if delay > 0:
        time.sleep(delay + 0.01)
    # Source values precede this whole-second boundary, including files with
    # recent dates in the base image. Only times produced by these operations
    # may be replaced with the reproducible construction clock.
    clock_start = time.time_ns() // 10**9 * 10**9
    for op in ops:
        if op.get('op') == 'rm':
            command('/bin/rm', '-R', root / op['path'])
        elif op.get('op') == 'mv':
            command('/bin/mv', root / op['path'], root / op['destination'])
        else:
            sources = [host if p == '@host-source' else root / p for p in op['sources']]
            # Path loses a trailing slash; preserve its cp operand semantics.
            sources = [str(p) + ('/' if name.endswith('/') else '') for p, name in zip(sources, op['sources'])]
            flags = []
            for field, flag in [('archive', '-a'), ('recursive', '-R'), ('preserve', '-p'), ('noAttributes', '-X')]:
                if op.get(field):
                    flags.append(flag)
            command('/bin/cp', *flags, '--', *sources, root / op['destination'])
            if op.get('preserveLinks'):
                preserve_links(root / op['sources'][0], root / op['destination'], command)
    after = metadata_files(root)
    old = {e['object']: e for e in before['entries']}
    clocks = {} if clocks is None else clocks
    for e in after['entries']:
        # Normalize only new runtime creation fields. Preserved 2001 source values
        # remain untouched and are compared exactly, including nanosecond precision.
        if e['object'] not in old:
            patch = {}
            for field, native in [('birthTime', 'birthNS'), ('modifyTime', 'modifyNS'), ('accessTime', 'accessNS')]:
                if e[native] >= clock_start:
                    patch[field] = {'value': '2025-06-07T08:09:10.000000000Z'}
            if patch:
                set_metadata(root.parent / e['path'], patch, command)
    after = metadata_files(root)
    for e in after['entries']:
        prior = old.get(e['object'])
        fields = clocks.setdefault(str(e['object']), [])
        for field in ('changeNS', 'modifyNS'):
            # A later preserved copy can replace an earlier operation-derived
            # mtime with an exact source value. Classification follows the final
            # observation, rather than retaining a stale previous-phase marker.
            if field == 'modifyNS' and prior is not None and e[field] != prior[field] and e[field] < clock_start and field in fields:
                fields.remove(field)
            if (prior is None and field == 'changeNS' or prior is not None and e[field] != prior[field] and e[field] >= clock_start) and field not in fields:
                fields.append(field)
    return clocks


def signatures(root, command):
    for name in ('Example.app', FRAMEWORK, 'Copies/Example.app', 'Copies/Second.app',
                 'Copies/' + FRAMEWORK, 'Copies/Native.framework', 'Copies/Continued.framework'):
        if (root / name).exists():
            command('codesign', '--verify', '--deep', '--strict', root / name)


def observe(raw, kind, command, work):
    require_disposable_host()
    with mounted(raw, kind, command, work) as (root, native):
        signatures(root, native)
        result = {'files': metadata_files(root), 'checkerStatus': 0}
    if kind == 'hfs':
        from hfs_editing import read_journal
        journal = read_journal(raw)
        if journal is not None:
            result['journal'] = journal
    return result


def capture(references, output, kind, major):
    require_disposable_host()
    from hfs_header_growth import retain_file
    producer = version(major)
    reference = json.loads((references / 'manifest.json').read_text())
    require(reference['major'] == major, 'copy source OS version')
    output.mkdir(parents=True)
    host_source(output / 'host-source')
    command = Commands(output / 'commands.json')
    cases = []
    with tempfile.TemporaryDirectory(prefix='image-copy-') as temporary:
        work = Path(temporary)
        for case in reference['cases']:
            image = work / (case['id'] + '-source.raw')
            archive = references / case['source']['image']
            require(sha256(archive) == case['source']['sha256'], 'copy source archive integrity')
            with gzip.open(archive, 'rb') as src, image.open('xb') as dst:
                shutil.copyfileobj(src, dst, 128 << 10)
            require(sha256(image) == case['source']['uncompressedSHA256'], 'copy decoded source integrity')
            with mounted(image, kind, command, work, writable=True) as (root, native):
                prepare(root, native)
            item = {'id': case['id'], 'source': retain_file(image, output / (case['id'] + '-source.raw.gz')),
                    'before': observe(image, kind, command, work), 'states': {}}
            clocks = {}
            for phase in ('copy', 'copy-final'):
                edited = work / (case['id'] + '-' + phase + '.raw')
                shutil.copyfile(image, edited)
                ops = operations(phase)
                with mounted(edited, kind, command, work, writable=True) as (root, native):
                    apply(root, ops, native, output / 'host-source', clocks)
                state = observe(edited, kind, command, work)
                state.update(operations=ops, clockFields=json.loads(json.dumps(clocks)))
                state['archive'] = retain_file(edited, output / (case['id'] + '-' + phase + '.raw.gz'))
                item['states'][phase] = state
                image = edited
            cases.append(item)
    names = tuple(dict.fromkeys(('image_copy.py', 'image_links.py', 'verify_image_metadata.py', 'image_metadata.py',
                                'metadata_edits.py', 'image_mutation.py', *reference['producer']['sources'])))
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in names}
    for name in names:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    producer['tools'] = dict(reference['producer']['tools'])
    producer['tools'].update({path: sha256(Path(path)) for path in ('/bin/cp', '/bin/ln', '/bin/mkdir', '/bin/mv', '/bin/rm', '/usr/bin/codesign')})
    producer['referenceManifestSHA256'] = sha256(references / 'manifest.json')
    shutil.copyfile(references / 'manifest.json', output / 'reference-manifest.json')
    inputs = [{'file': str(p.relative_to(output)), 'size': p.stat().st_size, 'sha256': sha256(p)}
              for p in sorted((output / 'host-source').rglob('*')) if p.is_file()]
    manifest = {'schema': 1, 'major': major, 'producer': producer, 'cases': cases, 'hostInputs': inputs,
                'contract': 'existing-' + kind + '-copy', 'modificationSeconds': STAMP,
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
