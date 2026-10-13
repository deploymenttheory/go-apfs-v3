#!/usr/bin/env python3
"""Independent Darwin permission/inheritance controls, only on disposable VMs.

Apple creates every source and executes every operation. Exact native filesec
observations use getattrlist, including ACL entries hidden from listxattr.
No Go implementation supplies expected permissions or inherited ACL bytes.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import struct
import tempfile

from capture import sha256
from container_building import require_disposable_host
from hfs_header_growth import retain_file
from image_mutation import copy_disk, raw_command
from image_repacking import Commands, attach, files, version
from verify_preservation import require

PROFILES = (('apfs', 'APFS'), ('apfs-case-sensitive', 'Case-sensitive APFS'),
            ('hfsplus', 'HFS+'), ('hfsx', 'Case-sensitive HFS+'))
SOURCES = ('phase5_permissions.py', 'capture.py', 'container_building.py',
           'hfs_header_growth.py', 'image_mutation.py', 'image_repacking.py',
           'image_building.py', 'file_compression.py', 'verify_preservation.py',
           'preservation.py', 'metadata_edits.py', 'content_replacement.py',
           'snapshot_reading.py')


def security(path):
    require_disposable_host()
    from metadata_edits import AttrList, LIB, checked
    # Public attr.h: EXTENDED_SECURITY, UUID and GRPUUID. attrreference follows
    # the four-byte result length; UUIDs occupy the next 32 fixed bytes.
    attrs = AttrList(5, 0, 0x01c00000, 0, 0, 0, 0)
    data = ctypes.create_string_buffer(4096)
    LIB.getattrlist.argtypes = [ctypes.c_char_p, ctypes.POINTER(AttrList),
                               ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    checked(LIB.getattrlist(os.fsencode(path), ctypes.byref(attrs), data,
                           len(data), 1), path)
    length, offset, size = struct.unpack_from('=IiI', data.raw)
    require(44 <= length <= len(data) and 0 <= size <= length, 'bounded native security attributes')
    if size == 0:
        return {'ownerUUID': data.raw[12:28].hex(), 'groupUUID': data.raw[28:44].hex(), 'acl': None}
    start = 4 + offset
    require(44 <= start and start + size <= length and size >= 44, 'native security reference')
    value = data.raw[start:start+size]
    magic, count, flags = struct.unpack_from('=I', value)[0], *struct.unpack_from('=II', value, 36)
    require(magic == 0x012cc16d and (count <= 128 or count == 0xffffffff), 'native filesec layout')
    require(size == 44 + (0 if count == 0xffffffff else count * 24), 'native filesec length')
    entries = []
    for n in range(0 if count == 0xffffffff else count):
        off = 44 + n * 24
        ace_flags, rights = struct.unpack_from('=II', value, off + 16)
        entries.append({'guid': value[off:off+16].hex(), 'flags': ace_flags, 'rights': rights})
    return {'ownerUUID': data.raw[12:28].hex(), 'groupUUID': data.raw[28:44].hex(),
            'acl': {'count': count, 'flags': flags, 'entries': entries}}


def mount(image, directory, command, readonly=False):
    require_disposable_host()
    cleanup, entries = attach(image, command, readonly)
    try:
        volumes = [e['dev-entry'] for e in entries if e.get('volume-kind')]
        require(len(volumes) == 1, 'single permission-control filesystem')
        directory.mkdir()
        command('diskutil', 'mount', *(['readOnly'] if readonly else []),
                '-mountOptions', 'owners,noatime', '-mountPoint', directory, volumes[0])
        return cleanup, volumes[0]
    except BaseException:
        command('hdiutil', 'detach', cleanup)
        raise


def observe(image, work, command, label):
    require_disposable_host()
    before = sha256(image)
    native = raw_command(command, image)
    directory = work / label
    cleanup, volume = mount(image, directory, native, readonly=True)
    try:
        native('diskutil', 'verifyVolume', volume)
        root = directory / 'Fixture'
        result = files(root)
        controls = {e['path']: security(directory / e['path']) for e in result['entries']}
        return {'files': result, 'security': controls, 'checkerStatus': 0}
    finally:
        native('hdiutil', 'detach', cleanup)
        require(sha256(image) == before, 'read-only permission observation changed source')


def create(root, command):
    require_disposable_host()
    command('sudo', 'mkdir', root)
    command('sudo', 'chown', f'{os.getuid()}:{os.getgid()}', root)
    for name in ('acl-file', 'write-user', 'write-root', 'chown-same', 'chown-group'):
        (root / name).write_bytes(b'Original permission contents\n')
    os.link(root / 'acl-file', root / 'acl-alias')
    os.symlink('acl-file', root / 'symlink')
    user = pwd.getpwuid(os.getuid()).pw_name
    command('chmod', '+a', f'user:{user} allow read,write,readsecurity', root / 'acl-file')
    for name in ('write-user', 'write-root', 'chown-same', 'chown-group'):
        command('sudo', 'chmod', '6755', root / name)
    policies = {
        'inherited': 'allow read,write,execute,file_inherit,directory_inherit',
        'only': 'allow read,write,file_inherit,directory_inherit,only_inherit',
        'limited': 'allow read,write,file_inherit,directory_inherit,limit_inherit',
        'files-only': 'allow read,write,file_inherit',
        'directories-only': 'allow read,write,directory_inherit',
    }
    for name, expression in policies.items():
        directory = root / name
        directory.mkdir()
        command('chmod', '+a', f'user:{user} {expression}', directory)
    for name, permission in (('other-owner', '0777'), ('setgid-parent', '2777')):
        directory = root / name
        directory.mkdir()
        command('sudo', 'chown', '60001:20', directory)
        command('sudo', 'chmod', permission, directory)


def create_copy_controls(root, command):
    require_disposable_host()
    from metadata_edits import set_metadata
    (root / 'plain-copy-source').write_bytes(b'Native ordinary copy source\n')
    (root / 'source-inherited').mkdir()
    command('chmod', '+a', f'user:{pwd.getpwuid(os.getuid()).pw_name} allow read,write,file_inherit,directory_inherit',
            root / 'source-inherited')
    (root / 'source-inherited/data').write_bytes(b'Native inherited copy source\n')
    for path in (root / 'plain-copy-source', root / 'acl-file', root / 'source-inherited', root / 'source-inherited/data'):
        set_metadata(path, {'birthTime': {'value': '2022-01-01T00:00:00.000000000Z'},
                            'modifyTime': {'value': '2023-01-01T00:00:00.000000000Z'},
                            'accessTime': {'value': '2024-01-01T00:00:00.000000000Z'}}, command)


def operate(root, command, copies=False):
    require_disposable_host()
    from metadata_edits import metadata
    operations = []

    def perform(op, action):
        target = root / op['path']
        if target.exists():
            op['before'] = {'metadata': metadata(target), 'security': security(target)}
        action()
        op['after'] = {'metadata': metadata(target), 'security': security(target)}
        operations.append(op)

    perform({'op': 'chmod', 'path': 'acl-alias', 'mode': '0751'},
            lambda: os.chmod(root / 'acl-alias', 0o751))
    if copies:
        for source, destination, preserve, no_attributes in (
                ('plain-copy-source', 'acl-alias', False, False),
                ('acl-file', 'inherited/copied', False, False),
                ('acl-file', 'inherited/preserved', True, False),
                ('acl-file', 'inherited/preserved-no-xattrs', True, True),
                ('source-inherited/data', 'inherited/without-source-inheritance', True, False),
                ('source-inherited/data', 'without-inheritance', True, False)):
            perform({'op': 'copy', 'path': destination, 'source': source,
                     'preserve': preserve, 'noAttributes': no_attributes, 'actorUID': os.getuid()},
                    lambda s=source, d=destination, p=preserve, x=no_attributes:
                    command('cp', *(['-p'] if p else []), *(['-X'] if x else []), root / s, root / d))
        return operations
    payload = b'Written permission contents\n'
    perform({'op': 'replace', 'path': 'write-user', 'actorUID': os.getuid()},
            lambda: (root / 'write-user').write_bytes(payload))
    perform({'op': 'replace', 'path': 'write-root', 'actorUID': 0},
            lambda: command('sudo', 'python3', '-c',
                            'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))',
                            root / 'write-root', payload.hex()))
    perform({'op': 'chown', 'path': 'chown-same', 'uid': os.getuid(), 'gid': os.getgid()},
            lambda: command('sudo', 'chown', f'{os.getuid()}:{os.getgid()}', root / 'chown-same'))
    perform({'op': 'chown', 'path': 'chown-group', 'gid': 20},
            lambda: command('sudo', 'chown', ':20', root / 'chown-group'))
    for name in ('inherited', 'only', 'limited', 'files-only', 'directories-only',
                 'other-owner', 'setgid-parent'):
        directory = root / name
        perform({'op': 'mkdir', 'path': name + '/child', 'actorUID': os.getuid()},
                lambda d=directory: (d / 'child').mkdir())
        perform({'op': 'create', 'path': name + '/data', 'actorUID': os.getuid()},
                lambda d=directory: (d / 'data').write_bytes(b'Created inherited contents\n'))
        perform({'op': 'create', 'path': name + '/child/grandchild', 'actorUID': os.getuid()},
                lambda d=directory: (d / 'child/grandchild').write_bytes(b'Created inherited contents\n'))
    return operations


def capture(major, output, copies=False):
    require_disposable_host()
    producer = version(major)
    producer.update(revision=os.environ['GITHUB_SHA'], run=os.environ['GITHUB_RUN_ID'],
                    actorUID=os.getuid(), actorGID=os.getgid(), actorGroups=os.getgroups())
    output.mkdir(parents=True)
    command = Commands(output / 'commands.json')
    cases = []
    for case_id, native_fs in PROFILES:
        with tempfile.TemporaryDirectory(prefix='phase5-permissions-') as tmp:
            work = Path(tmp)
            dmg = work / (case_id + '.dmg')
            command('hdiutil', 'create', '-size', str(128 << 20), '-layout', 'NONE',
                    '-fs', native_fs, '-volname', 'Permissions', dmg)
            directory = work / 'create'
            cleanup, _ = mount(dmg, directory, command)
            try:
                create(directory / 'Fixture', command)
                if copies:
                    create_copy_controls(directory / 'Fixture', command)
            finally:
                command('hdiutil', 'detach', cleanup)
            source = work / 'source.raw'
            copy_disk(dmg, source, command)
            before = observe(source, work, command, 'before')
            saved = retain_file(source, output / (case_id + '-source.raw.gz'))
            edited = work / 'after.raw'
            shutil.copyfile(source, edited)
            native = raw_command(command, edited)
            directory = work / 'edit'
            cleanup, _ = mount(edited, directory, native)
            try:
                operations = operate(directory / 'Fixture', native, copies)
            finally:
                native('hdiutil', 'detach', cleanup)
            after = observe(edited, work, command, 'after')
            saved_after = retain_file(edited, output / (case_id + '-after.raw.gz'))
            require(sha256(source) == saved['uncompressedSHA256'], 'permission edits changed source')
            cases.append({'id': case_id, 'source': saved, 'before': before,
                          'nativeAfter': saved_after, 'after': after, 'operations': operations})
    tools = ('/usr/bin/hdiutil', '/usr/sbin/diskutil', '/bin/chmod', '/usr/sbin/chown')
    if copies:
        tools += ('/bin/cp',)
    producer['tools'] = {path: sha256(Path(path)) for path in tools}
    producer['sources'] = {name: sha256(Path(__file__).with_name(name)) for name in SOURCES}
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    manifest = {'schema': 1, 'contract': ('phase5-copy-permissions' if copies else 'phase5-permission-inheritance'), 'major': major,
                'producer': producer, 'cases': cases, 'commandsSHA256': sha256(output / 'commands.json')}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-major', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--copy-only', action='store_true')
    args = parser.parse_args()
    capture(args.expected_major, args.output, args.copy_only)
