"""Native metadata, xattr and complete resource-fork edits on disposable images.

Explicit input values and actual final read-only observations are separate.
ctime and other unspecified times remain native observations; portable replay
preserves the source's unspecified times by its declared workspace policy.
"""
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
import stat
import subprocess

import file_compression as compression
from content_replacement import observe as observe_contents

LIB = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)


class AttrList(ctypes.Structure):
    _fields_ = [('count', ctypes.c_uint16), ('reserved', ctypes.c_uint16),
                ('common', ctypes.c_uint32), ('volume', ctypes.c_uint32),
                ('directory', ctypes.c_uint32), ('file', ctypes.c_uint32), ('fork', ctypes.c_uint32)]


class Timespec(ctypes.Structure):
    _fields_ = [('seconds', ctypes.c_int64), ('nanoseconds', ctypes.c_int64)]


def checked(result, path):
    if result < 0:
        raise OSError(ctypes.get_errno(), os.fspath(path))
    return result


def birth_ns(path):
    # Darwin getattrlist packs the timespec after a 4-byte length without padding.
    attrs = AttrList(5, 0, 0x200, 0, 0, 0, 0)
    data = ctypes.create_string_buffer(20)
    LIB.getattrlist.argtypes = [ctypes.c_char_p, ctypes.POINTER(AttrList), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    checked(LIB.getattrlist(os.fsencode(path), ctypes.byref(attrs), data, len(data), 1), path)
    stamp = Timespec.from_buffer_copy(data.raw[4:20])
    return stamp.seconds * 10**9 + stamp.nanoseconds


def timestamp(ns):
    seconds, fraction = divmod(ns, 10**9)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'


def metadata(path):
    s = path.lstat()
    values = {'mode': s.st_mode, 'uid': s.st_uid, 'gid': s.st_gid, 'bsdFlags': s.st_flags,
              'birthTime': timestamp(birth_ns(path)), 'modifyTime': timestamp(s.st_mtime_ns),
              'changeTime': timestamp(s.st_ctime_ns), 'accessTime': timestamp(s.st_atime_ns)}
    return {k: {'state': 2, 'value': v} for k, v in values.items()}


def observe(root, observe_files, native_xattrs):
    result = observe_contents(root, observe_files, native_xattrs)
    for entry in result['entries']:
        entry['birthNS'] = birth_ns(root.parent / entry['path'])
    return result


def set_attribute(path, name, data, mode=''):
    LIB.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    options = 1 | {'': 0, 'create': 2, 'replace': 4}[mode]  # XATTR_NOFOLLOW
    checked(LIB.setxattr(os.fsencode(path), name.encode(), data, len(data), 0, options), path)


def remove_attribute(path, name):
    LIB.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    checked(LIB.removexattr(os.fsencode(path), name.encode(), 1), path)


def set_metadata(path, patch, command):
    m = {k: v['value'] for k, v in patch.items()}
    if 'uid' in m or 'gid' in m:
        uid, gid = m.get('uid', -1), m.get('gid', -1)
        if uid in (-1, os.getuid()) and gid in (-1, *os.getgroups()):
            os.chown(path, uid, gid, follow_symlinks=False)
        else:
            # Disposable image files only. CI's passwordless sudo supplies the
            # owner change; portable edits never claim to enforce authorization.
            command('sudo', '-n', 'chown', '-h', f'{uid}:{gid}', path)
    if 'mode' in m:
        os.chmod(path, m['mode'] & 0o7777, follow_symlinks=False)
    if 'bsdFlags' in m:
        os.chflags(path, m['bsdFlags'], follow_symlinks=False)
    if any(k in m for k in ('birthTime', 'modifyTime', 'accessTime')):
        current = metadata(path)
        # Supply all three user-settable times to retain the other values. HFS+
        # treats atime-only setattrlist as a lazy kernel touch, and can move birth
        # time when only mtime is assigned. This is an explicit preservation op.
        values = []
        for k in ('birthTime', 'modifyTime', 'accessTime'):
            stamp = m.get(k, current[k]['value'])
            whole, fraction = stamp.rstrip('Z').split('.')
            seconds = int(datetime.strptime(whole, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
            values.append(Timespec(seconds, int(fraction.ljust(9, '0'))))
        data = (Timespec * 3)(*values)
        attrs = AttrList(5, 0, 0x1600, 0, 0, 0, 0)
        LIB.setattrlist.argtypes = [ctypes.c_char_p, ctypes.POINTER(AttrList), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        checked(LIB.setattrlist(os.fsencode(path), ctypes.byref(attrs), data, ctypes.sizeof(data), 1), path)


def operate(root, op, corpus, command):
    p = root / op['path']
    action = op['op']
    if action == 'metadata':
        set_metadata(p, op['metadata'], command)
    elif action == 'setxattr':
        set_attribute(p, op['attribute'], (corpus / op['data']).read_bytes(), op.get('attributeMode', ''))
    elif action == 'removexattr':
        remove_attribute(p, op['attribute'])
    elif action in ('resource-fork', 'replace'):
        target = p / '..namedfork/rsrc' if action == 'resource-fork' else p
        with target.open('wb') as stream:
            stream.write((corpus / op['data']).read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    elif action == 'rename':
        os.rename(p, root / op['to'])
    elif action == 'link':
        os.link(p, root / op['to'])
    else:
        raise ValueError(action)


def create(root, command):
    root.mkdir()
    (root / 'directory').mkdir()
    for name in ('ordinary', 'untouched', 'empty-fork', 'remove-fork', 'finder-zero', 'finder-remove', 'flags', 'owner', 'CON'):
        (root / name).write_bytes(('Original ' + name + '\n').encode())
    os.link(root / 'ordinary', root / 'alias')
    os.symlink('ordinary', root / 'link')
    for name in ('ordinary', 'empty-fork', 'remove-fork'):
        compression.xattr(root / name, compression.RESOURCE, b'Initial independent resource fork' * 137)
    for name in ('ordinary', 'finder-zero'):
        compression.xattr(root / name, 'com.apple.FinderInfo', b'TEXTttxt' + bytes(24))
    compression.xattr(root / 'ordinary', 'org.go-apfs.remove', b'Remove only this attribute')
    for name in ('ordinary', 'untouched'):
        compression.xattr(root / name, 'org.go-apfs.keep', b'Unrelated metadata\x00\xff')
    data = compression.plain(1200)
    compression.install(root / 'compressed-inline', 3, data, payload=compression.encode(3, data))
    data = compression.plain(65536 + 19)
    compression.install(root / 'compressed-resource', 4, data,
                        blocks=[compression.encode(4, data[i:i+65536]) for i in range(0, len(data), 65536)])
    os.link(root / 'compressed-resource', root / 'compressed-alias')


def capture_after(scratch, corpus, case_id, attach, command, observe_files, native_xattrs, sha256):
    payloads = {'large': bytes(range(256)) * 257, 'small': b'short\x00\xff', 'empty': b'',
                'finder': bytes(range(8)) + bytes([0x40]) + bytes(range(9, 32)),
                'finder-zero': bytes(32), 'finder-invalid': bytes(31)}
    inputs = {}
    for name, data in payloads.items():
        p = corpus / f'{case_id}-{name}.bin'
        p.write_bytes(data)
        inputs[name] = {'file': p.name, 'sha256': sha256(p), 'size': len(data)}
    def value(v):
        return {'state': 2, 'value': v}
    def patch(path, **fields):
        return {'op': 'metadata', 'path': path, 'metadata': {k: value(v) for k, v in fields.items()}}
    def attr(path, name, data='small', mode=''):
        return {'op': 'setxattr', 'path': path, 'attribute': name,
                'data': inputs[data]['file'], 'attributeMode': mode}
    def fork(path, data):
        return {'op': 'resource-fork', 'path': path, 'data': inputs[data]['file']}
    privileged = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=10).returncode == 0
    uid, gid = (60001, 60002) if privileged else (os.getuid(), os.getgid())
    operations = [
        patch('ordinary', mode=0o100751), patch('directory', mode=0o040750), patch('link', mode=0o120711),
        attr('ordinary', 'org.go-apfs.edit', 'large', 'create'),
        attr('alias', 'org.go-apfs.edit', 'small', 'replace'),
        attr('ordinary', 'org.go-apfs.empty', 'empty', 'create'),
        attr('directory', 'org.go-apfs.directory'), attr('link', 'org.go-apfs.link'),
        {'op': 'removexattr', 'path': 'ordinary', 'attribute': 'org.go-apfs.remove'},
        fork('ordinary', 'large'), fork('alias', 'small'), fork('empty-fork', 'empty'),
        {'op': 'removexattr', 'path': 'remove-fork', 'attribute': compression.RESOURCE},
        attr('finder-zero', 'com.apple.FinderInfo', 'finder-zero', 'replace'),
        attr('finder-remove', 'com.apple.FinderInfo', 'finder'),
        {'op': 'removexattr', 'path': 'finder-remove', 'attribute': 'com.apple.FinderInfo'},
        attr('directory', 'com.apple.FinderInfo', 'finder'), attr('link', 'com.apple.FinderInfo', 'finder'),
        patch('flags', bsdFlags=stat.UF_HIDDEN | stat.UF_NODUMP),
        patch('ordinary', birthTime='2023-11-14T22:13:20.123456789Z',
              modifyTime='2023-11-14T22:13:21.234567891Z', accessTime='2023-11-14T22:13:22.345678912Z'),
        patch('.', mode=0o040750),
        {'op': 'rename', 'path': 'ordinary', 'to': 'renamed'},
        {'op': 'link', 'path': 'alias', 'to': 'new-alias'},
        {'op': 'replace', 'path': 'compressed-alias', 'data': inputs['small']['file']},
        fork('compressed-resource', 'large'),
        attr('compressed-inline', 'org.go-apfs.compressed'),
        patch('compressed-inline', mode=0o100755, bsdFlags=stat.UF_COMPRESSED | stat.UF_HIDDEN),
        attr('CON', 'org.go-apfs.' + 'a' * (127 - len('org.go-apfs.'))),
        patch('owner', uid=uid, gid=gid),
    ]
    # Time assignment is last: reading a resource fork to observe an earlier
    # operation can itself update HFS+ access time on the writable mount.
    time_op = operations.pop(19)
    time_op['path'] = 'renamed'
    operations.append(time_op)
    rejections = [attr('renamed', 'org.go-apfs.edit', mode='create'),
                  attr('renamed', 'org.go-apfs.absent', mode='replace'),
                  {'op': 'removexattr', 'path': 'renamed', 'attribute': 'org.go-apfs.absent'},
                  attr('renamed', 'com.apple.FinderInfo', 'finder-invalid'),
                  fork('directory', 'small'), fork('link', 'small'),
                  attr('CON', 'a' * 128)]
    device, mount = attach(scratch)
    try:
        root = mount / 'Fixture'
        for op in operations:
            p = root / op['path']
            before_meta = metadata(p)
            before_attrs = native_xattrs(p, 0x21)
            op['object'] = p.lstat().st_ino
            operate(root, op, corpus, command)
            p = root / op['to'] if op['op'] == 'rename' else p
            after_meta = metadata(p)
            after_attrs = (before_attrs if op['op'] == 'metadata' and 'bsdFlags' not in op['metadata']
                           else native_xattrs(p, 0x21))
            fields = set(op.get('metadata', {}))
            attrs = set()
            if op['op'] in ('setxattr', 'removexattr', 'resource-fork'):
                attrs.add(op.get('attribute', compression.RESOURCE))
                if before_meta['bsdFlags'] != after_meta['bsdFlags']:
                    fields.add('bsdFlags')
            if op['op'] == 'metadata' and before_attrs.get('com.apple.FinderInfo') != after_attrs.get('com.apple.FinderInfo'):
                attrs.add('com.apple.FinderInfo')
            op['effects'] = {'metadata': sorted(fields), 'attributes': sorted(attrs)}
        for op in rejections:
            try:
                operate(root, op, corpus, command)
            except OSError as error:
                op['errno'] = error.errno
            else:
                raise RuntimeError(f'native rejection unexpectedly succeeded: {op}')
    finally:
        command('hdiutil', 'detach', device)
    image = corpus / (case_id + '-after.dmg')
    command('hdiutil', 'convert', scratch, '-format', 'UDZO', '-o', image)
    digest = sha256(image)
    device, mount = attach(image, readonly=True)
    try:
        after = observe(mount / 'Fixture', observe_files, native_xattrs)
    finally:
        command('hdiutil', 'detach', device)
    if sha256(image) != digest:
        raise RuntimeError('native readback changed metadata-edited image')
    command('hdiutil', 'verify', image)
    files = corpus / (case_id + '-after-files.json')
    files.write_text(json.dumps(after, indent=2) + '\n')
    return {'operations': operations, 'rejections': rejections, 'inputs': list(inputs.values()),
            'ownership': 'changed-with-sudo' if privileged else 'same-owner-local',
            'after': files.name, 'afterSHA256': sha256(files), 'image': image.name, 'imageSHA256': digest}
