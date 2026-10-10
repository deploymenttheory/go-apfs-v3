"""Apple file-command references for persistent portable editing sessions.

The recipe never invokes Go. All ordinary operations run /bin or /usr/bin tools.
Complete fork replacement uses native named-fork I/O. Timestamp intervals and
observed field changes are recorded separately from the final readonly tree.
"""
import ctypes
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import file_compression as compression
import metadata_edits
from metadata_edits import observe

FIXED_TIME = '2025-06-07T08:09:10.123456789Z'


def create(root, command):
    root.mkdir()
    for name in ('Source.app', 'Source.app/Contents', 'Source.app/Contents/MacOS',
                 'Source.app/Contents/Resources', 'Source.app/Contents/Resources/Empty',
                 'Applications', 'obsolete', 'obsolete/nested'):
        (root / name).mkdir()
    executable = root / 'Source.app/Contents/MacOS/Example'
    executable.write_bytes(b'Native application executable bytes\x00\xff\n' * 17)
    os.chmod(executable, 0o751)
    os.link(executable, root / 'Source.app/Contents/Resources/executable-alias')
    compression.xattr(executable, 'org.original', b'preserved attribute')
    compression.xattr(executable, compression.RESOURCE, b'Independent fork\x00' * 2051)
    (root / 'Source.app/Contents/Resources/caf\u00e9').write_bytes(b'Unicode resource\n')
    (root / 'Source.app/Contents/Resources/._ordinary').write_bytes(b'An ordinary dot-underscore file\n')
    (root / 'obsolete/nested/child').write_bytes(b'remove this tree\n')
    os.symlink('MacOS/Example', root / 'Source.app/Contents/Current')
    os.symlink('missing', root / 'Source.app/Contents/Resources/dangling')
    data = compression.plain(1200)
    compression.install(root / 'compressed', 3, data, payload=compression.encode(3, data))
    # Old timestamps make command-generated times independently distinguishable.
    stamp = {'state': 2, 'value': '2001-02-03T04:05:06.000000000Z'}
    for entry in reversed(list(root.rglob('*')) + [root]):
        metadata_edits.set_metadata(entry, {'birthTime': stamp, 'modifyTime': stamp, 'accessTime': stamp}, command)


def time_state(root):
    # lstat only: enumerating a writable directory would itself change its atime
    # and falsely attribute the observer's access to the command being measured.
    bundle = ['', '/Contents', '/Contents/MacOS', '/Contents/MacOS/Example',
              '/Contents/Resources', '/Contents/Resources/Empty',
              '/Contents/Resources/executable-alias', '/Contents/Resources/caf\u00e9',
              '/Contents/Resources/._ordinary', '/Contents/Current',
              '/Contents/Resources/dangling']
    paths = ['.', 'Applications', 'obsolete', 'obsolete/nested', 'obsolete/nested/child',
             'compressed', 'plain-copy', 'build-alias', 'app-link']
    paths += [prefix + suffix for prefix in ('Source.app', 'Applications/Source.app') for suffix in bundle]
    paths += ['Applications/Source.app/Contents/' + directory + suffix
              for directory in ('New', 'Moved') for suffix in ('', '/deep', '/build.bin')]
    result = {}
    for name in paths:
        p = root / name
        try:
            st = p.lstat()
        except FileNotFoundError:
            continue
        result[str(st.st_ino)] = {'birthTime': metadata_edits.birth_ns(p),
                                 'modifyTime': st.st_mtime_ns, 'changeTime': st.st_ctime_ns,
                                 'accessTime': st.st_atime_ns}
    return result


def mode_vectors():
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.setmode.argtypes = [ctypes.c_char_p]
    lib.setmode.restype = ctypes.c_void_p
    lib.getmode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.getmode.restype = ctypes.c_uint32
    lib.free.argtypes = [ctypes.c_void_p]
    expressions = ['755', '0000', 'u+x', 'go-w', 'u=rwx,go=rx', 'u=rwx,go=u-w',
                   'a+X', 'a-X', 'u=rwX,go=rX', 'g=u-w', 'o=g', '=rw,+X',
                   'a=,u+x', 'a+t', 'u+t', 'o+t', 'u+s,g+s', 'u=gr', 'u+gX-w',
                   'u=ugo', '=u', '-w', '', '999', 'u+z', 'a+,']
    result = []
    old = os.umask(0o022)
    try:
        for mask in (0, 0o022, 0o077):
            os.umask(mask)
            for expression in expressions:
                for original in (0o100644, 0o100751, 0o040755, 0o104755, 0o120777):
                    program = lib.setmode(expression.encode())
                    value = int(lib.getmode(program, original)) if program else 0
                    result.append({'expression': expression, 'input': original,
                                   'umask': mask, 'valid': bool(program), 'output': value})
                    if program:
                        lib.free(program)
    finally:
        os.umask(old)
    return result


def capture_after(scratch, corpus, case_id, attach, command, observe_files, native_xattrs, sha256):
    payload = corpus / (case_id + '-payload.bin')
    payload.write_bytes(b'Host build output\x00\xff\n' * 23)
    os.chmod(payload, 0o644)
    fork = corpus / (case_id + '-fork.bin')
    fork.write_bytes(b'short fork\x00\xff')
    empty = corpus / (case_id + '-empty.bin')
    empty.write_bytes(b'')
    inputs = [{'file': p.name, 'size': p.stat().st_size, 'sha256': sha256(p)}
              for p in (payload, fork, empty)]
    operations = [
        ['cp', '-a', '/Source.app', '/Applications/'],
        ['chmod', 'u+x,g=u-w,o=', '/Applications/Source.app/Contents/MacOS/Example'],
        ['chmod', '-R', 'u=rwX,go=rX', '/Applications/Source.app'],
        # Keep other-read/traverse permission after the final sudo ownership change,
        # so independent unprivileged readback can observe every directory.
        ['mkdir', '-pm775', '/Applications/Source.app/Contents/New/deep'],
        ['cp', '--from-host', '-X', '@' + payload.name, '/Applications/Source.app/Contents/New/build.bin'],
        ['chmod', '0644', '/Applications/Source.app/Contents/New/build.bin'],
        ['ln', '/Applications/Source.app/Contents/New/build.bin', '/build-alias'],
        ['cp', '--from-host', '-X', '@' + fork.name, '/build-alias'],
        ['ln', '-s', 'Applications/Source.app', '/app-link'],
        ['chmod', 'u+x', '/app-link/Contents/New/build.bin'],
        ['chflags', 'hidden', '/Applications/Source.app/Contents/New/build.bin'],
        ['xattr', '-w', 'org.command', 'command attribute', '/build-alias'],
        ['xattr', '-wx', 'org.binary', '0001ff', '/build-alias'],
        ['xattr', '-d', 'org.original', '/Applications/Source.app/Contents/MacOS/Example'],
        ['cp', '--from-host', '--resource-fork', '@' + fork.name, '/Applications/Source.app/Contents/MacOS/Example'],
        ['cp', '--from-host', '--resource-fork', '@' + empty.name, '/Applications/Source.app/Contents/Resources/executable-alias'],
        ['cp', '-p', '/compressed', '/plain-copy'],
        ['mv', '/Applications/Source.app/Contents/New', '/Applications/Source.app/Contents/Moved'],
        ['touch', '-d', '2009-08-07T06:05:04Z', '/build-alias'],
        ['touch', '-c', '/absent'],
        ['rm', '-r', '/obsolete'],
        ['rm', '-f', '/absent'],
    ]
    rejections = [
        ['cp', '-n', '/plain-copy', '/build-alias'],
        ['cp', '/build-alias', '/build-alias'],
        ['ln', '/Applications', '/directory-hardlink'],
        ['chmod', 'invalid', '/build-alias'],
        ['mv', '/Applications/Source.app', '/Applications/Source.app/Contents/cycle'],
    ]
    device, mount = attach(scratch, noatime=True)
    old_umask = os.umask(0o022)
    try:
        root = mount / 'Fixture'
        uid, gid = os.getuid(), os.getgid()
        sudo = subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).returncode == 0
        owner = '60001:60002' if sudo else f'{uid}:{gid}'
        operations.append(['chown', '-R', owner, '/Applications/Source.app'])
        recorded = []
        start_all = time.time_ns()
        def argv_for(op):
            executable = '/bin/' + op[0]
            if op[0] == 'chown':
                executable = '/usr/sbin/chown'
            if op[0] in ('touch', 'xattr', 'chflags'):
                executable = '/usr/bin/' + op[0]
            args = []
            for arg in op[1:]:
                if arg == '--from-host':
                    continue
                if arg.startswith('@'):
                    arg = str(corpus / arg[1:])
                elif arg.startswith('/'):
                    arg = str(root / arg.lstrip('/'))
                args.append(arg)
            return [executable, *args]
        for op in operations:
            before = time_state(root)
            start = time.time_ns()
            if '--resource-fork' in op:
                source = corpus / next(arg[1:] for arg in op if arg.startswith('@'))
                target = root / op[-1].lstrip('/')
                code = 'from pathlib import Path; import sys; Path(sys.argv[2]+"/..namedfork/rsrc").write_bytes(Path(sys.argv[1]).read_bytes())'
                command('python3', '-c', code, source, target)
            else:
                argv = argv_for(op)
                if op[0] == 'chown' and sudo:
                    argv = ['sudo', '-n', *argv]
                command(*argv)
            end = time.time_ns()
            after = time_state(root)
            effects = {oid: {name: value for name, value in fields.items()
                             if oid not in before or before[oid][name] != value}
                       for oid, fields in after.items()}
            recorded.append({'argv': op, 'startNS': start, 'endNS': end,
                             'effects': {k: v for k, v in effects.items() if v}})
        for op in rejections:
            command(*argv_for(op), expected_success=False)
        end_all = time.time_ns()
    finally:
        os.umask(old_umask)
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
        raise RuntimeError('native readback changed image')
    command('hdiutil', 'verify', image)
    files = corpus / (case_id + '-after-files.json')
    files.write_text(json.dumps(after, indent=2) + '\n')
    return {'readAccessPolicy': 'noatime', 'modeVectors': mode_vectors(), 'operations': recorded, 'rejections': rejections, 'inputs': inputs,
            'startNS': start_all, 'endNS': end_all, 'fixedTime': FIXED_TIME,
            'uid': uid, 'gid': gid, 'ownership': 'changed-with-sudo' if sudo else 'same-owner-local',
            'after': files.name, 'afterSHA256': sha256(files),
            'image': image.name, 'imageSHA256': digest}
