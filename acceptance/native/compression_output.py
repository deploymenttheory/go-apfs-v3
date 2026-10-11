"""Qualify Go file storage through Apple's kernel and public compression codec."""
import hashlib
import stat
import struct

import file_compression as compression
from preservation import digest_values
from verify_preservation import require


def ordinary_attributes(entry, raw):
    result = dict(raw)
    if entry['flags'] & stat.UF_COMPRESSED:
        result.pop(compression.ATTRIBUTE, None)
        # Native ordinary listxattr hides codec-owned resource storage. An
        # independent fork on an attribute-compressed file remains visible.
        if compression.RESOURCE not in entry['attributes']:
            result.pop(compression.RESOURCE, None)
    return result


def verify(path, expected, actual, raw_expected, policy):
    require(actual['flags'] & ~stat.UF_COMPRESSED == expected['flags'] & ~stat.UF_COMPRESSED,
            f'{path}: unrelated flags changed')
    raw = compression.xattr
    # SHOWCOMPRESSION records all backing attributes, including kernel-hidden ones.
    from capture import native_xattrs
    values = native_xattrs(path, 0x21)
    if actual['flags'] & stat.UF_COMPRESSED:
        require(policy == 'zlib', f'{path}: none retained active compression')
        header = values[compression.ATTRIBUTE]
        require(16 <= len(header) <= 3802, f'{path}: attribute capacity')
        magic, kind, size = struct.unpack_from('<IIQ', header)
        require(magic == 0x636d7066 and kind in (3, 4) and size == expected['size'], f'{path}: zlib header')
        fork = values.get(compression.RESOURCE, b'') if kind == 4 else b''
        decoded = compression.decode_storage(kind, size, header[16:], fork)
        require(len(decoded) == size and hashlib.sha256(decoded).hexdigest() == expected['sha256'],
                f'{path}: Apple public codec differs from native source')
        require(len(header) + len(fork) < size, f'{path}: compression did not reduce stored bytes')
        if path.name == 'mixed-blocks':
            require(kind == 4, 'mixed data uses block storage')
            offset, length = struct.unpack_from('<II', fork, 272)
            require(length == compression.BLOCK + 1 and fork[260 + offset] == 0xff,
                    'incompressible block has native stored marker')
        values.pop(compression.ATTRIBUTE)
        if kind == 4:
            values.pop(compression.RESOURCE)
    elif policy == 'none' and expected['flags'] & stat.UF_COMPRESSED:
        require(compression.ATTRIBUTE not in values, f'{path}: removed compression attribute')
    require(digest_values(values) == ordinary_attributes(expected, raw_expected), f'{path}: independent raw attributes/forks')
    require(actual['attributes'] == ordinary_attributes(expected, expected['attributes']), f'{path}: public attributes/forks')
    if path.parent.name == 'compression-writing':
        name = path.name
        force_compressed = name.startswith('size-') and expected['size'] > 1 or name in (
            'hardlink', 'mixed-blocks', 'attribute-edge-3300', 'attribute-edge-3900', 'independent-inline')
        if policy == 'zlib':
            require(bool(actual['flags'] & stat.UF_COMPRESSED) == force_compressed,
                    f'{path}: required compression or refusal control')
        if force_compressed and policy == 'zlib':
            kind = struct.unpack_from('<I', raw(path, compression.ATTRIBUTE), 4)[0]
            if name in ('attribute-edge-3300', 'independent-inline') or name.startswith('size-') and expected['size'] <= compression.BLOCK:
                require(kind == 3, f'{path}: required attribute storage')
            elif name != 'attribute-edge-3300':
                require(kind == 4, f'{path}: required resource storage')


def mutate(mount):
    """Native writes must remove stale storage and update every hard-link alias."""
    directory = mount / 'compression-writing'
    payload = b'Native write after portable compression.\n' * 4096
    path = directory / 'size-65537'
    path.write_bytes(payload)
    require((directory / 'hardlink').read_bytes() == payload, 'native compressed hard-link replacement')
    require(not path.stat().st_flags & stat.UF_COMPRESSED, 'native write clears compression')
    # Native decompression on write must preserve independent forks too.
    inline = directory / 'independent-inline'
    before = compression.xattr(inline, compression.RESOURCE)
    inline.write_bytes(payload)
    require(compression.xattr(inline, compression.RESOURCE) == before, 'native write retains independent fork')
    return payload


def verify_mutated(mount, payload):
    directory = mount / 'compression-writing'
    for name in ('size-65537', 'hardlink', 'independent-inline'):
        path = directory / name
        require(path.read_bytes() == payload and not path.stat().st_flags & stat.UF_COMPRESSED,
                f'{path}: native write survives remount')
    require(compression.xattr(directory / 'independent-inline', compression.RESOURCE) ==
            b'Independent fork must remain byte-exact.\x00\xff', 'independent fork survives remount')
