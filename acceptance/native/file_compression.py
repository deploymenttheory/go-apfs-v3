"""Independent decmpfs fixtures: Apple codec output, native filesystem reads.

No Go code is invoked. The format recipe installs codec output, then the final
read-only mount supplies the expected bytes, metadata and raw stored attributes.
"""

import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import zlib


ATTRIBUTE = "com.apple.decmpfs"
RESOURCE = "com.apple.ResourceFork"
BLOCK = 65536
KINDS = (1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
ALGORITHMS = {3: 0x205, 11: 0x801, 13: 0x702, 15: 0x100}


def xattr(path, name, data=None):
    """XATTR_SHOWCOMPRESSION exposes storage hidden by ordinary getxattr."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    p, n = os.fsencode(path), name.encode()
    if data is not None:
        lib.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        result = lib.setxattr(p, n, data, len(data), 0, 0x21)
    else:
        lib.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        lib.getxattr.restype = ctypes.c_ssize_t
        size = lib.getxattr(p, n, None, 0, 0, 0x21)
        if size < 0:
            raise OSError(ctypes.get_errno(), name, path)
        buffer = ctypes.create_string_buffer(size)
        result = lib.getxattr(p, n, buffer, size, 0, 0x21)
    if result < 0:
        raise OSError(ctypes.get_errno(), name, path)
    return None if data is not None else buffer.raw[:result]


def codec(data, algorithm, decode_size=None):
    lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
    function = lib.compression_encode_buffer if decode_size is None else lib.compression_decode_buffer
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                         ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    function.restype = ctypes.c_size_t
    capacity = len(data) * 2 + 4096 if decode_size is None else decode_size + 1
    output = ctypes.create_string_buffer(capacity)
    size = function(output, capacity, data, len(data), None, algorithm)
    if not size:
        raise RuntimeError(f"Apple codec {algorithm:#x} failed")
    return output.raw[:size]


def plain(size):
    pattern = bytes(range(256)) + b"Native compressed filesystem evidence.\n" * 17
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def writing_inputs(root):
    """Ordinary native files qualify new compression, without a Go recipe."""
    directory = root / 'compression-writing'
    directory.mkdir()
    for size in (0, 1, 3801, 3802, 65535, 65536, 65537, BLOCK * 3 + 17, BLOCK * 32 + 17):
        (directory / f'size-{size}').write_bytes(plain(size))
    random = b''.join(hashlib.sha256(struct.pack('<I', i)).digest() for i in range(BLOCK // 32))
    (directory / 'incompressible').write_bytes(random)
    (directory / 'mixed-blocks').write_bytes(plain(BLOCK) + random + plain(17))
    # These straddle attribute capacity with different amounts of random data.
    for count in (3300, 3900):
        (directory / f'attribute-edge-{count}').write_bytes(random[:count] + bytes(BLOCK - count))
    for name, data in (('independent-inline', plain(1200)), ('independent-resource', plain(BLOCK + 17))):
        path = directory / name
        path.write_bytes(data)
        xattr(path, RESOURCE, b'Independent fork must remain byte-exact.\x00\xff')
        xattr(path, 'org.go-apfs.compression-writing', b'Ordinary attribute retained.')
    inactive = directory / 'inactive-decmpfs'
    inactive.write_bytes(plain(BLOCK + 17))
    xattr(inactive, ATTRIBUTE, b'Inactive opaque metadata must remain unchanged.')
    os.link(directory / 'size-65537', directory / 'hardlink')


def stored(kind, data):
    return bytes([0xcc if kind in (9, 10) else 6 if kind in (7, 8) else 0xff]) + data


def encode(kind, data):
    if kind == 1:
        return data
    if kind in (9, 10):
        return stored(kind, data)
    algorithm = ALGORITHMS[kind if kind & 1 else kind - 1]
    result = codec(data, algorithm)
    if codec(result, algorithm, len(data)) != data:
        raise RuntimeError("native codec readback differs")
    # COMPRESSION_ZLIB produces raw DEFLATE. decmpfs prefixes the zlib header.
    return b"\x78\x5e" + result if kind in (3, 4) else result


def resource(kind, blocks, gaps=False):
    if kind != 4:
        offset = (len(blocks) + 1) * 4
        offsets = [offset]
        for block in blocks:
            offsets.append(offsets[-1] + len(block))
        return struct.pack("<" + "I" * len(offsets), *offsets) + b"".join(blocks)
    # A Resource Manager data area containing one cmpf resource. Descriptor
    # offsets are relative to the block count, and each has an explicit length.
    offset = 4 + len(blocks) * 8
    descriptors = []
    body = []
    for block in blocks:
        descriptors.append(struct.pack("<II", offset, len(block)))
        offset += len(block)
        body.append(block)
        if gaps:
            body.append(b"Unused resource data.")
            offset += len(body[-1])
    data = struct.pack("<I", len(blocks)) + b"".join(descriptors) + b"".join(body)
    mapping = bytes(24) + struct.pack(">HHH4sHHHHII", 28, 50, 0, b"cmpf", 0, 10, 1, 0xffff, 0, 0)
    header = struct.pack(">IIII", 256, 260 + len(data), len(data) + 4, len(mapping))
    return header + bytes(240) + struct.pack(">I", len(data)) + data + mapping


def install(path, kind, data, payload=None, blocks=None, gaps=False):
    path.touch()
    if path.name == "type-03":
        xattr(path, RESOURCE, b"Independent resource fork.\x00\xff")
        os.chmod(path, 0o751)
        xattr(path, "org.go-apfs.compressed", b"Preserved metadata")
    header = struct.pack("<IIQ", 0x636d7066, kind, len(data))
    if blocks is not None:
        xattr(path, RESOURCE, resource(kind, blocks, gaps))
    else:
        header += payload
    xattr(path, ATTRIBUTE, header)
    os.chflags(path, stat.UF_COMPRESSED)


def create(root, command):
    root.mkdir()
    writing_inputs(root)
    # ditto is the native filesystem producer for LZVN, whose public buffer API
    # has no algorithm constant. Preserve its complete output as its own case.
    source = root.parent / "compression-source"
    source.write_bytes(plain(BLOCK * 3 + 17))
    command("ditto", "--hfsCompression", "--noclone", source, root / "native-ditto")
    source.unlink()
    header = xattr(root / "native-ditto", ATTRIBUTE)
    if struct.unpack_from("<I", header, 4)[0] != 8:
        raise RuntimeError("ditto fixture must exercise native LZVN resource storage")
    raw = xattr(root / "native-ditto", RESOURCE)
    start, end = struct.unpack_from("<II", raw)
    lzvn_block = raw[start:end]
    for kind in KINDS:
        inline = kind == 1 or kind & 1
        data = plain(1200 if inline else BLOCK * 3 + 17)
        if kind == 7:
            # A native LZFSE small-input stream wraps a raw LZVN payload.
            framed = codec(data, 0x801)
            if framed[:4] != b"bvxn" or codec(framed, 0x801, len(data)) != data:
                raise RuntimeError("native small LZFSE fixture must contain LZVN")
            size = struct.unpack_from("<I", framed, 8)[0]
            payload = framed[12:12 + size]
        elif inline:
            payload = encode(kind, data)
        else:
            blocks = []
            for i in range(0, len(data), BLOCK):
                block = data[i:i + BLOCK]
                # The first native ditto block corresponds exactly to plain(BLOCK).
                blocks.append(lzvn_block if kind == 8 and i == 0 else
                              stored(kind, block) if kind in (8, 10) or i == BLOCK else
                              encode(kind, block))
        install(root / f"type-{kind:02d}", kind, data,
                payload=payload if inline else None, blocks=None if inline else blocks)
    for kind in (3, 7, 9, 11, 13, 15):
        install(root / f"stored-{kind:02d}", kind, plain(73), payload=stored(kind, plain(73)))
    rejected = root.parent / "RejectedCompression"
    rejected.mkdir()
    install(rejected / "lzfse-marker-zero", 11, plain(73), payload=b"\x00" + plain(73))
    data = plain(1200)
    install(root / "zlib-checksum", 3, data, payload=encode(3, data) + struct.pack(">I", zlib.adler32(data)))
    data = plain(BLOCK * 3 + 17)
    install(root / "zlib-gaps", 4, data,
            blocks=[encode(4, data[i:i + BLOCK]) for i in range(0, len(data), BLOCK)], gaps=True)
    install(root / "empty", 1, b"", payload=b"")
    os.link(root / "type-04", root / "hardlink")
    for label, attribute in [("valid", struct.pack("<IIQ", 0x636d7066, 9, 99) + b"\xccstale"),
                             ("malformed", b"not a compression header")]:
        path = root / ("inactive-" + label)
        path.write_bytes(b"The ordinary data fork is authoritative.\n")
        xattr(path, ATTRIBUTE, attribute)


def observe(root, observe_files, major):
    details = []

    def read(path):
        raw = xattr(path, ATTRIBUTE)
        active = bool(path.lstat().st_flags & stat.UF_COMPRESSED)
        result = {}
        attributes = {ATTRIBUTE: raw}
        if active:
            _, kind, size = struct.unpack_from("<IIQ", raw)
            storage = "attribute" if kind == 1 or kind & 1 else "resource-fork"
            if storage == "resource-fork" or path.name == "type-03":
                attributes[RESOURCE] = xattr(path, RESOURCE)
            expected = plain(size)
            # Decode the actual final stored bytes through Apple's public codec,
            # independently of both the fixture input and Go's interpretation.
            decoded = decode_storage(kind, size, raw[16:], attributes.get(RESOURCE))
            if decoded != expected:
                raise RuntimeError(f"native codec read differs: {path}")
            error = 0
            try:
                data = path.read_bytes()
            except OSError as failure:
                # Kernel registration and public codec availability are distinct.
                if kind not in (15, 16) or major >= 27 or failure.errno != errno.EIO:
                    raise
                error = failure.errno
                data = decoded
            if data != expected:
                raise RuntimeError(f"native read differs: {path}")
            details.append({"path": path.relative_to(root.parent).as_posix(), "type": kind,
                            "storage": storage, "nativeReadError": error,
                            "codecSHA256": hashlib.sha256(decoded).hexdigest(),
                            "samples": [{"offset": off, "hex": data[off:off + 37].hex()}
                                        for off in sorted(set([0, min(65519, size), max(0, size - 23)]))]})
        else:
            data = path.read_bytes()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["attributes"] = {name: {"size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                for name, value in attributes.items()}
        return result

    result = observe_files(root, read)
    result["compression"] = details
    # A malformed active file must not become successful empty data in Go, even
    # when the kernel returns premature EOF instead of a useful error code.
    path = root.parent / "RejectedCompression" / "lzfse-marker-zero"
    info = path.stat()
    error = 0
    try:
        rejected_data = path.read_bytes()
    except OSError as failure:
        error = failure.errno
        rejected_data = b""
    if info.st_size != 73 or not info.st_flags & stat.UF_COMPRESSED or rejected_data or error not in (0, errno.EIO, errno.EINVAL):
        raise RuntimeError("native malformed LZFSE control changed behavior")
    raw = xattr(path, ATTRIBUTE)
    result["compressionRejections"] = [{"path": "RejectedCompression/lzfse-marker-zero",
        "size": info.st_size, "flags": info.st_flags, "readSize": len(rejected_data),
        "readError": error, "attribute": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}]
    return result


def decode_storage(kind, size, inline, fork):
    def block(payload, length):
        if kind == 1:
            return payload
        marker = payload[0]
        if (kind in (3, 4, 13, 14, 15, 16) and marker == 0xff or
                kind in (7, 8) and marker == 6 or kind in (9, 10) and marker == 0xcc or
                kind in (11, 12) and marker == 0xff):
            return payload[1:]
        if kind in (7, 8):
            frame = struct.pack("<4sII", b"bvxn", length, len(payload)) + payload + b"bvx$"
            return codec(frame, 0x801, length)
        algorithm = ALGORITHMS[kind if kind & 1 else kind - 1]
        return codec(payload[2:] if kind in (3, 4) else payload, algorithm, length)

    if kind == 1 or kind & 1:
        return block(inline, size)
    result = []
    for i in range((size + BLOCK - 1) // BLOCK):
        if kind == 4:
            offset, length = struct.unpack_from("<II", fork, 264 + i * 8)
            payload = fork[260 + offset:260 + offset + length]
        else:
            start, end = struct.unpack_from("<II", fork, i * 4)
            payload = fork[start:end]
        decoded = block(payload, min(BLOCK, size - i * BLOCK))
        result.append(decoded)
    return b"".join(result)
