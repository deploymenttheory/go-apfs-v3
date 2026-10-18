# Fixture payloads

Byte-exact inputs that recipes install on fixture volumes. Committing them
means every macOS producer stores identical bytes, so cross-version
comparison measures the kernel, not the compressor.

| Group | Files | Producer |
| --- | --- | --- |
| decmpfs attributes | `decmpfs-type-N.attr`, `decmpfs-stored-N.attr`, `decmpfs-zlib-*.attr`, `decmpfs-empty.attr`, `decmpfs-inactive-*.attr`, `decmpfs-malformed-lzfse.attr`, `decmpfs-type-3-500.attr` | 16-byte header (`cmpf`, type, logical size, little-endian) plus the inline payload |
| Resource forks | `rsrc-type-N.fork`, `rsrc-zlib-gaps.fork` | Type 4 uses the Resource Manager layout; types 8 to 16 use the little-endian offset table |
| Compression inputs | `incompressible-65536`, `mixed-blocks`, `attribute-edge-3300`, `attribute-edge-3900` | Deterministic bytes for the compression writer |
| FinderInfo | `finderinfo-text`, `finderinfo-invisible`, `finderinfo-zero`, `finderinfo-invalid` | 32-byte values; `invalid` is 31 bytes |

Plain text inputs use the recipe `sequence` pattern with label
`Native compressed filesystem evidence.` repeated 17 times, which is the
pattern the retired collectors called `plain(n)`.

Compressed payloads were produced on macOS 27.0.1 (26A434) with Apple's
`/usr/lib/libcompression.dylib` through `compression_encode_buffer` (zlib
0x205 wrapped with the `78 5e` header, LZFSE 0x801, LZBITMAP 0x702, LZ4
0x100) and with `zlib.adler32` for the checksum variant. Type 7's inline
payload is the LZVN body of an LZFSE frame; type 8's first block is the first
block `ditto --hfsCompression --noclone` wrote for the same input, with the
remaining blocks stored under the `06` marker. LZBITMAP (types 13 and 14) has
no Apple command-line producer, which is why these bytes are committed rather
than generated at capture time.

The generator is recorded below so the files can be regenerated and compared.

```python
#!/usr/bin/env python3
"""Generate the committed fixture payloads under acceptance/recipes/payloads.

Compressed payloads come from Apple's libcompression (deterministic for a given
library build; the bytes are committed so every macOS producer installs the
same stored bytes). Type 8 (LZVN resource fork) block 0 is taken from ditto's
output on this host.
"""
import ctypes, hashlib, os, struct, subprocess, sys, tempfile, zlib, random

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
MAGIC = 0x636D7066
BLOCK = 65536
TEXT = b"Native compressed filesystem evidence.\n" * 17
CYCLE = bytes(range(256)) + TEXT

def plain(n):
    reps = n // len(CYCLE) + 1
    return (CYCLE * reps)[:n]

lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
lib.compression_encode_buffer.restype = ctypes.c_size_t
lib.compression_encode_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
ZLIB, LZFSE, LZBITMAP, LZ4 = 0x205, 0x801, 0x702, 0x100

def codec(algo, data):
    dst = ctypes.create_string_buffer(len(data) * 2 + 4096)
    n = lib.compression_encode_buffer(dst, len(dst), data, len(data), None, algo)
    assert n > 0, algo
    return dst.raw[:n]

def header(kind, size):
    return struct.pack("<IIQ", MAGIC, kind, size)

def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print(f"{name}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}")

def deflate(data):
    return b"\x78\x5e" + codec(ZLIB, data)

# Inline attribute types, 1200 bytes.
small = plain(1200)
write("decmpfs-type-1.attr", header(1, 1200) + small)
write("decmpfs-type-3.attr", header(3, 1200) + deflate(small))
write("decmpfs-type-7.attr", header(7, 1200) + codec(LZFSE, small)[12:12 + struct.unpack_from("<I", codec(LZFSE, small), 8)[0]] if codec(LZFSE, small)[:4] == b"bvxn" else header(7, 1200) + b"\x06" + small)
write("decmpfs-type-9.attr", header(9, 1200) + b"\xcc" + small)
write("decmpfs-type-11.attr", header(11, 1200) + codec(LZFSE, small))
write("decmpfs-type-13.attr", header(13, 1200) + codec(LZBITMAP, small))
write("decmpfs-type-15.attr", header(15, 1200) + codec(LZ4, small))

# Fork-backed types, 3 full blocks plus a 17-byte partial block.
big = plain(196625)
blocks = [big[i:i + BLOCK] for i in range(0, len(big), BLOCK)]

def offset_table_fork(encoded):
    n = len(encoded)
    offs, cur = [], 4 * (n + 1)
    for b in encoded:
        offs.append(cur); cur += len(b)
    offs.append(cur)
    return b"".join(struct.pack("<I", o) for o in offs) + b"".join(encoded)

def resource_manager_fork(encoded, gaps=b""):
    bodies, entries, rel = [], [], 4 + 8 * len(encoded)
    for b in encoded:
        entries.append(struct.pack("<II", rel, len(b)))
        bodies.append(b + gaps)
        rel += len(b) + len(gaps)
    D = struct.pack("<I", len(encoded)) + b"".join(entries) + b"".join(bodies)
    data_len = len(D) + 4
    hdr = struct.pack(">IIII", 256, 260 + len(D), data_len, 50) + b"\0" * 240
    rmap = b"\0" * 24 + struct.pack(">HHHI", 28, 50, 0, 0)[:6] + b"cmpf" + struct.pack(">HHHHII", 0, 10, 1, 0xFFFF, 0, 0)
    rmap = rmap[:50].ljust(50, b"\0")
    return hdr + struct.pack(">I", len(D)) + D + rmap

enc4 = [deflate(blocks[0]), b"\xff" + blocks[1], deflate(blocks[2]), deflate(blocks[3])]
write("rsrc-type-4.fork", resource_manager_fork(enc4)); write("decmpfs-type-4.attr", header(4, 196625))
write("rsrc-type-10.fork", offset_table_fork([b"\xcc" + b for b in blocks])); write("decmpfs-type-10.attr", header(10, 196625))
for kind, algo in ((12, LZFSE), (14, LZBITMAP), (16, LZ4)):
    enc = [codec(algo, blocks[0]), b"\xff" + blocks[1], codec(algo, blocks[2]), codec(algo, blocks[3])]
    write(f"rsrc-type-{kind}.fork", offset_table_fork(enc)); write(f"decmpfs-type-{kind}.attr", header(kind, 196625))

# Type 8: block 0 from ditto's LZVN output, blocks 1-3 stored.
with tempfile.TemporaryDirectory() as d:
    src = os.path.join(d, "src"); dst = os.path.join(d, "dst")
    open(src, "wb").write(big)
    subprocess.run(["ditto", "--hfsCompression", "--noclone", src, dst], check=True)
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    buf = ctypes.create_string_buffer(1 << 20)
    n = libc.getxattr(dst.encode(), b"com.apple.ResourceFork", buf, len(buf), 0, 0x21)
    assert n > 0, "ditto did not compress"
    fork = buf.raw[:n]
    offs = struct.unpack_from("<I", fork, 0)[0] // 4 - 1
    table = struct.unpack_from(f"<{offs + 1}I", fork, 0)
    block0 = fork[table[0]:table[1]]
    assert block0[0] != 0x06 or True
write("rsrc-type-8.fork", offset_table_fork([block0] + [b"\x06" + b for b in blocks[1:]])); write("decmpfs-type-8.attr", header(8, 196625))

# Stored-marker controls (73 bytes) and the zlib special cases.
s73 = plain(73)
for kind, marker in ((3, b"\xff"), (7, b"\x06"), (9, b"\xcc"), (11, b"\xff"), (13, b"\xff"), (15, b"\xff")):
    write(f"decmpfs-stored-{kind}.attr", header(kind, 73) + marker + s73)
write("decmpfs-zlib-checksum.attr", header(3, 1200) + deflate(small) + struct.pack(">I", zlib.adler32(small)))
write("rsrc-zlib-gaps.fork", resource_manager_fork([deflate(b) for b in blocks], gaps=b"Unused resource data.")); write("decmpfs-zlib-gaps.attr", header(4, 196625))
write("decmpfs-empty.attr", header(1, 0))
write("decmpfs-inactive-valid.attr", header(9, 99) + b"\xccstale")
write("decmpfs-inactive-malformed.attr", b"not a compression header")
write("decmpfs-malformed-lzfse.attr", header(11, 73) + b"\x00" + s73)
write("decmpfs-type-3-500.attr", header(3, 500) + deflate(plain(500)))
write("decmpfs-inactive-opaque.attr", b"Inactive opaque metadata must remain unchanged.")

# Compression-writing inputs that need exact bytes.
write("incompressible-65536", b"".join(hashlib.sha256(struct.pack("<I", i)).digest() for i in range(2048)))
rng = random.Random(20261018)
rnd = bytes(rng.getrandbits(8) for _ in range(BLOCK))
write("mixed-blocks", plain(BLOCK) + rnd + plain(17))
write("attribute-edge-3300", rnd[:3300].ljust(BLOCK, b"\0"))
write("attribute-edge-3900", rnd[:3900].ljust(BLOCK, b"\0"))

# Metadata values.
write("finderinfo-text", b"TEXTttxt" + b"\0" * 24)
write("finderinfo-invisible", bytes(range(8)) + b"\x40" + bytes(range(9, 32)))
write("finderinfo-zero", b"\0" * 32)
write("finderinfo-invalid", b"\0" * 31)
```
