"""Native content replacement: truncate/write existing inodes, then observe.

Reference data comes from final read-only mounts of before/after Apple images.
The portable operation preserves source timestamps; native write times are also
recorded, but are not substituted for that explicit preservation policy.
"""
import json
import os
from pathlib import Path
import stat
import struct

import file_compression as compression
from preservation import digest_values

# Seven operations cover aliases, growth, shrinkage, empty data, mapped names,
# inline compression with an independent fork, and compression-owned resource data.
PAYLOADS = (
    ("alias", b"Replaced through a hard-link alias.\x00\xff\n" * 4097),
    ("empty", b"An empty file now has data.\n"),
    ("type-03", bytes(range(256)) * 513 + b"inline replacement"),
    ("type-04", b""),
    ("native-ditto", b"short replacement\n"),
    ("inactive", b"Inactive compression remains opaque.\n"),
    ("CON", b"Replaced using the original macOS name.\n"),
)


def create(root, command):
    root.mkdir()
    (root / "links").mkdir()
    ordinary = root / "ordinary"
    ordinary.write_bytes(b"Original ordinary file.\n")
    compression.xattr(ordinary, compression.RESOURCE, b"Independent ordinary fork.\x00\xff" * 1025)
    compression.xattr(ordinary, "com.apple.FinderInfo", b"TEXTttxt" + bytes(24))
    os.link(ordinary, root / "alias")
    os.link(ordinary, root / "links/second")
    for name in ("empty", "CON", "untouched", "inactive"):
        (root / name).write_bytes(b"" if name == "empty" else b"Original " + name.encode() + b"\n")
    compression.xattr(root / "inactive", compression.ATTRIBUTE, b"inactive malformed bytes")
    compression.xattr(root / "inactive", compression.RESOURCE, b"Independent inactive fork")
    os.symlink("ordinary", root / "link")
    data = compression.plain(1200)
    # This helper installs the independent resource fork before UF_COMPRESSED.
    # Writing that fork after compression would first decompress the file.
    compression.install(root / "type-03", 3, data, payload=compression.encode(3, data))
    data = compression.plain(65536 + 17)
    compression.install(root / "type-04", 4, data,
                        blocks=[compression.encode(4, data[i:i+65536]) for i in range(0, len(data), 65536)])
    os.link(root / "type-04", root / "compressed-alias")
    plain = root.parent / "replacement-compression-input"
    plain.write_bytes(b"Native compressed replacement reference.\n" * 8192)
    command("ditto", "--hfsCompression", "--noclone", plain, root / "native-ditto")
    for name in ("ordinary", "type-03", "type-04", "native-ditto", "CON"):
        p = root / name
        os.chmod(p, 0o751)
        compression.xattr(p, "org.go-apfs.keep", b"Preserved ordinary attribute.\x00\xff")
        compression.xattr(p, "org.go-apfs.empty", b"")
        os.chflags(p, p.stat().st_flags | stat.UF_HIDDEN)
    for name, kind in (("type-03", 3), ("type-04", 4), ("native-ditto", 8)):
        p = root / name
        raw = compression.xattr(p, compression.ATTRIBUTE)
        if not p.stat().st_flags & stat.UF_COMPRESSED or struct.unpack_from("<I", raw, 4)[0] != kind:
            raise RuntimeError(f"missing native compressed replacement precondition: {name}")


def observe(root, observe_files, native_xattrs):
    result = observe_files(root)
    result["rawAttributes"] = [
        {"object": entry["object"], "attributes": digest_values(native_xattrs(root.parent / entry["path"], 0x21))}
        for entry in result["entries"]]
    return result


def capture_after(scratch, corpus, case_id, attach, command, observe_files, native_xattrs, sha256):
    operations = []
    device, mount = attach(scratch)
    try:
        for index, (name, data) in enumerate(PAYLOADS):
            payload = corpus / f"{case_id}-replacement-{index}.bin"
            payload.write_bytes(data)
            target = mount / "Fixture" / name
            identity = target.stat().st_ino
            # Native O_TRUNC preserves this inode. Never use rename/unlink here.
            with target.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if target.stat().st_ino != identity:
                raise RuntimeError("native content write changed object identity")
            operations.append({"path": "Fixture/" + name, "object": identity,
                               "payload": payload.name, "sha256": sha256(payload), "size": len(data)})
    finally:
        command("hdiutil", "detach", device)
    image = corpus / (case_id + "-after.dmg")
    command("hdiutil", "convert", scratch, "-format", "UDZO", "-o", image)
    digest = sha256(image)
    device, mount = attach(image, readonly=True)
    try:
        after = observe(mount / "Fixture", observe_files, native_xattrs)
    finally:
        command("hdiutil", "detach", device)
    if sha256(image) != digest:
        raise RuntimeError("native readback changed replacement image")
    command("hdiutil", "verify", image)
    files = corpus / (case_id + "-after-files.json")
    files.write_text(json.dumps(after, indent=2) + "\n")
    return {"operations": operations, "after": files.name, "afterSHA256": sha256(files),
            "image": image.name, "imageSHA256": digest}
