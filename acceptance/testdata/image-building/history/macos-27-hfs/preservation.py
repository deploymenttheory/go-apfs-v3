"""Native extraction references and Apple copyfile serialization controls.

Production Go is never used for capture. AppleDouble expected application results
come from Apple's own pack/unpack pair, independently of the portable codec.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def create(root, command, sensitive, create_files):
    create_files(root, command)
    for name in ("._ordinary", "CON", "con.txt", "trailing.", "a:b", "a\\b",
                 "line\nbreak", "caf\u00e9", "~encoded", "metadata", "blobs", "files", "L" * 240):
        (root / name).write_bytes(("ordinary source file: " + name + "\n").encode())
    (root / "case-pair").mkdir()
    (root / "case-pair" / "Name").write_bytes(b"upper spelling\n")
    if sensitive:
        (root / "case-pair" / "name").write_bytes(b"distinct lower spelling\n")
    os.link(root / "example.txt", root / "hard-alias")
    os.link(root / "example.txt", root / "many" / "hard-alias")
    os.symlink("/outside/this-workspace", root / "absolute-link")
    os.symlink("../../outside", root / "parent-link")
    command("xattr", "-w", "org.go-apfs.root", "root metadata", root)
    command("xattr", "-wx", "com.apple.FinderInfo", (b"TEXTttxt" + bytes(24)).hex(), root / "example.txt")
    for name, data in (("org.go-apfs.Mixed", "upper"), ("org.go-apfs.mixed", "lower")):
        command("xattr", "-w", name, data, root / "example.txt")
    plain = root.parent / "compression-input"
    plain.write_bytes(b"Native compressed extraction contents.\n" * 8192)
    command("ditto", "--hfsCompression", "--noclone", plain, root / "compressed")
    if not (root / "compressed").stat().st_flags & stat.UF_COMPRESSED:
        raise RuntimeError("native extraction compression precondition failed")


def digest_values(values):
    return {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in values.items()}


def observe(root, observe_files, native_xattrs, work, corpus, case_id, command, sha256):
    observation = observe_files(root)
    raw = []
    for entry in observation["entries"]:
        path = root.parent / entry["path"]
        raw.append({"object": entry["object"], "attributes": digest_values(native_xattrs(path, 0x21))})
    helper = Path(__file__).resolve()
    controls = []
    for name in ("example.txt", "empty", "binary.bin"):
        packed = corpus / (case_id + "-" + name + ".appledouble")
        command(sys.executable, helper, "pack", root / name, packed)
        restored = work / (case_id + "-unpacked-" + name)
        restored.write_bytes(b"independent native unpack destination\n")
        command(sys.executable, helper, "unpack", packed, restored)
        controls.append({"path": "Fixture/" + name, "file": packed.name,
                         "sha256": sha256(packed),
                         "unpackedAttributes": digest_values(native_xattrs(restored))})
    observation["preservation"] = {"rawAttributes": raw, "appleDouble": controls}
    return observation


def copyfile(operation, source, destination):
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.copyfile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
    lib.copyfile.restype = ctypes.c_int
    # COPYFILE_ALL with COPYFILE_PACK/UNPACK and NOFOLLOW source/destination.
    flags = 15 | (1 << (22 if operation == "pack" else 23)) | (1 << 18) | (1 << 19)
    result = lib.copyfile(os.fsencode(source), os.fsencode(destination), None, flags)
    if result:
        raise OSError(ctypes.get_errno(), "native copyfile " + operation)
    return {"operation": operation, "flags": flags, "status": result}


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("pack", "unpack"):
        raise ValueError("expected pack|unpack SOURCE DESTINATION")
    print(json.dumps(copyfile(*sys.argv[1:])))
