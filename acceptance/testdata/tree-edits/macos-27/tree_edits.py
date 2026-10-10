"""Native directory operations and file replacement, observed before and after.

Creation metadata is captured immediately after each native create. Portable
edits retain those supplied timestamps and existing objects' original timestamps.
"""
import errno
import json
import os
from datetime import datetime, timezone

import file_compression as compression
from content_replacement import observe


def create(root, command):
    root.mkdir()
    for name in ("Contents", "Contents/Resources", "move-dir", "empty-dir", "empty-target", "remove-dir"):
        (root / name).mkdir()
    for name in ("ordinary", "obsolete", "destination", "CaseName", "untouched", "move-dir/child"):
        (root / name).write_bytes(("Original " + name + "\n").encode())
    os.link(root / "ordinary", root / "alias")
    os.link(root / "destination", root / "destination-alias")
    compression.xattr(root / "ordinary", compression.RESOURCE, b"Independent fork\x00\xff" * 4097)
    compression.xattr(root / "ordinary", "org.go-apfs.keep", b"Ordinary opaque metadata")
    os.symlink("Contents", root / "directory-link")
    data = compression.plain(1200)
    compression.install(root / "compressed", 3, data, payload=compression.encode(3, data))
    os.link(root / "compressed", root / "compressed-alias")


def metadata(p):
    s = p.lstat()
    def timestamp(ns):
        seconds, fraction = divmod(ns, 10**9)
        return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"
    values = {"mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid, "bsdFlags": s.st_flags,
              "birthTime": timestamp(int(s.st_birthtime) * 10**9), "modifyTime": timestamp(s.st_mtime_ns),
              "changeTime": timestamp(s.st_ctime_ns), "accessTime": timestamp(s.st_atime_ns)}
    return {k: {"state": 2, "value": v} for k, v in values.items()}


def operate(root, op, corpus):
    p = root / op["path"]
    action = op["op"]
    if action == "mkdir":
        p.mkdir(mode=0o751)
        os.chmod(p, 0o751)
    elif action == "create":
        with p.open("xb") as f:
            f.write((corpus / op["data"]).read_bytes())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(p, 0o640)
    elif action == "symlink":
        os.symlink(op["target"], p)
    elif action == "link":
        os.link(root / op["from"], p)
    elif action == "rename":
        os.rename(p, root / op["to"])
    elif action == "remove":
        if p.is_dir() and not p.is_symlink():
            p.rmdir()
        else:
            p.unlink()
    elif action == "replace":
        with p.open("wb") as f:
            f.write((corpus / op["data"]).read_bytes())
            f.flush()
            os.fsync(f.fileno())
    else:
        raise ValueError(action)


def capture_after(scratch, corpus, case_id, attach, command, observe_files, native_xattrs, sha256):
    payload = corpus / (case_id + "-contents.bin")
    payload.write_bytes(b"New application content\x00\xff\n" * 37)
    operations = [
        {"op": "mkdir", "path": "Contents/_CodeSignature"},
        {"op": "create", "path": "Contents/_CodeSignature/CodeResources", "data": payload.name},
        {"op": "create", "path": "Contents/Resources/caf\u00e9", "data": payload.name},
        {"op": "create", "path": "CON", "data": payload.name},
        {"op": "symlink", "path": "Contents/Resources/current", "target": "caf\u00e9"},
        {"op": "link", "from": "ordinary", "path": "Contents/Resources/shared"},
        {"op": "link", "from": "ordinary", "path": "ordinary-new"},
        {"op": "link", "from": "Contents/_CodeSignature/CodeResources", "path": "Contents/Resources/seal-alias"},
        {"op": "remove", "path": "alias"},
        {"op": "rename", "path": "CaseName", "to": "casename"},
        {"op": "rename", "path": "move-dir", "to": "Contents/Moved"},
        {"op": "rename", "path": "ordinary", "to": "destination"},
        # Native rename between two existing names of the SAME inode is a no-op.
        {"op": "rename", "path": "destination", "to": "ordinary-new"},
        {"op": "rename", "path": "empty-dir", "to": "empty-target"},
        {"op": "remove", "path": "remove-dir"},
        {"op": "remove", "path": "obsolete"},
        {"op": "rename", "path": "compressed", "to": "Contents/Resources/compressed"},
        {"op": "replace", "path": "compressed-alias", "data": payload.name},
    ]
    rejections = [
        {"op": "create", "path": "destination", "data": payload.name},
        {"op": "create", "path": "Contents/Resources/cafe\u0301", "data": payload.name},
        {"op": "remove", "path": "Contents"},
        {"op": "rename", "path": "Contents", "to": "Contents/Resources/cycle"},
        {"op": "rename", "path": "Contents", "to": "destination"},
        {"op": "rename", "path": "destination", "to": "Contents"},
        {"op": "rename", "path": "missing", "to": "new-name"},
        {"op": "link", "from": "Contents", "path": "directory-hardlink"},
    ]
    probes = []
    device, mount = attach(scratch)
    try:
        root = mount / "Fixture"
        for index, op in enumerate(operations):
            operate(root, op, corpus)
            if op["op"] in ("create", "mkdir", "symlink"):
                op["metadata"] = metadata(root / op["path"])
                op["nativeObject"] = (root / op["path"]).lstat().st_ino
                op["attributes"] = []
                for name, value in native_xattrs(root / op["path"], 0x21).items():
                    blob = corpus / f"{case_id}-create-{index}-attribute-{len(op['attributes'])}.bin"
                    blob.write_bytes(value)
                    op["attributes"].append({"name": name, "data": blob.name, "sha256": sha256(blob)})
        for op in rejections:
            try:
                operate(root, op, corpus)
            except OSError as e:
                op["errno"] = e.errno
            else:
                raise RuntimeError(f"native rejection unexpectedly succeeded: {op}")
        for name in ("a" * 255, "a" * 256, "\u00e9" * 127, "\u00e9" * 255, "\U0001f600" * 255, "\U0001f600" * 128):
            op = {"op": "create", "path": name, "data": payload.name}
            try:
                operate(root, op, corpus)
            except OSError as e:
                if e.errno != errno.ENAMETOOLONG:
                    raise
                op["errno"] = e.errno
            else:
                op["metadata"] = metadata(root / name)
                op["attributes"] = []
                for key, value in native_xattrs(root / name, 0x21).items():
                    blob = corpus / f"{case_id}-name-{len(probes)}-attribute-{len(op['attributes'])}.bin"
                    blob.write_bytes(value)
                    op["attributes"].append({"name": key, "data": blob.name, "sha256": sha256(blob)})
                op["stored"] = next(p.name for p in root.iterdir() if p.lstat().st_ino == (root / name).stat().st_ino)
                (root / name).unlink()
            probes.append(op)
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
        raise RuntimeError("native readback changed edited image")
    command("hdiutil", "verify", image)
    files = corpus / (case_id + "-after-files.json")
    files.write_text(json.dumps(after, indent=2) + "\n")
    return {"operations": operations, "rejections": rejections, "nameProbes": probes,
            "after": files.name, "afterSHA256": sha256(files), "image": image.name, "imageSHA256": digest,
            "payload": payload.name, "payloadSHA256": sha256(payload)}
