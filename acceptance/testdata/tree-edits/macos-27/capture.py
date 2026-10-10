#!/usr/bin/env python3
"""Create independent native volume-inspection cases. Never invokes v3.

Every command has a deadline. Completion is published only after images are
detached, hashed, and all cases have succeeded. An existing corpus is never
overwritten. Run on macOS; replay the resulting corpus on any supported host.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-major", type=int, choices=[15, 26, 27], required=True)
    parser.add_argument("--scenario", choices=["volume-inspection", "file-reading", "file-semantics", "file-compression", "file-encryption", "disk-image-encryption", "snapshot-reading", "preservation", "content-replacement", "tree-edits"], default="volume-inspection")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("native capture requires macOS")
    product = subprocess.check_output(["sw_vers", "-productVersion"], text=True, timeout=10).strip()
    build = subprocess.check_output(["sw_vers", "-buildVersion"], text=True, timeout=10).strip()
    if int(product.split(".")[0]) != args.expected_major:
        parser.error(f"expected macOS {args.expected_major}, received {product}")
    output = args.output.absolute()
    if output.exists():
        parser.error(f"refusing to replace existing corpus: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apfs-native-", dir=output.parent) as temporary:
        work = Path(temporary)
        corpus = work / "corpus"
        corpus.mkdir()
        commands = []

        def run_command(*argv, fixture_input=None, expected_success=True):
            display = [str(arg) if len(str(arg)) <= 256 else f"<{len(str(arg))} characters>" for arg in argv]
            print("native:", " ".join(display), flush=True)
            # Persist a start before invoking native code, including commands
            # that time out or fail to launch. A partial transcript is diagnostic.
            record = {"argv": list(map(str, argv)), "status": "started", "expectedSuccess": expected_success}
            if fixture_input is not None:
                record["publicFixtureInput"] = fixture_input.decode()
            commands.append(record)

            def save():
                text = json.dumps(commands, indent=2) + "\n"
                (corpus / "commands.json").write_text(text)
                output.with_suffix(".diagnostics.json").write_text(text)

            save()
            try:
                result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, input=fixture_input, timeout=120, check=False)
            except subprocess.TimeoutExpired as error:
                record.update(status="timeout", stdout=(error.stdout or b"").decode(errors="replace"),
                              stderr=(error.stderr or b"").decode(errors="replace"))
                save()
                raise
            except OSError as error:
                record.update(status="launch-failed", error=str(error))
                save()
                raise
            record.update(status=result.returncode, stdout=result.stdout.decode(errors="replace"),
                          stderr=result.stderr.decode(errors="replace"))
            save()
            if result.returncode != 0 and expected_success:
                print(result.stderr.decode(errors="replace"), file=sys.stderr, end="")
                raise subprocess.CalledProcessError(result.returncode, argv,
                                                    output=result.stdout, stderr=result.stderr)
            if result.returncode == 0 and not expected_success:
                raise RuntimeError(f"command failed: {argv}: {result.stderr.decode(errors='replace')}")
            return result.stdout

        def command(*argv, **kwargs):
            # DiskImages can briefly retain a disposable image after unmount.
            # Only detach's EBUSY is retried; every attempt is recorded above.
            for attempt in range(6):
                try:
                    return run_command(*argv, **kwargs)
                except subprocess.CalledProcessError as error:
                    if argv[:2] != ("hdiutil", "detach") or error.returncode != errno.EBUSY or attempt == 5:
                        raise
                    time.sleep(1)

        def attach(image, readonly=False):
            options = ["-readonly"] if readonly else []
            data = command("hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen",
                           "-owners", "on", *options, image)
            attached = plistlib.loads(data)
            entities = attached["system-entities"]
            devices = [e["dev-entry"] for e in entities if "dev-entry" in e]
            try:
                mounted = [e["mount-point"] for e in entities if "mount-point" in e]
                if not devices or len(mounted) != 1:
                    raise RuntimeError("expected exactly one native mounted volume")
                return devices[0], Path(mounted[0])
            except BaseException:
                if devices:
                    command("hdiutil", "detach", devices[0])
                raise

        if args.scenario == "file-compression":
            import file_compression as compression
        if args.scenario == "preservation":
            import preservation
        if args.scenario in ("content-replacement", "tree-edits"):
            import content_replacement
            edits = content_replacement
            if args.scenario == "tree-edits":
                import tree_edits
                edits = tree_edits

        if args.scenario == "file-encryption":
            import file_encryption
            cases = file_encryption.capture(work, corpus, command, create_files, observe_files, sha256)
        elif args.scenario == "disk-image-encryption":
            import disk_image_encryption
            cases = disk_image_encryption.capture(work, corpus, command, create_files, observe_files, sha256)
        elif args.scenario == "snapshot-reading":
            import snapshot_reading
            cases = snapshot_reading.capture(work, corpus, command, create_files, observe_files, sha256)
        else:
            cases = []
            profiles = [("apfs", "APFS", "APFS", False),
                        ("apfs-case-sensitive", "Case-sensitive APFS", "APFS", True),
                        ("hfsplus", "HFS+", "HFS+", False),
                        ("hfsx", "Case-sensitive HFS+", "HFSX", True)]
            for case_id, native_format, expected_format, sensitive in profiles:
                scratch = work / (case_id + "-writable.dmg")
                name = "v3-" + case_id
                command("hdiutil", "create", "-size", "64m", "-layout", "GPTSPUD",
                        "-fs", native_format, "-volname", name, "-type", "UDIF", scratch)
                device, mount = attach(scratch)
                try:
                    # Ordinary content creates real catalog/object-map entries. This
                    # scenario asserts volume inspection only, not file semantics.
                    (mount / "example.txt").write_bytes(b"Native Apple filesystem fixture.\n")
                    (mount / "directory").mkdir()
                    (mount / "directory" / "empty").touch()
                    os.symlink("example.txt", mount / "link")
                    if args.scenario == "file-reading":
                        create_files(mount / "Fixture", command)
                    if args.scenario == "file-semantics":
                        create_semantics(mount / "Fixture", command, expected_format != "APFS")
                    if args.scenario == "file-compression":
                        compression.create(mount / "Fixture", command)
                    if args.scenario in ("content-replacement", "tree-edits"):
                        edits.create(mount / "Fixture", command)
                    if args.scenario == "preservation":
                        preservation.create(mount / "Fixture", command, sensitive, create_files)
                finally:
                    command("hdiutil", "detach", device)
                image = corpus / (case_id + ".dmg")
                command("hdiutil", "convert", scratch, "-format", "UDZO", "-o", image)
                before = sha256(image)
                device, mount = attach(image, readonly=True)
                try:
                    raw = command("diskutil", "info", "-plist", mount)
                    native = plistlib.loads(raw)
                    raw_path = corpus / (case_id + "-diskutil.plist")
                    raw_path.write_bytes(raw)
                    if native["VolumeName"] != name:
                        raise RuntimeError("native volume name differs from fixture recipe")
                    personality = native["FilesystemName"].lower()
                    if ("case-sensitive" in personality) != sensitive:
                        raise RuntimeError(f"unexpected native case policy: {personality}")
                    native_kind = native["FilesystemType"]
                    if native_kind != ("apfs" if expected_format == "APFS" else "hfs"):
                        raise RuntimeError(f"unexpected native filesystem type: {native_kind}")
                    expected = {"filesystem": expected_format, "name": native["VolumeName"],
                                "caseSensitive": sensitive,
                                "blockSize": native["VolumeAllocationBlockSize"],
                                "size": native["TotalSize"]}
                    if expected_format == "APFS":
                        expected["uuid"] = native["VolumeUUID"].upper()
                    file_observation = None
                    if args.scenario in ("file-reading", "file-semantics", "file-compression", "preservation", "content-replacement", "tree-edits"):
                        file_observation = corpus / (case_id + "-files.json")
                        if args.scenario in ("content-replacement", "tree-edits"):
                            observation = edits.observe(mount / "Fixture", observe_files, native_xattrs)
                        elif args.scenario == "preservation":
                            observation = preservation.observe(mount / "Fixture", observe_files, native_xattrs,
                                                               work, corpus, case_id, command, sha256)
                        else:
                            observation = (compression.observe(mount / "Fixture", observe_files, args.expected_major)
                                           if args.scenario == "file-compression" else observe_files(mount / "Fixture"))
                        if args.scenario == "file-semantics":
                            observation.update(observe_semantics(mount / "Fixture", expected_format != "APFS"))
                        file_observation.write_text(json.dumps(observation, indent=2) + "\n")
                finally:
                    command("hdiutil", "detach", device)
                if sha256(image) != before:
                    raise RuntimeError("native read-only examination changed the image")
                command("hdiutil", "verify", image)
                case = {"id": args.scenario + "/" + case_id,
                              "image": image.name, "sha256": before,
                              "observation": raw_path.name,
                              "observationSHA256": sha256(raw_path), "expected": expected}
                if args.scenario in ("content-replacement", "tree-edits"):
                    key = "treeEdits" if args.scenario == "tree-edits" else "replacement"
                    observation[key] = edits.capture_after(
                        scratch, corpus, case_id, attach, command, observe_files, native_xattrs, sha256)
                    file_observation.write_text(json.dumps(observation, indent=2) + "\n")
                if file_observation:
                    case.update(files=file_observation.name, filesSHA256=sha256(file_observation))
                cases.append(case)
        script = corpus / "capture.py"
        shutil.copyfile(__file__, script)
        manifest = {"schema": 1, "scenario": args.scenario, "producer": {
            "system": "macOS", "version": product, "build": build,
            "architecture": platform.machine(), "source": "capture.py",
            "sourceSHA256": sha256(script)}, "cases": cases}
        if args.scenario == "file-compression":
            helper = corpus / "file_compression.py"
            shutil.copyfile(Path(__file__).with_name("file_compression.py"), helper)
            manifest["producer"]["sources"] = [{"source": helper.name, "sha256": sha256(helper)}]
        if args.scenario == "file-encryption":
            manifest["cryptography"] = "cryptography.json"
            manifest["cryptographySHA256"] = sha256(corpus / "cryptography.json")
            helper = corpus / "file_encryption.py"
            shutil.copyfile(Path(__file__).with_name(helper.name), helper)
            manifest["producer"]["sources"] = [{"source": helper.name, "sha256": sha256(helper)}]
        if args.scenario == "disk-image-encryption":
            helper = corpus / "disk_image_encryption.py"
            shutil.copyfile(Path(__file__).with_name(helper.name), helper)
            manifest["producer"]["sources"] = [{"source": helper.name, "sha256": sha256(helper)}]
        if args.scenario == "snapshot-reading":
            helper = corpus / "snapshot_reading.py"
            shutil.copyfile(Path(__file__).with_name(helper.name), helper)
            manifest["producer"]["sources"] = [{"source": helper.name, "sha256": sha256(helper)}]
        if args.scenario == "preservation":
            helper = corpus / "preservation.py"
            shutil.copyfile(Path(__file__).with_name(helper.name), helper)
            manifest["producer"]["sources"] = [{"source": helper.name, "sha256": sha256(helper)}]
        if args.scenario in ("content-replacement", "tree-edits"):
            manifest["producer"]["sources"] = []
            helpers = ["content_replacement.py", "file_compression.py", "preservation.py"]
            if args.scenario == "tree-edits":
                helpers.append("tree_edits.py")
            for name in helpers:
                helper = corpus / name
                shutil.copyfile(Path(__file__).with_name(name), helper)
                manifest["producer"]["sources"].append({"source": name, "sha256": sha256(helper)})
        (corpus / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # This directory is visible at its final path only after complete capture.
        corpus.rename(output)
    print(f"Complete native corpus: {output}")


def create_files(root, command):
    """A bounded recipe with enough entries to force multi-node native trees."""
    root.mkdir()
    (root / "example.txt").write_bytes(b"Native Apple filesystem fixture.\n")
    (root / "empty").touch()
    (root / "binary.bin").write_bytes(bytes(range(256)) * 512 + b"\x00")
    (root / "caf\u00e9-\u03bb-\U0001f600.txt").write_bytes(b"Unicode names survive enumeration.\n")
    os.symlink("example.txt", root / "link")
    os.symlink("absent", root / "dangling-link")
    with open(root / "sparse", "wb") as stream:
        stream.write(b"start")
        stream.seek(2 * 1024 * 1024 + 7)
        stream.write(b"end")
    (root / "many").mkdir()
    for n in range(96):
        (root / "many" / f"entry-{n:03d}").write_bytes(f"record {n}\n".encode())
    os.chmod(root / "example.txt", 0o751)
    os.chflags(root / "example.txt", stat.UF_HIDDEN)
    for name, data in [("binary", b"\x00\xffvalue\x00"), ("empty", b""),
                       ("large", bytes(range(256)) * 128)]:
        command("/usr/bin/xattr", "-wx", "org.go-apfs." + name, data.hex(), root / "example.txt")
    with open(str(root / "example.txt") + "/..namedfork/rsrc", "wb") as stream:
        stream.write(bytes(range(255, -1, -1)) * 128 + b"\x00")


def observe_files(root, read=None):
    """Observe the final read-only native mount. No expected values come from v3."""
    records = []

    def visit(path):
        info = path.lstat()
        record = {"path": path.relative_to(root.parent).as_posix(), "object": info.st_ino,
                  "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                  "flags": info.st_flags, "birthSeconds": int(info.st_birthtime),
                  "modifyNS": info.st_mtime_ns, "changeNS": info.st_ctime_ns,
                  "accessNS": info.st_atime_ns, "size": info.st_size,
                  "links": info.st_nlink, "attributes": {}}
        for name, data in native_xattrs(path).items():
            record["attributes"][name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if stat.S_ISREG(info.st_mode):
            if read is None:
                record["sha256"] = sha256(path)
            else:
                detail = read(path)
                record["attributes"].update(detail.pop("attributes", {}))
                record.update(detail)
        elif stat.S_ISLNK(info.st_mode):
            record["target"] = os.readlink(path)
        records.append(record)
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)

    visit(root)
    return {"schema": 1, "root": "Fixture", "entries": records}


# Each pair isolates a named comparison rule. Results are observed with lstat,
# including negative lookups; the collector never computes Unicode equivalence.
NAME_CASES = [
    ("ascii", "ReadMe", ["readme", "README"]),
    ("canonical", "caf\u00e9", ["cafe\u0301", "CAF\u00c9"]),
    ("reorder", "a\u0301\u0327", ["a\u0327\u0301"]),
    ("hangul", "\uac01", ["\u1100\u1161\u11a8"]),
    ("sharp-s", "Stra\u00dfe", ["STRASSE", "Strasse"]),
    ("sigma", "\u03a3", ["\u03c3", "\u03c2"]),
    ("iota", "\u03b1\u0345\u0301", ["\u03b1\u0301\u03b9", "\u03b1\u0301\u0345"]),
    ("angstrom", "\u212b", ["\u00c5", "A\u030a"]),
    ("ligature", "\ufb00", ["ff", "FF"]),
    ("deseret", "\U00010400", ["\U00010428"]),
    ("unicode-11", "\u1c90", ["\u10d0"]),
    ("unicode-14", "\U00010570", ["\U00010597"]),
    ("unicode-16", "\u1c89", ["\u1c8a"]),
    ("ignorable", "ab", ["a\u200cb", "a\ufeffb"]),
    ("colon", "a:b", ["A:B"]),
]


def create_semantics(root, command, fragmented):
    root.mkdir()
    (root / "names").mkdir()
    for label, stored, _ in NAME_CASES:
        directory = root / "names" / label
        directory.mkdir()
        (directory / stored).write_bytes((label + "\n").encode())
    (root / "links").mkdir()
    original = root / "links" / "original"
    original.write_bytes(b"before linking\n")
    os.link(original, root / "alias")
    os.link(original, root / "links" / "second")
    os.link(original, root / "removed")
    (root / "removed").unlink()
    (root / "alias").write_bytes(bytes(range(256)) * 33 + b"modified through alias\n")
    os.chmod(root / "links" / "second", 0o751)
    command("/usr/bin/xattr", "-wx", "org.go-apfs.link", "00ff006c696e6b", root / "alias")
    with open(str(original) + "/..namedfork/rsrc", "wb") as stream:
        stream.write(bytes(range(255, -1, -1)) * 129)
    if fragmented:
        # Fill the small dedicated fixture volume, then release alternating
        # allocations. The native extent map below must prove >8 extents.
        guards = root.parent / "allocation-guards"
        guards.mkdir()
        chunk = bytes(512 * 1024)
        count = 0
        while os.statvfs(root).f_bavail * os.statvfs(root).f_frsize > 1536 * 1024:
            if count >= 256:
                raise RuntimeError("fragmentation recipe exceeded bounded allocation budget")
            (guards / str(count)).write_bytes(chunk)
            count += 1
        for n in range(0, count, 2):
            (guards / str(n)).unlink()
        for filename, fork in [("fragmented-data", False), ("fragmented-resource", True)]:
            path = root / filename
            path.touch()
            target = str(path) + ("/..namedfork/rsrc" if fork else "")
            with open(target, "wb") as stream:
                for _ in range(40):
                    stream.write(bytes(range(256)) * 1024)
                stream.write(b"extent-tail")
            if len(native_extents(target)) <= 8:
                raise RuntimeError(f"native fork did not require overflow extents: {filename}")


def native_extents(path):
    # Darwin sys/fcntl.h: F_LOG2PHYS_EXT=65, struct log2phys uses pack(4).
    class Log2Phys(ctypes.Structure):
        _layout_ = "ms"
        _pack_ = 4
        _fields_ = [("flags", ctypes.c_uint32), ("contiguous", ctypes.c_int64),
                    ("offset", ctypes.c_int64)]
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    # arm64 variadic calls require the fixed arguments to be declared explicitly.
    libc.fcntl.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.fcntl.restype = ctypes.c_int
    if ctypes.sizeof(Log2Phys) != 20:
        raise RuntimeError("Darwin log2phys layout mismatch")
    result = []
    with open(path, "rb") as source:
        size = os.fstat(source.fileno()).st_size
        offset = 0
        while offset < size:
            mapping = Log2Phys(0, size - offset, offset)
            if libc.fcntl(source.fileno(), 65, ctypes.byref(mapping)) < 0:
                raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(path))
            length = min(mapping.contiguous, size - offset)
            if length <= 0 or mapping.offset < 0 or len(result) >= 4096:
                raise RuntimeError("invalid or excessive native extent mapping")
            result.append({"logical": offset, "physical": mapping.offset, "length": length})
            offset += length
    return result


def observe_semantics(root, fragmented):
    queries = []
    for label, stored, alternatives in NAME_CASES:
        for spelling in [stored, *alternatives, "absent"]:
            path = root / "names" / label / spelling
            try:
                object_id = path.lstat().st_ino
            except FileNotFoundError:
                object_id = 0
            queries.append({"path": path.relative_to(root.parent).as_posix(), "object": object_id})
    aliases = [root / "alias", root / "links" / "original", root / "links" / "second"]
    if len({p.stat().st_ino for p in aliases}) != 1 or any(p.stat().st_nlink != 3 for p in aliases):
        raise RuntimeError("native hard-link identity/count precondition failed")
    extents = []
    if fragmented:
        for name, attribute in [("fragmented-data", ""), ("fragmented-resource", "com.apple.ResourceFork")]:
            path = str(root / name) + ("/..namedfork/rsrc" if attribute else "")
            ranges = native_extents(path)
            if len(ranges) <= 8:
                raise RuntimeError("read-only native fork no longer exercises overflow extents")
            samples = []
            with open(path, "rb") as source:
                for item in ranges[1:]:
                    offset = max(0, item["logical"] - 17)
                    source.seek(offset)
                    data = source.read(34)
                    samples.append({"offset": offset, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            extents.append({"path": "Fixture/" + name, "attribute": attribute, "ranges": ranges, "samples": samples})
    return {"lookups": queries, "fragmentedForks": extents}


def native_xattrs(path, flags=1):
    # CPython exposes os.*xattr on Linux but not Darwin. Call macOS's public
    # sys/xattr.h interfaces directly with XATTR_NOFOLLOW (1). No Go involved.
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t
    libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.getxattr.restype = ctypes.c_ssize_t
    encoded = os.fsencode(path)

    def checked(result):
        if result < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(path))
        return result

    size = checked(libc.listxattr(encoded, None, 0, flags))
    names = ctypes.create_string_buffer(size)
    actual = checked(libc.listxattr(encoded, names, size, flags))
    values = {}
    for name in sorted(filter(None, names.raw[:actual].split(b"\x00"))):
        size = checked(libc.getxattr(encoded, name, None, 0, 0, flags))
        data = ctypes.create_string_buffer(size)
        actual = checked(libc.getxattr(encoded, name, data, size, 0, flags))
        values[os.fsdecode(name)] = data.raw[:actual]
    return values


if __name__ == "__main__":
    main()
