#!/usr/bin/env python3
"""Create independent native volume-inspection cases. Never invokes v3.

Every command has a deadline. Completion is published only after images are
detached, hashed, and all cases have succeeded. An existing corpus is never
overwritten. Run on macOS; replay the resulting corpus on any supported host.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import stat
import subprocess
import tempfile


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
    parser.add_argument("--scenario", choices=["volume-inspection", "file-reading"], default="volume-inspection")
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

        def command(*argv):
            print("native:", " ".join(map(str, argv)), flush=True)
            # Persist a start before invoking native code, including commands
            # that time out or fail to launch. A partial transcript is diagnostic.
            record = {"argv": list(map(str, argv)), "status": "started"}
            commands.append(record)

            def save():
                text = json.dumps(commands, indent=2) + "\n"
                (corpus / "commands.json").write_text(text)
                output.with_suffix(".diagnostics.json").write_text(text)

            save()
            try:
                result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=120, check=False)
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
            if result.returncode:
                raise RuntimeError(f"command failed: {argv}: {result.stderr.decode(errors='replace')}")
            return result.stdout

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
                if args.scenario == "file-reading":
                    file_observation = corpus / (case_id + "-files.json")
                    file_observation.write_text(json.dumps(observe_files(mount / "Fixture"), indent=2) + "\n")
            finally:
                command("hdiutil", "detach", device)
            if sha256(image) != before:
                raise RuntimeError("native read-only examination changed the image")
            command("hdiutil", "verify", image)
            case = {"id": args.scenario + "/" + case_id,
                          "image": image.name, "sha256": before,
                          "observation": raw_path.name,
                          "observationSHA256": sha256(raw_path), "expected": expected}
            if file_observation:
                case.update(files=file_observation.name, filesSHA256=sha256(file_observation))
            cases.append(case)
        script = corpus / "capture.py"
        shutil.copyfile(__file__, script)
        manifest = {"schema": 1, "scenario": args.scenario, "producer": {
            "system": "macOS", "version": product, "build": build,
            "architecture": platform.machine(), "source": "capture.py",
            "sourceSHA256": sha256(script)}, "cases": cases}
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


def observe_files(root):
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
            record["sha256"] = sha256(path)
        elif stat.S_ISLNK(info.st_mode):
            record["target"] = os.readlink(path)
        records.append(record)
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)

    visit(root)
    return {"schema": 1, "root": "Fixture", "entries": records}


def native_xattrs(path):
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

    size = checked(libc.listxattr(encoded, None, 0, 1))
    names = ctypes.create_string_buffer(size)
    actual = checked(libc.listxattr(encoded, names, size, 1))
    values = {}
    for name in sorted(filter(None, names.raw[:actual].split(b"\x00"))):
        size = checked(libc.getxattr(encoded, name, None, 0, 0, 1))
        data = ctypes.create_string_buffer(size)
        actual = checked(libc.getxattr(encoded, name, data, size, 0, 1))
        values[os.fsdecode(name)] = data.raw[:actual]
    return values


if __name__ == "__main__":
    main()
