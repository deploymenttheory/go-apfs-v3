#!/usr/bin/env python3
"""Create independent native volume-inspection cases. Never invokes v3.

Every command has a deadline. Completion is published only after images are
detached, hashed, and all cases have succeeded. An existing corpus is never
overwritten. Run on macOS; replay the resulting corpus on any supported host.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile


def sha256(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-major", type=int, choices=[15, 26, 27], required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("native capture requires macOS")
    product = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
    build = subprocess.check_output(["sw_vers", "-buildVersion"], text=True).strip()
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
            result = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=120, check=False)
            # Scratch paths are retained as diagnostic facts, never replay inputs.
            commands.append({"argv": list(map(str, argv)), "status": result.returncode,
                             "stdout": result.stdout.decode(errors="replace"),
                             "stderr": result.stderr.decode(errors="replace")})
            (corpus / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            output.with_suffix(".diagnostics.json").write_text(json.dumps(commands, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"command failed: {argv}: {result.stderr.decode(errors='replace')}")
            return result.stdout

        def attach(image, readonly=False):
            options = ["-readonly"] if readonly else []
            data = command("hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen",
                           *options, image)
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
            finally:
                command("hdiutil", "detach", device)
            if sha256(image) != before:
                raise RuntimeError("native read-only examination changed the image")
            command("hdiutil", "verify", image)
            cases.append({"id": "volume-inspection/" + case_id,
                          "image": image.name, "sha256": before,
                          "observation": raw_path.name,
                          "observationSHA256": sha256(raw_path), "expected": expected})
        script = corpus / "capture.py"
        shutil.copyfile(__file__, script)
        manifest = {"schema": 1, "scenario": "volume-inspection", "producer": {
            "system": "macOS", "version": product, "build": build,
            "architecture": platform.machine(), "source": "capture.py",
            "sourceSHA256": sha256(script)}, "cases": cases}
        (corpus / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # This directory is visible at its final path only after complete capture.
        corpus.rename(output)
    print(f"Complete native corpus: {output}")


if __name__ == "__main__":
    main()
