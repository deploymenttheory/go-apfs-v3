#!/usr/bin/env python3
"""Independently verify portable output, then let Apple unpack its metadata.

No Go code is executed here. Expected names/stat/attribute/content values come
from read-only native mounts; copyfile compares portable output with the original
Apple-produced control on this Mac. Archive transport need not retain host links
or permissions: those are preserved as logical values in the workspace.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from capture import native_xattrs
from preservation import copyfile, digest_values


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), f"expected regular file: {path}")
    h = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(65536), b""):
            h.update(data)
    return {"size": path.stat().st_size, "sha256": h.hexdigest()}


def read_json(path):
    return json.loads(path.read_text())


def timestamp_ns(value):
    require(value.endswith("Z"), "non-UTC recorded time")
    whole, _, fraction = value[:-1].partition(".")
    seconds = int(datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return seconds * 10**9 + int((fraction + "000000000")[:9])


def verify_workspace(root, expected, sensitive, volume_format):
    manifest = read_json(root / "metadata/manifest.json")
    require(manifest["schema"] == 1, "workspace schema")
    require(manifest["names"] == {"format": volume_format, "caseSensitive": sensitive,
                                  "normalizationInsensitive": True}, "filename rules")
    objects = {o["node"]["identity"]["object"]: o for o in manifest["objects"]}
    require(len(objects) == len(manifest["objects"]), "duplicate workspace identity")
    entries = manifest["entries"]
    native = {e["path"]: e for e in expected["entries"]}
    raw = {e["object"]: e["attributes"] for e in expected["preservation"]["rawAttributes"]}
    directories = {}
    observed = set()
    projected = set()
    verified = {}
    origins = set()

    def blob(value):
        name = value["sha256"]
        require(len(name) == 64 and all(c in "0123456789abcdef" for c in name), "unsafe blob name")
        if name not in verified:
            verified[name] = digest(root / "metadata/blobs" / name)
        require(verified[name] == value, "blob bytes differ from manifest")
        return value

    for i, entry in enumerate(entries):
        original = base64.b64decode(entry["nameBytes"] or "", validate=True).decode("utf-8")
        require("/" not in original and original not in (".", ".."), "unsafe original component")
        if i == 0:
            require(entry["object"] == manifest["root"] and entry["parent"] == 0 and original == "", "workspace root")
            logical = expected["root"]
        else:
            logical = directories[entry["parent"]] + "/" + original
        require(logical in native and logical not in observed, f"unexpected original path: {logical}")
        observed.add(logical)
        want = native[logical]
        obj = objects[entry["object"]]
        node = obj["node"]
        require(node["identity"]["object"] == want["object"], "native identity changed")
        origins.add((node["identity"]["volume"], node["identity"]["view"]))
        mode = want["mode"] & 0o170000
        for field, key in (("mode", "mode"), ("uid", "uid"), ("gid", "gid"), ("bsdFlags", "flags")):
            require(node["metadata"][field] == {"state": 2, "value": want[key]}, f"{logical}: {field}")
        for field, key in (("birthTime", "birthSeconds"), ("modifyTime", "modifyNS"),
                           ("changeTime", "changeNS"), ("accessTime", "accessNS")):
            value = node["metadata"][field]
            ns = timestamp_ns(value["value"])
            require(value["state"] == 2 and (ns // 10**9 if field == "birthTime" else ns) == want[key],
                    f"{logical}: {field}")
        host = entry["hostPath"]
        require(host == "files" or host.startswith("files/"), "projection root")
        require(all(part not in ("", ".", "..") and "\\" not in part for part in host.split("/")), "unsafe projection")
        projected.add(host)
        target = root / host
        actual_mode = target.lstat().st_mode
        require(not stat.S_ISLNK(actual_mode), "projection follows a symlink")
        if mode == stat.S_IFDIR:
            require(stat.S_ISDIR(actual_mode), "directory projection")
            directories[entry["object"]] = logical
        else:
            require(node["size"] == want["size"] and node["links"] == {"state": 2, "value": want["links"]}, "size or link identity")
            if mode == stat.S_IFREG:
                value = {"size": want["size"], "sha256": want["sha256"]}
                require(blob(obj["data"]) == value and digest(target) == value, f"{logical}: logical data")
                blob(obj["rawData"])
            else:
                require(mode == stat.S_IFLNK and entry["materialized"] == "symlink-record", "unrecognized object")
                value = base64.b64decode(obj["targetBytes"], validate=True)
                require(value == want["target"].encode() and target.read_bytes() == value, "symlink bytes")
        attributes = {}
        for attribute in obj["attributes"]:
            name = base64.b64decode(attribute["nameBytes"], validate=True).decode("utf-8")
            require(name not in attributes, "duplicate attribute")
            attributes[name] = blob(attribute["value"])
        for name, value in raw[want["object"]].items():
            require(attributes.get(name) == value, f"{logical}: raw attribute {name}")
    require(observed == set(native) and len(origins) == 1, "incomplete or mixed workspace")
    actual = {str(p.relative_to(root)).replace(os.sep, "/") for p in (root / "files").rglob("*")}
    require(actual | {"files"} == projected, "extra or missing projected entries")
    report = manifest["report"]
    require(report["objects"] == len(objects) and report["entries"] == len(entries), "preservation report counts")
    require(report["mappedNames"] >= 8 and report["symlinksRecorded"] >= 3 and
            report["hardLinks"] + report["hardLinksCopied"] == 2, "missing preservation outcomes")
    require(report["storedBytes"] == sum(v["size"] for v in verified.values()), "stored byte accounting")
    return len(entries)


def verify_case(corpus, output, case, scratch):
    observation = corpus / case["files"]
    require(digest(observation)["sha256"] == case["filesSHA256"], "native observation digest")
    expected = read_json(observation)
    count = verify_workspace(output / "workspace", expected, case["expected"]["caseSensitive"],
                             "APFS" if case["expected"]["filesystem"] == "APFS" else "HFS+")
    controls = expected["preservation"]["appleDouble"]
    require(len(controls) == 3 and {p.name for p in (output / "appledouble").iterdir()} == {c["file"] for c in controls},
            "AppleDouble control inventory")
    for i, control in enumerate(controls):
        original = corpus / control["file"]
        require(digest(original)["sha256"] == control["sha256"], "native AppleDouble digest")
        results = []
        for label, source in (("native", original), ("portable", output / "appledouble" / control["file"])):
            destination = scratch / (str(i) + label)
            destination.write_bytes(b"independent native unpack destination\n")
            copyfile("unpack", source, destination)
            results.append(digest_values(native_xattrs(destination)))
        require(results[0] == control["unpackedAttributes"], "native unpack control changed")
        require(results[0] == results[1], f"Apple rejected portable metadata: {control['file']}")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-major", required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--outputs", type=Path, required=True)
    parser.add_argument("--producers", default="15,26,27")
    parser.add_argument("--consumers", default="Linux,Windows,macOS")
    args = parser.parse_args()
    version = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
    require(version.split(".")[0] == args.expected_major, "wrong macOS verification runner")
    cases, entries = 0, 0
    for consumer in args.consumers.split(","):
        for major in args.producers.split(","):
            corpus = args.corpus / ("macos-" + major)
            manifest = read_json(corpus / "manifest.json")
            require(manifest["scenario"] == "preservation" and manifest["producer"]["version"].split(".")[0] == major,
                    "native capture provenance")
            required = {"preservation/" + p for p in ("apfs", "apfs-case-sensitive", "hfsplus", "hfsx")}
            require({c["id"] for c in manifest["cases"]} == required and len(manifest["cases"]) == 4, "native inventory")
            for case in manifest["cases"]:
                output = args.outputs / ("preservation-" + consumer) / ("macos-" + major) / case["id"].split("/")[1]
                with tempfile.TemporaryDirectory(prefix="apfs-v3-native-unpack-") as scratch:
                    entries += verify_case(corpus, output, case, Path(scratch))
                cases += 1
                print(f"macOS {version}: verified {consumer} output from macOS {major}: {case['id']}", flush=True)
    print(json.dumps({"macOS": version, "workspaces": cases, "entries": entries, "nativeUnpackComparisons": cases * 3}))


if __name__ == "__main__":
    main()
