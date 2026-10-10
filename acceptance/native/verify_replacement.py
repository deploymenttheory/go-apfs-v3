#!/usr/bin/env python3
"""Verify each host's replacement output against native before/after observations.

This invokes no Go code. Native captures perform O_TRUNC writes on existing
inodes; Python checks the resulting portable file bytes, forks, compression
cleanup and relationships. Source timestamps are preserved by explicit API policy.
"""
import argparse
import base64
from pathlib import Path
import subprocess
import json

from verify_preservation import digest, read_json, require, verify_workspace


def verify_case(corpus, output, case):
    before_file = corpus / case["files"]
    require(digest(before_file)["sha256"] == case["filesSHA256"], "native before digest")
    before = read_json(before_file)
    reference = before["replacement"]
    after_file = corpus / reference["after"]
    require(digest(after_file)["sha256"] == reference["afterSHA256"], "native after digest")
    require(digest(corpus / case["image"])["sha256"] == case["sha256"], "native source image digest")
    require(digest(corpus / reference["image"])["sha256"] == reference["imageSHA256"], "native edited image digest")
    after = read_json(after_file)
    operations = reference["operations"]
    require(len(operations) == 7, "incomplete native replacement inventory")
    changed = {op["object"] for op in operations}
    require(len(changed) == len(operations), "duplicate replacement target")
    source_by_id = {e["object"]: e for e in before["entries"]}
    before_paths = {e["path"]: e for e in before["entries"]}
    after_paths = {e["path"]: e for e in after["entries"]}
    require(set(before_paths) == set(after_paths), "native replacement changed directory entries")
    for op in operations:
        expected = {"size": op["size"], "sha256": op["sha256"]}
        require(digest(corpus / op["payload"]) == expected, "replacement input digest")
        require(before_paths[op["path"]]["object"] == op["object"] == after_paths[op["path"]]["object"], "native replacement identity")
        require({k: after_paths[op["path"]][k] for k in expected} == expected, "native replacement bytes differ from input")
    opts = {"minimum_mapped": 1, "minimum_symlinks": 1, "aliases": 3}
    kind = "APFS" if case["expected"]["filesystem"] == "APFS" else "HFS+"
    sensitive = case["expected"]["caseSensitive"]
    verify_workspace(output / "before", before, sensitive, kind, **opts)
    count = verify_workspace(output / "after", after, sensitive, kind, modified_objects=changed,
                             source_times={i: source_by_id[i] for i in changed}, **opts)
    baseline = read_json(output / "before/metadata/manifest.json")
    result = read_json(output / "after/metadata/manifest.json")
    require(result["parentManifestSHA256"] == digest(output / "before/metadata/manifest.json")["sha256"], "missing baseline provenance")
    original_objects = {o["node"]["identity"]["object"]: o for o in baseline["objects"]}
    actual_objects = {o["node"]["identity"]["object"]: o for o in result["objects"]}
    require(set(original_objects) == set(actual_objects), "replacement added/removed objects")
    raw_after = {e["object"]: e["attributes"] for e in after["rawAttributes"]}
    for raw in before["rawAttributes"]:
        oid = raw["object"]
        obj = actual_objects[oid]
        require(obj["node"]["identity"] == original_objects[oid]["node"]["identity"], "lost source view")
        attributes = {base64.b64decode(a["nameBytes"], validate=True).decode(): a["value"] for a in obj["attributes"]}
        removed = set(raw["attributes"]) - set(raw_after[oid])
        require(not removed.intersection(attributes), "native-removed compression storage survived")
        if oid in changed:
            require(obj["rawData"] == obj["data"] and obj["node"]["compression"] == {"state": 1, "value": {"type": 0}}, "inconsistent replacement storage")
        else:
            require(obj == original_objects[oid], "untouched object changed")
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
    require(version.split(".")[0] == args.expected_major, "wrong native verification runner")
    cases, entries = 0, 0
    for consumer in args.consumers.split(","):
        for major in args.producers.split(","):
            corpus = args.corpus / ("macos-" + major)
            manifest = read_json(corpus / "manifest.json")
            require(manifest["schema"] == 1 and manifest["scenario"] == "content-replacement" and
                    manifest["producer"]["version"].split(".")[0] == major, "native provenance")
            required = {"content-replacement/" + p for p in ("apfs", "apfs-case-sensitive", "hfsplus", "hfsx")}
            require(len(manifest["cases"]) == 4 and {c["id"] for c in manifest["cases"]} == required, "incomplete native cases")
            for case in manifest["cases"]:
                output = args.outputs / ("replacement-" + consumer) / ("macos-" + major) / case["id"].split("/")[1]
                entries += verify_case(corpus, output, case)
                cases += 1
                print(f"macOS {version}: verified {consumer} replacements from macOS {major}: {case['id']}", flush=True)
    print(json.dumps({"macOS": version, "workspacePairs": cases, "entries": entries, "nativeReplacements": cases * 7}))


if __name__ == "__main__":
    main()
