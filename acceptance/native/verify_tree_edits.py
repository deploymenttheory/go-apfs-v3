#!/usr/bin/env python3
"""Compare edited portable trees with native operations without invoking Go."""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess

from verify_preservation import digest, read_json, require, timestamp_ns, verify_workspace


def paths(manifest, root):
    result, directories = {}, {}
    for i, e in enumerate(manifest["entries"]):
        name = base64.b64decode(e["nameBytes"] or "", validate=True).decode()
        p = root if i == 0 else directories[e["parent"]] + "/" + name
        require(p not in result, "duplicate workspace path")
        result[p] = e["object"]
        directories[e["object"]] = p
    return result


def verify_case(corpus, output, case):
    require(digest(corpus / case["files"])["sha256"] == case["filesSHA256"], "native before digest")
    require(digest(corpus / case["image"])["sha256"] == case["sha256"], "native before image digest")
    before = read_json(corpus / case["files"])
    ref = before["treeEdits"]
    for name, key in (("after", "afterSHA256"), ("image", "imageSHA256"), ("payload", "payloadSHA256")):
        require(digest(corpus / ref[name])["sha256"] == ref[key], "native after/input digest")
    after = read_json(corpus / ref["after"])
    require(len(ref["operations"]) == 18 and len(ref["rejections"]) == 8 and len(ref["nameProbes"]) == 6, "native operation inventory")
    for op in ref["operations"] + ref["nameProbes"]:
        for a in op.get("attributes", []):
            require(digest(corpus / a["data"])["sha256"] == a["sha256"], "creation attribute digest")
    baseline = read_json(output / "before/metadata/manifest.json")
    result = read_json(output / "after/metadata/manifest.json")
    require(result["parentManifestSHA256"] == digest(output / "before/metadata/manifest.json")["sha256"], "baseline provenance")
    actual_paths = paths(result, before["root"])
    require(set(actual_paths) == {e["path"] for e in after["entries"]}, "extra/missing final paths")
    originals = {e["object"]: e for e in before["entries"]}
    creations = {op["nativeObject"]: op for op in ref["operations"] if "metadata" in op}
    mapped, reverse = {}, {}
    created, modified, links_modified = set(), set(), set()
    times = {}
    expected = copy.deepcopy(after)
    for e in expected["entries"]:
        native = e["object"]
        actual = actual_paths[e["path"]]
        require(native not in mapped or mapped[native] == actual, "split native hard-link identity")
        require(actual not in reverse or reverse[actual] == native, "merged unrelated objects")
        mapped[native], reverse[actual] = actual, native
        if native in creations:
            created.add(actual)
            op = creations[native]
            m = op["metadata"]
            times[actual] = {"birthSeconds": timestamp_ns(m["birthTime"]["value"]) // 10**9,
                             "modifyNS": timestamp_ns(m["modifyTime"]["value"]),
                             "changeNS": timestamp_ns(m["changeTime"]["value"]),
                             "accessNS": timestamp_ns(m["accessTime"]["value"])}
            if e["mode"] & 0o170000 == 0o100000:
                modified.add(actual)
                require(digest(corpus / op["data"])["sha256"] == e["sha256"], "new file bytes")
                if e["links"] > 1:
                    links_modified.add(actual)
        else:
            require(native == actual and native in originals, "source inode changed")
            original = originals[native]
            times[actual] = original
            if e["mode"] & 0o170000 != 0o040000 and e["links"] != original["links"]:
                links_modified.add(actual)
            if e.get("sha256") != original.get("sha256") and e["mode"] & 0o170000 == 0o100000:
                modified.add(actual)
        e["object"] = actual
    for e in expected["rawAttributes"]:
        e["object"] = mapped[e["object"]]
    opts = {"minimum_mapped": 0, "minimum_symlinks": 1, "aliases": 3}
    kind = "APFS" if case["expected"]["filesystem"] == "APFS" else "HFS+"
    verify_workspace(output / "before", before, case["expected"]["caseSensitive"], kind, **opts)
    opts.update(minimum_mapped=2, minimum_symlinks=2, aliases=4)
    count = verify_workspace(output / "after", expected, case["expected"]["caseSensitive"], kind,
                             schema=3, created_objects=created, modified_objects=modified,
                             links_modified_objects=links_modified, source_times=times, **opts)
    before_objects = {o["node"]["identity"]["object"]: o for o in baseline["objects"]}
    result_objects = {o["node"]["identity"]["object"]: o for o in result["objects"]}
    raw_after = {e["object"]: e["attributes"] for e in expected["rawAttributes"]}
    for oid, obj in result_objects.items():
        if oid not in created:
            original = copy.deepcopy(before_objects[oid])
            require(obj["node"]["identity"] == original["node"]["identity"], "source view changed")
            if oid not in modified:
                original["node"]["links"] = obj["node"]["links"]
                if oid in links_modified:
                    original["node"]["linksModified"] = True
                require(obj == original, "untouched object values changed")
        if oid in modified:
            require(obj["data"] == obj["rawData"] and obj["node"]["compression"]["state"] == 1, "edited storage")
            attributes = {base64.b64decode(a["nameBytes"], validate=True).decode(): a["value"] for a in obj["attributes"]}
            require(attributes == raw_after[oid], "edited attributes differ from native result")
    return count


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-major", required=True)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--outputs", type=Path, required=True)
    p.add_argument("--producers", default="15,26,27")
    p.add_argument("--consumers", default="Linux,Windows,macOS")
    args = p.parse_args()
    version = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
    require(version.split(".")[0] == args.expected_major, "wrong native verification runner")
    cases, entries = 0, 0
    for consumer in args.consumers.split(","):
        for major in args.producers.split(","):
            corpus = args.corpus / ("macos-" + major)
            manifest = read_json(corpus / "manifest.json")
            require(manifest["schema"] == 1 and manifest["scenario"] == "tree-edits" and
                    manifest["producer"]["version"].split(".")[0] == major, "native provenance")
            required = {"tree-edits/" + f for f in ("apfs", "apfs-case-sensitive", "hfsplus", "hfsx")}
            require(len(manifest["cases"]) == 4 and {c["id"] for c in manifest["cases"]} == required, "incomplete native cases")
            for case in manifest["cases"]:
                output = args.outputs / ("tree-edits-" + consumer) / ("macos-" + major) / case["id"].split("/")[1]
                entries += verify_case(corpus, output, case)
                cases += 1
                print(f"macOS {version}: verified {consumer} tree edits from macOS {major}: {case['id']}", flush=True)
    print(json.dumps({"macOS": version, "workspacePairs": cases, "entries": entries, "nativeOperations": cases * 18}))


if __name__ == "__main__":
    main()
