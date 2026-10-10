#!/usr/bin/env python3
"""Verify exported command sessions against Apple observations without invoking Go."""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess

from verify_preservation import digest, read_json, require, timestamp_ns, verify_workspace

FIELDS = {'mode', 'uid', 'gid', 'bsdFlags', 'birthTime', 'modifyTime', 'accessTime', 'changeTime'}
NEW = {'Applications/Source.app/Contents/Moved', 'Applications/Source.app/Contents/Moved/deep',
       'Applications/Source.app/Contents/Moved/build.bin', 'build-alias', 'app-link'}


def attributes(obj):
    return {base64.b64decode(a['nameBytes'], validate=True).decode(): a['value'] for a in obj['attributes']}


def paths(manifest):
    directories, result = {}, {}
    objects = {o['node']['identity']['object']: o for o in manifest['objects']}
    for i, entry in enumerate(manifest['entries']):
        name = base64.b64decode(entry['nameBytes'] or '', validate=True).decode()
        p = '' if i == 0 else '/'.join(filter(None, (directories[entry['parent']], name)))
        require(p not in result, 'duplicate logical path')
        obj = objects[entry['object']]
        result[p] = obj
        if obj['node']['metadata']['mode']['value'] & 0o170000 == 0o040000:
            directories[entry['object']] = p
    return result


def verify_case(corpus, output, case, allow_same_owner=False):
    for name, key in (('files', 'filesSHA256'), ('image', 'sha256')):
        require(digest(corpus / case[name])['sha256'] == case[key], 'native before digest')
    before = read_json(corpus / case['files'])
    ref = before['fileCommands']
    require(ref['readAccessPolicy'] == 'noatime', 'unqualified access-time policy')
    require(len(ref['operations']) == 23 and len(ref['rejections']) == 5 and len(ref['inputs']) == 3 and
            len(ref['modeVectors']) == 390, 'command reference inventory')
    require(allow_same_owner or ref['ownership'] == 'changed-with-sudo', 'actual ownership assignment missing')
    for item in ref['inputs']:
        require(digest(corpus / item['file']) == {'size': item['size'], 'sha256': item['sha256']}, 'host input digest')
    for name, key in (('after', 'afterSHA256'), ('image', 'imageSHA256')):
        require(digest(corpus / ref[name])['sha256'] == ref[key], 'native after digest')
    after = read_json(corpus / ref['after'])
    require(len(before['entries']) == 17 and len(after['entries']) == 31, 'native tree inventory')
    kind = 'APFS' if case['expected']['filesystem'] == 'APFS' else 'HFS+'
    opts = {'minimum_mapped': 1, 'minimum_symlinks': 2, 'aliases': 1}
    verify_workspace(output / 'before', before, case['expected']['caseSensitive'], kind, **opts)
    baseline = read_json(output / 'before/metadata/manifest.json')
    result = read_json(output / 'after/metadata/manifest.json')
    old = {o['node']['identity']['object']: o for o in baseline['objects']}
    by_path = paths(result)
    before_paths = paths(baseline)
    before_raw = {o["object"]: o["attributes"] for o in before["rawAttributes"]}
    expected = copy.deepcopy(after)
    mapped, reverse, created, modified, links = {}, {}, set(), set(), set()
    metadata, edits, wanted_attrs = {}, {}, {}
    fixed = timestamp_ns(ref['fixedTime'])
    unit = 10**9 if kind == 'HFS+' else 1
    fixed = fixed // unit * unit

    def clock(ns):
        return fixed if ref['startNS'] // unit * unit <= ns <= ref['endNS'] // unit * unit + unit - 1 else ns

    native_attrs = {o['object']: o['attributes'] for o in after['rawAttributes']}
    for entry in expected['entries']:
        p = entry['path'].removeprefix(before['root']).lstrip('/')
        require(p in by_path, 'missing logical path: ' + p)
        obj = by_path[p]
        node = obj['node']
        native, portable = entry['object'], node['identity']['object']
        require(mapped.get(native, portable) == portable and reverse.get(portable, native) == native, 'hard-link identity differs')
        mapped[native], reverse[portable] = portable, native
        entry['object'] = portable
        source = old.get(native)
        if source:
            require(node['identity'] == source['node']['identity'] and not node.get('created'), 'original identity changed')
            allowed = {'changeTime', 'modifyTime'} if p in ('', 'Applications') else set()
            for name, value in source['node']['metadata'].items():
                if name not in allowed:
                    require(node['metadata'][name] == value, 'untouched metadata changed')
            require(obj.get('data') == source.get('data') and obj.get('rawData') == source.get('rawData') and
                    obj.get('targetBytes') == source.get('targetBytes') and attributes(obj) == attributes(source),
                    'untouched source contents changed')
        else:
            created.add(portable)
            require(node.get('created'), 'new object lacks creation provenance')
            allowed = FIELDS
            if entry['mode'] & 0o170000 == 0o100000:
                modified.add(portable)
                require(obj['data'] == obj['rawData'] and node['compression']['state'] == 1, 'new copy is not logical uncompressed data')
                entry['flags'] &= ~32
            if p in ('build-alias', 'Applications/Source.app/Contents/Moved/build.bin'):
                links.add(portable)
            if ref['ownership'] == 'changed-with-sudo' and p.startswith('Applications/Source.app'):
                require(entry['uid'] == 60001 and entry['gid'] == 60002, 'native owner change missing')
        # Cumulative explicit assignments can include unchanged values. Their
        # allowed field set is checked here; all values are checked independently
        # against native observations by verify_workspace below.
        fields = node.get('metadataModified', [])
        require(fields == sorted(set(fields)) and set(fields) <= allowed, 'invalid metadata provenance')
        if source:
            required = {name for name in allowed if node['metadata'][name] != source['node']['metadata'][name]}
            require(required <= set(fields), 'missing changed-field provenance')
        if fields:
            metadata[portable] = fields
        copy_source = source
        if not copy_source and p.startswith('Applications/Source.app') and p not in NEW:
            copy_source = before_paths[p.removeprefix('Applications/')]
        extras = {}
        if copy_source:
            oid = copy_source['node']['identity']['object']
            extras = {k: v for k, v in attributes(copy_source).items() if k not in before_raw[oid]}
        names = node.get('attributesModified', [])
        require(names == sorted(set(names)), 'invalid attribute provenance')
        if source:
            require(not names, 'unchanged source attribute marked edited')
        else:
            require(set(names) <= set(native_attrs[native]) | set(extras) | {'org.original', 'com.apple.ResourceFork'}, 'unexpected edited attribute')
        if names:
            edits[portable] = names
        require(set(node.get('metadataDefaulted', [])) <= {'mode', 'uid', 'gid', 'bsdFlags'} and
                (not node.get('metadataDefaulted') or p in ('build-alias', 'Applications/Source.app/Contents/Moved/build.bin')),
                'unexpected host default')
        require(not node.get('attributesUnavailable'), 'the recipe uses -X for host imports')
        for field in ('birthNS', 'modifyNS', 'changeNS', 'accessNS'):
            entry[field] = clock(entry[field])
        entry['birthSeconds'] = entry['birthNS'] // 10**9
        attrs = dict(extras)
        attrs.update(native_attrs[native])
        if p in NEW:
            # Runner process authorization can add this value at creation. The
            # raw observation stays intact; existing/copied provenance is exact.
            attrs.pop('com.apple.provenance', None)
            if entry['mode'] & 0o170000 == 0o120000:
                attrs.pop('com.apple.fs.symlink', None)  # targetBytes is the logical symlink.
        if p == 'plain-copy':
            attrs.pop('com.apple.decmpfs', None)  # native copyfile can retain compressed storage.
        require(attributes(obj) == attrs, 'extra, missing or changed attribute at ' + p)
        wanted_attrs[portable] = attrs
    expected['rawAttributes'] = [{'object': oid, 'attributes': attrs} for oid, attrs in wanted_attrs.items()]
    opts.update(aliases=2, minimum_symlinks=5)
    return verify_workspace(output / 'after', expected, case['expected']['caseSensitive'], kind, schema=5,
                            created_objects=created, modified_objects=modified, links_modified_objects=links,
                            metadata_changes=metadata, attribute_changes=edits, **opts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    parser.add_argument('--allow-same-owner', action='store_true')
    args = parser.parse_args()
    version = subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip()
    require(version.split('.')[0] == args.expected_major, 'wrong native runner')
    require(not args.allow_same_owner or (args.producers == args.expected_major and args.consumers == 'macOS'), 'same-owner mode is local-only')
    cases, entries = 0, 0
    for consumer in args.consumers.split(','):
        for major in args.producers.split(','):
            corpus = args.corpus / ('macos-' + major)
            manifest = read_json(corpus / 'manifest.json')
            require(manifest['scenario'] == 'file-commands' and manifest['producer']['version'].split('.')[0] == major, 'native provenance')
            required = {'file-commands/' + f for f in ('apfs', 'apfs-case-sensitive', 'hfsplus', 'hfsx')}
            require(len(manifest['cases']) == 4 and {c['id'] for c in manifest['cases']} == required, 'native cases')
            for case in manifest['cases']:
                output = args.outputs / ('file-commands-' + consumer) / ('macos-' + major) / case['id'].split('/')[1]
                entries += verify_case(corpus, output, case, args.allow_same_owner)
                cases += 1
                print(f"macOS {version}: verified {consumer} file commands from macOS {major}: {case['id']}", flush=True)
    print(json.dumps({'macOS': version, 'workspacePairs': cases, 'entries': entries, 'nativeCommands': cases * 23}))


if __name__ == '__main__':
    main()
