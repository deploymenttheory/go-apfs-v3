#!/usr/bin/env python3
"""Independently verify metadata edits against native before/after observations."""
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess

from verify_preservation import digest, read_json, require, verify_workspace


def verify_case(corpus, output, case, allow_same_owner=False):
    for name, key in (('files', 'filesSHA256'), ('image', 'sha256')):
        require(digest(corpus / case[name])['sha256'] == case[key], 'native before digest')
    before = read_json(corpus / case['files'])
    ref = before['metadataEdits']
    for name, key in (('after', 'afterSHA256'), ('image', 'imageSHA256')):
        require(digest(corpus / ref[name])['sha256'] == ref[key], 'native after digest')
    require(len(ref['operations']) == 29 and len(ref['rejections']) == 7 and len(ref['inputs']) == 6,
            'native metadata operation inventory')
    require(allow_same_owner or ref['ownership'] == 'changed-with-sudo', 'missing actual native ownership change')
    inputs = set()
    for item in ref['inputs']:
        require(digest(corpus / item['file']) == {'size': item['size'], 'sha256': item['sha256']}, 'edit input digest')
        inputs.add(item['file'])
    metadata, attributes, modified = {}, {}, set()
    for op in ref['operations']:
        require('data' not in op or op['data'] in inputs, 'unverified edit input')
        oid = op['object']
        for key, table in (('metadata', metadata), ('attributes', attributes)):
            if op['effects'][key]:
                table[oid] = sorted(set(table.get(oid, [])) | set(op['effects'][key]))
        if op['op'] == 'replace':
            modified.add(oid)
    for op in ref['rejections']:
        require(op['errno'] != 0 and ('data' not in op or op['data'] in inputs), 'native rejection evidence')
    after = read_json(corpus / ref['after'])
    require(len(before['entries']) == 16 and len(after['entries']) == 17, 'entry inventory')
    originals = {e['object']: e for e in before['entries']}
    expected = copy.deepcopy(after)
    links = set()
    for e in expected['entries']:
        oid = e['object']
        require(oid in originals, 'unexpected new identity')
        old = originals[oid]
        for field, keys in (('birthTime', ('birthSeconds', 'birthNS')), ('modifyTime', ('modifyNS',)),
                            ('accessTime', ('accessNS',)), ('changeTime', ('changeNS',))):
            if field not in metadata.get(oid, []):
                for key in keys:
                    e[key] = old[key]
        if e['mode'] & 0o170000 != 0o040000 and e['links'] != old['links']:
            links.add(oid)
        if e['path'] == 'Fixture/owner' and ref['ownership'] == 'changed-with-sudo':
            require(e['uid'] == 60001 and e['gid'] == 60002 and
                    e['uid'] != old['uid'] and e['gid'] != old['gid'], 'ownership mutation missing')
    kind = 'APFS' if case['expected']['filesystem'] == 'APFS' else 'HFS+'
    opts = {'minimum_mapped': 1, 'minimum_symlinks': 1, 'aliases': 2}
    verify_workspace(output / 'before', before, case['expected']['caseSensitive'], kind, **opts)
    opts['aliases'] = 3
    count = verify_workspace(output / 'after', expected, case['expected']['caseSensitive'], kind,
                             schema=4, modified_objects=modified, links_modified_objects=links,
                             metadata_changes=metadata, attribute_changes=attributes, **opts)
    baseline = read_json(output / 'before/metadata/manifest.json')
    result = read_json(output / 'after/metadata/manifest.json')
    require(result['parentManifestSHA256'] == digest(output / 'before/metadata/manifest.json')['sha256'], 'baseline provenance')
    old_objects = {o['node']['identity']['object']: o for o in baseline['objects']}
    old_raw = {o['object']: o['attributes'] for o in before['rawAttributes']}
    new_raw = {o['object']: o['attributes'] for o in after['rawAttributes']}
    def attrs(obj):
        return {base64.b64decode(a['nameBytes'], validate=True).decode(): a['value'] for a in obj['attributes']}
    for obj in result['objects']:
        oid = obj['node']['identity']['object']
        old = old_objects[oid]
        require(obj['node']['identity'] == old['node']['identity'], 'source identity changed')
        wanted = {k: v for k, v in attrs(old).items() if k not in old_raw[oid]}
        wanted.update(new_raw[oid])
        require(attrs(obj) == wanted, 'extra, missing or changed raw attribute')
        if oid in modified:
            require(obj['data'] == obj['rawData'] and obj['node']['compression']['state'] == 1, 'replacement storage')
        else:
            require(obj.get('data') == old.get('data') and obj.get('rawData') == old.get('rawData') and
                    obj['node']['compression'] == old['node']['compression'] and obj.get('targetBytes') == old.get('targetBytes'),
                    'unrelated data, compression or symlink changed')
        # Compare complete unchanged metadata observations, including state and
        # precision, rather than assuming matching native visible fields suffice.
        for name, value in old['node']['metadata'].items():
            if name not in metadata.get(oid, []):
                if name == 'bsdFlags' and oid in modified:
                    # Complete content replacement clears UF_COMPRESSED, as
                    # qualified by the existing replacement family.
                    value = dict(value, value=value['value'] & ~0x20)
                require(obj['node']['metadata'][name] == value, f'unspecified metadata changed: {oid} {name}')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    parser.add_argument('--allow-same-owner', action='store_true', help='local diagnostic corpus without sudo; forbidden in the release matrix')
    args = parser.parse_args()
    version = subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip()
    require(version.split('.')[0] == args.expected_major, 'wrong native verification runner')
    require(not args.allow_same_owner or (args.producers == args.expected_major and args.consumers == 'macOS'), 'same-owner mode is local-only')
    cases, entries = 0, 0
    for consumer in args.consumers.split(','):
        for major in args.producers.split(','):
            corpus = args.corpus / ('macos-' + major)
            manifest = read_json(corpus / 'manifest.json')
            require(manifest['schema'] == 1 and manifest['scenario'] == 'metadata-edits' and
                    manifest['producer']['version'].split('.')[0] == major, 'native provenance')
            required = {'metadata-edits/' + f for f in ('apfs', 'apfs-case-sensitive', 'hfsplus', 'hfsx')}
            require(len(manifest['cases']) == 4 and {c['id'] for c in manifest['cases']} == required, 'native case inventory')
            for case in manifest['cases']:
                output = args.outputs / ('metadata-edits-' + consumer) / ('macos-' + major) / case['id'].split('/')[1]
                entries += verify_case(corpus, output, case, args.allow_same_owner)
                cases += 1
                print(f"macOS {version}: verified {consumer} metadata edits from macOS {major}: {case['id']}", flush=True)
    print(json.dumps({'macOS': version, 'workspacePairs': cases, 'entries': entries, 'nativeOperations': cases * 29}))


if __name__ == '__main__':
    main()
