"""Reviewed projection of complete Actions captures into logical corpus roots.

This only links ordinary captured files. It never changes a manifest, collector,
observation or disk byte. Reused logical families retain distinct corpus IDs;
their common captured origin is explicit here and in the publication ledger.
"""
import json
import os
from pathlib import Path

from release_assets import require


def sources():
    result = {}
    for name in ('native', 'files', 'semantics', 'compression', 'encryption', 'encrypted-dmg',
                 'snapshots', 'preservation', 'replacement', 'tree-edits', 'metadata-edits',
                 'file-commands', 'image-building', 'image-repacking', 'apfs-lifecycle'):
        result[name] = {'artifact': 'native-corpus-{major}',
                        'path': 'volumes' if name == 'native' else name, 'capture': name}
    for prefix in ('apfs', 'hfs', 'hfs-journaled'):
        for suffix, directory in (('editing', ''), ('metadata-editing', 'metadata'),
                                  ('link-editing', 'links'), ('copy', 'copy')):
            name = prefix + '-' + suffix
            result[name] = {'artifact': prefix + '-edit-reference-{major}',
                            'path': directory, 'capture': name}
        if prefix != 'apfs':
            name = prefix + '-catalog-editing'
            result[name] = {'artifact': prefix + '-edit-reference-{major}', 'path': '', 'capture': name}
    result['apfs-directory-editing'] = {'artifact': 'apfs-edit-reference-{major}',
                                        'path': 'directories', 'capture': 'apfs-directory-editing'}
    for name, family in (('apfs-geometry', 'apfs'), ('hfs-metadata-growth', 'hfs'),
                         ('hfs-fragmented-metadata', 'hfs-fragmented'),
                         ('permission-inheritance', 'permissions'), ('copy-permissions', 'copy-permissions'),
                         ('apfs-directory-statistics', 'statistics'),
                         ('apfs-directory-statistics-transitions', 'statistics-transitions')):
        result[name] = {'artifact': 'offline-editing-' + family + '-reference-{major}',
                        'path': '', 'capture': name}
    for name in ('apfs-recovery', 'hfs-recovery'):
        result[name] = {'artifact': name + '-reference-{major}', 'path': '', 'capture': name, 'source_root': True}
    for alias, captured in (('copy-setid-permissions', 'copy-permissions'),
                             ('copy-truncation-permissions', 'copy-permissions'),
                             ('hfs-metadata-lifecycle', 'hfs-fragmented-metadata')):
        result[alias] = dict(result[captured])
    return dict(sorted(result.items()))


def assemble(downloads, destination, mapping=None):
    """Select each recorded source directory; preserve every byte within it."""
    downloads, destination = Path(downloads).resolve(), Path(destination).absolute()
    require(downloads.is_dir() and not destination.exists() and not destination.is_symlink(),
            'complete capture download and absent assembly directory required')
    require(not destination.is_relative_to(downloads) and not downloads.is_relative_to(destination),
            'native capture assembly must be separate from downloaded evidence')
    destination.mkdir(mode=0o700, parents=True)
    inputs = []
    for name, spec in (mapping or sources()).items():
        require(name and '/' not in name and '\\' not in name and name not in ('.', '..'),
                'logical native corpus ID required')
        count, total = 0, 0
        for major in (15, 26, 27):
            original = downloads / spec['artifact'].format(major=major) / spec['path']
            if not spec.get('source_root'):
                original /= 'macos-' + str(major)
            require(original.is_dir() and not original.is_symlink() and original.resolve().is_relative_to(downloads),
                    'required native capture source missing/aliased: ' + str(original))
            target = destination / name / ('macos-' + str(major))
            target.mkdir(parents=True)
            for path in sorted(original.rglob('*')):
                require(not path.is_symlink(), 'native capture contains an aliased member')
                relative = path.relative_to(original)
                result = target / relative
                if path.is_dir():
                    result.mkdir(parents=True, exist_ok=True)
                    continue
                require(path.is_file(), 'native capture contains a special member')
                count += 1
                total += path.stat().st_size
                require(count <= 100000 and total <= 16 << 30, 'native corpus assembly exceeds bounds')
                result.parent.mkdir(parents=True, exist_ok=True)
                os.link(path, result)
        inputs.append({'id': name, 'path': str(destination / name)})
    result = destination / 'inputs.json'
    with result.open('x', encoding='utf-8') as stream:
        json.dump({'schema': 1, 'inputs': inputs}, stream, indent=2)
        stream.write('\n')
    return result
