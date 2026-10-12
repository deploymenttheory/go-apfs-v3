"""Shared native/portable directory-state comparison with explicit clock policy."""
from verify_preservation import require

STAMP = 1749283750


def compare(actual, expected, before, moved=None, changed=None):
    if moved is None:
        moved = {'Fixture/Catalog/Forked': 'Fixture/independent',
                 'Fixture/Catalog/linked': 'Fixture/alias', 'Fixture/small': ''}
    if changed is None:
        changed = lambda path: path in ('Fixture', 'Fixture/small') or path.startswith('Fixture/Catalog')
    observed = {entry['path']: entry for entry in actual['entries']}
    want = {entry['path']: entry for entry in expected['entries']}
    original = {entry['path']: entry['object'] for entry in before['entries']}
    require(set(observed) == set(want), 'directory paths exactly match native operations')
    native_to_go, go_to_native = {}, {}
    for path, entry in want.items():
        got = observed[path]
        native_id, go_id = entry['object'], got['object']
        require(native_to_go.get(native_id, go_id) == go_id, 'native aliases remain shared')
        require(go_to_native.get(go_id, native_id) == native_id, 'distinct native identities remain distinct')
        native_to_go[native_id], go_to_native[go_id] = go_id, native_id
        source = moved.get(path, path)
        if source in original:
            require(go_id == original[source], 'original inode preserved: ' + path)
        else:
            require(go_id not in set(original.values()), 'new entries do not reuse original inodes')
        entry = dict(entry)
        if changed(path):
            entry['changeNS'] = STAMP * 1000000000
            if entry['mode'] & 0o170000 == 0o040000:
                entry['modifyNS'] = STAMP * 1000000000
        for key in ('mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS', 'changeNS',
                    'accessNS', 'size', 'links', 'sha256', 'target', 'rawAttributes'):
            if key in entry:
                require(got.get(key) == entry[key], f'{path} {key}: {got.get(key)} != {entry[key]}')

