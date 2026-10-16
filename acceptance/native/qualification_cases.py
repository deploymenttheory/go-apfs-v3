"""Independent native verification inventories from reviewed reference cases."""
from pathlib import Path

from qualification import read_document, require


HOSTS = ('Linux', 'Windows', 'macOS')
SOURCES = (15, 26, 27)
ROOT = Path(__file__).resolve().parents[2]


def require_axes(args):
    require(args.producers == '15,26,27' and args.consumers == 'Linux,Windows,macOS',
            'complete native source and portable host axes required')


def reference_cases(corpus, corpus_id, manifest='manifest.json', sources=SOURCES, direct=False):
    catalog = read_document(ROOT / 'acceptance/qualification/corpus.json')
    entry = next(e for e in catalog['entries'] if e['id'] == corpus_id)
    references = [c for c in entry['captures'] if c['manifest'].partition('/')[0].startswith('macos-')
                  and c['manifest'].partition('/')[2] == manifest]
    require(references, 'reviewed native case contract absent: ' + corpus_id)
    result = []
    for source in sources:
        path = Path(corpus) / manifest if direct else Path(corpus) / f'macos-{source}' / manifest
        document = read_document(path)
        reference = next((c for c in references if c['major'] == source), references[0])
        expected = {c.removeprefix('cases/') for c in reference['cases'] if c.startswith('cases/')}
        ids = [case['id'] for case in document['cases']]
        require(set(ids) == expected and len(ids) == len(expected),
                'native source case inventory differs from reviewed contract')
        result.extend((source, case) for case in document['cases'])
    return result


def image_targets(corpus, outputs, corpus_id, host_prefix, patterns,
                  manifest='manifest.json', sources=SOURCES):
    """Declare every source/profile/encoding/host before verification starts."""
    targets = []
    for source, case in reference_cases(corpus, corpus_id, manifest, sources):
        for host in HOSTS:
            for pattern in patterns:
                relative = pattern.format(source=source, case=case['id'], profile=case['id'].split('/')[-1])
                targets.append(Path(outputs) / (host_prefix + host) / relative)
    return targets


def continuation_targets(directory, kind, metadata=False, raw_suffix=False):
    profiles = ('apfs', 'apfs-case-sensitive') if kind == 'apfs' else ('hfsplus', 'hfsx')
    if metadata and kind == 'hfs':
        profiles += ('hfsplus-empty-attributes', 'hfsx-empty-attributes')
    suffix = '.raw.dmg' if raw_suffix else '.dmg'
    return [Path(directory) / f'macos-{source}-{profile}{suffix}'
            for source in SOURCES for profile in profiles]


def image_verification(corpus, outputs, corpus_id, host_prefix, patterns, name, major,
                       manifest='manifest.json', continued=None):
    from qualification import NativeEvidence, ReplayEvidence
    replay = ReplayEvidence(outputs, ROOT)
    replay.bind_input(corpus_id, corpus)
    return NativeEvidence(replay, image_targets(corpus, outputs, corpus_id, host_prefix,
        patterns, manifest), ROOT, outputs, name, major,
        continuation=(lambda case, file: continued is not None and continued(file['path'])))


def continuation_verification(directory, kind, name, major, metadata=False, raw_suffix=False):
    from qualification import NativeEvidence, ReplayEvidence
    replay = ReplayEvidence(directory, ROOT)
    return NativeEvidence(replay, continuation_targets(directory, kind, metadata, raw_suffix),
                          ROOT, directory, name, major, continuation=True)


def recovery_verification(references, outputs, diagnostics, major, apfs=False):
    from qualification import NativeEvidence, ReplayEvidence
    corpus_id = 'apfs-recovery' if apfs else 'hfs-recovery'
    replay = ReplayEvidence(outputs.parent, ROOT)
    replay.bind_input(corpus_id, references, prefix=f'macos-{major}')
    targets = [Path(outputs) / (case['id'] + suffix)
               for _, case in reference_cases(references, corpus_id, 'recovery.json', (major,), direct=True)
               for suffix in ('-UDRO.dmg', '-UDZO.dmg', '-edited.dmg')]
    if apfs:
        targets += [Path(outputs) / ('fault-' + stage + '.dmg')
                    for stage in ('data', 'metadata', 'ephemeral', 'mapping', 'superblock', 'block-zero')]
    return NativeEvidence(replay, targets, ROOT, diagnostics, corpus_id, major,
        continuation=lambda case, file: file['path'].endswith('-UDRO.dmg') or '/fault-' in file['path'])


def packaging_verification(args, repacking=False):
    from encrypted_output import BUILD_PROFILES
    from qualification import NativeEvidence, ReplayEvidence
    require_axes(args)
    corpus_id = 'image-repacking' if repacking else 'image-building'
    replay = ReplayEvidence(args.outputs, ROOT)
    replay.bind_input(corpus_id, args.corpus)
    targets = []
    for source, case in reference_cases(args.corpus, corpus_id):
        profile = case['id'].split('/')[-1]
        for host in HOSTS:
            base = Path(args.outputs) / (corpus_id + '-' + host) / f'macos-{source}' / profile
            for encoding in ('UDRO', 'UDZO'):
                targets.append(base / (encoding + '.dmg'))
                encrypted = ((profile == 'hfsx-apm-raw' and encoding == 'UDRO') or
                    (profile != 'hfsx-apm-raw' and encoding == 'UDZO')) if repacking else (profile, encoding) in BUILD_PROFILES
                if encrypted:
                    targets.append(base / 'encrypted' / (encoding + '.dmg'))
                if repacking and profile == 'hfsplus-gpt' and encoding == 'UDZO':
                    targets += [base / p / 'UDZO.dmg' for p in ('rewrapped', 'decrypted')]
            if not repacking:
                encoding = 'UDZO' if case['expected']['caseSensitive'] else 'UDRO'
                targets += [base / 'file-compression' / p / (encoding + '.dmg') for p in ('zlib', 'none')]
                if profile == 'apfs':
                    targets.append(base / 'empty/UDZO.dmg')
    if repacking:
        replay.bind_input('encrypted-dmg', args.corpus.parent / 'encrypted-dmg')
        for source in SOURCES:
            for host in HOSTS:
                base = Path(args.outputs) / ('image-repacking-' + host) / f'macos-{source}/hfsplus-encrypted-raw'
                targets += [base / 'UDZO.dmg', base / 'encrypted/UDZO.dmg']
    else:
        targets += image_targets(args.corpus, args.outputs, corpus_id, 'image-building-',
            ['macos-{source}/containers/{case}/UDRO.dmg', 'macos-{source}/containers/{case}/UDZO.dmg'],
            manifest='containers/manifest.json')
        for source in SOURCES:
            for host in HOSTS:
                targets.append(Path(args.outputs) / ('image-building-' + host) /
                               f'macos-{source}/containers/group/encrypted/UDZO.dmg')
    def modified(case, file):
        name = file['path']
        return (not repacking and '/encrypted/' not in name and
                ('/containers/' in name or '/file-compression/' in name or
                 case['native_case'].split('/')[-1] in ('apfs', 'apfs-case-sensitive')))
    return NativeEvidence(replay, targets, ROOT, args.outputs, corpus_id, args.expected_major,
                          continuation=modified)
