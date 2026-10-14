#!/usr/bin/env python3
"""Check retained qualification evidence using regular files, without native tools."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import zipfile

FAMILIES = {'apfs', 'hfs', 'hfs-fragmented', 'permissions', 'statistics',
            'copy-permissions', 'statistics-transitions'}
MAJORS = {15, 26, 27}
HOSTS = {'Linux', 'Windows', 'macOS'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate(root, index, portable_artifacts=None):
    checked = set()

    def file_record(record):
        key = (record['path'], record['sha256'], record.get('decodedSHA256'))
        if key in checked:
            return
        path = root / record['path']
        require(path.resolve().is_relative_to(root.resolve()), 'evidence path outside repository')
        data = path.read_bytes()
        require(digest(data) == record['sha256'], 'file digest: ' + record['path'])
        if 'decodedSHA256' in record:
            original = gzip.decompress(data) if path.suffix == '.gz' else data
            require(digest(original) == record['decodedSHA256'],
                    'decoded digest: ' + record['path'])
        checked.add(key)

    def references(value):
        if isinstance(value, dict):
            # Native provenance also records paths inside the captured Apple
            # source tree. Only repository paths identify standalone files.
            if ('path' in value and 'sha256' in value and
                    value['path'].startswith(('docs/', 'acceptance/'))):
                file_record(value)
            members = value.get('files', [])
            archived_members = (members and 'archive' in value and
                                all('path' in member for member in members))
            if archived_members:
                file_record(value['archive'])
                with zipfile.ZipFile(root / value['archive']['path']) as z:
                    require(set(z.namelist()) == {m['path'] for m in members}, 'historical archive inventory')
                    for member in members:
                        require(digest(z.read(member['path'])) == member['sha256'], 'historical member digest')
            for key, child in value.items():
                if archived_members and key == 'files':
                    continue
                references(child)
        elif isinstance(value, list):
            for child in value:
                references(child)

    references(index)
    verdict = index['qualificationVerdict']
    require(isinstance(verdict, dict), 'missing qualification verdict')
    require(index['status'] == 'qualified' and verdict['conclusion'] == 'success', 'pending qualification')
    ledger = json.loads((root / verdict['ledger']['path']).read_text())
    references(ledger)

    def snapshot(name):
        record, = [r for r in ledger['metadataSnapshots'] if r['path'].endswith('/' + name)]
        return json.loads(gzip.decompress((root / record['path']).read_bytes()))

    commits = [snapshot(kind + '-commit.json.gz') for kind in ('source', 'execution', 'merged')]
    require({c['tree']['sha'] for c in commits} == {ledger['identicalGitTree']}, 'construction Git trees differ')
    require([c['sha'] for c in commits] == [ledger[k] for k in ('sourceRevision', 'executionRevision', 'mergedRevision')],
            'construction revision binding')
    native_run, portable_run = snapshot('native-run.json.gz'), snapshot('portable-run.json.gz')
    require(all(r['status'] == 'completed' and r['conclusion'] == 'success' and
                r['head_sha'] == ledger['sourceRevision'] for r in (native_run, portable_run)), 'full regression verdict')
    native = [j for p in snapshot('native-jobs.json.gz') for j in p['jobs']]
    portable = [j for p in snapshot('portable-jobs.json.gz') for j in p['jobs']]
    original = [j for p in snapshot('native-original-jobs.json.gz') for j in p['jobs']]
    original_by_id = {j['id']: j for j in original}
    require(len(original_by_id) == len(original), 'duplicate original job')
    skips = {'hfs_edits / journal_recovery',
             'Record offline editing ${{ inputs.offline_reference_kind }} edit controls (macOS ${{ matrix.major }})',
             'offline_edits / Validate archived native controls and portable outputs'}
    require({j['name'] for j in native if j['conclusion'] == 'skipped'} == skips, 'unexpected native skip')
    require(all(j['conclusion'] == 'success' or j['name'] in skips for j in native), 'unsuccessful native job')
    require(all(j['conclusion'] == 'success' for j in portable), 'unsuccessful portable job')
    for workflow, jobs in zip(ledger['workflows'], (portable, native)):
        require(workflow['successfulJobs'] == sum(j['conclusion'] == 'success' for j in jobs), 'workflow job count')
    require(any(j['name'] == 'quality' and j['conclusion'] == 'success' for j in portable), 'missing full quality gate')
    require(any(j['name'] == 'Require all filesystem compatibility checks' and j['conclusion'] == 'success'
                for j in native), 'missing full compatibility gate')

    artifacts = {a['id']: a for p in snapshot('native-artifacts.json.gz') for a in p['artifacts']}

    def job_record(record, expected):
        actual = original_by_id[record['id']]
        require(actual['name'].rsplit(' / ', 1)[-1] == expected and actual['conclusion'] == 'success',
                'missing successful executed job: ' + expected)
        require(record['conclusion'] == 'success' and record['headRevision'] == actual['head_sha'], 'job revision')

    def archive(record):
        a = artifacts[record['artifact']['id']]
        require(a['name'] == record['artifact']['name'] and a['digest'] == 'sha256:' + record['archive']['sha256'],
                'original GitHub artifact digest')
        z = zipfile.ZipFile(root / record['archive']['path'])
        names = [n for n in z.namelist() if not n.endswith('/')]
        require(len(names) == len(set(names)), 'duplicate archive member')
        require(set(names) == {f['member'] for f in record['archive']['files']}, 'archive member inventory')
        for member in record['archive']['files']:
            p = PurePosixPath(member['member'])
            require(not p.is_absolute() and '..' not in p.parts, 'unsafe archive member')
            data = z.read(member['member'])
            require(digest(data) == member['sha256'] and len(data) == member['bytes'], 'archive member digest')
        return z

    require(set(ledger['families']) == FAMILIES, 'seven required capabilities')
    total_outputs = total_cases = 0
    for family, entry in ledger['families'].items():
        captures, replays, readbacks = entry['nativeCaptures'], entry['portableReplays'], entry['appleVerdicts']
        require(len(captures) == 3 and {c['major'] for c in captures} == MAJORS, family + ' source versions')
        require(len(replays) == 9 and {(r['major'], r['host']) for r in replays} ==
                {(m, h) for m in MAJORS for h in HOSTS}, family + ' portable coverage')
        require(len(readbacks) == 3 and {v['major'] for v in readbacks} == MAJORS, family + ' Apple runners')
        captures_by_id = {}
        for capture in captures:
            job_record(capture['job'], f'Record Apple {family} editing controls (macOS {capture["major"]})')
            with archive(capture) as z:
                data = z.read(capture['manifestMember'])
                require(digest(data) == capture['manifestSHA256'], 'native manifest digest')
                manifest = json.loads(data)
                require(manifest['producer']['revision'] == ledger['executionRevision'], 'native execution revision')
                require(digest(z.read(f'macos-{capture["major"]}/commands.json')) == manifest['commandsSHA256'],
                        'native command digest')
                for source, expected in manifest['producer']['sources'].items():
                    require(digest(z.read(f'macos-{capture["major"]}/{source}')) == expected, 'collector source digest')
                for item in capture['recordedArchives']:
                    require(digest(z.read(f'macos-{capture["major"]}/' + item['image'])) == item['sha256'],
                            'original native image/observation digest')
                total_cases += len(manifest['cases'])
                captures_by_id[capture['artifact']['id']] = manifest
        replay_by_id = {}
        for replay in replays:
            job_record(replay['job'], f'Edit offline editing {family} controls ({replay["host"]}, macOS {replay["major"]} sources)')
            require(replay['artifact']['digest'] == artifacts[replay['artifact']['id']]['digest'], 'portable artifact digest')
            replay_by_id[replay['artifact']['id']] = replay
        verified = {}
        for readback in readbacks:
            job_record(readback['job'], f'Apple checks and continued writes of offline editing {family} outputs (macOS {readback["major"]})')
            with archive(readback) as z:
                observed = json.loads(z.read(readback['verdictMember']))
                require(observed == readback['verdict'], 'unaltered Apple verdict')
                commands = json.loads(z.read(readback['diagnosticsMember']))
                if 'commandsSHA256' in observed:
                    require(digest(z.read(readback['diagnosticsMember'])) == observed['commandsSHA256'], 'Apple commands digest')
                members = [c['argv'][-1].removeprefix('artifacts/outputs/') for c in commands
                           if c['argv'][:2] == ['hdiutil', 'verify'] and c['status'] == 0]
                require(len(members) == len(set(members)) == observed.get('verified', observed.get('verifiedOutputs')),
                        'native verified output count')
                require(sorted(members) == readback['verifiedLinuxMembers'], 'native verified members')
                checkers = [c for c in commands if
                            PurePosixPath(c['argv'][1] if c['argv'][0] == 'sudo' else c['argv'][0]).name
                            in ('fsck_apfs', 'fsck_hfs') or c['argv'][:2] == ['diskutil', 'verifyVolume']]
                require(checkers and all(c['status'] == 0 for c in checkers) and
                        len(checkers) == readback['checkerInvocations'], 'successful native filesystem checks')
                verified[readback['artifact']['id']] = set(members)
        outputs = entry['outputs']
        require(len({o['relativePath'] for o in outputs}) == len(outputs), 'duplicate output binding')
        for output in outputs:
            require(re.fullmatch('[0-9a-f]{64}', output['sha256']) and output['bytes'] > 0, 'invalid output digest/length')
            require(output['portableHostsByteIdentical'] and len(output['hosts']) == 3 and
                    {h['host'] for h in output['hosts']} == HOSTS, 'missing output host')
            manifest = captures_by_id[output['nativeCaptureArtifactID']]
            case = manifest['cases'][int(output['nativeCasePointer'].rsplit('/', 1)[-1])]
            parts = PurePosixPath(output['relativePath']).parts
            case_id = parts[1] if len(parts) > 2 else parts[1].removesuffix('-UDRO.dmg').removesuffix('-UDZO.dmg')
            require(case['id'] == case_id and parts[0] == f'macos-{output["sourceMajor"]}', 'output/native case binding')
            require(output['sourceMajor'] == manifest['major'], 'output/native source version')
            for host in output['hosts']:
                replay = replay_by_id[host['artifactID']]
                require((replay['host'], replay['major']) == (host['host'], output['sourceMajor']), 'output replay binding')
                require(host['tarMember'] == f'offline-editing-{family}-{host["host"]}/' + output['relativePath'], 'output member binding')
            require(set(output['appleVerdictArtifactIDs']) == set(verified), 'missing Apple output verdict')
            for aid in output['appleVerdictArtifactIDs']:
                require(f'offline-editing-{family}-Linux/' + output['relativePath'] in verified[aid], 'output not checked by Apple')
        require(all(len(v) == len(outputs) for v in verified.values()), 'unbound verified outputs')
        if portable_artifacts is not None:
            expected = {h['tarMember']: (o['sha256'], o['bytes']) for o in outputs for h in o['hosts']}
            seen = set()
            for replay in replays:
                data = (portable_artifacts / f'{replay["artifact"]["id"]}.zip').read_bytes()
                require('sha256:' + digest(data) == replay['artifact']['digest'], 'downloaded portable artifact digest')
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    require(z.namelist() == [replay['tarMember']], 'portable archive inventory')
                    packed = z.read(replay['tarMember'])
                require(digest(packed) == replay['tarSHA256'], 'portable tar digest')
                with tarfile.open(fileobj=io.BytesIO(packed), mode='r|gz') as tar:
                    for member in tar:
                        if member.isdir():
                            continue
                        require(member.isfile() and member.name in expected and member.name not in seen,
                                'unexpected or duplicate portable member')
                        d, size = hashlib.sha256(), 0
                        with tar.extractfile(member) as stream:
                            while chunk := stream.read(1 << 20):
                                d.update(chunk)
                                size += len(chunk)
                        require((d.hexdigest(), size) == expected[member.name], 'actual portable output digest/length')
                        seen.add(member.name)
            require(seen == set(expected), 'missing actual portable output')
        total_outputs += len(outputs)
    require((total_cases, total_outputs) == (72, 180), 'complete source/output inventory')
    require(ledger['coverage']['hostOutputs'] == total_outputs * 3, 'host output count')
    profiles = ledger['hfsCopyProfiles']
    require(len(profiles) == 9 and len({p['jobID'] for p in profiles}) == 9, 'nine HFS copy jobs')
    for entry in profiles:
        require(len(entry['profiles']) == 4 and all(p['elapsedSeconds'] < p['deadlineSeconds'] == 300
                for p in entry['profiles']), 'bounded HFS copy profiles')
        log = gzip.decompress((root / entry['log']['path']).read_bytes()).decode(errors='replace')
        timings = re.findall(r'--- PASS: (TestNativeHFS(?:Journaled)?ImageCopy) \(([\d.]+)s\)', log)
        children = re.findall(r'--- PASS: (TestNativeHFS(?:Journaled)?ImageCopy/macos-\d+/(?:hfsplus|hfsx)) \(', log)
        require(len(children) == len(set(children)) == 4, 'nonempty distinct HFS copy selectors')
        require([(p['test'], p['elapsedSeconds']) for p in entry['profiles']] ==
                [(test, float(elapsed)) for test, elapsed in timings], 'actual HFS profile timings')
    return len(checked), ledger['coverage']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path)
    parser.add_argument('--portable-artifacts', type=Path,
                        help='also hash original portable artifacts saved as ARTIFACT_ID.zip')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    index_path = args.index or root / 'docs/offline-editing-evidence.json'
    try:
        files, coverage = validate(root, json.loads(index_path.read_text()), args.portable_artifacts)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        sys.exit('Invalid offline editing evidence: ' + str(error))
    print(f'Validated {files} retained file digests; {coverage["nativeCaptures"]} native captures, '
          f'{coverage["portableReplays"]} portable replays, {coverage["appleVerdicts"]} Apple verdicts '
          f'and {coverage["hostOutputs"]} output bindings.')
