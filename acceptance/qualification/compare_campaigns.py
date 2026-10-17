"""Compare independently admitted original campaign evidence.

This module compares case identities and deterministic plaintext bytes. Its
input indexes must come from the existing complete-workflow admission, not from
successful process statuses or caller-authored plans. It executes no tests or
Apple tools and cannot promote inputs or change required checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

import ci_reuse
import native_reuse
from release_assets import GitHub, fetch, read_document, require


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def build_environment(environment, stage):
    """Keep actual code-generation settings; installation paths are transport."""
    identity = {key: environment[key] for key in
                ('os', 'architecture', 'version', 'build', 'toolchain', 'race', 'tools')}
    if stage == 'replay':
        settings = [flag.removeprefix('go-environment=') for flag in environment['flags']
                    if flag.startswith('go-environment=')]
        require(len(settings) == 1, 'original compiler/build environment missing or ambiguous')
        settings = json.loads(settings[0])
        require(isinstance(settings, dict), 'original compiler environment is not an object')
        # Actual tool hashes remain required. These locations can differ across
        # equivalent runner installations without changing their executable bytes.
        for location in ('GOROOT', 'GOTOOLDIR'):
            settings.pop(location, None)
        identity['go_environment'] = settings
    return identity


def randomized_output(case, path):
    variant = case.get('variant', '')
    return ('/encrypted/' in path or 'encrypted-aes' in variant or
            'encrypted-input/rewrapped' in variant)


def case_identity(item, invocation):
    stage, case = invocation['stage'], dict(item['case'])
    case['outputs'] = list(case.get('outputs') or [])
    if stage != 'replay':
        # Native corpus names can contain the actual source/output digest.
        # Case names, source versions, variants, tools and every native output
        # scope remain required; their actual bytes were individually admitted.
        case.pop('corpus', None)
    inputs = []
    if stage == 'replay' or stage == 'capture' and invocation['production_sha256']:
        for source in item['inputs']:
            use = source['use']
            if use in ('retained', 'native-capture'):
                use = 'reference'
            identity = source['source_sha256']
            if source['use'] == 'native-continuation':
                require(case.get('continuation') is True, 'mutable source is not a continuation case')
                # Native writes can set current timestamps. Full native/Go/native
                # admission must prove each fresh source/output; the index keeps
                # its unique original hash, without asserting byte equality.
                identity = 'individually-verified-native-continuation'
            inputs.append({'id': source['id'], 'use': use, 'source_sha256': identity})
    identity = {'stage': stage, 'case': case,
                'environment': build_environment(invocation['environment'], stage),
                'inputs': inputs, 'required_controls': item['required_controls']}
    if case.get('continuation'):
        # Journaled/nonjournaled chains can share case names and mutable input
        # IDs. Their original artifact identifies the independently authenticated
        # executor/matrix slot. Preserve it until an explicit semantic mapping
        # exists; changing timestamps cannot make distinct chains duplicates.
        path = PurePosixPath(invocation['original_receipt']['path'])
        require(len(path.parts) > 1, 'native continuation lost its original executor context')
        identity['continuation_executor'] = path.parts[0]
    return identity


def output_identity(item, invocation):
    case, stage = item['case'], invocation['stage']
    expected = list(case.get('outputs') or [])
    outputs = item['outputs']
    require([file['path'] for file in outputs] == expected,
            'case output inventory differs from the admitted declarations')
    plaintext, checked = [], []
    for file in outputs:
        name = file['path']
        if stage != 'replay' or case.get('continuation') or randomized_output(case, name):
            checked.append(name)
        elif name.endswith(('.dmg', '.raw', '.raw.gz', '.appledouble')):
            plaintext.append(file)
        else:
            require(PurePosixPath(name).suffix == '.json',
                    'unclassified deterministic output requires a comparison policy: ' + name)
            # Diagnostic/workspace manifests can include original source paths.
            # The unchanged assertions and independent native check establish
            # their semantics; this is not a raw-manifest byte-equality claim.
            checked.append(name)
    return {'production_sha256': invocation['production_sha256'],
            'deterministic_plaintext': plaintext, 'admitted_without_byte_comparison': checked}


def inventory(indexes):
    scopes, copies, plaintext, checked = {}, 0, 0, 0
    tests, test_copies = {}, 0
    for index in indexes:
        proof = index['evidence']
        require(proof['schema'] == 1 and len(index['cases']) == proof['qualified_cases'] and
                proof['qualified_cases'] > 0, 'complete admitted case index required')
        expected = {file['sha256'] for file in proof['original_receipts']}
        invocations = {}
        for invocation in index['invocations']:
            sha = invocation['original_receipt']['sha256']
            require(sha in expected and sha not in invocations,
                    'case invocation is missing, duplicated or not admitted')
            invocations[sha] = invocation
        require(set(invocations) == expected, 'original invocation inventory differs from admission')
        seen_tests, tested_invocations = set(), set()
        for item in index['test_executions']:
            sha = item['original_receipt_sha256']
            require(sha in invocations and invocations[sha]['stage'] == 'replay',
                    'Go test has no admitted original replay invocation')
            require(item['package'] and item['status'] in ('pass', 'skip'),
                    'original Go test/package verdict is missing')
            identity = {'package': item['package'], 'test': item.get('test', ''),
                        'status': item['status'],
                        'environment': build_environment(invocations[sha]['environment'], 'replay')}
            key = canonical(identity)
            require((sha, key) not in seen_tests, 'one original Go test was indexed more than once')
            seen_tests.add((sha, key))
            tested_invocations.add(sha)
            if key in tests:
                test_copies += 1
            tests[key] = identity
        require(tested_invocations == {sha for sha, item in invocations.items() if item['stage'] == 'replay'},
                'original Go invocation lost its package/test execution inventory')
        seen = set()
        for item in index['cases']:
            sha = item['original_receipt_sha256']
            require(sha in invocations, 'case has no admitted original invocation')
            invocation = invocations[sha]
            # Independent capture is provenance of the shared reviewed pin,
            # not a new assertion required on every compatible implementation.
            if invocation['stage'] == 'capture' and not invocation['production_sha256']:
                continue
            require(invocation['stage'] in ('capture', 'replay', 'apple-verification'),
                    'unknown execution stage')
            key = canonical(case_identity(item, invocation))
            execution = (sha, key)
            require(execution not in seen, 'one original case was indexed more than once')
            seen.add(execution)
            value = output_identity(item, invocation)
            if key in scopes:
                require(scopes[key]['outputs'] == value,
                        'identical case/input scopes produced conflicting deterministic plaintext')
                copies += 1
                scopes[key]['executions'].append(invocation['origin'])
            else:
                scopes[key] = {'scope': json.loads(key), 'outputs': value,
                               'executions': [invocation['origin']]}
                plaintext += len(value['deterministic_plaintext'])
                checked += len(value['admitted_without_byte_comparison'])
    return {'scopes': scopes, 'repeated_scopes': copies,
            'plaintext_outputs': plaintext, 'outputs_without_byte_comparison': checked,
            'go_tests': tests, 'repeated_go_tests': test_copies}


def compare_indexes(baseline, candidate):
    """Describe scope agreement; complete API/source/pin admission precedes this.

    Missing input/host/race/native obligations or changed plaintext fail agreement.
    Added scopes are reported separately. This function never authenticates its
    own arguments or approves test retirement.
    """
    old, new = inventory(baseline), inventory(candidate)
    missing = sorted(set(old['scopes']) - set(new['scopes']))
    added = sorted(set(new['scopes']) - set(old['scopes']))
    changed = sorted(key for key in set(old['scopes']) & set(new['scopes'])
                     if old['scopes'][key]['outputs'] != new['scopes'][key]['outputs'])
    missing_tests = sorted(set(old['go_tests']) - set(new['go_tests']))
    added_tests = sorted(set(new['go_tests']) - set(old['go_tests']))
    return {'schema': 1, 'kind': 'admitted-case-comparison',
            'scope_agreement': not missing and not changed and not missing_tests,
            'baseline_scopes': len(old['scopes']), 'candidate_scopes': len(new['scopes']),
            'baseline_repeated_scopes': old['repeated_scopes'],
            'candidate_repeated_scopes': new['repeated_scopes'],
            'plaintext_outputs': new['plaintext_outputs'],
            'outputs_without_byte_comparison': new['outputs_without_byte_comparison'],
            'baseline_go_tests': len(old['go_tests']), 'candidate_go_tests': len(new['go_tests']),
            'baseline_repeated_go_tests': old['repeated_go_tests'],
            'candidate_repeated_go_tests': new['repeated_go_tests'],
            'missing_go_tests': [old['go_tests'][key] for key in missing_tests],
            'added_go_tests': [new['go_tests'][key] for key in added_tests],
            'missing': [old['scopes'][key]['scope'] for key in missing],
            'added': [new['scopes'][key]['scope'] for key in added],
            'changed': [{'scope': old['scopes'][key]['scope'],
                         'baseline': old['scopes'][key]['outputs'],
                         'candidate': new['scopes'][key]['outputs']} for key in changed]}


def checkout(root):
    root = Path(root).resolve(strict=True)
    subprocess.run(['git', 'diff', '--quiet', 'HEAD'], cwd=root, check=True)
    require(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'],
                                        cwd=root, text=True).strip(),
            'comparison source roots must have no untracked dependencies')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip()
    require(re.fullmatch('[a-f0-9]{40}', revision) and re.fullmatch('[a-f0-9]{40}', tree),
            'committed source checkout required')
    pin = root / 'acceptance/qualification/references.json'
    require(pin.is_file() and not pin.is_symlink() and pin.stat().st_size <= 64 << 10,
            'both campaigns require the same reviewed Apple input pin')
    subprocess.run(['git', 'ls-files', '--error-unmatch', 'acceptance/qualification/references.json'],
                   cwd=root, check=True, stdout=subprocess.DEVNULL)
    return {'root': str(root), 'revision': revision, 'tree': tree,
            'pin_sha256': hashlib.sha256(pin.read_bytes()).hexdigest()}


def assertion_sources(root):
    """Keep filesystem assertions unchanged while changing their scheduling."""
    root = Path(root)
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root, text=True).split('\0')
    files = {}
    for name in names:
        controls = name.startswith(('acceptance/qualification/', 'internal/qualification/'))
        native = name.startswith('acceptance/native/') and not Path(name).name.startswith('test_')
        if not (name.endswith('_test.go') and not controls or native):
            continue
        path = root / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 << 20,
                'assertion source missing, aliased or too large: ' + name)
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(files, 'filesystem assertion source inventory is empty')
    return files


def nonreceipt_checks(root):
    """Keep uninstrumented source, library-race and cross-build checks intact.

    The complete API admission requires these jobs to execute successfully.
    Preserve their execution definitions as well: registered acceptance cases
    alone cannot prove that a changed library-race selector kept every package.
    """
    path = Path(root) / '.github/workflows/ci.yml'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 << 20,
            'original CI execution definitions are missing or aliased')
    text = path.read_text(encoding='utf-8')
    require(text.count('\njobs:\n') == 1, 'unknown CI layout needs an explicit check-definition policy')
    header, body = text.split('\njobs:\n')
    headers = list(re.finditer(r'^  ([a-z][a-z_0-9]*):\n', body, re.MULTILINE))
    require(headers and len(headers) == len(re.findall(r'^  [^\s#][^\n]*:', body, re.MULTILINE)) and
            not re.search(r'(?:^|[ \t])[&*][A-Za-z_]', text) and
            all(not line.strip() or line.startswith(('  ', '#')) for line in body.splitlines()),
            'unknown CI job layout needs an explicit check-definition policy')
    result = {'workflow_environment': hashlib.sha256(header.encode()).hexdigest()}
    for position, match in enumerate(headers):
        name = match[1]
        if name not in ('source_checks', 'build', 'race_library'):
            continue
        require(name not in result, 'duplicated original CI check definition')
        end = headers[position + 1].start() if position + 1 < len(headers) else len(body)
        # Whole-job scheduling can change; successful original execution is
        # still mandatory. Steps, selectors, matrices, environments, tools,
        # runner labels and process deadlines remain byte-bound.
        section = ''.join(line for line in body[match.start():end].splitlines(keepends=True)
                          if not line.startswith(('    needs:', '    if:')))
        result[name] = hashlib.sha256(section.encode()).hexdigest()
    require(len(result) == 4, 'required original source/library-race/cross-build definition missing')
    return result


def checked_pin_sources(client, source_roots, directory, verifier, execute=subprocess.run):
    """Admit the exact permanent release once; Go computes source identities."""
    directory = Path(directory)
    directory.mkdir(parents=True)
    pin = read_document(Path(source_roots[0]['root']) / 'acceptance/qualification/references.json', 64 << 10)
    require(pin['repository'] == client.repository, 'comparison pin belongs to another repository')
    fetch(pin, directory, client=client)
    result = None
    for number, source in enumerate(source_roots):
        root = Path(source['root'])
        response = execute([str(verifier), '-root', str(root), '-check-references',
                            str(root / 'acceptance/qualification/references.json'),
                            '-bundle-dir', str(directory), '-reference-identities'],
                           check=True, capture_output=True, text=True)
        original = response.stdout
        identities = json.loads(original)
        require(isinstance(identities, list) and identities, 'verified pin has no source identities')
        if result is not None:
            require(identities == result, 'source checkouts interpret the reviewed pin differently')
        result = identities
        (directory / f'sources-{number}.json').write_text(original, encoding='utf-8')
    return result


def verify_replay_pin(indexes, sources):
    """The same pin file is insufficient if execution used different bytes."""
    expected = {(source['id'], source['source_major']): source for source in sources}
    require(len(expected) == len(sources), 'reviewed source identity inventory is duplicated')
    for index in indexes:
        invocations = {item['original_receipt']['sha256']: item for item in index['invocations']}
        for item in index['cases']:
            if invocations[item['original_receipt_sha256']]['stage'] != 'replay':
                continue
            for source in item['inputs']:
                if source['use'] == 'native-continuation':
                    require(item['case'].get('continuation') is True,
                            'fresh modified source is not a declared continuation')
                    continue
                reference = expected.get((source['id'], item['case'].get('source', 0)))
                require(reference, 'replay source is absent from the reviewed pin: ' + source['id'])
                if source['use'] == 'current-go':
                    require(reference['capture_class'] == 'current-go-experiment',
                            'independent Apple input was relabelled as current-Go data')
                else:
                    require(source['use'] in ('retained', 'native-capture') and
                            source['source_sha256'] == reference['source_sha256'],
                            'replay actually used different bytes from the reviewed pin: ' + source['id'])


def admit_campaign(client, sources, runs, directory, verifier, execute=subprocess.run, reference_assets=None):
    """Run the existing complete API admission and the Go inspector once per rail."""
    root, tree = Path(sources['root']), sources['tree']
    indexes, reports = [], {}
    for workflow, run_id in zip(('ci', 'native'), runs):
        require(type(run_id) is int and run_id > 0, 'explicit original workflow IDs required')
        run = client.request(f'/repos/{client.repository}/actions/runs/{run_id}')
        require(run['id'] == run_id and run['path'] == f'.github/workflows/{workflow}.yml' and
                run['repository']['full_name'] == client.repository and
                run['head_repository']['full_name'] == client.repository and
                run['status'] == 'completed' and run['conclusion'] == 'success' and
                (run['event'] == 'pull_request' or run['event'] in ('push', 'workflow_dispatch', 'schedule')
                 and run['head_branch'] == 'main'),
                'comparison requires a complete trusted original ' + workflow + ' workflow')
        target = Path(directory) / workflow

        def inspect(command, **kwargs):
            if command[:3] != ['go', 'run', './acceptance/qualification']:
                return execute(command, cwd=root, **kwargs)
            require('-check-execution-evidence' in command,
                    'comparison can invoke only ordinary-file evidence inspection')
            result = execute([str(verifier), '-root', str(root), *command[3:], '-execution-index'],
                             cwd=root, **kwargs)
            if result.returncode == 0:
                index = json.loads(result.stdout)
                require(index['evidence']['origin']['run'] == str(run_id),
                        'case index lost its original workflow origin')
                (target / 'index.json').write_text(result.stdout, encoding='utf-8')
                result.stdout = json.dumps(index['evidence'])
            return result

        controller = ci_reuse if workflow == 'ci' else native_reuse
        options = {'execute': inspect}
        if workflow == 'ci':
            options['reference_assets'] = reference_assets
            options['source_root'] = root
        reports[workflow] = controller.qualify(client, run, tree, target, **options)
        indexes.append(read_document(target / 'index.json', 128 << 20))
    return {'sources': sources, 'reports': reports, 'indexes': indexes}


def compare_campaigns(client, baseline_root, candidate_root, baseline_runs, candidate_runs, workspace):
    """Admit both complete benches; an index cannot authenticate itself."""
    require(len(baseline_runs) == len(candidate_runs) == 2,
            'both campaigns require their complete CI and native workflow IDs')
    require(baseline_runs[0] != candidate_runs[0] and baseline_runs[1] != candidate_runs[1],
            'baseline and candidate must be independent original executions')
    baseline, candidate = checkout(baseline_root), checkout(candidate_root)
    require(baseline['pin_sha256'] == candidate['pin_sha256'], 'reviewed Apple input pins differ')
    old_assertions, new_assertions = assertion_sources(baseline['root']), assertion_sources(candidate['root'])
    require(old_assertions == new_assertions,
            'filesystem assertions or native helper sources changed; scheduling equivalence is unproven')
    old_checks, new_checks = nonreceipt_checks(baseline['root']), nonreceipt_checks(candidate['root'])
    require(old_checks == new_checks,
            'source/library-race/cross-build execution definitions changed; equivalence is unproven')
    workspace = Path(workspace).resolve()
    require(not workspace.exists() and not workspace.is_symlink() and
            all(not workspace.is_relative_to(Path(source['root'])) for source in (baseline, candidate)),
            'comparison needs absent managed scratch outside source checkouts')
    workspace.mkdir(parents=True)
    verifier = workspace / ('qualification.exe' if os.name == 'nt' else 'qualification')
    # The current inspector reads each original checkout through -root. It
    # neither invokes acceptance tests nor executes a native filesystem program.
    inspector_root = Path(__file__).resolve().parents[2]
    subprocess.run(['go', 'build', '-o', str(verifier), './acceptance/qualification'],
                   cwd=inspector_root, check=True)
    pinned_sources = checked_pin_sources(client, (baseline, candidate), workspace / 'references', verifier)
    old = admit_campaign(client, baseline, baseline_runs, workspace / 'baseline', verifier,
                         reference_assets=workspace / 'references')
    new = admit_campaign(client, candidate, candidate_runs, workspace / 'candidate', verifier,
                         reference_assets=workspace / 'references')
    verify_replay_pin(old['indexes'], pinned_sources)
    verify_replay_pin(new['indexes'], pinned_sources)
    productions = {invocation['production_sha256'] for campaign in (old, new)
                   for index in campaign['indexes'] for invocation in index['invocations']
                   if invocation['production_sha256']}
    require(len(productions) == 1, 'campaigns qualified different filesystem production code')
    report = compare_indexes(old['indexes'], new['indexes'])
    report.update({'baseline': {'sources': baseline, 'runs': list(baseline_runs)},
                   'candidate': {'sources': candidate, 'runs': list(candidate_runs)},
                   'production_sha256': productions.pop(),
                   'assertion_sources': old_assertions,
                   'nonreceipt_checks': old_checks,
                   'reviewed_sources': pinned_sources,
                   'inspector_sha256': hashlib.sha256(verifier.read_bytes()).hexdigest()})
    (workspace / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    for side in ('baseline', 'candidate'):
        parser.add_argument('--' + side + '-root', required=True, type=Path)
        parser.add_argument('--' + side + '-ci-run', required=True, type=int)
        parser.add_argument('--' + side + '-native-run', required=True, type=int)
    parser.add_argument('--workspace', required=True, type=Path)
    args = parser.parse_args()
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    if not token:
        # Keep authentication in memory; only the fixed GitHub API receives it.
        token = subprocess.check_output(['gh', 'auth', 'token'], text=True).strip()
    client = GitHub(args.repository, token)
    report = compare_campaigns(client, args.baseline_root, args.candidate_root,
                               (args.baseline_ci_run, args.baseline_native_run),
                               (args.candidate_ci_run, args.candidate_native_run), args.workspace)
    print(json.dumps(report, indent=2))
    return 0 if report['scope_agreement'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
