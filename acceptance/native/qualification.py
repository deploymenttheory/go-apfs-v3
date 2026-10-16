"""Check portable execution evidence before Apple qualifies its output bytes.

The file-only checks import on every host. Native tools remain in the original
disposable-VM programs; this module never mounts or creates a filesystem.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tempfile


ACCEPTANCE_PACKAGE = 'github.com/deploymenttheory/go-apfs-v3/acceptance'
MAX_RECEIPT = 32 << 20
MAX_EVENTS = 512 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate evidence field: ' + key)
        result[key] = value
    return result


def read_document(path, maximum=MAX_RECEIPT):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            'missing/oversized evidence document: ' + str(path))
    with path.open('r', encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def canonical(value):
    # Go struct fields retain their declared order in the received document.
    # These contracts contain integers, strings and arrays; no float coercion.
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    for value, escape in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                          ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        text = text.replace(value, escape)
    return text.encode('utf-8')


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'ordinary evidence file required: ' + str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(64 << 10), b''):
            digest.update(data)
    return digest.hexdigest()


def portable_path(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name and
            not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
            'unsafe evidence member path')
    return PurePosixPath(name)


def verify_file(root, record):
    relative = portable_path(record['path'])
    target = Path(root).joinpath(*relative.parts)
    # Parent aliases must not make archive evidence refer outside its tree.
    require(target.resolve().is_relative_to(Path(root).resolve()), 'evidence member escapes root')
    require(target.is_file() and not target.is_symlink() and
            target.stat().st_size == record['bytes'] and file_digest(target) == record['sha256'],
            'changed/missing evidence member: ' + record['path'])


def source_identities(root):
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others',
                                     '--exclude-standard', '-z'], cwd=root).decode().rstrip('\0').split('\0')
    production, contract = [], []
    for name in sorted(paths):
        if name.startswith(('.github/', 'docs/', 'acceptance/testdata/')) or name.endswith('.md') or name == 'AGENTS.md':
            continue
        harness = name.startswith(('acceptance/', 'internal/qualification/'))
        if not harness and name not in ('go.mod', 'go.sum') and Path(name).suffix not in ('.go', '.s', '.S', '.c', '.h', '.syso'):
            continue
        if name.endswith('_test.go') and not harness:
            continue
        if harness and (not name.endswith(('.go', '.json')) or name == 'acceptance/qualification/corpus.json' or name.startswith('acceptance/native/')):
            continue
        source = Path(root) / name
        if name.endswith('.go'):
            require(not any(line.strip().startswith(('//go:embed ', '#cgo '))
                            for line in source.read_text(encoding='utf-8').splitlines()),
                    'embedded or external build inputs require an explicit qualification identity contract')
        record = {'path': name, 'bytes': source.stat().st_size, 'sha256': file_digest(source)}
        (contract if harness else production).append(record)
    require(production and contract, 'actual source identities missing')
    return identity(production), identity(contract)


def verify_events(path, plan, optional=()):
    require(path.stat().st_size <= MAX_EVENTS, 'execution stream exceeds bound')
    states = {name: 'absent' for name in plan['required_runs']}
    package_started, package_passed = False, False
    package = ACCEPTANCE_PACKAGE if plan['stage'] == 'replay' else 'apple-native'
    with path.open('r', encoding='utf-8') as stream:
        for line in stream:
            require(len(line) <= 8 << 20, 'execution event exceeds bound')
            event = json.loads(line, object_pairs_hook=unique_object)
            action, test = event.get('Action'), event.get('Test', '')
            require(action not in ('fail', 'build-fail'), 'execution/build failed')
            if event.get('Package') != package:
                continue
            if not test:
                if action == 'start':
                    require(not package_started and not package_passed, 'duplicate package execution')
                    package_started = True
                elif action == 'pass':
                    require(package_started and not package_passed, 'package completion out of order')
                    package_passed = True
                elif action == 'skip':
                    raise ValueError('acceptance package skipped')
                continue
            if test in optional:
                continue
            require(test in states, 'unplanned Go execution: ' + test)
            if action == 'run':
                require(package_started and not package_passed and states[test] == 'absent', 'duplicate/out-of-order case')
                states[test] = 'running'
            elif action == 'pass':
                require(states[test] == 'running', 'case verdict without execution')
                states[test] = 'passed'
            elif action == 'skip':
                raise ValueError('required case skipped: ' + test)
            else:
                require(action in ('output', 'pause', 'cont') and states[test] == 'running', 'invalid case event')
    require(package_started and package_passed and all(s == 'passed' for s in states.values()),
            'required case execution incomplete')


class ReplayEvidence:
    """Admit returned execution records, then bind checked files to their cases."""

    def __init__(self, outputs, source_root):
        self.outputs = Path(outputs)
        self.production, self.contract = source_identities(source_root)
        registry = read_document(Path(source_root) / 'acceptance/qualification/registry.json')
        self.optional = {r['function'] for r in (registry['reviewed_exits'] or [])}
        self.entries = []
        self.bound_inputs = {}
        paths = sorted(self.outputs.rglob('.qualification/*/receipt.json'))
        require(paths, 'portable execution receipts missing')
        for path in paths:
            record = read_document(path)
            plan = record['plan']
            require(record['schema'] == plan['schema'] == 1 and plan['stage'] == 'replay', 'wrong execution receipt kind')
            require(plan['production_sha256'] == self.production and plan['contract_sha256'] == self.contract,
                    'portable output belongs to different source/build contract')
            require(identity(plan) == record['fingerprint'], 'portable execution fingerprint differs')
            required = plan['cases']
            require(required and len(required) == len(record['verdicts']), 'case verdict inventory differs')
            require([c['test'] for c in required] == sorted({c['test'] for c in required}), 'duplicate/unsorted required case')
            for case, verdict in zip(required, record['verdicts']):
                require(case == verdict['case'] and verdict['status'] == 'pass', 'missing/skipped/mismatched case verdict')
            origin = record['origin']
            run = os.environ.get('READBACK_RUN') or os.environ.get('GITHUB_RUN_ID')
            if run:
                require(origin['run'] == run, 'portable execution belongs to another run')
                if run == os.environ.get('GITHUB_RUN_ID'):
                    require(origin['revision'] == os.environ['GITHUB_SHA'], 'portable execution revision differs')
            require(all(origin.values()), 'portable execution origin missing')
            verify_file(path.parent, record['events'])
            verify_events(path.parent / record['events']['path'], plan, self.optional)
            metadata = read_document(path.parent / 'inputs.json')
            require(metadata['schema'] == 1 and metadata['output_environment'], 'output/input binding absent')
            declared = {}
            for entry in metadata['inputs']:
                value = {'schema': 1, 'id': entry['id'], 'bindings': entry['bindings'],
                         'files': entry['files'], 'captures': entry['captures']}
                require(identity(value) == entry['tree_sha256'], 'input snapshot identity differs')
                require(entry['id'] not in declared, 'duplicate input identity')
                declared[entry['id']] = entry['tree_sha256']
            for continuation in metadata['continuations']:
                value = continuation['input']
                require(value['use'] == 'native-continuation' and identity(continuation['files']) == value['tree_sha256'],
                        'native continuation input identity differs')
                require(value['id'] not in declared, 'duplicate input identity')
                declared[value['id']] = value['tree_sha256']
            require(len(plan['inputs']) == len({v['id'] for v in plan['inputs']}), 'duplicate required input identity')
            require(declared == {v['id']: v['tree_sha256'] for v in plan['inputs']}, 'input snapshot coverage differs')
            files = record['outputs']
            require([f['path'] for f in files] == sorted({f['path'] for f in files}), 'duplicate/unsorted output records')
            for case in required:
                for name in case['outputs'] or ():
                    require(any(f['path'] == name for f in files), 'required portable output absent: ' + name)
            self.entries.append({'root': path.parents[2], 'record': record, 'metadata': metadata,
                                 'files': {f['path']: f for f in files}})

    def file(self, image, verify=True):
        image = Path(image).resolve()
        matches = []
        for entry in self.entries:
            root = entry['root'].resolve()
            if not image.is_relative_to(root):
                continue
            name = entry['metadata']['output_environment'] + '/' + image.relative_to(root).as_posix()
            if name not in entry['files']:
                continue
            cases = [c for c in entry['record']['plan']['cases'] if name in (c['outputs'] or ())]
            if not cases:
                # Sequential invocations may share an output archive root.
                # Only the invocation that required this file can qualify it.
                continue
            record = entry['files'][name]
            if verify:
                require(image.stat().st_size == record['bytes'] and file_digest(image) == record['sha256'],
                        'portable output bytes differ from execution receipt')
            matches.append((entry, record, cases))
        require(len(matches) == 1, 'missing/ambiguous portable output provenance: ' + str(image))
        return matches[0]

    def bind_input(self, corpus_id, root, prefix=None):
        found = False
        for entry in self.entries:
            for snapshot in entry['metadata']['inputs']:
                if snapshot['id'] != corpus_id:
                    continue
                for record in snapshot['files']:
                    if prefix is not None:
                        if not record['path'].startswith(prefix + '/'):
                            continue
                        record = dict(record, path=record['path'][len(prefix) + 1:])
                    found = True
                    key = (str(Path(root).resolve()), record['path'], record['sha256'])
                    if key not in self.bound_inputs:
                        verify_file(root, record)
                        self.bound_inputs[key] = (Path(root), record)
        require(found, 'required original input snapshot absent: ' + corpus_id)

    def verify_inputs(self):
        for root, record in self.bound_inputs.values():
            verify_file(root, record)


def native_environment(major, arguments):
    from container_building import require_disposable_host
    from image_repacking import version
    require_disposable_host()
    actual = version(major)
    paths = [Path(sys.executable).resolve()]
    for name in ('hdiutil', 'diskutil', 'codesign', 'sw_vers'):
        tool = shutil.which(name)
        require(tool, 'native tool unavailable: ' + name)
        paths.append(Path(tool).resolve())
    paths += [Path('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs').resolve(),
              Path('/sbin/fsck_hfs').resolve()]
    tools = [{'path': p.as_posix().lstrip('/'), 'bytes': p.stat().st_size,
              'sha256': file_digest(p)} for p in sorted(set(paths))]
    return {'os': 'darwin', 'architecture': actual['architecture'],
            'version': actual['version'], 'build': actual['build'],
            'toolchain': 'Python ' + platform.python_version(), 'flags': list(arguments),
            'race': False, 'tools': tools}


def native_contract(source_root):
    root = Path(source_root)
    sources = sorted((root / 'acceptance/native').rglob('*'))
    records = [{'path': p.relative_to(root).as_posix(), 'bytes': p.stat().st_size,
                'sha256': file_digest(p)} for p in sources
               if p.is_file() and p.suffix in ('.py', '.c', '.h', '.entitlements')]
    require(records, 'native execution source contract absent')
    return identity(records)


class NativeEvidence:
    """Verify a predeclared set of portable outputs with actual Apple programs.

    Case contexts complete only after the original native assertions. An alias
    group must have identical bytes. Randomized ciphertext is checked one file
    at a time. Finishing a program cannot invent missing case verdicts.
    """

    def __init__(self, replay, targets, source_root, outputs, name, major,
                 continuation=False, arguments=None):
        self.replay = replay
        self.source_root = source_root
        self.directory = Path(outputs)
        self.targets = {}
        self.checked_targets = set()
        self.environment = native_environment(major, sys.argv[1:] if arguments is None else arguments)
        inputs, cases, files = {}, [], []
        for target in targets:
            target = Path(target).resolve()
            require(target not in self.targets, 'duplicate required Apple output check')
            # Declare expected bytes from the producer proof; case() hashes
            # the actual file before Apple can check it. Planning adds no
            # redundant scan over every disk image.
            entry, file, obligations = replay.file(target, verify=False)
            producer = entry['record']['plan']['environment']['os']
            key = producer + '/' + file['path']
            require(not any(f['path'] == key for f in files), 'ambiguous portable producer/output')
            files.append({'path': key, 'bytes': file['bytes'], 'sha256': file['sha256']})
            obligation = obligations[0]
            require(all(c['source'] == obligation['source'] and c['native_case'] == obligation['native_case']
                        for c in obligations), 'output spans incompatible source cases')
            source = 'macos-' + str(obligation['source'])
            require('/' + source + '/' in '/' + file['path'] or
                    '/' + source + '-' in '/' + file['path'],
                    'portable output source differs from its executed case')
            input = next(i for i in entry['record']['plan']['inputs'] if i['id'] == obligation['corpus'])
            scoped_id = input['id'] + '-' + input['tree_sha256']
            for dependency in entry['record']['plan']['inputs']:
                dependency_id = dependency['id'] + '-' + dependency['tree_sha256']
                inputs[dependency_id] = dict(dependency, id=dependency_id)
            case = {'family': obligation['family'], 'test': name + '/' + key,
                    'corpus': scoped_id}
            if obligation.get('manifest'):
                case['manifest'] = obligation['manifest']
            case.update(native_case=obligation['native_case'], source=obligation['source'],
                        variant=obligation.get('variant', '') + '/' + producer,
                        continuation=(continuation(obligation, file) if callable(continuation) else continuation)
                        or obligation.get('continuation', False), outputs=[key])
            if not case['continuation']:
                del case['continuation']
            self.targets[target] = case
            cases.append(case)
        require(cases, 'required Apple verification set is empty')
        cases.sort(key=lambda c: c['test'])
        files.sort(key=lambda f: f['path'])
        self.plan = {'schema': 1, 'stage': 'apple-verification',
                     'contract_sha256': native_contract(source_root),
                     'production_sha256': replay.production,
                     'inputs': sorted(inputs.values(), key=lambda i: i['id']), 'outputs': files,
                     'environment': self.environment, 'cases': cases,
                     'required_runs': [c['test'] for c in cases]}
        self.fingerprint = identity(self.plan)
        self.base = self.directory / (name + '-macos-' + str(major))
        self.events = self.base.with_suffix('.events.jsonl')
        self.stream = self.events.open('x', encoding='utf-8')
        self.emit('start')

    def emit(self, action, test=None):
        record = {'Action': action, 'Package': 'apple-native'}
        if test:
            record['Test'] = test
        self.stream.write(json.dumps(record, separators=(',', ':')) + '\n')
        self.stream.flush()

    @contextmanager
    def case(self, targets, identical=True):
        targets = [Path(p).resolve() for p in targets]
        require(targets and len(set(targets)) == len(targets), 'empty/duplicate Apple case group')
        digests = set()
        for target in targets:
            require(target in self.targets and target not in self.checked_targets,
                    'unexpected/duplicate Apple case completion: ' + str(target))
            _, record, _ = self.replay.file(target)
            digests.add(record['sha256'])
        require(not identical or len(digests) == 1, 'native verification alias group has different bytes')
        for target in targets:
            case = self.targets[target]
            self.emit('run', case['test'])
        try:
            yield
        except BaseException:
            for target in targets:
                self.emit('fail', self.targets[target]['test'])
            self.stream.close()
            raise
        for target in targets:
            self.replay.file(target)
            case = self.targets[target]
            self.emit('pass', case['test'])
            self.checked_targets.add(target)

    def finish(self):
        require(self.checked_targets == set(self.targets), 'required Apple verification cases missing')
        self.replay.verify_inputs()
        require(native_contract(self.source_root) == self.plan['contract_sha256'] and
                source_identities(self.source_root)[0] == self.replay.production,
                'native verification sources changed during execution')
        for target in self.targets:
            self.replay.file(target)
        self.emit('pass')
        self.stream.close()
        return publish_receipt(self.plan, self.events, self.plan['outputs'], self.base.with_suffix('.receipt.json'))


def publish_receipt(plan, events, outputs, destination):
    verify_events(events, plan)
    origin = {'revision': os.environ['GITHUB_SHA'], 'run': os.environ['GITHUB_RUN_ID'],
              'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job': os.environ['GITHUB_JOB']}
    record = {'schema': 1, 'plan': plan, 'fingerprint': identity(plan),
              'origin': origin, 'verdicts': [{'case': c, 'status': 'pass'} for c in plan['cases']],
              'outputs': outputs,
              'events': {'path': events.name, 'bytes': events.stat().st_size,
                         'sha256': file_digest(events)}}
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent,
                                     prefix='.native-receipt-', delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, destination)
    finally:
        temporary.unlink()
    return record
