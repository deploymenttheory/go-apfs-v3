#!/usr/bin/env python3
"""Require each caller-declared native plan's complete original execution proof.

Plans are written before execution by the independent case inventory. Callers
name their required scopes explicitly; available receipts cannot select the set.
"""
import argparse
import os
from pathlib import Path

from qualification import (identity, native_contract, read_document, require,
                           source_identities, verify_events, verify_file)
from qualification_cases import ROOT


def complete(plans, source_root=ROOT):
    require(plans and len(set(map(str, plans))) == len(plans), 'empty/duplicate required native scope')
    fingerprints = set()
    destinations = {Path(p).with_name(Path(p).name.removesuffix('plan.json') + 'receipt.json') for p in plans}
    discovered = {p for root in {p.parent for p in destinations} for p in root.glob('*.receipt.json')}
    discovered.update(p for p in destinations if p.name == 'receipt.json' and p.is_file())
    require(discovered == destinations, 'required native receipt set missing/extra')
    production, _ = source_identities(source_root)
    contract = native_contract(source_root)
    origin = {key: os.environ[value] for key, value in (
        ('revision', 'GITHUB_SHA'), ('run', 'GITHUB_RUN_ID'),
        ('attempt', 'GITHUB_RUN_ATTEMPT'), ('job', 'GITHUB_JOB'))}
    for path in plans:
        path = Path(path)
        expected = read_document(path)
        require(expected['schema'] == 1 and expected['stage'] in ('capture', 'apple-verification'),
                'required native plan has the wrong stage/schema')
        require(expected['environment']['os'] == 'darwin' and expected['environment']['tools'],
                'native Apple environment/tool identities missing')
        require(expected['contract_sha256'] == contract and
                (expected['production_sha256'] == production or
                 expected['stage'] == 'capture' and expected['production_sha256'] == ''),
                'native plan belongs to another production/verification contract')
        require(expected['production_sha256'] or
                not any(i['use'] == 'current-go' for i in expected['inputs']),
                'current-Go native experiment has no production identity')
        destination = path.with_name(path.name.removesuffix('plan.json') + 'receipt.json')
        record = read_document(destination)
        fingerprint = identity(expected)
        require(fingerprint not in fingerprints, 'duplicate required native execution')
        fingerprints.add(fingerprint)
        require(record['schema'] == 1 and record['plan'] == expected and
                record['fingerprint'] == fingerprint and record['origin'] == origin,
                'native execution plan/origin differs; inherited verdicts are not admitted')
        cases = expected['cases']
        require(cases and [c['test'] for c in cases] == sorted({c['test'] for c in cases})
                and len(cases) == len(record['verdicts']), 'native case verdict inventory differs')
        for case, verdict in zip(cases, record['verdicts']):
            require(verdict == {'case': case, 'status': 'pass'}, 'native case verdict missing/skipped/failed/mismatched')
        files = record['outputs']
        require([f['path'] for f in files] == sorted({f['path'] for f in files}), 'duplicate/unsorted native output inventory')
        by_path = {file['path']: file for file in files}
        for case in cases:
            require(all(name in by_path for name in case['outputs']), 'required native output missing')
        require(all(by_path.get(file['path']) == file for file in expected['outputs']),
                'qualified output bytes differ from expected native plan')
        verify_file(path.parent, record['events'])
        verify_events(path.parent / record['events']['path'], expected)
        if expected['stage'] == 'capture':
            for file in files:
                verify_file(path.parent, file)
    return len(fingerprints)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='append', required=True, type=Path)
    args = parser.parse_args()
    print('Completed', complete(args.plan), 'required native qualification scopes')


if __name__ == '__main__':
    main()
