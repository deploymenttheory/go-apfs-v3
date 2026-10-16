#!/usr/bin/env python3
"""Qualify and publish immutable reference candidates for reviewed promotion.

This Linux control-plane program never invokes Apple filesystem tools. Existing
required workflows execute the complete capture/replay/Apple verification bench.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.error

from reference_campaign import download_campaign, inspect_campaign, refresh_for_completion
from reference_sources import assemble
from refresh_control import record_qualified
from release_assets import GitHub, MAX_ASSET, read_document, require


def write_document(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def file_asset(path, prefix, suffix):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_ASSET,
            'candidate asset is missing, aliased or exceeds the release bound')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(64 << 10), b''):
            digest.update(data)
    return {'name': prefix + digest.hexdigest() + suffix, 'bytes': path.stat().st_size,
            'sha256': digest.hexdigest()}


def archive_evidence(evidence, control, destination):
    """Retain original metadata bytes with fixed transport headers and bounds."""
    members = []
    for prefix, root in (('execution', Path(evidence)), ('campaign', Path(control))):
        for path in sorted(root.rglob('*')):
            require(not path.is_symlink(), 'aliased candidate qualification evidence')
            if path.is_dir():
                continue
            require(path.is_file(), 'special candidate evidence member')
            members.append((prefix + '/' + path.relative_to(root).as_posix(), path))
    require(members and len(members) <= 100000, 'candidate evidence member inventory exceeds bound')
    total = sum(path.stat().st_size for _, path in members)
    require(total <= 16 << 30, 'candidate qualification evidence exceeds retained byte bound')
    with Path(destination).open('xb') as output:
        # JSON/event streams benefit from compression. Source disk archives
        # are not embedded here or recompressed into the evidence archive.
        import gzip
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0, compresslevel=1) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, path in members:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = path.stat().st_size, 0o600, 0
                    with path.open('rb') as source:
                        archive.addfile(info, source)
                    require(output.tell() <= MAX_ASSET, 'candidate evidence asset exceeds release bound')
    return file_asset(destination, 'qualification-sha256-', '.tar.gz')


def upload_immutable(client, release_id, asset, path):
    existing = client.pages(f'/repos/{client.repository}/releases/{release_id}/assets')
    matches = [row for row in existing if row['name'] == asset['name']]
    require(len(matches) <= 1, 'duplicate addressed asset in candidate release')
    if matches:
        row = matches[0]
        require(row['state'] == 'uploaded' and row['size'] == asset['bytes'] and
                row['digest'] == 'sha256:' + asset['sha256'], 'existing addressed release object differs')
        return {**asset, 'id': row['id']}
    return client.upload(release_id, asset, path)


def existing_publication(client, release, origin, contract, directory):
    """Published candidates are immutable, including on duplicated events."""
    require(release['draft'] is False and release['prerelease'] is True,
            'existing reference candidate is not published')
    assets = client.pages(f'/repos/{client.repository}/releases/{release["id"]}/assets')
    catalogs = [a for a in assets if a['name'].startswith('catalog-sha256-')]
    require(len(catalogs) == 1, 'published candidate has no unique original catalog')
    original = catalogs[0]
    catalog = {'id': original['id'], 'name': original['name'], 'bytes': original['size'],
               'sha256': original['digest'].removeprefix('sha256:')}
    directory.mkdir()
    path = client.download(catalog, directory)
    manifest = read_document(path)
    require(manifest['origin'] == origin and manifest['capture_contract_sha256'] == contract,
            'published candidate belongs to another capture campaign')
    by_id = {a['id']: a for a in assets}
    for expected in [*manifest['assets'], manifest['qualification_evidence'], catalog]:
        client.validate_asset(expected)
        actual = by_id.get(expected['id'])
        require(actual and actual['name'] == expected['name'] and actual['size'] == expected['bytes'] and
                actual['state'] == 'uploaded' and actual['digest'] == 'sha256:' + expected['sha256'],
                'published candidate asset inventory differs')
    return {'schema': 1, 'repository': client.repository, 'release_id': release['id'], 'catalog': catalog}, manifest


def create_promotion(client, pin, origin):
    """Create a normal review PR; never merge or rewrite the approved pin."""
    root = f'/repos/{client.repository}'
    repository = client.request(root)
    branch = repository['default_branch']
    require(branch == 'main', 'explicit trusted promotion base required')
    base = client.request(root + '/git/ref/heads/main')['object']['sha']
    head = 'references/' + origin['run'] + '-' + origin['attempt']
    existing = client.pages(root + '/pulls', parameters={'state': 'all', 'head': client.repository.split('/')[0] + ':' + head})
    require(len(existing) <= 1, 'duplicate reference promotion requests')
    if existing:
        return existing[0]['html_url']
    try:
        client.request(root + '/git/ref/heads/' + head)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        error.close()
        client.request(root + '/git/refs', 'POST', {'ref': 'refs/heads/' + head, 'sha': base})
    try:
        previous = client.request(root + '/contents/acceptance/qualification/references.json?ref=' + head)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        error.close()
        previous = None
    content = (json.dumps(pin, indent=2) + '\n').encode()
    value = {'message': 'test(acceptance): promote independently qualified Apple references',
             'branch': head, 'content': base64.b64encode(content).decode()}
    unchanged = False
    if previous is not None:
        require(previous['type'] == 'file' and previous['encoding'] == 'base64' and previous['size'] <= 64 << 10,
                'existing reference pin is not an ordinary bounded file')
        value['sha'] = previous['sha']
        unchanged = base64.b64decode(previous['content']) == content
    if not unchanged:
        client.request(root + '/contents/acceptance/qualification/references.json', 'PUT', value)
    request = client.request(root + '/pulls', 'POST', {
        'title': 'test(acceptance): promote independently qualified Apple references',
        'head': head, 'base': branch,
        'body': ('Pins immutable Apple-created filesystem references from complete native campaign '
                 f"[{origin['run']}](https://github.com/{client.repository}/actions/runs/{origin['run']}). "
                 'Original disk, observation and collector bytes retain their captured hashes.\n\n'
                 'Review and merge this input update explicitly. Future Go outputs and Apple verdicts '
                 'still execute afresh; this pin inherits no implementation verdict.\n')})
    return request['html_url']


def publish(client, campaign, workspace, execute=subprocess.run):
    require(campaign['state'] == 'ready', 'complete native and portable campaign required')
    workspace = Path(workspace).absolute()
    require(not workspace.exists(), 'publication requires absent managed scratch')
    workspace.mkdir(parents=True, mode=0o700)
    control = workspace / 'control'; control.mkdir()
    for name in ('native', 'ci', 'jobs', 'artifacts', 'origin'):
        write_document(control / (name + '.json'), campaign[name])
    origin = campaign['origin']
    contract_result = execute(['go', 'run', './acceptance/qualification', '-capture-contract'],
                              check=True, capture_output=True, text=True)
    contract = contract_result.stdout.strip()
    require(len(contract) == 64 and all(c in 'abcdef0123456789' for c in contract), 'capture dependency contract missing')
    tag = 'native-corpus-' + contract[:16] + '-' + origin['run'] + '-' + origin['attempt']
    release = None
    try:
        release = client.request(f'/repos/{client.repository}/releases/tags/{tag}')
        require(release['tag_name'] == tag and release['prerelease'] is True,
                'existing candidate release identity differs')
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        error.close()
    if release is not None and release['draft'] is False:
        pin, manifest = existing_publication(client, release, origin, contract, workspace / 'published')
        promotion = create_promotion(client, pin, origin)
        record_qualified(client, datetime.now(timezone.utc), manifest, pin)
        write_document(workspace / 'publication.json', {'schema': 1, 'pin': pin, 'promotion': promotion})
        return promotion
    download_campaign(client.repository, origin['run'], campaign['captures'], campaign['proof'], workspace, execute)
    inputs = assemble(workspace / 'captures', workspace / 'inputs')
    candidate = workspace / 'candidate'
    execute(['go', 'run', './acceptance/qualification', '-prepare-references', str(inputs),
             '-candidate-dir', str(candidate)], check=True)
    proof = execute(['go', 'run', './acceptance/qualification', '-check-reference-evidence',
                     str(workspace / 'evidence'), '-candidate-dir', str(candidate),
                     '-reference-origin', str(control / 'origin.json')], capture_output=True, text=True)
    (control / 'evidence.stdout.log').write_text(proof.stdout, encoding='utf-8')
    (control / 'evidence.stderr.log').write_text(proof.stderr, encoding='utf-8')
    proof.check_returncode()
    summary = json.loads(proof.stdout)
    require(summary['schema'] == 1 and summary['qualified_portable_cases'] > 0 and
            summary['qualified_native_file_obligations'] > 0 and summary['origin'] == origin,
            'candidate execution proof did not complete')
    write_document(control / 'qualification.json', summary)
    ready = read_document(candidate / 'candidate.json')
    require(summary['capture_contract_sha256'] == ready['capture_contract_sha256'],
            'candidate changed after qualification')
    evidence_path = workspace / 'qualification.tar.gz'
    evidence = archive_evidence(workspace / 'evidence', control, evidence_path)
    addressed_evidence = candidate / evidence['name']; evidence_path.rename(addressed_evidence)
    require(ready['capture_contract_sha256'] == contract, 'capture contract changed during candidate qualification')
    if release is None:
        release = client.create_candidate_release(tag, 'main', 'Qualified independent Apple filesystem references; promotion requires review.')
    assets = []
    for bundle in ready['bundles']:
        asset = {'name': 'sha256-' + bundle['sha256'] + '.tar.gz', **bundle}
        assets.append(upload_immutable(client, release['id'], asset, candidate / asset['name']))
    permanent_evidence = upload_immutable(client, release['id'], evidence, addressed_evidence)
    manifest = {'schema': 1, 'capture_contract_sha256': ready['capture_contract_sha256'], 'origin': origin,
                'corpus': ready['corpus'], 'assets': sorted(assets, key=lambda a: a['name']),
                'qualification_evidence': permanent_evidence}
    temporary_catalog = candidate / 'catalog.json'
    write_document(temporary_catalog, manifest)
    catalog = file_asset(temporary_catalog, 'catalog-sha256-', '.json')
    catalog_path = candidate / catalog['name']; temporary_catalog.rename(catalog_path)
    pinned_catalog = upload_immutable(client, release['id'], catalog, catalog_path)
    pin = {'schema': 1, 'repository': client.repository, 'release_id': release['id'], 'catalog': pinned_catalog}
    pin_path = workspace / 'references.json'; write_document(pin_path, pin)
    # Re-admit exact catalog, corpus and evidence bytes before making the draft
    # visible. This catches binding drift and changed original digests too.
    execute(['go', 'run', './acceptance/qualification', '-check-references', str(pin_path),
             '-bundle-dir', str(candidate)], check=True)
    client.finish_candidate_release(release['id'])
    promotion = create_promotion(client, pin, origin)
    record_qualified(client, datetime.now(timezone.utc), manifest, pin)
    write_document(workspace / 'publication.json', {'schema': 1, 'pin': pin, 'promotion': promotion})
    return promotion


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selected = parser.add_mutually_exclusive_group(required=True)
    selected.add_argument('--run')
    selected.add_argument('--completed-run')
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--select', action='store_true', help='authenticate ready campaign and emit its checkout/run only')
    args = parser.parse_args()
    client = GitHub(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_TOKEN'])
    run = args.run or refresh_for_completion(client, args.completed_run)
    if run is None:
        print('No completed independent reference refresh for this source revision.')
        return
    campaign = inspect_campaign(client, run)
    if campaign['state'] != 'ready':
        print('Full native qualification passed; matching successful CI is still required.')
        return
    if args.select:
        require(os.environ.get('GITHUB_OUTPUT'), 'selection requires the Actions output channel')
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            stream.write('revision=' + campaign['origin']['revision'] + '\n')
            stream.write('native_run=' + campaign['origin']['run'] + '\n')
        return
    print(publish(client, campaign, args.workspace))


if __name__ == '__main__':
    main()
