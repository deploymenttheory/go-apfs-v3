"""Pinned release transport for native references; never inherit a test verdict.

API requests carry repository credentials. Signed asset redirects are fetched
without those credentials. Each stored object is bounded and checked against
its reviewed byte count and SHA-256 before atomic publication.
"""
import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_ASSET = (2 << 30) - 1
MAX_JSON = 16 << 20
API_VERSION = '2022-11-28'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate release metadata field')
        result[key] = value
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, stream, code, message, headers, target):
        return None


class GitHub:
    def __init__(self, repository, token, api='https://api.github.com', opener=None, anonymous=None):
        require(re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*', repository),
                'explicit native reference repository required')
        parsed = urllib.parse.urlsplit(api)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
                not parsed.password and not parsed.query and not parsed.fragment,
                'HTTPS GitHub API origin required')
        self.repository, self.token, self.api = repository, token, api.rstrip('/')
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.anonymous = anonymous or urllib.request.build_opener(NoRedirect())

    def request(self, path, method='GET', value=None):
        require(path.startswith('/') and not path.startswith('//') and '?' not in path.split('/')[0]
                and not any(part in ('.', '..') for part in path.split('/')),
                'relative API resource required')
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        data = None if value is None else json.dumps(value, separators=(',', ':')).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.api + path, data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=60) as response:
            data = response.read(MAX_JSON + 1)
        require(len(data) <= MAX_JSON, 'GitHub metadata response exceeds bound')
        return json.loads(data, object_pairs_hook=unique_object) if data else None

    def pages(self, path, field=None, maximum=10000, parameters=None):
        result = []
        require('?' not in path, 'paginated API path must not contain query parameters')
        parameters = dict(parameters or {})
        require(not ({'page', 'per_page'} & parameters.keys()), 'pagination parameters are caller independent')
        for page in range(1, (maximum + 99) // 100 + 1):
            query = urllib.parse.urlencode({**parameters, 'per_page': 100, 'page': page})
            value = self.request(path + '?' + query)
            rows = value[field] if field else value
            require(isinstance(rows, list) and len(rows) <= 100, 'invalid paginated API response')
            result.extend(rows)
            require(len(result) <= maximum, 'GitHub inventory exceeds bound')
            if len(rows) < 100:
                return result
        raise ValueError('GitHub inventory is incomplete at page bound')

    def create_candidate_release(self, tag, target, body):
        require(re.fullmatch('native-corpus-[a-f0-9]{16}-[1-9][0-9]*-[1-9][0-9]*', tag),
                'content/run-addressed native candidate tag required')
        # The trusted default-branch transport tag is independent of the actual
        # collector revision retained in the candidate catalog and receipts.
        # GITHUB_TOKEN cannot create tags that introduce workflow changes.
        require(isinstance(target, str) and target and '..' not in target, 'explicit trusted release target required')
        result = self.request(f'/repos/{self.repository}/releases', 'POST', {
            'tag_name': tag, 'target_commitish': target, 'name': tag,
            'body': body, 'draft': True, 'prerelease': True, 'make_latest': 'false'})
        require(result.get('prerelease') is True and result.get('draft') is True and
                result['tag_name'] == tag, 'candidate release state differs')
        return result

    def upload(self, release_id, asset, path):
        """Stream one addressed object; never replace an existing asset."""
        require(type(release_id) is int and release_id > 0, 'explicit candidate release required')
        name, count, digest = asset['name'], asset['bytes'], asset['sha256']
        self.validate_asset({**asset, 'id': 1})
        path = Path(path)
        self.verify(path, count, digest)
        # This repository uses github.com. Never forward its token to a URL
        # supplied in a response or to a signed object-storage redirect.
        require(self.api == 'https://api.github.com', 'GitHub upload origin is not configured')
        url = ('https://uploads.github.com/repos/' + self.repository + '/releases/' +
               str(release_id) + '/assets?name=' + urllib.parse.quote(name, safe=''))
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION,
                   'Content-Type': 'application/octet-stream', 'Content-Length': str(count)}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        with path.open('rb') as stream:
            request = urllib.request.Request(url, data=stream, headers=headers, method='POST')
            with self.opener.open(request, timeout=60) as response:
                data = response.read(MAX_JSON + 1)
        require(len(data) <= MAX_JSON, 'GitHub upload metadata exceeds bound')
        value = json.loads(data, object_pairs_hook=unique_object)
        self.verify(path, count, digest)
        require(type(value['id']) is int and value['id'] > 0 and value['name'] == name and
                value['size'] == count and value['state'] == 'uploaded' and
                value['digest'] == 'sha256:' + digest, 'uploaded asset byte identity differs')
        return {'id': value['id'], 'name': name, 'bytes': count, 'sha256': digest}

    def finish_candidate_release(self, release_id):
        """Publish only after the caller has uploaded and checked every asset."""
        require(type(release_id) is int and release_id > 0, 'explicit candidate release required')
        result = self.request(f'/repos/{self.repository}/releases/{release_id}', 'PATCH', {
            'draft': False, 'prerelease': True, 'make_latest': 'false'})
        require(result.get('draft') is False and result.get('prerelease') is True,
                'published candidate release state differs')
        return result

    @staticmethod
    def validate_asset(asset):
        name, count, digest = asset['name'], asset['bytes'], asset['sha256']
        require(type(asset['id']) is int and asset['id'] > 0 and type(count) is int and 0 < count <= MAX_ASSET
                and re.fullmatch('[a-f0-9]{64}', digest or ''), 'invalid native reference asset pin')
        require(name in ('sha256-' + digest + '.tar.gz', 'catalog-sha256-' + digest + '.json',
                         'qualification-sha256-' + digest + '.tar.gz'), 'asset name is not content-addressed')
        if name.endswith('.json'):
            require(count <= MAX_JSON, 'native reference catalog exceeds metadata bound')

    def download(self, asset, directory):
        name, count, digest = asset['name'], asset['bytes'], asset['sha256']
        self.validate_asset(asset)
        directory = Path(directory)
        require(directory.is_dir() and not directory.is_symlink(), 'existing ordinary asset cache required')
        destination = directory / name
        if destination.exists() or destination.is_symlink():
            self.verify(destination, count, digest)
            return destination
        headers = {'Accept': 'application/octet-stream', 'X-GitHub-Api-Version': API_VERSION}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(self.api + f'/repos/{self.repository}/releases/assets/{asset["id"]}', headers=headers)
        try:
            response = self.opener.open(request, timeout=60)
        except urllib.error.HTTPError as redirect:
            if redirect.code not in (301, 302, 303, 307, 308):
                raise
            try:
                target = redirect.headers.get('Location', '')
                parsed = urllib.parse.urlsplit(target)
                require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and
                        not parsed.password and not parsed.fragment, 'unsafe release asset redirect')
            finally:
                redirect.close()
            # Explicitly build a new request with no Authorization headers.
            response = self.anonymous.open(urllib.request.Request(target), timeout=60)
        temporary = None
        try:
            with response, tempfile.NamedTemporaryFile(dir=directory, prefix='.native-asset-', delete=False) as stream:
                temporary = Path(stream.name)
                observed, total = hashlib.sha256(), 0
                while data := response.read(min(64 << 10, count - total + 1)):
                    total += len(data)
                    require(total <= count, 'release asset exceeds reviewed byte count')
                    observed.update(data)
                    stream.write(data)
                require(total == count and observed.hexdigest() == digest, 'release asset byte identity differs')
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                self.verify(destination, count, digest)
            return destination
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def verify(path, count, digest):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == count,
                'cached native reference size/type differs')
        observed = hashlib.sha256()
        with path.open('rb') as stream:
            for data in iter(lambda: stream.read(64 << 10), b''):
                observed.update(data)
        require(observed.hexdigest() == digest, 'cached native reference digest differs')


def read_document(path, maximum=MAX_JSON):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            'missing/oversized native reference document')
    with path.open(encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def fetch(pin, directory, token='', client=None, inputs=None, metadata_only=False):
    """Fetch exact reviewed transport; Go still admits corpus semantics/bytes."""
    require(not metadata_only or inputs is None, 'metadata admission cannot select input payloads')
    require(set(pin) == {'schema', 'repository', 'release_id', 'catalog'} and pin['schema'] == 1
            and type(pin['release_id']) is int and pin['release_id'] > 0,
            'invalid reviewed native reference release pin')
    client = client or GitHub(pin['repository'], token)
    require(client.repository == pin['repository'], 'reference transport repository differs')
    client.validate_asset(pin['catalog'])
    require(pin['catalog']['name'].startswith('catalog-sha256-'), 'reviewed native catalog asset required')
    release = client.request(f'/repos/{client.repository}/releases/{pin["release_id"]}')
    require(release['id'] == pin['release_id'] and release['prerelease'] is True and
            release['draft'] is False, 'reviewed candidate release is absent or unpublished')
    available = client.pages(f'/repos/{client.repository}/releases/{pin["release_id"]}/assets')
    inventory = {}
    for asset in available:
        require(asset['id'] not in inventory, 'duplicate release asset ID')
        inventory[asset['id']] = asset
    def check(asset):
        client.validate_asset(asset)
        actual = inventory.get(asset['id'])
        require(actual and actual['name'] == asset['name'] and actual['size'] == asset['bytes'] and
                actual['state'] == 'uploaded', 'pinned asset is not part of the reviewed release')
    check(pin['catalog'])
    catalog_path = client.download(pin['catalog'], directory)
    manifest = read_document(catalog_path)
    require(manifest['schema'] == 1 and manifest['origin']['repository'] == pin['repository'],
            'native reference origin differs')
    assets = [*manifest['assets'], manifest['qualification_evidence']]
    require(len({a['id'] for a in assets}) == len(assets) and
            len({a['name'] for a in assets}) == len(assets) and
            pin['catalog']['id'] not in {a['id'] for a in assets}, 'duplicate reference asset pin')
    for asset in assets:
        check(asset)
    selected = [] if metadata_only else assets
    if inputs is not None:
        require(inputs and len(set(inputs)) == len(inputs), 'explicit unique required corpus inputs expected')
        entries = {e['id']: e for e in manifest['corpus']['entries']}
        names = set()
        for identity in inputs:
            require(identity in entries and entries[identity]['location']['kind'] == 'bundle',
                    'selected independent reference input missing: ' + identity)
            bundle = entries[identity]['location']['bundle']
            names.add('sha256-' + bundle['sha256'] + '.tar.gz')
        selected = [a for a in manifest['assets'] if a['name'] in names]
        require(len(selected) == len(names), 'selected reference transport asset missing')
        selected.append(manifest['qualification_evidence'])
    for asset in selected:
        client.download(asset, directory)
    return catalog_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--input', action='append', help='required corpus ID; omit to fetch the complete reviewed release')
    args = parser.parse_args()
    print(fetch(read_document(args.pin, 64 << 10), args.directory, os.environ.get('GITHUB_TOKEN', ''), inputs=args.input))


if __name__ == '__main__':
    main()
