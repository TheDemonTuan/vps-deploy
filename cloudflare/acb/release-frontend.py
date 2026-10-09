#!/usr/bin/env python3
"""Publish verified static artifacts, or roll back an exact acb-web version.

Only bootstrap uses `wrangler deploy`; it cannot attach routes or public previews.
Normal releases use immutable versions and never touch VPS/backend state. JSON
summaries distinguish public HTTP checks from the operator's bank browser proof.

Run from the checkout root with --sha <40hex> --mode publish|bootstrap|rollback
--summary <private-json-path>; rollback additionally requires --version-id <UUID>.
Publish/bootstrap consume web/{dist,wrangler.jsonc,release-sha,SHA256SUMS}; the
manifest uses web-relative paths and must cover every public file exactly.
GH_TOKEN/GITHUB_REPOSITORY retrieve old artifacts for rollback checks. Missing
or expired artifacts permit explicit rollback HTTP mode, never a checksum claim;
retrieval or integrity errors fail closed. Cloudflare credentials stay off VPS.
"""
import argparse
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

API_BASE = 'https://api.cloudflare.com/client/v4'
GH_BASE = 'https://api.github.com'
WORKER = 'acb-web'
HOSTS = ('bank.tuannguyenviet.site', 'transactions.tuannguyenviet.site')
SHA = r'[0-9a-f]{40}'
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
MAX_ARCHIVE = 500 * 1024 * 1024


class ReleaseError(RuntimeError):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


OPENER = urllib.request.build_opener(SafeRedirect())


class API:
    def __init__(self):
        self.token = os.environ.get('CLOUDFLARE_API_TOKEN', '')
        self.account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
        self.zone = os.environ.get('CLOUDFLARE_ZONE_ID', '')
        if not self.token or not all(re.fullmatch(r'[0-9a-f]{32}', item) for item in (self.account, self.zone)):
            raise ReleaseError('Cloudflare token and valid account/zone IDs are required before mutation')
        self.worker = f'/accounts/{self.account}/workers/scripts/{WORKER}'

    def get(self, path, missing_worker=False):
        request = urllib.request.Request(API_BASE + path, headers={'Authorization': 'Bearer ' + self.token})
        try:
            with OPENER.open(request, timeout=30) as response:
                data = json.load(response)
        except urllib.error.HTTPError as error:
            # Only the documented missing-script code is absence, not permission,
            # transport, or arbitrary 404 errors.
            if missing_worker and error.code == 404:
                try:
                    body = json.load(error)
                    if any(item.get('code') == 10007 for item in body.get('errors', [])):
                        return None
                except (ValueError, AttributeError):
                    pass
            raise ReleaseError(f'Cloudflare GET failed (HTTP {error.code})') from None
        except (urllib.error.URLError, ValueError) as error:
            raise ReleaseError(f'Cloudflare GET failed ({type(error).__name__})') from None
        if not isinstance(data, dict) or data.get('success') is not True or 'result' not in data:
            raise ReleaseError('Cloudflare GET returned an unsuccessful or malformed response')
        return data

    def items(self, path, key=None):
        items, page = [], 1
        while True:
            data = self.get(path + ('&' if '?' in path else '?') + f'page={page}&per_page=100')
            result = data['result']
            rows = result.get(key) if key and isinstance(result, dict) else result
            if not isinstance(rows, list):
                raise ReleaseError('Malformed Cloudflare list response')
            items.extend(rows)
            total = data.get('result_info', {}).get('total_pages', 1)
            if not isinstance(total, int) or total < page:
                raise ReleaseError('Malformed Cloudflare pagination')
            if page == total:
                return items
            page += 1

    def versions(self):
        versions = self.items(self.worker + '/versions?deployable=true', 'items')
        if len({item['id'] for item in versions}) != len(versions):
            raise ReleaseError('Duplicate version IDs')
        return versions

    def active(self):
        data = self.get(self.worker + '/deployments')['result']
        deployments = data.get('deployments') if isinstance(data, dict) else None
        if not isinstance(deployments, list) or not deployments:
            raise ReleaseError('Worker has no active deployment; bootstrap must be explicit')
        deployment = deployments[0]
        versions = deployment.get('versions', [])
        if len(versions) != 1 or versions[0].get('percentage') != 100:
            raise ReleaseError('Manual gradual rollout detected; refusing to overwrite it')
        version_id = versions[0].get('version_id', '')
        if not re.fullmatch(UUID, version_id) or not re.fullmatch(UUID, deployment.get('id', '')):
            raise ReleaseError('Malformed deployment identity')
        return {'deployment_id': deployment['id'], 'version_id': version_id}

    def version(self, version_id):
        versions = [item for item in self.versions() if item['id'] == version_id]
        if len(versions) != 1:
            raise ReleaseError('Exact version is not in the acb-web version window')
        details = self.get(self.worker + '/versions/' + version_id)['result']
        # Detail lookup is not limited to Wrangler's ten displayed versions.
        version = details
        tag = version.get('annotations', {}).get('workers/tag', '')
        if not re.fullmatch(SHA, tag):
            raise ReleaseError('Version has no valid frontend release SHA tag')
        if details.get('id') != version_id:
            raise ReleaseError('Version detail identity mismatch')
        if details.get('metadata', {}).get('hasPreview') is True:
            raise ReleaseError('Public version preview detected')
        return version, details

    def exposure(self, bootstrap=False):
        zone = self.get(f'/zones/{self.zone}')['result']
        if zone.get('account', {}).get('id') != self.account or zone.get('name') != 'tuannguyenviet.site':
            raise ReleaseError('Zone/account ownership does not match the production host allowlist')
        routes = self.items(f'/zones/{self.zone}/workers/routes')
        allowed = {host + '/*' for host in HOSTS}
        for route in routes:
            pattern = route['pattern']
            hostname = re.sub(r'^https?://', '', pattern).split('/', 1)[0]
            overlaps = any(fnmatch.fnmatchcase(host, hostname) for host in HOSTS)
            if route.get('script') == WORKER and (bootstrap or pattern not in allowed):
                raise ReleaseError('Worker is attached to a public or unmanaged route')
            if bootstrap and overlaps and route.get('script'):
                raise ReleaseError('Bootstrap would overlap an existing Worker route')
        domains = self.items(f'/accounts/{self.account}/workers/domains')
        if any(item.get('service') == WORKER or item.get('hostname') in HOSTS for item in domains):
            raise ReleaseError('Custom Domain conflicts with path-based static hosting')
        settings = self.get(self.worker + '/settings', missing_worker=bootstrap)
        if settings is None:
            return False
        self.get(self.worker + '/script-settings')
        subdomain = self.get(self.worker + '/subdomain')['result']
        if subdomain.get('enabled') is not False or subdomain.get('previews_enabled') is not False:
            raise ReleaseError('workers.dev or version preview exposure is not disabled')
        return True


def run(command, cwd):
    try:
        result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=300, check=False,
                                env=dict(os.environ, CI='true', NO_COLOR='1', WRANGLER_SEND_METRICS='false'))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(f'Command failed ({type(error).__name__})') from None
    if result.returncode:
        # Error pages and API response bodies are deliberately not published.
        if len(command) > 1 and Path(command[1]).resolve() == Path(__file__).with_name('verify-frontend.py').resolve():
            diagnostic = result.stderr.strip()
            if diagnostic.startswith('FAIL frontend verification: ') and '\n' not in diagnostic and len(diagnostic) <= 4096:
                raise ReleaseError(diagnostic)
        raise ReleaseError(f'{Path(command[0]).name} command exited {result.returncode}')
    return result.stdout


def artifact_checksum(directory, sha):
    directory = Path(directory)
    if any((directory / name).is_symlink() for name in ('dist', 'release-sha', 'wrangler.jsonc', 'SHA256SUMS')):
        raise ReleaseError('Artifact root symlinks are forbidden')
    if (directory / 'release-sha').read_text().strip() != sha:
        raise ReleaseError('Artifact SHA does not match the requested release')
    manifest = (directory / 'SHA256SUMS').read_bytes()
    records = {}
    for line in manifest.decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ReleaseError('Invalid artifact checksum manifest')
        digest, name = match.groups()
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name or name in records or str(path) != name:
            raise ReleaseError('Unsafe or duplicate artifact checksum path')
        if name not in ('release-sha', 'wrangler.jsonc', 'manifest.json') and not name.startswith('dist/'):
            raise ReleaseError('Unexpected artifact checksum path')
        target = directory / name
        if target.is_symlink() or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ReleaseError('Artifact checksum mismatch: ' + name)
        records[name] = digest
    actual = {'release-sha', 'wrangler.jsonc'} | {
        'dist/' + path.relative_to(directory / 'dist').as_posix()
        for path in (directory / 'dist').rglob('*') if path.is_file()}
    if (directory / 'manifest.json').is_file():
        actual.add('manifest.json')
        identity = json.loads((directory / 'manifest.json').read_text())
        if identity != {'app': 'acb', 'source_repository': 'TheDemonTuan/acb-transaction-webhook', 'source_sha': sha}:
            raise ReleaseError('Artifact source identity mismatch')
    if set(records) != actual or not {'dist/index.html', 'dist/__release'} <= actual:
        raise ReleaseError('Artifact manifest does not cover exactly the public files and configuration')
    if any(path.is_symlink() for path in (directory / 'dist').rglob('*')):
        raise ReleaseError('Artifact symlinks are forbidden')
    if (directory / 'dist/__release').read_bytes() != (sha + '\n').encode():
        raise ReleaseError('Artifact public release identity mismatch')
    config = json.loads((directory / 'wrangler.jsonc').read_text())
    allowed_config = {'$schema', 'name', 'compatibility_date', 'workers_dev', 'preview_urls', 'routes', 'assets'}
    if set(config) - allowed_config or config.get('compatibility_date') != '2026-10-04':
        raise ReleaseError('Artifact configuration is not the pinned static-only configuration')
    if (config.get('name') != WORKER or config.get('routes') != [] or
            config.get('workers_dev') is not False or config.get('preview_urls') is not False or
            'main' in config or config.get('assets') != {
                'directory': './dist', 'not_found_handling': 'single-page-application',
                'html_handling': 'none', 'run_worker_first': False}):
        raise ReleaseError('Artifact Wrangler configuration violates static-only/no-traffic contract')
    return hashlib.sha256(manifest).hexdigest()


def github(path, binary=False):
    token = os.environ.get('GH_TOKEN', '')
    if not token:
        raise ReleaseError('GH_TOKEN is required to inspect previous frontend artifacts')
    request = urllib.request.Request(GH_BASE + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with OPENER.open(request, timeout=60) as response:
            if binary:
                data = response.read(MAX_ARCHIVE + 1)
                if len(data) > MAX_ARCHIVE:
                    raise ReleaseError('Frontend artifact archive exceeds the download limit')
                return data
            return json.load(response)
    except (urllib.error.URLError, ValueError) as error:
        raise ReleaseError(f'Previous artifact retrieval failed ({type(error).__name__})') from None


def previous_artifact(sha, directory, summary):
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ReleaseError('GITHUB_REPOSITORY is required to inspect previous frontend artifacts')
    artifacts, page = [], 1
    while True:
        data = github(f'/repos/{repo}/actions/artifacts?name=frontend-dist-{sha}&per_page=100&page={page}')
        rows = data.get('artifacts')
        if not isinstance(rows, list) or not isinstance(data.get('total_count'), int):
            raise ReleaseError('Malformed GitHub artifact list')
        artifacts.extend(rows)
        if len(artifacts) >= data['total_count'] or not rows:
            break
        page += 1
    matches = [item for item in artifacts if item.get('name') == 'frontend-dist-' + sha
               and item.get('expired') is False and item.get('workflow_run', {}).get('head_sha') == sha]
    if not matches:
        summary.update(artifact_available=False, checksum_verified=False,
                       checksum_note='Artifact unavailable; explicit rollback HTTP mode, no byte-to-artifact proof')
        return None
    item = max(matches, key=lambda value: (value['created_at'], value['id']))
    archive = zipfile.ZipFile(io.BytesIO(github(f'/repos/{repo}/actions/artifacts/{item["id"]}/zip', binary=True)))
    entries = archive.infolist()
    if len(entries) > 25000 or sum(entry.file_size for entry in entries) > MAX_ARCHIVE:
        raise ReleaseError('Frontend artifact exceeds extraction limits')
    names = set()
    for entry in entries:
        name = entry.filename.rstrip('/')
        path = PurePosixPath(name)
        if (not name or str(path) != name or path.is_absolute() or '..' in path.parts or '\\' in name or
                name in names or (entry.external_attr >> 16) & 0o170000 == 0o120000 or
                (name not in ('dist', 'release-sha', 'SHA256SUMS', 'wrangler.jsonc', 'manifest.json') and not name.startswith('dist/'))):
            raise ReleaseError('Unsafe frontend artifact archive entry')
        names.add(name)
        target = directory / name
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(entry))
    digest = artifact_checksum(directory, sha)
    summary.update(artifact_available=True, artifact_id=item['id'], artifact_checksum=digest, checksum_verified=True)
    return directory / 'dist'


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')


class Publisher:
    def __init__(self, root, api=None, runner=run):
        self.root = Path(root).resolve()
        self.api = api or API()
        self.runner = runner
        self.summary = {'worker': WORKER, 'checks': [], 'backend': 'Independent; not read, changed, or rolled back'}

    def wrangler(self, *args):
        executable = os.environ.get('WRANGLER_BIN', 'node_modules/wrangler/bin/wrangler.js')
        return self.runner(['node', executable, *args], self.root / 'web')

    def routes(self):
        self.runner([sys.executable, str(Path(__file__).with_name('cloudflare-routes.py')), 'check'], self.root)
        self.summary['checks'].append('Cloudflare route check passed')
    def converge(self, sha, timeout=45):
        verifier_path = Path(__file__).with_name('verify-frontend.py')
        spec = importlib.util.spec_from_file_location('acb_release_verifier', verifier_path)
        vf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vf)
        client = vf.Client('https://' + HOSTS[1])
        deadline = time.monotonic() + timeout
        consecutive = 0
        while True:
            ready = False
            try:
                res = client.get('/__release?smoke=' + sha)
                ready = (res.status == 200 and res.mime() == 'text/plain' and
                         res.body == (sha + '\n').encode() and
                         'no-store' in vf.cache_directives(res))
            except vf.VerificationError:
                pass
            consecutive = consecutive + 1 if ready else 0
            if consecutive >= 3:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReleaseError(f'Static release did not converge to {sha} within {timeout}s')
            time.sleep(min(2, remaining))

    def verify(self, sha, artifact):
        mode = 'static' if artifact else 'rollback'
        self.converge(sha)
        command = [sys.executable, str(Path(__file__).with_name('verify-frontend.py')), '--origin',
                   'https://' + HOSTS[1], '--sha', sha, '--mode', mode, '--surface', 'viewer']
        if artifact:
            command += ['--artifact', str(artifact)]
        self.runner(command, self.root)
        self.summary['checks'].append(f'Viewer {mode} HTTP checks passed for {sha}')
        self.runner([sys.executable, str(Path(__file__).with_name('verify-frontend.py')), '--origin',
                     'https://' + HOSTS[0], '--sha', sha, '--mode', 'access'], self.root)
        self.summary['checks'].append('Unauthenticated bank Access redirect passed; bank SHA/browser not verified')

    def assert_active(self, expected):
        active = self.api.active()
        if active != expected:
            self.summary['deployment_drift'] = {'expected': expected, 'actual': active}
            raise ReleaseError('Deployment drift detected; refusing to overwrite another deployment')

    def candidate(self, output, sha, bootstrap=False):
        clean = re.sub(r'\x1b\[[0-9;]*m', '', output)
        ids = re.findall(r'(?:Worker |Current )?Version ID:\s*(' + UUID + r')', clean)
        if len(set(ids)) != 1:
            raise ReleaseError('Current Wrangler upload did not return one exact version ID')
        version_id = ids[0]
        listed = json.loads(self.wrangler('versions', 'list', '--json'))
        if not isinstance(listed, list):
            raise ReleaseError('Malformed Wrangler version list')
        matches = [item for item in listed if item.get('id') == version_id and
                   item.get('annotations', {}).get('workers/tag') == sha]
        if len(matches) != 1:
            raise ReleaseError('Upload ID and tagged Wrangler version list disagree')
        version, _ = self.api.version(version_id)
        if version.get('annotations', {}).get('workers/tag') != sha:
            raise ReleaseError('Uploaded version tag disagrees with the verified artifact')
        if bootstrap and version.get('annotations', {}).get('workers/message') != 'bootstrap ' + sha:
            raise ReleaseError('Bootstrap version message identity mismatch')
        return version_id

    def restore(self, previous, previous_sha, expected):
        self.assert_active(expected)
        # Restore service first. Artifact/network failures must not leave a bad
        # candidate serving merely because checksum evidence is unavailable.
        self.wrangler('rollback', previous['version_id'], '--message', 'frontend verification failed')
        restored = self.api.active()
        if restored['version_id'] != previous['version_id']:
            raise ReleaseError('Exact previous version rollback was not confirmed')
        self.summary['restored_deployment'] = restored
        self.summary['rollback'] = {'version_id': previous['version_id'], 'sha': previous_sha}
        with tempfile.TemporaryDirectory(prefix='frontend-rollback-') as temporary:
            artifact = previous_artifact(previous_sha, Path(temporary), self.summary['rollback'])
            self.verify(previous_sha, artifact)
        self.routes()
        self.api.exposure()
        self.assert_active(restored)
        self.summary['rollback']['public_checks_passed'] = True

    def execute(self, sha, mode, version_id, summary_path):
        self.summary.update(requested_sha=sha, mode=mode, status='failed', public_checks_passed=False)
        try:
            if mode == 'bootstrap':
                self.bootstrap(sha, summary_path)
                return
            self.routes()
            if not self.api.exposure():
                raise ReleaseError('Worker must exist before normal publication')
            previous = self.api.active()
            previous_version, _ = self.api.version(previous['version_id'])
            previous_sha = previous_version['annotations']['workers/tag']
            self.summary.update(previous_deployment=previous, previous_sha=previous_sha)
            if mode == 'publish':
                digest = artifact_checksum(self.root / 'web', sha)
                self.summary.update(frontend_sha=sha, artifact_checksum=digest, checksum_verified=True)
                if previous_sha == sha:
                    self.verify(sha, self.root / 'web/dist')
                    self.routes()
                    self.api.exposure()
                    self.assert_active(previous)
                    self.summary.update(status='already_current', public_checks_passed=True, active_deployment=previous)
                    return
                output = self.wrangler('versions', 'upload', '--tag', sha, '--message', 'frontend ' + sha)
                save(str(summary_path) + '.upload.json', {'wrangler_upload_output': output})
                self.summary['upload_evidence_path'] = str(summary_path) + '.upload.json'
                candidate = self.candidate(output, sha)
                if candidate == previous['version_id']:
                    raise ReleaseError('Upload returned the previously active version instead of a new candidate')
                artifact = self.root / 'web/dist'
            else:
                candidate = version_id
                version, _ = self.api.version(candidate)
                if version['annotations']['workers/tag'] != sha:
                    raise ReleaseError('Rollback version does not match the requested source SHA')
                self.summary['frontend_sha'] = sha
                artifact = None
            self.summary['candidate_version_id'] = candidate
            self.assert_active(previous)
            switched = None
            try:
                if mode == 'publish':
                    self.wrangler('versions', 'deploy', candidate + '@100', '--yes', '--message', 'frontend ' + sha)
                else:
                    self.wrangler('rollback', candidate, '--message', 'intentional frontend rollback ' + sha)
                switched = self.api.active()
                if switched['version_id'] != candidate or switched['deployment_id'] == previous['deployment_id']:
                    raise ReleaseError('Candidate deployment identity was not confirmed')
                self.summary['candidate_deployment'] = switched
                if mode == 'rollback':
                    self.summary['rollback_artifact'] = {}
                    with tempfile.TemporaryDirectory(prefix='frontend-rollback-') as temporary:
                        artifact = previous_artifact(sha, Path(temporary), self.summary['rollback_artifact'])
                        self.verify(sha, artifact)
                else:
                    self.verify(sha, artifact)
                self.routes()
                self.api.exposure()
                self.assert_active(switched)
            except (ReleaseError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
                self.summary['candidate_error'] = str(error) if isinstance(error, ReleaseError) else type(error).__name__
                if switched is None:
                    # A CLI transport failure can occur after the deployment was
                    # accepted. Roll back only a confirmed candidate, not drift.
                    live = self.api.active()
                    if live == previous:
                        raise
                    if live['version_id'] != candidate:
                        self.summary['deployment_drift'] = {'expected_version': candidate, 'actual': live}
                        raise ReleaseError('Deployment drift after CLI error; rollback refused') from None
                    switched = live
                if switched['version_id'] != candidate or switched == previous:
                    self.summary['deployment_drift'] = {'expected_version': candidate, 'actual': switched}
                    raise ReleaseError('Candidate not active; rollback refused') from None
                self.restore(previous, previous_sha, switched)
                raise
            self.summary.update(status='passed', public_checks_passed=True, active_deployment=switched)
        except (ReleaseError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
            # Never record arbitrary HTTP response text or command stderr.
            self.summary['error'] = str(error) if isinstance(error, ReleaseError) else type(error).__name__
            raise ReleaseError(self.summary['error']) from None
        finally:
            save(summary_path, self.summary)

    def bootstrap(self, sha, summary_path):
        exists = self.api.exposure(bootstrap=True)
        if exists:
            active = self.api.active()
            version, details = self.api.version(active['version_id'])
            tag = version['annotations']['workers/tag']
            resources = details.get('resources', {})
            if (version.get('annotations', {}).get('workers/message') != 'bootstrap ' + tag or
                    resources.get('bindings') or resources.get('script', {}).get('handlers') or
                    resources.get('script', {}).get('named_handlers')):
                raise ReleaseError('Existing Worker is not an unexposed static bootstrap; refusing overwrite')
            self.summary['previous_deployment'] = active
        digest = artifact_checksum(self.root / 'web', sha)
        self.summary.update(frontend_sha=sha, artifact_checksum=digest, checksum_verified=True)
        # Re-inspect immediately before the sole initial-service creation path.
        still_exists = self.api.exposure(bootstrap=True)
        if still_exists != exists:
            raise ReleaseError('Bootstrap Worker existence drift; refusing overwrite')
        if exists:
            self.assert_active(active)
        output = self.wrangler('deploy', '--message', 'bootstrap ' + sha, '--tag', sha)
        save(str(summary_path) + '.upload.json', {'wrangler_upload_output': output})
        self.summary['upload_evidence_path'] = str(summary_path) + '.upload.json'
        candidate = self.candidate(output, sha, bootstrap=True)
        active = self.api.active()
        if active['version_id'] != candidate:
            raise ReleaseError('Bootstrap deployment identity mismatch')
        self.api.exposure(bootstrap=True)
        self.summary.update(status='bootstrapped_no_traffic', candidate_version_id=candidate,
                            active_deployment=active, public_checks_passed=False,
                            traffic_note='No routes switched. Public smoke and owner browser acceptance are still required at cutover.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--mode', choices=('publish', 'bootstrap', 'rollback'), required=True)
    parser.add_argument('--version-id')
    parser.add_argument('--summary', required=True, type=Path)
    args = parser.parse_args(argv)
    if not re.fullmatch(SHA, args.sha):
        parser.error('--sha must be a 40-character lowercase commit SHA')
    if (args.mode == 'rollback') != bool(args.version_id) or (args.version_id and not re.fullmatch(UUID, args.version_id)):
        parser.error('--version-id must be an exact UUID and is required only for rollback')
    publisher = None
    try:
        publisher = Publisher(Path.cwd())
        publisher.execute(args.sha, args.mode, args.version_id, args.summary)
    except ReleaseError as error:
        # Credentials fail before constructing a publisher, so retain a receipt
        # even on that path without any Cloudflare mutation.
        if publisher is None:
            save(args.summary, {'mode': args.mode, 'requested_sha': args.sha, 'status': 'failed', 'error': str(error)})
        print('Frontend release failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
