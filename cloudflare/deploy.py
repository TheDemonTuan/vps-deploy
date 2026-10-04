#!/usr/bin/env python3
"""Resolve registered CI artifacts, validate bytes, and invoke platform-owned adapters."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
SHA = re.compile(r'[0-9a-f]{40}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
MAX_BYTES = 500 * 1024 * 1024
APPS = ('acb', 'uptimeflare')


class Failure(RuntimeError):
    pass


class Ineligible(Failure):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise Failure('Refusing non-HTTPS artifact redirect')
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            result.remove_header('Authorization')
        return result


class GitHub:
    def __init__(self, token=None, base='https://api.github.com'):
        self.token = token if token is not None else os.environ.get('GH_TOKEN', '')
        self.base = base
        self.opener = urllib.request.build_opener(SafeRedirect())
        if not self.token:
            raise Failure('GH_TOKEN is required for source CI verification')

    def get(self, suffix, binary=False):
        request = urllib.request.Request(self.base + suffix, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'vps-deploy-cloudflare'})
        try:
            with self.opener.open(request, timeout=60) as response:
                if binary:
                    result = response.read(MAX_BYTES + 1)
                    if len(result) > MAX_BYTES:
                        raise Failure('Artifact archive exceeds download limit')
                    return result
                return json.load(response)
        except (urllib.error.URLError, ValueError) as error:
            raise Failure('GitHub source verification failed (' + type(error).__name__ + ')') from None


def registration(app):
    if app not in APPS:
        raise Failure('Unregistered application')
    value = json.loads((ROOT / 'registry' / (app + '.json')).read_text())
    if value['app'] != app or not re.fullmatch(r'TheDemonTuan/[A-Za-z0-9_.-]+', value['repository']):
        raise Failure('Invalid platform registration')
    return value


def validate_run(api, config, run_id, explicit=False):
    if type(run_id) is not int or run_id <= 0:
        raise Failure('Source run must be a positive integer')
    prefix = '/repos/' + config['repository']
    run = api.get(prefix + '/actions/runs/' + str(run_id))
    workflow = api.get(prefix + '/actions/workflows/' + str(run.get('workflow_id', '')))
    allowed = config['manual_branches'] if explicit else [config['branch']]
    if (run.get('status') != 'completed' or run.get('conclusion') != 'success' or
            run.get('event') not in (('push', 'workflow_dispatch') if explicit else ('push',)) or
            run.get('head_branch') not in allowed or
            run.get('head_repository', {}).get('full_name') != config['repository'] or
            workflow.get('path') != '.github/workflows/' + config['workflow'] or
            not SHA.fullmatch(run.get('head_sha', ''))):
        raise Ineligible('Source run is not successful registered-branch CI')
    head = api.get(prefix + '/git/ref/heads/' + urllib.parse.quote(run['head_branch'], safe=''))['object']['sha']
    if not SHA.fullmatch(head):
        raise Failure('Malformed source branch head')
    if head != run['head_sha']:
        comparison = api.get(prefix + '/compare/' + run['head_sha'] + '...' + head)
        files = comparison.get('files')
        if (comparison.get('status') != 'ahead' or not isinstance(files, list) or len(files) >= 300 or
                comparison.get('total_commits', 0) > 250 or
                any(any(item.get('filename', '').startswith(path) or item.get('previous_filename', '').startswith(path)
                        for path in config['frontend_paths']) for item in files)):
            raise Ineligible('Source artifact is stale for current frontend inputs')
    return run


def artifacts(api, config, run):
    result, page = [], 1
    while True:
        data = api.get('/repos/' + config['repository'] + '/actions/runs/' + str(run['id']) +
                       '/artifacts?per_page=100&page=' + str(page))
        rows = data.get('artifacts')
        if not isinstance(rows, list):
            raise Failure('Malformed source artifact list')
        result.extend(rows)
        if len(rows) < 100:
            break
        page += 1
    name = config['artifact_prefix'] + run['head_sha']
    matches = [item for item in result if item.get('name') == name and item.get('expired') is False]
    if len(matches) > 1:
        raise Failure('Ambiguous source artifact identity')
    if not matches:
        return None
    item = matches[0]
    if (item.get('workflow_run', {}).get('head_sha') != run['head_sha'] or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', item.get('digest', ''))):
        raise Failure('Artifact run identity or server digest is missing')
    return item


def resolve_route_restore(api, config, run_id):
    if config['app'] != 'acb' or type(run_id) is not int or run_id <= 0:
        raise Failure('Route restoration requires ACB and an explicit central cutover run ID')
    repository = 'TheDemonTuan/vps-deploy'
    prefix = '/repos/' + repository
    run = api.get(prefix + '/actions/runs/' + str(run_id))
    workflow = api.get(prefix + '/actions/workflows/' + str(run.get('workflow_id', '')))
    if (run.get('status') != 'completed' or run.get('event') != 'workflow_dispatch' or
            run.get('head_branch') != 'main' or run.get('head_repository', {}).get('full_name') != repository or
            workflow.get('path') != '.github/workflows/cloudflare-deploy.yml' or
            not SHA.fullmatch(run.get('head_sha', ''))):
        raise Failure('Route snapshots must come from a completed central main-branch dispatch')
    data = api.get(prefix + '/actions/runs/' + str(run_id) + '/artifacts?per_page=100')
    if data.get('total_count', 0) > 100 or not isinstance(data.get('artifacts'), list):
        raise Failure('Incomplete central receipt artifact list')
    matches = [item for item in data['artifacts'] if item.get('name') == 'cloudflare-receipt-acb-' + str(run_id) and item.get('expired') is False]
    if len(matches) != 1:
        raise Failure('Exactly one unexpired central ACB receipt artifact is required')
    item = matches[0]
    if (item.get('workflow_run', {}).get('head_sha') != run['head_sha'] or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', item.get('digest', ''))):
        raise Failure('Central receipt artifact identity or digest is missing')
    return {'app': 'acb', 'mode': 'restore-routes', 'sha': run['head_sha'], 'run_id': run_id,
            'artifact_id': item['id'], 'archive_digest': item['digest']}


def resolve(api, config, mode, source_run_id=None, sha=None):
    if mode == 'restore-routes':
        return resolve_route_restore(api, config, source_run_id)
    if mode in ('bootstrap', 'cutover') and config['app'] != 'acb':
        raise Failure('Bootstrap and cutover are reserved for unexposed ACB static assets')
    if mode in ('survey', 'check'):
        return {'app': config['app'], 'mode': mode, 'sha': '', 'run_id': 0}
    if mode == 'rollback':
        if not SHA.fullmatch(sha or ''):
            raise Failure('Rollback requires --sha matching both requested version tags')
        return {'app': config['app'], 'mode': mode, 'sha': sha, 'run_id': 0}
    explicit = source_run_id is not None
    if explicit:
        runs = [{'id': source_run_id}]
    else:
        query = urllib.parse.urlencode({'branch': config['branch'], 'event': 'push', 'status': 'success', 'per_page': 100})
        data = api.get('/repos/' + config['repository'] + '/actions/workflows/' + config['workflow'] + '/runs?' + query)
        runs = data.get('workflow_runs')
        if not isinstance(runs, list):
            raise Failure('Malformed source workflow run list')
    for candidate in runs:
        try:
            run = validate_run(api, config, candidate['id'], explicit)
        except Ineligible:
            if explicit:
                raise
            continue
        item = artifacts(api, config, run)
        if item is not None:
            return {'app': config['app'], 'mode': mode, 'sha': run['head_sha'], 'run_id': run['id'],
                    'artifact_id': item['id'], 'archive_digest': item['digest']}
    if explicit:
        raise Failure('Explicit successful source run has no eligible unexpired artifact')
    return None


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or str(path) != name or path.is_absolute() or '..' in path.parts or
            '\\' in name or ':' in name or any(ord(char) < 32 for char in name)):
        raise Failure('Unsafe archive or checksum path')
    return path


def extract(raw, directory, server_digest):
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != server_digest:
        raise Failure('Downloaded ZIP does not match GitHub artifact digest')
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        entries = archive.infolist()
        if len(entries) > 25000 or sum(item.file_size for item in entries) > MAX_BYTES:
            raise Failure('Artifact extraction exceeds limits')
        names = set()
        for item in entries:
            name = item.filename.rstrip('/') if item.is_dir() else item.filename
            safe_name(name)
            kind = stat.S_IFMT(item.external_attr >> 16)
            if name.casefold() in names or kind not in (0, stat.S_IFREG, stat.S_IFDIR) or item.flag_bits & 1:
                raise Failure('Duplicate, link, device, or encrypted artifact entry')
            names.add(name.casefold())
        # Validate the entire archive before writing any entry.
        for item in entries:
            target = directory / item.filename
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item))
        return directory
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        if isinstance(error, Failure):
            raise
        raise Failure('Invalid artifact ZIP (' + type(error).__name__ + ')') from None


def checksum(directory, config, sha):
    records = {}
    manifest = (directory / 'SHA256SUMS').read_bytes()
    for line in manifest.decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise Failure('Malformed checksum manifest')
        digest, name = match.groups()
        safe_name(name)
        if name in records or name == 'SHA256SUMS':
            raise Failure('Duplicate or self-referential checksum')
        target = directory / name
        if target.is_symlink() or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise Failure('Artifact checksum mismatch: ' + name)
        records[name] = digest
    paths = list(directory.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise Failure('Artifact symlinks are forbidden')
    actual = {path.relative_to(directory).as_posix() for path in paths if path.is_file()} - {'SHA256SUMS'}
    if set(records) != actual:
        raise Failure('Checksums must cover every artifact file exactly')
    identity = json.loads((directory / 'manifest.json').read_text())
    if identity != {'app': config['app'], 'source_repository': config['repository'], 'source_sha': sha}:
        raise Failure('Artifact manifest does not match registered source CI')
    return hashlib.sha256(manifest).hexdigest()


def cloudflare(suffix):
    token = os.environ.get('CLOUDFLARE_API_TOKEN', '')
    account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
    if not token or not re.fullmatch(r'[0-9a-f]{32}', account):
        raise Failure('Central Cloudflare token and account ID are required')
    request = urllib.request.Request('https://api.cloudflare.com/client/v4' + suffix,
                                     headers={'Authorization': 'Bearer ' + token})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        raise Failure('Cloudflare GET ' + suffix.split('?')[0] + ' failed (HTTP ' + str(error.code) + ')') from None
    except (urllib.error.URLError, ValueError) as error:
        raise Failure('Cloudflare read failed (' + type(error).__name__ + ')') from None
    if not isinstance(value, dict) or value.get('success') is not True:
        raise Failure('Cloudflare read returned an unsuccessful response')
    return value['result']


def account_zone(config):
    account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
    values = cloudflare('/zones?name=' + config['zone_name'] + '&per_page=50')
    matches = [item for item in values if item.get('name') == config['zone_name'] and item.get('account', {}).get('id') == account]
    if len(matches) != 1:
        raise Failure('Central token cannot resolve exactly one registered zone in its account')
    return matches[0]['id']


def survey(config):
    account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
    scripts = cloudflare('/accounts/' + account + '/workers/scripts')
    names = {item['id'] for item in scripts}
    result = {'status': 'read_only', 'app': config['app'], 'workers': {name: name in names for name in config['workers']},
              'note': 'No scripts, routes, secrets, triggers, database, or VPS state modified'}
    if config['app'] == 'acb':
        zone = account_zone(config)
        routes = cloudflare('/zones/' + zone + '/workers/routes')
        result.update(zone_readable=True, registered_worker_route_count=sum(item.get('script') in config['workers'] for item in routes))
    return result


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def execute(api, config, selection, summary, version_id=None, monitor_version_id=None):
    mode, sha = selection['mode'], selection['sha']
    if mode == 'survey':
        save(summary, survey(config))
        return
    env = os.environ.copy()
    if config['app'] == 'acb':
        env['CLOUDFLARE_ZONE_ID'] = account_zone(config)
    env['GITHUB_REPOSITORY'] = config['repository']
    env['WRANGLER_BIN'] = str(ROOT / 'node_modules/wrangler/bin/wrangler.js')
    if config['app'] == 'acb':
        adapter = ROOT / 'acb/release-frontend.py'
    else:
        env['UPTIMEFLARE_PUBLIC_TRANSPORT'] = 'chromium'
        adapter = ROOT / 'uptimeflare.py'
    with tempfile.TemporaryDirectory(prefix='cloudflare-release-') as temporary:
        staging = Path(temporary)
        digest = None
        if mode == 'restore-routes':
            if resolve_route_restore(api, config, selection['run_id']) != selection:
                raise Failure('Central route snapshot artifact changed after the production gate')
            raw = api.get('/repos/TheDemonTuan/vps-deploy/actions/artifacts/' + str(selection['artifact_id']) + '/zip', binary=True)
            extract(raw, staging, selection['archive_digest'])
            snapshots = []
            for host, hostname in (('bank', 'bank.tuannguyenviet.site'), ('viewer', 'transactions.tuannguyenviet.site')):
                path = staging / (host + '-routes.json')
                snapshot = json.loads(path.read_text())
                if snapshot.get('host') != hostname or snapshot.get('zone_id') != env['CLOUDFLARE_ZONE_ID'] or snapshot.get('schema') != 1:
                    raise Failure('Central route snapshot host, schema or zone mismatch')
                output = summary.parent / path.name
                save(output, snapshot)
                snapshots.append(output)
            restored = []
            for snapshot in snapshots:
                result = subprocess.run([sys.executable, str(ROOT / 'acb/cloudflare-routes.py'), 'restore', '--snapshot', str(snapshot)], cwd=staging, env=env, check=False)
                restored.append({'snapshot': snapshot.name, 'restored': result.returncode == 0})
                save(summary, {'app': 'acb', 'mode': mode, 'status': 'restored' if all(item['restored'] for item in restored) else 'failed',
                               'snapshot_run_id': selection['run_id'], 'source_archive_digest': selection['archive_digest'],
                               'route_restoration': restored, 'worker_version_changed': False, 'vps_metadata_changed': False})
                if result.returncode:
                    raise Failure('Route snapshot restoration refused; live drift is not overwritten')
            return
        if mode in ('publish', 'bootstrap', 'cutover'):
            # Resolve again immediately before consuming bytes; reject failed reruns, stale heads and drift.
            checked = resolve(api, config, mode, selection['run_id'])
            if checked != selection:
                raise Failure('Source artifact changed after the production gate')
            raw = api.get('/repos/' + config['repository'] + '/actions/artifacts/' + str(selection['artifact_id']) + '/zip', binary=True)
            artifact = staging / ('web' if config['app'] == 'acb' else 'artifact')
            artifact.mkdir(mode=0o700)
            extract(raw, artifact, selection['archive_digest'])
            digest = checksum(artifact, config, sha)
        if mode == 'check' and config['app'] == 'acb':
            command = [sys.executable, str(ROOT / 'acb/cloudflare-routes.py'), 'check']
        elif mode == 'cutover' and config['app'] == 'acb':
            snapshots = [summary.parent / (host + '-routes.json') for host in ('viewer', 'bank')]
            routes_bin = str(ROOT / 'acb/cloudflare-routes.py')
            verify_bin = str(ROOT / 'acb/verify-frontend.py')
            # Align the unexposed service with the verified artifact before any
            # traffic switch. Bootstrap rejects already-routed services.
            subprocess.run([sys.executable, str(adapter), '--mode', 'bootstrap', '--sha', sha, '--summary', str(summary.resolve())], cwd=staging, env=env, check=True)
            try:
                for host, snapshot in zip(('viewer', 'bank'), snapshots):
                    subprocess.run([sys.executable, routes_bin, 'apply', '--host', host, '--snapshot', str(snapshot)], cwd=staging, env=env, check=True)
                    verification = [sys.executable, verify_bin, '--sha', sha]
                    if host == 'viewer':
                        verification += ['--origin', 'https://transactions.tuannguyenviet.site', '--mode', 'static', '--surface', 'viewer', '--artifact', str(artifact / 'dist')]
                    else:
                        verification += ['--origin', 'https://bank.tuannguyenviet.site', '--mode', 'access']
                    subprocess.run(verification, cwd=staging, env=env, check=True)
                # The normal publisher confirms both route sets, service
                # exposure and the active artifact without another upload.
                subprocess.run([sys.executable, str(adapter), '--mode', 'publish', '--sha', sha, '--summary', str(summary.resolve())], cwd=staging, env=env, check=True)
                receipt = json.loads(summary.read_text())
                if receipt.get('status') not in ('passed', 'already_current') or receipt.get('public_checks_passed') is not True:
                    raise Failure('Cutover publication did not confirm public checks')
                receipt.update(mode='cutover', status='pending_owner_acceptance', routes_verified=True,
                               owner_browser_checks_passed=False, metadata_migration_authorized=False,
                               traffic_note='Routes switched; authenticated owner acceptance is required before VPS metadata migration or frontend removal.')
                save(summary, receipt)
            except (Failure, OSError, ValueError, subprocess.SubprocessError) as error:
                restored = []
                for snapshot in reversed(snapshots):
                    if snapshot.exists():
                        result = subprocess.run([sys.executable, routes_bin, 'restore', '--snapshot', str(snapshot)], cwd=staging, env=env, check=False)
                        restored.append({'snapshot': snapshot.name, 'restored': result.returncode == 0})
                receipt = json.loads(summary.read_text()) if summary.exists() else {}
                receipt.update(status='failed', mode='cutover', route_restoration=restored,
                               owner_browser_checks_passed=False, metadata_migration_authorized=False)
                save(summary, receipt)
                raise Failure('Cutover failed; snapshot restoration results retained in receipt') from error
            command = [sys.executable, '-c', 'pass']
        else:
            command = [sys.executable, str(adapter), '--mode', mode, '--sha', sha, '--summary', str(summary.resolve())]
            if config['app'] == 'uptimeflare':
                command += ['--root', str(artifact if mode == 'publish' else staging)]
            if version_id:
                command += ['--version-id', version_id]
            if monitor_version_id:
                command += ['--monitor-version-id', monitor_version_id]
        result = subprocess.run(command, cwd=staging, env=env, check=False)
        receipt = json.loads(summary.read_text()) if summary.exists() else {'status': 'passed' if result.returncode == 0 else 'failed'}
        receipt.update(app=config['app'], source_repository=config['repository'], source_run_id=selection['run_id'],
                       requested_sha=sha, artifact_checksum=digest, source_archive_digest=selection.get('archive_digest'))
        save(summary, receipt)
        if result.returncode:
            raise Failure('Trusted deployment adapter failed; consult its sanitized receipt')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('resolve', 'execute'))
    parser.add_argument('--app', choices=(*APPS, 'all'), required=True)
    parser.add_argument('--mode', choices=('publish', 'bootstrap', 'rollback', 'survey', 'check', 'cutover', 'restore-routes'), default='publish')
    parser.add_argument('--source-run-id', type=int)
    parser.add_argument('--sha')
    parser.add_argument('--version-id')
    parser.add_argument('--monitor-version-id')
    parser.add_argument('--scheduled', action='store_true')
    parser.add_argument('--selection', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.app == 'all' and (args.source_run_id or args.mode in ('bootstrap', 'rollback')):
            raise Failure('Explicit source run, bootstrap and rollback require exactly one app')
        if args.mode == 'rollback':
            if not UUID.fullmatch(args.version_id or '') or (args.app == 'uptimeflare' and not UUID.fullmatch(args.monitor_version_id or '')):
                raise Failure('Rollback requires exact app version UUID(s)')
        elif args.version_id or args.monitor_version_id:
            raise Failure('Version IDs are accepted only for rollback')
        api = GitHub()
        if args.operation == 'resolve':
            selections = []
            for app in APPS if args.app == 'all' else (args.app,):
                config = registration(app)
                if args.scheduled and not config['automatic']:
                    continue
                selected = resolve(api, config, args.mode, args.source_run_id, args.sha)
                if selected:
                    selections.append(selected)
            save(args.output, {'include': selections})
            print('Eligible registered application releases: ' + str(len(selections)))
        else:
            if args.app == 'all' or args.selection is None:
                raise Failure('Execute requires one app and its resolved selection')
            selected = json.loads(args.selection.read_text())
            if selected['app'] != args.app or selected['mode'] != args.mode:
                raise Failure('Selection does not match the registered requested app/mode')
            execute(api, registration(args.app), selected, args.output, args.version_id, args.monitor_version_id)
    except (Failure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Failure) else type(error).__name__
        receipt = {}
        if args.operation == 'execute' and args.output.exists():
            try:
                receipt = json.loads(args.output.read_text())
            except (OSError, ValueError):
                pass
        receipt.update(status='failed', controller_error=message)
        save(args.output, receipt)
        print('Central Cloudflare deployment refused: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
