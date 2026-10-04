"""CGW's single-writer, durable-fence upgrade transaction (not a gateway deploy)."""
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import time
from pathlib import Path
from contextlib import closing

from core import (Failure, command, container, container_digest, digest, docker, fault,
                  fsync_dir, image_id, inspect, load, require, save, trusted_path)

NAME = '9router-cgw-runtime'
VOLUME = '9router-cgw-data'
REPOSITORY = 'ghcr.io/thedemontuan/9router-cgw-runtime'


class Budget:
    def __init__(self, end=None):
        self.end = min(end or time.time() + 1800, time.time() + 1800)
        self.phase_end = self.end - 60

    def phase(self, seconds):
        self.phase_end = min(time.time() + seconds, self.end - 60)
        self.remaining()

    def remaining(self, ceiling=300):
        left = min(self.phase_end, self.end - 60) - time.time()
        require(left > 0, 'CGW_DEADLINE')
        return max(1, min(ceiling, math.ceil(left)))


def browser_manifest(image, budget):
    """Read only the image's public pin, with no host state or network attached."""
    require(re.fullmatch(re.escape(REPOSITORY) + r'@sha256:[0-9a-f]{64}', image or ''), 'INVALID_IMAGE')
    image_id(image)
    raw = docker('run', '--rm', '--pull', 'never', '--read-only', '--network', 'none',
                 '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                 '--entrypoint', 'bun', image, '-e',
                 "process.stdout.write(require('node:fs').readFileSync('/opt/cgw/image-build-manifest.json','utf8'))",
                 timeout=budget.remaining())
    try:
        require(len(raw) <= 65536, 'CGW_BROWSER_MANIFEST')
        browser = json.loads(raw)['browser']
        architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine)
        pin = browser['platforms'][architecture]
        require(browser['distribution'] == 'google-chrome-for-testing' and
                browser['installRoot'] == '/opt/cgw-browser' and
                re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', browser['version']) and
                all(re.fullmatch(r'[0-9a-f]{64}', pin[key]) for key in ('sha256', 'binarySha256')),
                'CGW_BROWSER_MANIFEST')
        return browser, architecture, pin
    except (KeyError, TypeError, ValueError):
        raise Failure('CGW_BROWSER_MANIFEST') from None


def browser_directory(cfg, image, budget):
    """Version-bound immutable private payload; never install or replace it here."""
    browser, architecture, pin = browser_manifest(image, budget)
    directory = trusted_path(cfg / 'cgw-browsers' / pin['sha256'], directory=True)
    try:
        proof = load(trusted_path(directory / '.cgw-chrome.json'))
        require(proof['version'] == browser['version'] and proof['architecture'] == architecture and
                proof['archiveSha256'] == pin['sha256'] and proof['binarySha256'] == pin['binarySha256'] and
                isinstance(proof['files'], dict) and proof['files'].get('chrome') == pin['binarySha256'],
                'CGW_BROWSER_PROOF')
        actual = {}
        for path in directory.rglob('*'):
            budget.remaining()
            trusted_path(path, directory=path.is_dir())
            readable = 0o005 if path.is_dir() else 0o004
            require(path.stat().st_mode & readable == readable, 'CGW_BROWSER_PROOF')
            if path.is_file() and path != directory / '.cgw-chrome.json':
                checksum = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        budget.remaining()
                        checksum.update(chunk)
                actual[path.relative_to(directory).as_posix()] = checksum.hexdigest()
        require(actual == proof['files'], 'CGW_BROWSER_PROOF')
        require((directory / 'chrome').stat().st_mode & 0o111 and directory.stat().st_mode & 0o005 == 0o005,
                'CGW_BROWSER_PROOF')
    except (KeyError, TypeError, ValueError, OSError):
        raise Failure('CGW_BROWSER_PROOF') from None
    return directory


def browser_mount(value, cfg, image, budget):
    directory = browser_directory(cfg, image, budget)
    mounts = [row for row in value.get('Mounts', []) if row.get('Destination') == '/opt/cgw-browser']
    require(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and mounts[0].get('RW') is False and
            mounts[0].get('Source') == str(directory), 'CGW_BROWSER_MOUNT')
    return directory


def compose(release, cfg, image, budget, *args):
    require(re.fullmatch(re.escape(REPOSITORY) + r'@sha256:[0-9a-f]{64}', image or ''), 'INVALID_IMAGE')
    browser = browser_directory(cfg, image, budget)
    env = dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', CGW_IMAGE=image,
               CGW_CONFIG_DIR=str(cfg), CGW_BROWSER_DIR=str(browser))
    return command('/usr/bin/docker', 'compose', '-p', '9router-cgw', '-f',
                   str(trusted_path(release / 'apps/9router/docker-compose.cgw-runtime.yml')),
                   '--ansi=never', '--progress=plain', *args, env=env, timeout=budget.remaining())


def network(profile):
    require(profile.get('cgw_network') == '9router-cgw', 'CGW_NETWORK')
    for name, internal, label in (('9router-cgw', True, 'cgw'), ('9router-cgw-egress', False, 'egress')):
        value = inspect('network', name)
        labels = value.get('Labels') or {}
        require(value.get('Internal') is internal and value.get('Driver') == 'bridge' and
                labels.get('com.docker.compose.project') == '9router-cgw' and
                labels.get('com.docker.compose.network') == label, 'CGW_NETWORK')


# The token stays in the container: never argv, environment, stdout or diagnostics.
ADMIN_SCRIPT = """const fs=require('node:fs');
const token=fs.readFileSync('/run/secrets/cgw-admin-token','utf8').trim();
const [path,body]=process.argv.slice(1);
const r=await fetch('http://127.0.0.1:17841'+path,{method:body?'POST':'GET',
headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},
...(body?{body}:{}),redirect:'error',signal:AbortSignal.timeout(8000)});
if(!r.ok) process.exit(1); const data=await r.text(); if(data.length>65536)process.exit(1);console.log(data);"""


def admin(path, body=None, budget=None):
    require(path in ('/healthz', '/admin/profiles', '/admin/drain', '/admin/quiesce', '/admin/resume'), 'CGW_ADMIN_PATH')
    raw = docker('exec', NAME, 'bun', '-e', ADMIN_SCRIPT, path,
                 json.dumps(body, separators=(',', ':')) if body is not None else '',
                 timeout=budget.remaining(10) if budget else 10)
    require(len(raw) <= 65536, 'CGW_DIAGNOSTIC')
    value = json.loads(raw)
    require(type(value) is dict, 'CGW_DIAGNOSTIC')
    return value


def diagnostics(profile, ref=None, operation_id=None, fence_state=None, budget=None):
    value = container(NAME, ref, running=True)
    require(container_digest(value, REPOSITORY) == (ref or container_digest(value, REPOSITORY)), 'CGW_IMAGE')
    network(profile)
    health = admin('/healthz', budget=budget)
    result = admin('/admin/profiles', budget=budget)
    require(health.get('service') == '9router-cgw-runtime' and health.get('protocolVersion') == 1 and
            result.get('protocolVersion') == 1 and result.get('stateSchemaVersion') == 1 and
            type(result.get('acceptedRequestCount')) is int and result['acceptedRequestCount'] >= 0 and
            type(result.get('profiles')) is list, 'CGW_PROTOCOL')
    for key in ('activeHttpRequests', 'activeBrowserTurns', 'pendingToolCalls'):
        require(type(health.get(key)) is int and health[key] >= 0, 'CGW_DIAGNOSTIC')
    if operation_id:
        require(result.get('operationFence') == {'operationId': operation_id, 'state': fence_state}, 'CGW_FENCE')
    result['idle'] = result.get('physicalIdle') is True and all(health[k] == 0 for k in
                     ('activeHttpRequests', 'activeBrowserTurns', 'pendingToolCalls'))
    return result


def volume_path():
    obj = inspect('volume', VOLUME)
    require(obj.get('Driver') == 'local' and not obj.get('Options'), 'CGW_VOLUME')
    path = Path(obj['Mountpoint'])
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), 'CGW_VOLUME')
    return path


def writers_gone(budget):
    # Docker stop waits for the container cgroup to die; also exclude any other
    # container attached to the volume, including independently named writers.
    ids = docker('ps', '-aq', '--filter', 'volume=' + VOLUME, timeout=budget.remaining(10)).split()
    for ident in ids:
        value = inspect('container', ident)
        require(not value['State'].get('Running') and value['State'].get('Pid', 0) == 0 and
                not value['State'].get('Restarting'), 'CGW_WRITER_ACTIVE')


def stop(release, cfg, ref, budget):
    compose(release, cfg, ref, budget, 'stop', '-t', '30', 'cgw-runtime')
    writers_gone(budget)


def start(release, cfg, ref, budget):
    writers_gone(budget)
    compose(release, cfg, ref, budget, 'up', '-d', '--no-deps', '--pull', 'never', 'cgw-runtime')


def wait_diagnostics(profile, ref, op, fence, budget):
    while True:
        try:
            return diagnostics(profile, ref, op, fence, budget)
        except (Failure, ValueError):
            budget.remaining()
            time.sleep(min(2, budget.remaining(2)))


def tree_manifest(path, budget, sync=False):
    result = {}
    for root, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            budget.remaining()
            p = Path(root) / name
            info = p.lstat()
            require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'CGW_SNAPSHOT_TYPE')
            if p.is_file():
                result[str(p.relative_to(path))] = {'sha256': digest(p.read_bytes()),
                    'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
                if sync:
                    with p.open('rb') as stream:
                        os.fsync(stream.fileno())
        if sync:
            fsync_dir(root)
    return result


def validate_database(path):
    database = path / 'runtime.sqlite'
    require(database.is_file() and not database.is_symlink(), 'CGW_SNAPSHOT_DATABASE')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True)) as connection:
        require(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'CGW_SNAPSHOT_DATABASE')
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require({'profiles', 'thread_bindings', 'request_claims'} <= tables, 'CGW_SNAPSHOT_SCHEMA')
        version = connection.execute('PRAGMA user_version').fetchone()[0]
    # Quiesce must have checkpointed and closed WAL before the copy.
    require(not (path / 'runtime.sqlite-wal').exists() or (path / 'runtime.sqlite-wal').stat().st_size == 0, 'CGW_LIVE_WAL')
    return version


def snapshot(state_dir, intent, diagnostics_value, budget):
    writers_gone(budget)
    source = volume_path()
    directory = state_dir / 'cgw-snapshots'
    directory.mkdir(mode=0o700, exist_ok=True)
    trusted_path(directory, directory=True)
    target = directory / intent['operationId']
    require(not target.exists(), 'CGW_SNAPSHOT_EXISTS')
    target.mkdir(mode=0o700)
    source_manifest = tree_manifest(source, budget)
    def copy(src, dst):
        budget.remaining()
        shutil.copy2(src, dst)
        info = os.stat(src)
        os.chown(dst, info.st_uid, info.st_gid)
        return dst
    shutil.copytree(source, target / 'data', copy_function=copy)
    for root, dirs, _ in os.walk(source):
        dst = target / 'data' / Path(root).relative_to(source)
        info = os.stat(root)
        os.chown(dst, info.st_uid, info.st_gid)
    copied = tree_manifest(target / 'data', budget, sync=True)
    require(copied == source_manifest, 'CGW_SNAPSHOT_CHANGED')
    manifest = {'version': 1, 'protocolVersion': 1, 'stateSchemaVersion': diagnostics_value['stateSchemaVersion'],
                'sqliteUserVersion': validate_database(target / 'data'), 'operationId': intent['operationId'],
                'acceptedRequestCount': diagnostics_value['acceptedRequestCount'], 'files': copied}
    save(target / 'manifest.json', manifest)
    fsync_dir(target)
    fsync_dir(directory)
    return str(target), digest((target / 'manifest.json').read_bytes())


def verified_snapshot(intent, budget):
    target = trusted_path(intent['snapshot'], directory=True)
    require(digest((target / 'manifest.json').read_bytes()) == intent['snapshotHash'], 'CGW_SNAPSHOT_UNVERIFIED')
    value = json.loads((target / 'manifest.json').read_bytes())
    require(value['operationId'] == intent['operationId'] and value['acceptedRequestCount'] == intent['acceptedRequestCount'] and
            value['stateSchemaVersion'] == 1 and value['protocolVersion'] == 1 and
            tree_manifest(target / 'data', budget) == value['files'] and
            validate_database(target / 'data') == value['sqliteUserVersion'], 'CGW_SNAPSHOT_UNVERIFIED')
    return target / 'data'


def phase(state, state_dir, name, profile, **kwargs):
    state['revision'] += 1
    state['operation'].update(phase=name, **kwargs)
    save(state_dir / 'state.json', state)
    fault(profile, name)


def finish(state, state_dir):
    state['revision'] += 1
    state['operation'] = None
    save(state_dir / 'state.json', state)


def resume_old(state, state_dir, cfg, release, profile, budget):
    intent = state['operation']
    previous = intent['previous']
    require(previous and image_id(previous) == intent['previous_id'], 'RECOVERY_REQUIRED')
    try:
        value = diagnostics(profile, previous, budget=budget)
    except Failure:
        # An unreachable running runtime is not evidence of physical quiescence.
        # Do not turn recovery diagnostics failure into Docker's forced stop deadline.
        current = inspect('container', NAME)
        require(current['Image'] == intent['previous_id'] and
                not current['State'].get('Running') and current['State'].get('Pid', 0) == 0 and
                not current['State'].get('Restarting'), 'RECOVERY_REQUIRED')
        writers_gone(budget)
        start(release, cfg, previous, budget)
        while True:
            try:
                value = diagnostics(profile, previous, budget=budget)
                break
            except Failure:
                budget.remaining()
                time.sleep(min(2, budget.remaining(2)))
    fence = value.get('operationFence')
    if fence is not None:
        require(fence.get('operationId') == intent['operationId'], 'CGW_FENCE')
        admin('/admin/resume', {'operationId': intent['operationId']}, budget)
    value = diagnostics(profile, previous, budget=budget)
    require(value.get('operationFence') is None, 'CGW_FENCE')
    finish(state, state_dir)


def restore(state, state_dir, cfg, release, profile, budget):
    intent = state['operation']
    require(intent['phase'] not in ('cgw_committed', 'cgw_resumed'), 'RECOVERY_REQUIRED')
    # Validate the retained old pin before stopping a candidate or restoring data.
    browser_directory(cfg, intent['previous'], budget)
    # A crashed/unreachable candidate's admission ledger cannot be inferred from
    # the old snapshot. Re-open the same candidate fenced to obtain durable proof.
    if not intent.get('restoreProven'):
        try:
            current = diagnostics(profile, intent['image'], intent['operationId'], 'quiesced', budget)
        except Failure:
            stop(release, cfg, intent['image'], budget)
            start(release, cfg, intent['image'], budget)
            current = wait_diagnostics(profile, intent['image'], intent['operationId'], 'quiesced', budget)
        require(current['acceptedRequestCount'] == intent['acceptedRequestCount'] and current['idle'] and
                current['stateSchemaVersion'] == intent['stateSchemaVersion'], 'RECOVERY_REQUIRED')
    stop(release, cfg, intent['image'], budget)
    source = verified_snapshot(intent, budget)
    require(image_id(intent['previous']) == intent['previous_id'], 'RECOVERY_REQUIRED')
    destination = volume_path()
    # Persist restore intent before touching any private data; interrupted restore
    # is repeatable only from this same verified, fenced snapshot.
    phase(state, state_dir, 'cgw_restoring', profile, restoreProven=True)
    for child in destination.iterdir():
        budget.remaining()
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    shutil.copytree(source, destination, dirs_exist_ok=True)
    for root, dirs, files in os.walk(source):
        for name in [''] + dirs + files:
            src = Path(root) / name
            dst = destination / src.relative_to(source)
            info = src.stat()
            os.chown(dst, info.st_uid, info.st_gid)
    require(tree_manifest(destination, budget, sync=True) == tree_manifest(source, budget), 'CGW_RESTORE_CHANGED')
    validate_database(destination)
    phase(state, state_dir, 'cgw_restored', profile)
    start(release, cfg, intent['previous'], budget)
    value = wait_diagnostics(profile, intent['previous'], intent['operationId'], 'quiesced', budget)
    require(value['acceptedRequestCount'] == intent['acceptedRequestCount'], 'RECOVERY_REQUIRED')
    resume_old(state, state_dir, cfg, release, profile, budget)


def deploy(req, state, state_dir, cfg, release, profile):
    require(profile.get('cgw_image_repository') == REPOSITORY and state.get('cgw') and state['cgw'].get('current'), 'CGW_NOT_ADOPTED')
    previous, ref = state['cgw']['current'], req['image']
    budget = Budget()
    if previous == ref:
        browser_mount(container(NAME, ref, running=True), cfg, ref, budget)
        value = diagnostics(profile, ref, budget=budget)
        require(value.get('operationFence') is None, 'CGW_FENCE')
        return
    before = diagnostics(profile, previous, budget=budget)
    require(before.get('operationFence') is None, 'CGW_FENCE')
    state['operation'] = {'component': 'cgw', 'request_id': req['request_id'], 'operationId': req['request_id'],
                          'previous': previous, 'previous_id': image_id(previous), 'image': ref,
                          'deadline': budget.end, 'stateSchemaVersion': before['stateSchemaVersion']}
    phase(state, state_dir, 'cgw_prepared', profile)
    try:
        budget.phase(300)
        from operations import anonymous_image
        anonymous_image(ref)
        # Pull without Compose: its required browser bind is validated only after
        # the candidate's exact image manifest is available locally.
        docker('pull', ref, timeout=budget.remaining())
        image_id(ref)
        browser_directory(cfg, ref, budget)
        browser_mount(container(NAME, previous, running=True), cfg, previous, budget)
        phase(state, state_dir, 'cgw_draining', profile)
        admin('/admin/drain', {'operationId': req['request_id']}, budget)
        try:
            budget.phase(900)
            while True:
                value = diagnostics(profile, previous, req['request_id'], 'draining', budget)
                if value['idle']:
                    break
                budget.remaining()
                time.sleep(min(2, budget.remaining(2)))
        except Failure as error:
            if error.code == 'CGW_DEADLINE':
                raise Failure('CGW_DRAIN_BUSY') from None
            raise
        budget.phase(300)
        # Phase persisted before the side effect: crash after quiesce remains recoverable.
        phase(state, state_dir, 'cgw_quiescing', profile)
        admin('/admin/quiesce', {'operationId': req['request_id']}, budget)
        value = diagnostics(profile, previous, req['request_id'], 'quiesced', budget)
        require(value['idle'], 'CGW_NOT_IDLE')
        phase(state, state_dir, 'cgw_quiesced', profile, acceptedRequestCount=value['acceptedRequestCount'])
        stop(release, cfg, previous, budget)
        phase(state, state_dir, 'cgw_stopped', profile)
        path, checksum = snapshot(state_dir, state['operation'], value, budget)
        phase(state, state_dir, 'cgw_snapshot_verified', profile, snapshot=path, snapshotHash=checksum)
        phase(state, state_dir, 'cgw_switching', profile)
        start(release, cfg, ref, budget)
        phase(state, state_dir, 'cgw_candidate', profile)
        candidate = wait_diagnostics(profile, ref, req['request_id'], 'quiesced', budget)
        require(candidate['idle'] and candidate['acceptedRequestCount'] == value['acceptedRequestCount'], 'CGW_CANDIDATE_ADMITTED')
        state['cgw'] = {'current': ref, 'previous': previous}
        phase(state, state_dir, 'cgw_committed', profile)
        budget.phase(240)
        admin('/admin/resume', {'operationId': req['request_id']}, budget)
        require(diagnostics(profile, ref, budget=budget).get('operationFence') is None, 'CGW_FENCE')
        phase(state, state_dir, 'cgw_resumed', profile)
        finish(state, state_dir)
    except Exception as error:
        code = error.code if isinstance(error, Failure) else 'CGW_HOST_IO'
        try:
            budget.phase(240)
            reconcile(req, state, state_dir, cfg, release, profile, budget)
        except Exception:
            phase(state, state_dir, 'recovery_required', profile, error_code=code,
                  recoveryPhase=state['operation'].get('recoveryPhase', state['operation']['phase']))
            raise Failure('RECOVERY_REQUIRED') from None
        raise Failure(code) from None


def reconcile(req, state, state_dir, cfg, release, profile, budget=None):
    intent = state.get('operation')
    if not intent:
        require(diagnostics(profile, state['cgw']['current']).get('operationFence') is None, 'CGW_FENCE')
        return
    require(intent['component'] == 'cgw', 'RECOVERY_REQUIRED')
    budget = budget or Budget()  # Explicit reconciliation owns a new bounded operation.
    budget.phase(240)
    stage = intent['phase']
    if stage == 'recovery_required':
        stage = intent.get('recoveryPhase', '')
    if stage in ('cgw_committed', 'cgw_resumed'):
        require(state['cgw']['current'] == intent['image'], 'RECOVERY_REQUIRED')
        value = diagnostics(profile, intent['image'], budget=budget)
        require(value['acceptedRequestCount'] >= intent['acceptedRequestCount'], 'RECOVERY_REQUIRED')
        if value.get('operationFence') is not None:
            require(value['operationFence'] == {'operationId': intent['operationId'], 'state': 'quiesced'} and
                    value['acceptedRequestCount'] == intent['acceptedRequestCount'], 'CGW_FENCE')
            admin('/admin/resume', {'operationId': intent['operationId']}, budget)
        require(diagnostics(profile, intent['image'], budget=budget).get('operationFence') is None, 'CGW_FENCE')
        finish(state, state_dir)
    elif stage in ('cgw_prepared', 'cgw_draining', 'cgw_quiescing', 'cgw_quiesced', 'cgw_stopped', 'cgw_snapshot_verified'):
        resume_old(state, state_dir, cfg, release, profile, budget)
    elif stage in ('cgw_switching', 'cgw_candidate'):
        restore(state, state_dir, cfg, release, profile, budget)
    elif stage == 'cgw_restored':
        resume_old(state, state_dir, cfg, release, profile, budget)
    elif stage == 'cgw_restoring':
        # A partial restore is never launched. Repeat the verified restore with
        # the already persisted zero-admission proof, and keep the fence closed.
        require(intent.get('restoreProven') is True, 'RECOVERY_REQUIRED')
        stop(release, cfg, intent['image'], budget)
        restore(state, state_dir, cfg, release, profile, budget)
    else:
        raise Failure('RECOVERY_REQUIRED')


def validate_tunnel_secrets(config):
    directory = trusted_path(config / 'cgw-tunnel-keys', directory=True)
    info = directory.stat()
    require(info.st_mode & 0o777 == 0o750 and info.st_gid == 10001, 'CGW_SECRET_POLICY')
    profiles = json.loads((config / 'cgw-tunnel-profiles.json').read_bytes())
    require(type(profiles) is dict, 'CGW_TUNNEL_POLICY')
    for profile_id, record in profiles.items():
        require(type(profile_id) is str and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?', profile_id) and
                type(record) is dict and set(record) == {'tunnelId', 'runtimeKeyFile'} and
                type(record['tunnelId']) is str and bool(record['tunnelId']) and
                record['runtimeKeyFile'] == '/run/secrets/cgw-tunnel-keys/' + profile_id + '.key', 'CGW_TUNNEL_POLICY')
        key = trusted_path(directory / (profile_id + '.key'))
        require(key.stat().st_mode & 0o777 == 0o640 and key.stat().st_gid == 10001, 'CGW_SECRET_POLICY')
