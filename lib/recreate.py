import os
import sys
import json
import time
import uuid
import stat
import tarfile
import hashlib
import sqlite3
import subprocess
from pathlib import Path

from core import (
    Failure,
    atomic,
    command,
    container,
    container_digest,
    digest,
    docker,
    fault,
    image_id,
    inspect,
    lock,
    require,
    save,
    trusted_path,
)
from operations import environment, compose, matching, state_phase, finish, recovered, pull
import route

def container_name(profile):
    return profile['app'] + '-single'

def volume_name(profile):
    return profile['app'] + '-data'

def backup_root(state_dir, profile):
    root = state_dir / 'backups'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root

def internal_call(container_id, method, path, body=None, timeout=10):
    body_json = json.dumps(body) if body is not None else 'null'
    script = f"""
const http = require('node:http');
const body = {json.dumps(body_json)};
const options = {{
    hostname: '127.0.0.1',
    port: 7456,
    path: {json.dumps(path)},
    method: {json.dumps(method)},
    headers: {{
        'Content-Type': 'application/json',
    }},
    timeout: {timeout * 1000},
}};
const req = http.request(options, (res) => {{
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {{
        console.log(JSON.stringify({{ status: res.statusCode, body: data }}));
    }});
}});
req.on('error', err => {{
    console.error(err);
    process.exit(1);
}});
if (body !== 'null') req.write(body);
req.end();
"""
    cmd = ['docker', 'exec', container_id, 'node', '-e', script]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    require(proc.returncode == 0, 'DEPLOYMENT_EXEC_FAILED')
    try:
        res = json.loads(proc.stdout.strip())
        status = res['status']
        data = json.loads(res['body']) if res['body'] else {}
        return status, data
    except (ValueError, KeyError):
        raise Failure('DEPLOYMENT_RESPONSE_MALFORMED')

def get_volume_mountpoint(vol_name):
    vol = inspect('volume', vol_name)
    mountpoint = vol.get('Mountpoint')
    require(mountpoint and os.path.isabs(mountpoint), 'VOLUME_MOUNTPOINT_INVALID')
    return Path(mountpoint)

def verify_no_writers(profile, allow_container_id=None):
    vol_name = volume_name(profile)
    out = docker('ps', '-q')
    cids = [line.strip() for line in out.splitlines() if line.strip()]
    for cid in cids:
        if allow_container_id and cid.startswith(allow_container_id):
            continue
        c_info = inspect('container', cid)
        if not c_info['State']['Running']:
            continue
        for m in c_info.get('Mounts', []):
            if m.get('Type') == 'volume' and m.get('Name') == vol_name:
                if m.get('RW', True):
                    raise Failure('CONCURRENT_WRITER')

def fence(profile, operation_id):
    cname = container_name(profile)
    status, data = internal_call(cname, 'POST', '/api/deployment/fence', {'operationId': operation_id})
    require(status == 200, 'DEPLOYMENT_FENCE_FAILED')
    return data

def resume(profile, operation_id):
    cname = container_name(profile)
    status, data = internal_call(cname, 'POST', '/api/deployment/resume', {'operationId': operation_id})
    require(status in (200, 404), 'DEPLOYMENT_RESUME_FAILED')
    return data

def wait_idle_and_quiesce(profile, operation_id, timeout=120):
    cname = container_name(profile)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, data = internal_call(cname, 'GET', '/api/deployment/status')
        if status == 200 and data.get('idle') is True:
            q_status, q_data = internal_call(cname, 'POST', '/api/deployment/quiesce', {'operationId': operation_id})
            if q_status == 200 and q_data.get('phase') == 'quiesced' and q_data.get('idle') is True:
                return q_data
        time.sleep(2)
    # Deadline reached without idle: resume admission and fail deployment
    try:
        resume(profile, operation_id)
    except Exception:
        pass
    raise Failure('RECREATE_BUSY')

def check_sqlite_integrity(mountpoint):
    db_path = mountpoint / 'app.sqlite'
    if not db_path.exists():
        return True
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    try:
        cursor = conn.cursor()
        cursor.execute('PRAGMA integrity_check;')
        rows = cursor.fetchall()
        require(len(rows) == 1 and rows[0][0] == 'ok', 'SQLITE_CORRUPT')
    finally:
        conn.close()
    return True

def snapshot_data_volume(profile, state_dir, request_id, old_image, phase):
    mountpoint = get_volume_mountpoint(volume_name(profile))
    check_sqlite_integrity(mountpoint)

    backup_dir = backup_root(state_dir, profile) / request_id
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    tar_path = backup_dir / 'data.tar'
    manifest_path = backup_dir / 'manifest.json'

    # Archive entire volume directory contents
    with tarfile.open(tar_path, 'w') as tar:
        for entry in os.scandir(mountpoint):
            tar.add(entry.path, arcname=entry.name)
    os.chmod(tar_path, 0o600)

    chk = digest(tar_path.read_bytes())
    manifest = {
        'schemaVersion': 1,
        'app': profile['app'],
        'requestId': request_id,
        'image': old_image,
        'phase': phase,
        'checksum': chk,
        'timestamp': time.time(),
    }
    atomic(manifest_path, json.dumps(manifest, indent=2).encode('utf-8'))
    return str(tar_path), chk

def restore_data_volume(profile, state_dir, request_id, expected_checksum):
    tar_path = backup_root(state_dir, profile) / request_id / 'data.tar'
    require(tar_path.is_file(), 'BACKUP_NOT_FOUND')
    chk = digest(tar_path.read_bytes())
    require(chk == expected_checksum, 'BACKUP_CHECKSUM_MISMATCH')

    mountpoint = get_volume_mountpoint(volume_name(profile))
    verify_no_writers(profile)

    # Clean out existing files
    for entry in os.scandir(mountpoint):
        if entry.is_dir() and not entry.is_symlink():
            import shutil
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)

    # Extract verified snapshot
    with tarfile.open(tar_path, 'r') as tar:
        tar.extractall(mountpoint)
    check_sqlite_integrity(mountpoint)

def entry_record(image_ref, req):
    return {
        'slot': 'single',
        'image': image_ref,
        'platform_ref': req['platform_ref'],
        'manifest_sha256': req['manifest_sha256'],
    }

def check_rollback_compatibility(profile, current_image, previous_image):
    compat_path = Path('/etc/vps-deploy/apps') / profile['app'] / 'rollback-compatibility.json'
    if not compat_path.exists():
        compat_path = Path(profile.get('rollback_compat_file', ''))
    require(compat_path.is_file() and not compat_path.is_symlink(), 'RECREATE_ROLLBACK_INCOMPATIBLE')
    try:
        data = json.loads(compat_path.read_text('utf-8'))
        require(data.get('schemaVersion') == 1, 'RECREATE_ROLLBACK_INCOMPATIBLE')
        pairs = data.get('approvedPairs', [])
        for p in pairs:
            if p.get('currentImage') == current_image and p.get('previousImage') == previous_image:
                return True
    except Exception:
        pass
    raise Failure('RECREATE_ROLLBACK_INCOMPATIBLE')

def prune_backups(state_dir, profile, keep=7):
    root = backup_root(state_dir, profile)
    candidates = []
    for item in root.iterdir():
        if item.is_dir() and (item / 'manifest.json').is_file():
            try:
                m = json.loads((item / 'manifest.json').read_text('utf-8'))
                candidates.append((m.get('timestamp', 0), item))
            except Exception:
                pass
    candidates.sort(key=lambda x: x[0], reverse=True)
    import shutil
    for _, path in candidates[keep:]:
        try:
            shutil.rmtree(path)
        except Exception:
            pass

def transaction(req, state, state_dir, cfg, release, profile, locks):
    old = state['active']
    require(old and state['operation'] is None, 'RECOVERY_REQUIRED')
    require(old['slot'] == 'single', 'STRATEGY_MISMATCH')

    cname = container_name(profile)
    c_info = container(cname, old['image'], running=True)
    require(profile['edge_network'] in c_info['NetworkSettings']['Networks'], 'EDGE_NETWORK')

    ref = req['image']
    target_entry = entry_record(ref, req)

    route_path = Path(profile['dynamic_dir']) / profile['route_name']
    _, old_raw, _ = route.preflight(route.dynamic(profile), profile)
    old_hash, old_gen = digest(old_raw), state['generation']

    # Pull and verify candidate image before touching runtime
    pull(release, profile, cfg, ref, 'single')

    snapshot_file = state_dir / 'requests' / req['request_id'] / 'route.snapshot'
    with lock(locks / 'traefik.lock', 60):
        _, snapshot_raw, _ = route.preflight(route.dynamic(profile), profile)
        require(digest(snapshot_raw) == old_hash, 'ROUTE_CAS')
        atomic(snapshot_file, snapshot_raw)
        intent = {
            'request_id': req['request_id'],
            'component': 'app',
            'phase': 'prepared',
            'old_hash': old_hash,
            'old_generation': old_gen,
            'snapshot': str(snapshot_file),
            'target': 'single',
            'image': ref,
            'target_entry': target_entry,
            'old_entry': old,
        }
        state['operation'] = intent
        state_phase(state, 'prepared')
        save(state_dir / 'state.json', state)
    fault(profile, 'prepared')

    # Fence and wait for idle
    fence(profile, req['request_id'])
    state_phase(state, 'fenced')
    save(state_dir / 'state.json', state)
    fault(profile, 'fenced')

    # Wait for idle and quiesce
    wait_idle_and_quiesce(profile, req['request_id'], timeout=120)
    state_phase(state, 'quiesced')
    save(state_dir / 'state.json', state)
    fault(profile, 'quiesced')

    # Stop old writer gracefully
    state_phase(state, 'stopping')
    save(state_dir / 'state.json', state)
    fault(profile, 'stopping')

    docker('stop', '-t', '30', cname)
    verify_no_writers(profile)
    state_phase(state, 'stopped')
    save(state_dir / 'state.json', state)
    fault(profile, 'stopped')

    # Snapshot data volume
    data_tar, data_chk = snapshot_data_volume(profile, state_dir, req['request_id'], old['image'], 'snapshotted')
    intent['data_snapshot'] = data_tar
    intent['data_checksum'] = data_chk
    state_phase(state, 'snapshotted')
    save(state_dir / 'state.json', state)
    fault(profile, 'snapshotted')

    # Start candidate on same singleton service
    try:
        compose(release, profile, cfg, ref, 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        new_cid = inspect('container', cname)['Id']
        c_cand = container(cname, ref, running=True)
        require(profile['edge_network'] in c_cand['NetworkSettings']['Networks'], 'EDGE_NETWORK')
        state_phase(state, 'candidate_started')
        save(state_dir / 'state.json', state)
        fault(profile, 'candidate_started')

        # Check candidate internal state: accepting should still be false
        status, sdata = internal_call(cname, 'GET', '/api/deployment/status')
        require(status == 200 and sdata.get('accepting') is False, 'CANDIDATE_NOT_FENCED')
        check_sqlite_integrity(get_volume_mountpoint(volume_name(profile)))
    except Exception as exc:
        # Candidate failed: stop candidate, restore snapshot, restart old
        try:
            docker('stop', '-t', '10', cname)
        except Exception:
            pass
        restore_data_volume(profile, state_dir, req['request_id'], data_chk)
        compose(release, profile, cfg, old['image'], 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        resume(profile, req['request_id'])
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)
        raise Failure('RECREATE_CANDIDATE_FAILED') from exc

    # Render route generation and CAS publish
    generation = uuid.uuid4().hex
    new_raw = route.render(profile, 'single', generation)
    new_hash = digest(new_raw)
    candidate_route = state_dir / 'requests' / req['request_id'] / 'route.candidate'
    atomic(candidate_route, new_raw)

    with lock(locks / 'traefik.lock', 60):
        _, current, others = route.preflight(route.dynamic(profile), profile)
        require(digest(current) == old_hash, 'ROUTE_CAS')
        route.unchanged(others, route_path.parent, profile['route_name'])
        state_phase(state, 'publishing', new_generation=generation, new_hash=new_hash)
        save(state_dir / 'state.json', state)
        fault(profile, 'publishing')

        route.publish(route_path, new_raw, old_hash)
        route.ack(profile, ('single', generation))
        state_phase(state, 'route_verified')
        save(state_dir / 'state.json', state)

    # Commit target state
    state['previous'] = old
    finish(state, state_dir, target_entry, generation)
    state_phase(state, 'committed')
    save(state_dir / 'state.json', state)
    fault(profile, 'committed')

    # Resume candidate admission
    resume(profile, req['request_id'])
    status, rdata = internal_call(cname, 'GET', '/api/deployment/status')
    require(status == 200 and rdata.get('accepting') is True, 'CANDIDATE_NOT_ACCEPTING')

    state['operation'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)
    prune_backups(state_dir, profile, keep=7)

def rollback(req, state, state_dir, cfg, release, profile, locks):
    old = state['active']
    previous = state['previous']
    require(old and previous and state['operation'] is None, 'RECOVERY_REQUIRED')
    require(old['slot'] == 'single' and previous['slot'] == 'single', 'STRATEGY_MISMATCH')

    check_rollback_compatibility(profile, old['image'], previous['image'])

    cname = container_name(profile)
    c_info = container(cname, old['image'], running=True)
    require(profile['edge_network'] in c_info['NetworkSettings']['Networks'], 'EDGE_NETWORK')

    ref = previous['image']
    target_entry = previous

    route_path = Path(profile['dynamic_dir']) / profile['route_name']
    _, old_raw, _ = route.preflight(route.dynamic(profile), profile)
    old_hash, old_gen = digest(old_raw), state['generation']

    pull(release, profile, cfg, ref, 'single')

    snapshot_file = state_dir / 'requests' / req['request_id'] / 'route.snapshot'
    with lock(locks / 'traefik.lock', 60):
        _, snapshot_raw, _ = route.preflight(route.dynamic(profile), profile)
        require(digest(snapshot_raw) == old_hash, 'ROUTE_CAS')
        atomic(snapshot_file, snapshot_raw)
        intent = {
            'request_id': req['request_id'],
            'component': 'app',
            'phase': 'prepared',
            'old_hash': old_hash,
            'old_generation': old_gen,
            'snapshot': str(snapshot_file),
            'target': 'single',
            'image': ref,
            'target_entry': target_entry,
            'old_entry': old,
        }
        state['operation'] = intent
        state_phase(state, 'prepared')
        save(state_dir / 'state.json', state)
    fault(profile, 'prepared')

    fence(profile, req['request_id'])
    state_phase(state, 'fenced')
    save(state_dir / 'state.json', state)
    fault(profile, 'fenced')

    wait_idle_and_quiesce(profile, req['request_id'], timeout=120)
    state_phase(state, 'quiesced')
    save(state_dir / 'state.json', state)
    fault(profile, 'quiesced')

    state_phase(state, 'stopping')
    save(state_dir / 'state.json', state)
    fault(profile, 'stopping')

    docker('stop', '-t', '30', cname)
    verify_no_writers(profile)
    state_phase(state, 'stopped')
    save(state_dir / 'state.json', state)
    fault(profile, 'stopped')

    data_tar, data_chk = snapshot_data_volume(profile, state_dir, req['request_id'], old['image'], 'snapshotted')
    intent['data_snapshot'] = data_tar
    intent['data_checksum'] = data_chk
    state_phase(state, 'snapshotted')
    save(state_dir / 'state.json', state)
    fault(profile, 'snapshotted')

    try:
        compose(release, profile, cfg, ref, 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        c_cand = container(cname, ref, running=True)
        require(profile['edge_network'] in c_cand['NetworkSettings']['Networks'], 'EDGE_NETWORK')
        state_phase(state, 'candidate_started')
        save(state_dir / 'state.json', state)
        fault(profile, 'candidate_started')

        status, sdata = internal_call(cname, 'GET', '/api/deployment/status')
        require(status == 200 and sdata.get('accepting') is False, 'CANDIDATE_NOT_FENCED')
        check_sqlite_integrity(get_volume_mountpoint(volume_name(profile)))
    except Exception as exc:
        try:
            docker('stop', '-t', '10', cname)
        except Exception:
            pass
        restore_data_volume(profile, state_dir, req['request_id'], data_chk)
        compose(release, profile, cfg, old['image'], 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        resume(profile, req['request_id'])
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)
        raise Failure('RECREATE_CANDIDATE_FAILED') from exc

    generation = uuid.uuid4().hex
    new_raw = route.render(profile, 'single', generation)
    new_hash = digest(new_raw)
    candidate_route = state_dir / 'requests' / req['request_id'] / 'route.candidate'
    atomic(candidate_route, new_raw)

    with lock(locks / 'traefik.lock', 60):
        _, current, others = route.preflight(route.dynamic(profile), profile)
        require(digest(current) == old_hash, 'ROUTE_CAS')
        route.unchanged(others, route_path.parent, profile['route_name'])
        state_phase(state, 'publishing', new_generation=generation, new_hash=new_hash)
        save(state_dir / 'state.json', state)
        fault(profile, 'publishing')

        route.publish(route_path, new_raw, old_hash)
        route.ack(profile, ('single', generation))
        state_phase(state, 'route_verified')
        save(state_dir / 'state.json', state)

    state['previous'] = old
    finish(state, state_dir, target_entry, generation)
    state_phase(state, 'committed')
    save(state_dir / 'state.json', state)
    fault(profile, 'committed')

    resume(profile, req['request_id'])
    status, rdata = internal_call(cname, 'GET', '/api/deployment/status')
    require(status == 200 and rdata.get('accepting') is True, 'CANDIDATE_NOT_ACCEPTING')

    state['operation'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)

def reconcile(req, state, state_dir, cfg, release, profile, locks):
    intent = state.get('operation')
    cname = container_name(profile)
    old = state['active']

    if not intent:
        # No pending operation, verify strict health
        container(cname, old['image'], running=True)
        matching(state, profile)
        return

    req_id = intent['request_id']
    phase = intent.get('phase')

    if phase == 'committed':
        # Candidate committed, just verify route, image, and resume
        target = intent['target_entry']
        container(cname, target['image'], running=True)
        matching(state, profile)
        try:
            resume(profile, req_id)
        except Exception:
            pass
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)
        return

    # Before committed: check whether candidate ever started
    data_chk = intent.get('data_checksum')
    snapshot_complete = data_chk and intent.get('data_snapshot') and Path(intent['data_snapshot']).is_file()

    # Determine container running state
    c_info = None
    try:
        c_info = inspect('container', cname)
    except Exception:
        pass

    cand_started = False
    if c_info and c_info['State']['Running']:
        if c_info['Image'] == image_id(intent['image']) and intent['image'] != old['image']:
            cand_started = True

    if cand_started or phase in ('candidate_started', 'publishing', 'route_verified'):
        # Candidate started, volume might be modified: stop candidate, restore snapshot
        require(snapshot_complete, 'RECOVERY_REQUIRED')
        try:
            docker('stop', '-t', '10', cname)
        except Exception:
            pass
        restore_data_volume(profile, state_dir, req_id, data_chk)
        compose(release, profile, cfg, old['image'], 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        # Restore route if modified
        route_path = Path(profile['dynamic_dir']) / profile['route_name']
        snap_path = Path(intent['snapshot'])
        if snap_path.is_file():
            cur_hash = digest(route_path.read_bytes())
            if cur_hash != intent['old_hash']:
                route.publish(route_path, snap_path.read_bytes(), cur_hash)
        resume(profile, req_id)
        recovered(state, state_dir, 'RECREATE_CANDIDATE_FAILED')
    else:
        # Candidate never started, volume untouched
        if c_info and not c_info['State']['Running']:
            # Restart old container on intact volume
            compose(release, profile, cfg, old['image'], 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        try:
            resume(profile, req_id)
        except Exception:
            pass
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)

def backup(profile, cfg, state_dir, locks):
    old = load(state_dir / 'state.json')['active']
    require(old, 'NOT_ADOPTED')
    cname = container_name(profile)
    container(cname, old['image'], running=True)

    backup_id = f"backup-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    release = Path('/opt/vps-deploy/releases') / profile['platform_ref']

    fence(profile, backup_id)
    try:
        wait_idle_and_quiesce(profile, backup_id, timeout=120)
        docker('stop', '-t', '30', cname)
        verify_no_writers(profile)
        tar_path, chk = snapshot_data_volume(profile, state_dir, backup_id, old['image'], 'backup')
    finally:
        compose(release, profile, cfg, old['image'], 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)
        try:
            resume(profile, backup_id)
        except Exception:
            pass

    prune_backups(state_dir, profile, keep=7)
    return {'backupId': backup_id, 'tarPath': tar_path, 'checksum': chk}
