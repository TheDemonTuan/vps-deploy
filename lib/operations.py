import subprocess
import json
import os
import time
import uuid
from pathlib import Path

from core import Failure, atomic, command, container, digest, docker, fault, image_id, lock, require, save, trusted_path
import route


def environment(profile, config, image):
    values = {}
    if config is not None:
        runtime = trusted_path(config / 'runtime.env')
        require(runtime.stat().st_mode & 0o777 == 0o600, 'UNSAFE_RUNTIME_ENV')
        allowed = set(profile['registration']['runtime']['allowed_env'])
        for line in runtime.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            require(separator and key not in values and key in allowed, 'INVALID_RUNTIME_ENV')
            values[key] = value
        require(all(values.get(key) for key in profile['registration']['runtime']['required_env']), 'MISSING_RUNTIME_ENV')
    policy = profile['registration']['manifest']
    # The registry's `host` runs the single writer; every replica host gets a read-only role.
    node = profile.get('host_registration', {}).get('host', profile['registration']['host'])
    values.update(IMAGE_REF=image, APP_ID=profile['app'], APP_PORT=str(policy['runtime']['port']), HEALTH_PATH=policy['health']['path'], HEALTH_TIMEOUT=str(policy['health']['timeout_seconds']), COMPOSE_PROJECT=profile['compose_project'], DASHBOARD_HOST=profile['dashboard_host'], API_HOST=profile['api_host'], EDGE_NETWORK=profile['edge_network'], NODE_ROLE='primary' if node == profile['registration']['host'] else 'replica')
    return dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', **values)


def compose(release, profile, config, image, slot=None, *args, timeout=300):
    base = release / 'apps' / profile['app']
    files = ['--env-file', str(trusted_path(config / 'runtime.env')), '-p', profile['compose_project'], '-f', str(trusted_path(base / 'docker-compose.prod.yml'))]
    return command('/usr/bin/docker', 'compose', *files, '--ansi=never', '--progress=plain', *args, env=environment(profile, config, image), timeout=timeout)


def health(profile, slot, ref=None, idle=False):
    obj = container(profile['app'] + '-' + slot, ref, running=True)
    require(profile['edge_network'] in obj['NetworkSettings']['Networks'], 'EDGE_NETWORK')
    try:
        output = command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'health', slot, 'idle' if idle else 'health', env=environment(profile, None, ref or ''), timeout=8)
        return json.loads(output)
    except (ValueError, Failure):
        raise Failure('DRAIN_UNSAFE' if idle else 'DIRECT_IDENTITY') from None


def wait_health(profile, slot, ref, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return health(profile, slot, ref)
        except Failure:
            time.sleep(2)
    raise Failure('CANDIDATE_UNHEALTHY')


def anonymous_image(ref):
    if ref.startswith('localhost:5000/'):
        return
    import urllib.parse
    import urllib.request
    repository, digest_ref = ref.split('@', 1)
    name = repository.removeprefix('ghcr.io/')
    token_url = 'https://ghcr.io/token?' + urllib.parse.urlencode({'scope': 'repository:' + name + ':pull', 'service': 'ghcr.io'})
    try:
        with urllib.request.urlopen(token_url, timeout=8) as response:
            token = json.load(response)['token']
        url = 'https://ghcr.io/v2/' + name + '/manifests/' + digest_ref
        accept = ', '.join(('application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.docker.distribution.manifest.v2+json'))
        request = urllib.request.Request(url, method='HEAD', headers={'Authorization': 'Bearer ' + token, 'Accept': accept})
        with urllib.request.urlopen(request, timeout=8) as response:
            require(response.status == 200 and response.headers.get('Docker-Content-Digest') == digest_ref, 'ANONYMOUS_IMAGE_REQUIRED')
    except (OSError, KeyError, ValueError):
        raise Failure('ANONYMOUS_IMAGE_REQUIRED') from None

def pull(release, profile, cfg, ref, slot):
    require(type(ref) is str and ref.startswith(profile['image_repository']), 'INVALID_IMAGE')
    try:
        return image_id(ref)
    except Failure:
        pass
    # A private app image is pulled with root's registry login.
    if profile['registration'].get('image_access', 'public') != 'private':
        anonymous_image(ref)
    command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'pull', str(release), str(cfg), slot, env=environment(profile, cfg, ref), timeout=650)
    return image_id(ref)


def state_phase(state, phase, **kwargs):
    state['revision'] += 1
    state['operation'].update(phase=phase, **kwargs)
    return state


def entry(slot, image, req):
    return {'slot': slot, 'image': image, 'platform_ref': req['platform_ref'], 'manifest_sha256': req['manifest_sha256']}


def matching(state, profile, expected=None):
    active = state['active']
    require(active is not None, 'NOT_ADOPTED')
    require(active['slot'] in ('blue', 'green'), 'INVALID_STATE')
    target, raw, _ = route.preflight(route.dynamic(profile), profile)
    configured = route.route_state(raw, profile)
    require(configured == (active['slot'], state['generation']), 'ROUTE_STATE_MISMATCH')
    require(route.probe(profile) == configured, 'ROUTE_OBSERVED_MISMATCH')
    health(profile, active['slot'], active['image'])
    if expected is not None:
        require(configured == expected, 'ROUTE_STATE_MISMATCH')
    return target, raw


def recovered(state, state_dir, code):
    state_phase(state, 'recovery_required', error_code=code)
    save(state_dir / 'state.json', state)
    raise Failure('RECOVERY_REQUIRED')


def finish(state, state_dir, target_entry, gen):
    old = state['active']
    state['active'] = target_entry
    state['previous'] = old
    state['generation'] = gen
    state['draining'] = old['slot'] if old and old['slot'] != target_entry['slot'] else None
    state_phase(state, 'committed')
    save(state_dir / 'state.json', state)


def transaction(req, state, state_dir, cfg, release, profile, locks):
    old = state['active']
    require(old and state['operation'] is None, 'RECOVERY_REQUIRED')
    previous = state['previous']
    require(req['op'] == 'deploy' or previous and previous['slot'] != old['slot'], 'PREVIOUS_INVALID')
    target = ('green' if old['slot'] == 'blue' else 'blue') if req['op'] == 'deploy' else previous['slot']
    ref = req['image'] if req['op'] == 'deploy' else previous['image']
    require(target != old['slot'], 'PREVIOUS_INVALID')
    route_path, old_raw = matching(state, profile)
    old_hash, old_gen = digest(old_raw), state['generation']
    if req['op'] == 'rollback':
        require(state['previous'] and state['previous']['slot'] == target, 'PREVIOUS_INVALID')
        container(profile['app'] + '-' + target, ref)
    else:
        try:
            target_container = container(profile['app'] + '-' + target)
        except Failure:
            target_container = None
        if target_container and target_container['State']['Running']:
            health(profile, target, idle=True)
    snapshot = state_dir / 'requests' / req['request_id'] / 'route.snapshot'
    with lock(locks / 'traefik.lock', 60):
        _, snapshot_raw, _ = route.preflight(route.dynamic(profile), profile)
        require(digest(snapshot_raw) == old_hash, 'ROUTE_CAS')
        atomic(snapshot, snapshot_raw)
        intent = {'request_id': req['request_id'], 'component': 'app', 'phase': 'prepared', 'old_hash': old_hash, 'old_generation': old_gen, 'snapshot': str(snapshot), 'target': target, 'image': ref, 'target_entry': entry(target, ref, req) if req['op'] == 'deploy' else previous}
        state['operation'] = intent
        state_phase(state, 'prepared')
        save(state_dir / 'state.json', state)
    fault(profile, 'prepared')
    if req['op'] == 'rollback':
        command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'rollback', target, env=environment(profile, None, ref), timeout=70)
    else:
        pull(release, profile, cfg, ref, target)
        command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'candidate', str(release), str(cfg), target, env=environment(profile, cfg, ref), timeout=80)
    wait_health(profile, target, ref)
    state_phase(state, 'candidate_ready')
    save(state_dir / 'state.json', state)
    fault(profile, 'candidate_ready')
    generation = uuid.uuid4().hex
    new_raw = route.render(profile, target, generation)
    new_hash = digest(new_raw)
    candidate = state_dir / 'requests' / req['request_id'] / 'route.candidate'
    atomic(candidate, new_raw)
    with lock(locks / 'traefik.lock', 60):
        _, current, others = route.preflight(route.dynamic(profile), profile)
        require(digest(current) == old_hash, 'ROUTE_CAS')
        route.unchanged(others, route_path.parent, profile['route_name'])
        state_phase(state, 'publishing', new_generation=generation, new_hash=new_hash)
        save(state_dir / 'state.json', state)
        fault(profile, 'publishing')
        trust = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
        if route.edge_node(profile):
            trust['EDGE_NODE'] = route.edge_node(profile)
        if profile.get('fixture_ci'):
            trust['CURL_CA_BUNDLE'] = profile['ca_bundle']
            if profile.get('fault_file'):
                trust['VPS_DEPLOY_FIXTURE_FAULT'] = profile['fault_file']
        result = subprocess.run(['/usr/bin/bash', str(Path(__file__).with_name('traefik.sh')), 'cutover', profile['api_host'], str(route_path), str(snapshot), str(candidate), old_hash, new_hash, old['slot'], old_gen, target, generation, str(Path(__file__).with_name('route.py')), profile['registration']['manifest']['health']['path'], profile['registration']['route']['generation_header'], str(profile['registration']['manifest']['route']['timeout_seconds'])], env=trust, cwd='/', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=80)
        if result.returncode == 10:
            state['operation'] = None
            state['revision'] += 1
            save(state_dir / 'state.json', state)
            raise Failure('ROUTE_ACK_FAILED')
        if result.returncode:
            recovered(state, state_dir, 'ROUTE_RESTORE_FAILED')
        route.unchanged(others, route_path.parent, profile['route_name'])
        fault(profile, 'ack_before_commit')
        state_phase(state, 'route_verified')
        save(state_dir / 'state.json', state)
        fault(profile, 'route_verified')
        try:
            finish(state, state_dir, intent['target_entry'], generation)
        except OSError:
            recovered(state, state_dir, 'STATE_COMMIT_FAILED')
        fault(profile, 'committed')
    state['operation'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)
    if state['draining']:
        try:
            drained = command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'handoff', state['draining'], env=environment(profile, None, ref), timeout=8)
            if drained.strip() == 'IDLE':
                cleanup(state, state_dir, profile)
        except (Failure, subprocess.TimeoutExpired):
            pass



def reconcile(req, state, state_dir, cfg, release, profile, locks):
    intent = state['operation']
    with lock(locks / 'traefik.lock', 60):
        if not intent:
            matching(state, profile)
            return
        require(intent['component'] == 'app', 'RECOVERY_REQUIRED')
        if intent['phase'] == 'committed':
            matching(state, profile)
            state['operation'] = None
            state['revision'] += 1
            save(state_dir / 'state.json', state)
            return
        snapshot = Path(intent['snapshot'])
        require(snapshot.is_file() and digest(snapshot.read_bytes()) == intent['old_hash'], 'RECOVERY_REQUIRED')
        target, raw, others = route.preflight(route.dynamic(profile), profile)
        current_hash = digest(raw)
        old = state['active']
        if current_hash == intent.get('new_hash') and route.route_state(raw, profile) == (intent['target'], intent['new_generation']):
            try:
                wait_health(profile, intent['target'], intent['image'], 6)
                route.ack(profile, (intent['target'], intent['new_generation']))
                route.unchanged(others, target.parent, profile['route_name'])
                finish(state, state_dir, intent['target_entry'], intent['new_generation'])
                state['operation'] = None
                state['revision'] += 1
                save(state_dir / 'state.json', state)
                return
            except Failure:
                recovered(state, state_dir, 'RECOVERY_UNPROVEN')
        if current_hash == intent['old_hash']:
            route.ack(profile, (old['slot'], intent['old_generation']))
        elif current_hash == intent.get('new_hash'):
            snapshot = Path(intent['snapshot'])
            require(snapshot.is_file() and digest(snapshot.read_bytes()) == intent['old_hash'], 'RECOVERY_REQUIRED')
            route.publish(target, snapshot.read_bytes(), current_hash)
            route.ack(profile, (old['slot'], intent['old_generation']))
        else:
            recovered(state, state_dir, 'ROUTE_DIVERGED')
        health(profile, old['slot'], old['image'])
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)


def cleanup(state, state_dir, profile):
    slot = state.get('draining')
    if not slot or state['operation']:
        return
    matching(state, profile)
    try:
        health(profile, slot, idle=True)
    except Failure:
        return
    matching(state, profile)
    docker('stop', profile['app'] + '-' + slot, timeout=60)
    state['draining'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)
