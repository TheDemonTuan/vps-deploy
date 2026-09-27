import subprocess
import json
import os
import time
import uuid
from pathlib import Path

from core import Failure, atomic, command, container, digest, docker, fault, image_id, lock, require, save
import route


def environment(profile, config, image, rtk=False):
    values = {}
    if not rtk:
        runtime = config / 'runtime.env'
        require(not runtime.is_symlink() and runtime.stat().st_mode & 0o077 == 0 and runtime.stat().st_uid == 0, 'UNSAFE_RUNTIME_ENV')
        for line in runtime.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if key not in {'INITIAL_PASSWORD', 'PUBLIC_URL', 'CLOUDFLARE_ACCESS_TEAM_NAME', 'CLOUDFLARE_ACCESS_AUD', 'RTK_URL', 'CHATGPT_WEB_SOCKET_ROOT', 'CHATGPT_WEB_SOCKET_GID'}:
                continue
            require(separator and key not in values, 'INVALID_RUNTIME_ENV')
            values[key] = value
        require(values.get('INITIAL_PASSWORD'), 'MISSING_RUNTIME_ENV')
    values.update({'IMAGE_REF': image, 'RTK_IMAGE': image, 'DASHBOARD_HOST': profile['dashboard_host'], 'API_HOST': profile['api_host'], 'EDGE_NETWORK': profile['edge_network'], 'RTK_NETWORK': profile['rtk_network'], 'RTK_PROJECT': '9router-rtk'})
    return dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', **values)


def compose(release, profile, config, image, slot=None, rtk=False, *args, timeout=300):
    base = release / 'apps/9router'
    if rtk:
        files = ['-f', str(base / 'docker-compose.rtk.yml')]
    else:
        files = ['--env-file', str(config / 'runtime.env'), '-p', '9router', '-f', str(base / 'docker-compose.prod.yml')]
        if profile.get('bridge_socket_gid') is not None:
            socket_dir = Path(profile['bridge_socket_root'])
            require(socket_dir.is_dir() and not socket_dir.is_symlink(), 'BRIDGE_SOCKET')
            matches = [s for s in socket_dir.iterdir() if s.is_socket() and s.stat().st_gid == profile['bridge_socket_gid'] and s.stat().st_mode & 0o777 == 0o660]
            require(matches, 'BRIDGE_SOCKET')
            files += ['-f', str(base / 'docker-compose.chatgpt-web.yml')]
    env = environment(profile, config, image, rtk)
    env.update({'CHATGPT_WEB_SOCKET_GID': str(profile.get('bridge_socket_gid', '')), 'CHATGPT_WEB_SOCKET_ROOT': profile.get('bridge_socket_root', '')})
    return command('/usr/bin/docker', 'compose', *files, '--ansi=never', '--progress=plain', *args, env=env, timeout=timeout)


def health(slot, ref=None, idle=False):
    obj = container('9router-' + slot, ref, running=True)
    require('edge-9router' in obj['NetworkSettings']['Networks'], 'EDGE_NETWORK')
    try:
        output = command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'health', slot, 'idle' if idle else 'health', timeout=8)
        return json.loads(output)
    except (ValueError, Failure):
        raise Failure('DRAIN_UNSAFE' if idle else 'DIRECT_IDENTITY') from None


def wait_health(slot, ref, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return health(slot, ref)
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

def pull(release, profile, cfg, ref, slot, rtk=False):
    anonymous_image(ref)
    try:
        return image_id(ref)
    except Failure:
        pass
    if not rtk:
        command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'pull', str(release), str(cfg), slot, env=environment(profile, cfg, ref), timeout=650)
        return image_id(ref)
    for attempt in range(2):
        try:
            compose(release, profile, cfg, ref, slot, rtk, 'pull', 'rtk', timeout=300)
            return image_id(ref)
        except (Failure, subprocess.TimeoutExpired):
            if attempt:
                raise Failure('IMAGE_PULL_FAILED') from None
            time.sleep(5)


def rtk_health(name):
    container(name, running=True)
    command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'rtk', name, timeout=10)


def rtk_wait(name, ref, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            container(name, ref, running=True)
            rtk_health(name)
            return
        except Failure:
            time.sleep(1)
    raise Failure('RTK_UNHEALTHY')


def state_phase(state, phase, **kwargs):
    state['revision'] += 1
    state['operation'].update(phase=phase, **kwargs)
    return state


def entry(slot, image, req):
    return {'slot': slot, 'image': image, 'platform_ref': req['platform_ref'], 'manifest_sha256': req['manifest_sha256']}


def matching(state, profile, expected=None):
    active = state['active']
    require(active is not None, 'NOT_ADOPTED')
    target, raw, _ = route.preflight(route.dynamic(profile), profile)
    configured = route.route_state(raw)
    require(configured == (active['slot'], state['generation']), 'ROUTE_STATE_MISMATCH')
    require(route.probe(profile) == configured, 'ROUTE_OBSERVED_MISMATCH')
    health(active['slot'], active['image'])
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


def rtk_network(profile):
    network = json.loads(docker('network', 'inspect', profile['rtk_network']))[0]
    labels = network.get('Labels') or {}
    require(network.get('Internal') is True and network.get('Driver') == 'bridge' and labels.get('com.docker.compose.project') == '9router-rtk' and labels.get('com.docker.compose.network') == 'rtk', 'RTK_NETWORK')

def transaction(req, state, state_dir, cfg, release, profile, locks):
    old = state['active']
    require(old and state['operation'] is None, 'RECOVERY_REQUIRED')
    rtk_network(profile)
    previous = state['previous']
    require(req['op'] == 'deploy' or previous and previous['slot'] != old['slot'], 'PREVIOUS_INVALID')
    target = ('green' if old['slot'] == 'blue' else 'blue') if req['op'] == 'deploy' else previous['slot']
    ref = req['image'] if req['op'] == 'deploy' else previous['image']
    require(target != old['slot'], 'PREVIOUS_INVALID')
    route_path, old_raw = matching(state, profile)
    old_hash, old_gen = digest(old_raw), state['generation']
    if req['op'] == 'rollback':
        require(state['previous'] and state['previous']['slot'] == target, 'PREVIOUS_INVALID')
        container('9router-' + target, ref)
    else:
        try:
            target_container = container('9router-' + target)
        except Failure:
            target_container = None
        if target_container and target_container['State']['Running']:
            health(target, idle=True)
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
        command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'rollback', target, timeout=70)
    else:
        pull(release, profile, cfg, ref, target)
        command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'candidate', str(release), str(cfg), target, env=environment(profile, cfg, ref), timeout=80)
    wait_health(target, ref)
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
        route.unchanged(others)
        state_phase(state, 'publishing', new_generation=generation, new_hash=new_hash)
        save(state_dir / 'state.json', state)
        fault(profile, 'publishing')
        trust = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
        if profile.get('fixture_ci'):
            trust['CURL_CA_BUNDLE'] = profile['ca_bundle']
            if profile.get('fault_file'):
                trust['VPS_DEPLOY_FIXTURE_FAULT'] = profile['fault_file']
        result = subprocess.run(['/usr/bin/bash', str(Path(__file__).with_name('traefik.sh')), 'cutover', profile['api_host'], str(route_path), str(snapshot), str(candidate), old_hash, new_hash, old['slot'], old_gen, target, generation, str(Path(__file__).with_name('route.py'))], env=trust, cwd='/', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=80)
        if result.returncode == 10:
            state['operation'] = None
            state['revision'] += 1
            save(state_dir / 'state.json', state)
            raise Failure('ROUTE_ACK_FAILED')
        if result.returncode:
            recovered(state, state_dir, 'ROUTE_RESTORE_FAILED')
        route.unchanged(others)
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
            drained = command('/usr/bin/bash', str(Path(__file__).with_name('bluegreen.sh')), 'handoff', state['draining'], timeout=8)
            if drained.strip() == 'IDLE':
                cleanup(state, state_dir, profile)
        except (Failure, subprocess.TimeoutExpired):
            pass


def rtk_deploy(req, state, state_dir, cfg, release, profile):
    ref = req['image']
    rtk_network(profile)
    previous = state['rtk']['current']
    name = '9router-rtk-rtk-1'
    if previous == ref:
        rtk_wait(name, ref)
        return
    old_id = image_id(previous) if previous else None
    if previous:
        container(name, previous)
    state['operation'] = {'request_id': req['request_id'], 'component': 'rtk', 'phase': 'rtk_prepared', 'previous': previous, 'previous_id': old_id, 'image': ref}
    state_phase(state, 'rtk_prepared')
    save(state_dir / 'state.json', state)
    pull(release, profile, cfg, ref, None, True)
    try:
        compose(release, profile, cfg, ref, None, True, 'up', '-d', '--no-deps', '--pull', 'never', 'rtk')
        rtk_network(profile)
        state_phase(state, 'rtk_started')
        save(state_dir / 'state.json', state)
        fault(profile, 'rtk_started')
        rtk_wait(name, ref)
    except Failure:
        if not previous:
            recovered(state, state_dir, 'RTK_NO_PREVIOUS')
        require(image_id(previous) == old_id, 'RTK_PREVIOUS_ID')
        compose(release, profile, cfg, previous, None, True, 'up', '-d', '--no-deps', '--pull', 'never', 'rtk')
        rtk_network(profile)
        rtk_wait(name, previous)
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)
        raise Failure('RTK_UPGRADE_FAILED') from None
    state['rtk'] = {'current': ref, 'previous': previous}
    state['operation'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)


def reconcile(req, state, state_dir, cfg, release, profile, locks):
    intent = state['operation']
    if req['component'] == 'rtk':
        if intent and intent['component'] == 'rtk':
            name = '9router-rtk-rtk-1'
            try:
                rtk_wait(name, intent['image'])
                state['rtk'] = {'current': intent['image'], 'previous': intent['previous']}
            except Failure:
                previous = intent['previous']
                require(previous and image_id(previous) == intent['previous_id'], 'RECOVERY_REQUIRED')
                try:
                    rtk_wait(name, previous)
                except Failure:
                    compose(release, profile, cfg, previous, None, True, 'up', '-d', '--no-deps', '--pull', 'never', 'rtk')
                    rtk_wait(name, previous)
            state['operation'] = None
            state['revision'] += 1
            save(state_dir / 'state.json', state)
        else:
            rtk_wait('9router-rtk-rtk-1', state['rtk']['current'])
        return
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
        if current_hash == intent.get('new_hash') and route.route_state(raw) == (intent['target'], intent['new_generation']):
            try:
                wait_health(intent['target'], intent['image'], 6)
                route.ack(profile, (intent['target'], intent['new_generation']))
                route.unchanged(others)
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
        health(old['slot'], old['image'])
        state['operation'] = None
        state['revision'] += 1
        save(state_dir / 'state.json', state)


def cleanup(state, state_dir, profile):
    slot = state.get('draining')
    if not slot or state['operation']:
        return
    matching(state, profile)
    try:
        health(slot, idle=True)
    except Failure:
        return
    matching(state, profile)
    docker('stop', '9router-' + slot, timeout=60)
    state['draining'] = None
    state['revision'] += 1
    save(state_dir / 'state.json', state)
