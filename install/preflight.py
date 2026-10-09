#!/usr/bin/python3
"""Read-only live Compose parity before activation or enrollment."""
import json
import subprocess

from core import Failure, container, container_digest, require


def check(root, app, registration, binding, runtime, previous, *, cgw_transition=False,
          source_sha=None, platform_ref=None):
    if registration['manifest'].get('strategy') == 'penpot':
        require(app == 'penpot' and not cgw_transition, 'PENPOT_COMPOSE_ARGUMENT')
        from penpot_preflight import check as penpot_check
        return penpot_check(root, registration, binding, runtime, source_sha, platform_ref)
    names = registration['runtime']
    raw = runtime.read_text()
    present = {line.split('=', 1)[0] for line in raw.splitlines() if '=' in line and not line.startswith('#')}
    require(set(names['required_env']) <= present, 'MISSING_RUNTIME_ENV')
    require(present <= set(names['allowed_env']), 'UNSAFE_RUNTIME_ENV')
    image = registration['manifest']['image']
    if previous and previous.get('fixture_ci'):
        image = previous['image_repository']
    strategy = registration['manifest'].get('strategy', 'blue-green')
    require(strategy == 'blue-green', 'STRATEGY_MISMATCH')
    slots = {}
    for slot in ('blue', 'green'):
        name = app + '-' + slot
        try:
            value = container(name)
        except Failure as exc:
            if exc.code == 'COMMAND_FAILED':
                continue
            raise
        if value['State']['Running']:
            slots[slot] = value
    require(slots, 'NO_RUNNING_SLOT')
    for value in slots.values():
        container_digest(value, image)
    require(not any(mount['Destination'] == '/run/9router-chatgpt-web' for value in slots.values() for mount in value['Mounts']), 'CGW_SOCKET_CUTOVER_REQUIRED')
    cgw = 'cgw' in registration['manifest']
    # Only installer-verified prior enrollment may compare a pre-CGW live gateway
    # against the base compose. Provisioned runtime policy remains mandatory.
    require(not cgw_transition or cgw and previous and not previous.get('cgw_network'), 'CGW_TRANSITION_POLICY')
    overlay = cgw and not cgw_transition
    config = runtime.parent
    allowed_binds = {str(config / name) for name in ('cgw-data-token', 'cgw-admin-token', 'cgw-client-keys.json')} if overlay else set()
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'APP_ID': app,
           'APP_PORT': str(registration['manifest']['runtime']['port']),
           'HEALTH_PATH': registration['manifest']['health']['path'],
           'HEALTH_TIMEOUT': str(registration['manifest']['health']['timeout_seconds']),
           'COMPOSE_PROJECT': binding['compose_project'],
           'IMAGE_REF': container_digest(next(iter(slots.values())), image),
           'DASHBOARD_HOST': binding['dashboard_host'], 'DASHBOARD_ALIAS_HOST': binding['dashboard_alias_host'],
           'API_HOST': binding['api_host'], 'EDGE_NETWORK': binding['edge_network']}
    if 'rtk' in registration['manifest']:
        env['RTK_NETWORK'] = binding['rtk_network']
    argv = ['/usr/bin/docker', 'compose', '--env-file', str(runtime), '-p', binding['compose_project'],
            '-f', str(root / 'apps' / app / 'docker-compose.prod.yml')]
    if cgw:
        env['CGW_CONFIG_DIR'] = str(config)
        env['CGW_NETWORK'] = binding['cgw_network']
        if overlay:
            argv += ['-f', str(root / 'apps' / app / 'docker-compose.chatgpt-web.yml')]
        from cgw import network, diagnostics
        network(dict(cgw_network=binding['cgw_network']))
        proof = diagnostics(dict(cgw_network=binding['cgw_network']))
        require(proof.get('operationFence') is None, 'CGW_FENCE')
        for name in ('cgw-data-token', 'cgw-admin-token', 'cgw-client-keys.json', 'cgw-tunnel-profiles.json', 'cgw.env', 'cgw-seccomp.json'):
            from core import trusted_path
            path = trusted_path(config / name)
            info = path.stat()
            mode = 0o640 if name not in ('cgw.env', 'cgw-seccomp.json') else 0o600
            require(info.st_mode & 0o777 == mode and (mode == 0o600 or info.st_gid == 10001), 'CGW_SECRET_POLICY')
        from cgw import validate_tunnel_secrets
        validate_tunnel_secrets(config)
    result = subprocess.run(argv + ['config', '--format', 'json'], env=env, capture_output=True)
    require(result.returncode == 0, 'COMPOSE_POLICY')
    composed = json.loads(result.stdout)
    services = composed['services']
    expected_services = {app + '-blue', app + '-green'}
    require(set(services) == expected_services, 'COMPOSE_POLICY')
    require(all(not service.get('ports') for service in services.values()), 'COMPOSE_POLICY')
    for service in services.values():
        require(all(mount.get('type') == 'volume' or mount.get('type') == 'bind' and mount.get('source') in allowed_binds and mount.get('read_only') is True for mount in service.get('volumes', [])), 'COMPOSE_POLICY')
    mismatch = set()
    for slot, value in slots.items():
        service = services[app + '-' + slot]
        require(service.get('container_name') == app + '-' + slot, 'COMPOSE_POLICY')
        current = dict(row.split('=', 1) for row in value['Config']['Env'] if '=' in row)
        for key, expected in service.get('environment', {}).items():
            if current.get(key) != str(expected):
                mismatch.add('env:' + key)
        wanted_mounts = {(mount['target'], mount.get('source')) for mount in service.get('volumes', []) if mount.get('type') == 'volume'}
        actual_mounts = {(mount['Destination'], mount.get('Name')) for mount in value['Mounts'] if mount.get('Type') == 'volume'}
        if wanted_mounts != actual_mounts:
            mismatch.add('volumes')
        networks = {composed['networks'][name]['name'] for name in service['networks']}
        if networks != set(value['NetworkSettings']['Networks']):
            mismatch.add('networks')
        wanted_binds = {(mount['target'], mount['source'], True) for mount in service.get('volumes', []) if mount.get('type') == 'bind'}
        actual_binds = {(mount['Destination'], mount['Source'], not mount['RW']) for mount in value['Mounts'] if mount.get('Type') == 'bind'}
        if wanted_binds != actual_binds:
            mismatch.add('secrets')
    require(not mismatch, 'COMPOSE_PARITY:' + ','.join(sorted(mismatch)))
    if cgw:
        runtime_parity(root, config, binding)
    return composed


def adopt_cgw(root, config, state_dir, profile):
    """Adopt a provisioned runtime while the caller holds the operation lock."""
    from core import load, save, trusted_path
    from cgw import NAME, diagnostics
    from operations import matching
    require(profile.get('cgw_image_repository'), 'INVALID_COMPONENT')
    path = trusted_path(state_dir / 'state.json')
    state = load(path)
    require(state.get('version') == 1 and type(state.get('revision')) is int and
            state['revision'] >= 1 and state.get('operation') is None and
            not state.get('cgw'), 'CGW_ADOPTION_UNSAFE')
    matching(state, profile)
    image = container_digest(container(NAME, running=True), profile['cgw_image_repository'])
    proof = diagnostics(profile, image)
    require(proof.get('operationFence') is None, 'CGW_FENCE')
    require(proof.get('idle') is True, 'CGW_ADOPTION_BUSY')
    runtime_parity(root, config, profile)
    state['cgw'] = {'current': image, 'previous': None}
    state['revision'] += 1
    save(path, state)
    return state


def runtime_parity(root, config, binding):
    from cgw import NAME, REPOSITORY, VOLUME, BROWSER_VOLUME, cache_mount
    live = container(NAME, running=True)
    ref = container_digest(live, REPOSITORY)
    cache_mount(live)
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'CGW_CONFIG_DIR': str(config),
           'CGW_IMAGE': ref}
    result = subprocess.run(['/usr/bin/docker', 'compose', '-p', '9router-cgw', '-f',
        str(root / 'apps/9router/docker-compose.cgw-runtime.yml'), 'config', '--format', 'json'],
        env=env, capture_output=True, timeout=30)
    require(result.returncode == 0, 'CGW_COMPOSE_POLICY')
    composed = json.loads(result.stdout)
    require(set(composed['services']) == {'browser-init', 'cgw-runtime'}, 'CGW_COMPOSE_POLICY')
    desired = composed['services']['cgw-runtime']
    host = live['HostConfig']
    require(live['Config'].get('User') == '10001:10001' and host.get('ReadonlyRootfs') is True and
            host.get('Init') is True and host.get('Privileged') is False and
            set(host.get('CapDrop') or []) == {'ALL'} and not host.get('CapAdd') and
            host.get('ShmSize') == 1073741824 and host.get('IpcMode') != 'host' and
            host.get('NanoCpus') == 1000000000 and host.get('Memory') == 2147483648 and
            host.get('PidMode') != 'host' and host.get('NetworkMode') != 'host', 'CGW_SANDBOX_POLICY')
    security = host.get('SecurityOpt') or []
    require(any(row in ('no-new-privileges', 'no-new-privileges:true') for row in security) and
            any(row.startswith('seccomp=') and row != 'seccomp=unconfined' for row in security), 'CGW_SANDBOX_POLICY')
    seccomp = json.loads((config / 'cgw-seccomp.json').read_bytes())
    require(seccomp.get('defaultAction') in ('SCMP_ACT_ERRNO', 'SCMP_ACT_KILL', 'SCMP_ACT_KILL_PROCESS') and
            any(row.get('action') == 'SCMP_ACT_ALLOW' and {'clone', 'setns', 'unshare'} <= set(row.get('names', []))
                for row in seccomp.get('syscalls', [])), 'CGW_SANDBOX_POLICY')
    require(set(live['NetworkSettings']['Networks']) == {'9router-cgw', '9router-cgw-egress'}, 'CGW_NETWORK')
    ports = host.get('PortBindings') or {}
    require(ports == {'5900/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '17842'}]}, 'CGW_VIEWER_POLICY')
    require(set(host.get('Tmpfs') or {}) == {'/tmp', '/run'}, 'CGW_TMPFS_POLICY')
    wanted = {(m['target'], composed['volumes'][m['source']]['name'] if m['type'] == 'volume' else m['source'], m.get('read_only', False)) for m in desired.get('volumes', [])}
    actual = {(m['Destination'], m.get('Name') if m['Type'] == 'volume' else m['Source'], not m['RW']) for m in live['Mounts'] if m['Type'] in ('volume', 'bind')}
    require(wanted == actual and ('/data', VOLUME, False) in actual and
            ('/opt/cgw-browser', BROWSER_VOLUME, True) in actual and
            not any(m['Destination'] == '/var/run/docker.sock' for m in live['Mounts']), 'CGW_VOLUME_POLICY')
    current = dict(row.split('=', 1) for row in live['Config']['Env'] if '=' in row)
    require(all(current.get(key) == str(value) for key, value in desired.get('environment', {}).items()), 'CGW_COMPOSE_PARITY')
    return composed
