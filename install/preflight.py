#!/usr/bin/python3
"""Read-only live Compose parity before activation or enrollment."""
import json
import subprocess

from core import Failure, container, container_digest, require


def check(root, app, registration, binding, runtime, previous):
    names = registration['runtime']
    raw = runtime.read_text()
    present = {line.split('=', 1)[0] for line in raw.splitlines() if '=' in line and not line.startswith('#')}
    require(set(names['required_env']) <= present, 'MISSING_RUNTIME_ENV')
    require(present <= set(names['allowed_env']), 'UNSAFE_RUNTIME_ENV')
    image = registration['manifest']['image']
    if previous and previous.get('fixture_ci'):
        image = previous['image_repository']
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
    sockets = [mount for value in slots.values() for mount in value['Mounts'] if mount['Destination'] == '/run/9router-chatgpt-web']
    require(not sockets or previous and previous.get('bridge_socket_root') and all(previous['bridge_socket_root'] == m['Source'] for m in sockets), 'BRIDGE_PROFILE_REQUIRED')
    if sockets:
        require(type(previous.get('bridge_socket_gid')) is int, 'HOST_POLICY')
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
    if sockets:
        env['CHATGPT_WEB_SOCKET_ROOT'] = previous['bridge_socket_root']
        env['CHATGPT_WEB_SOCKET_GID'] = str(previous['bridge_socket_gid'])
        argv += ['-f', str(root / 'apps' / app / 'docker-compose.chatgpt-web.yml')]
    result = subprocess.run(argv + ['config', '--format', 'json'], env=env, capture_output=True)
    require(result.returncode == 0, 'COMPOSE_POLICY')
    composed = json.loads(result.stdout)
    services = composed['services']
    require(set(services) == {app + '-blue', app + '-green'}, 'COMPOSE_POLICY')
    require(all(not service.get('ports') for service in services.values()), 'COMPOSE_POLICY')
    for service in services.values():
        require(all(mount.get('type') == 'volume' or sockets and mount.get('type') == 'bind' and mount.get('source') == previous['bridge_socket_root'] for mount in service.get('volumes', [])), 'COMPOSE_POLICY')
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
    require(not mismatch, 'COMPOSE_PARITY:' + ','.join(sorted(mismatch)))
    return composed
