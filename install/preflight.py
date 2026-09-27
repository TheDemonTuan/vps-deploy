#!/usr/bin/python3
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import APP_IMAGE, Failure, container, container_digest, require


def main():
    root, runtime = map(Path, sys.argv[1:])
    require(runtime.is_file() and not runtime.is_symlink(), 'UNSAFE_RUNTIME_ENV')
    profile_path = Path('/etc/vps-deploy/apps/9router/host.json')
    profile = json.loads(profile_path.read_text()) if profile_path.exists() else {}
    raw = runtime.read_text()
    require('INITIAL_PASSWORD=' in raw, 'MISSING_RUNTIME_ENV')
    listed = subprocess.run(['/usr/bin/docker', 'container', 'ls', '-a', '--format', '{{.Names}}'], capture_output=True, check=True, text=True).stdout.splitlines()
    live = {slot: container('9router-' + slot) for slot in ('blue', 'green') if '9router-' + slot in listed}
    live = {slot: value for slot, value in live.items() if value['State']['Running']}
    require(len(live) >= 1, 'NO_RUNNING_SLOT')
    sockets = [m for value in live.values() for m in value['Mounts'] if m['Destination'] == '/run/9router-chatgpt-web']
    require(not sockets or all(profile.get('bridge_socket_root') == m['Source'] for m in sockets), 'BRIDGE_PROFILE_REQUIRED')
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'IMAGE_REF': container_digest(next(iter(live.values())), APP_IMAGE), 'DASHBOARD_HOST': profile.get('dashboard_host', '9router.tuannguyenviet.site'), 'API_HOST': profile.get('api_host', '9router-api.tuannguyenviet.site'), 'EDGE_NETWORK': 'edge-9router', 'RTK_NETWORK': '9router-rtk'}
    args = ['/usr/bin/docker', 'compose', '--env-file', str(runtime), '-p', '9router', '-f', str(root/'apps/9router/docker-compose.prod.yml')]
    if sockets:
        env['CHATGPT_WEB_SOCKET_ROOT'] = profile['bridge_socket_root']
        env['CHATGPT_WEB_SOCKET_GID'] = str(profile['bridge_socket_gid'])
        args += ['-f', str(root/'apps/9router/docker-compose.chatgpt-web.yml')]
    config = subprocess.run(args + ['config', '--format', 'json'], env=env, capture_output=True, check=True)
    services = json.loads(config.stdout)['services']
    mismatch = []
    for slot, value in live.items():
        service = services['9router-' + slot]
        current_env = dict(row.split('=', 1) for row in value['Config']['Env'] if '=' in row)
        for name, expected in service['environment'].items():
            if current_env.get(name) != str(expected):
                mismatch.append(name)
        actual_volumes = {(m['Destination'], m.get('Name')) for m in value['Mounts'] if m['Destination'] == '/app/data'}
        if actual_volumes != {('/app/data', '9router-data')}:
            mismatch.append('volume:/app/data')
        if not {'edge-9router', '9router_internal', '9router-rtk'} <= set(value['NetworkSettings']['Networks']):
            mismatch.append('networks')
    require(not mismatch, 'COMPOSE_PARITY:' + ','.join(sorted(set(mismatch))))


if __name__ == '__main__':
    try:
        main()
    except Failure as error:
        print(error.code, file=sys.stderr)
        sys.exit(1)
