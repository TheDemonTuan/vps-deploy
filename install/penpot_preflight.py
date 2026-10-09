"""Read-only six-service enrollment parity; never pull or start containers."""
import json
import subprocess
from pathlib import Path

from core import (PENPOT_ROLES, SHA, container_digest, digest, image_map, manifest, require)
import penpot


def check(root, registration, binding, runtime, source_sha, platform_ref):
    require(binding.get('compose_project') == 'penpot' and binding.get('edge_network') == 'edge-penpot',
            'PENPOT_COMPOSE_ARGUMENT')
    require(type(source_sha) is str and SHA.fullmatch(source_sha) and
            type(platform_ref) is str and SHA.fullmatch(platform_ref), 'PENPOT_ENROLLMENT_REVISION')
    runtime = Path(runtime)
    values = penpot.runtime_values(penpot.bounded_file(runtime), registration)
    raw = penpot.bounded_file(runtime.parent / 'app.yml')
    manifest(raw, registration)
    repositories = registration['manifest']['images']
    profile = dict(binding, app='penpot', registration=registration, image_repositories=repositories)
    refs = {}
    for role in PENPOT_ROLES:
        live = penpot.container('penpot-' + role, running=True)
        ref = container_digest(live, repositories[role])
        labels = penpot.inspect('image', ref).get('Config', {}).get('Labels') or {}
        require(labels.get('org.opencontainers.image.source') == 'https://github.com/TheDemonTuan/penpot' and
                labels.get('org.opencontainers.image.revision') == source_sha, 'PENPOT_IMAGE_REVISION')
        refs[role] = ref
    image_map(refs, repositories)
    entry = {'slot': 'single', 'images': refs, 'source_sha': source_sha,
             'platform_ref': platform_ref, 'manifest_sha256': digest(raw)}
    penpot.stack_health(profile, entry)
    penpot.owned_volumes(profile)
    expected_networks = {
        'penpot_penpot': (True, set(penpot.APP_SERVICES) | set(penpot.DATASTORE_IMAGES)),
        'penpot-egress': (False, {'penpot-frontend', 'penpot-backend', 'penpot-exporter'}),
        'edge-penpot': (True, {'edge-traefik', 'penpot-frontend'}),
    }
    for name, (internal, members) in expected_networks.items():
        network = penpot.inspect('network', name)
        require(network.get('Driver') == 'bridge' and network.get('Internal') is internal and
                (network.get('Labels') or {}).get('vps-deploy.app') == 'penpot' and
                {value.get('Name') for value in (network.get('Containers') or {}).values()} == members,
                'PENPOT_NETWORK_OWNERSHIP')
    values.update({'PENPOT_' + role.upper() + '_IMAGE': ref for role, ref in refs.items()})
    compose = penpot.trusted_path(Path(root) / 'apps/penpot/docker-compose.prod.yml')
    result = subprocess.run(['/usr/bin/docker', 'compose', '--env-file', str(runtime), '-p', 'penpot',
                             '-f', str(compose), 'config', '--format', 'json'],
                            env=dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', **values),
                            capture_output=True, timeout=30)
    require(result.returncode == 0, 'PENPOT_COMPOSE_POLICY')
    composed = json.loads(result.stdout)
    services = composed['services']
    require(set(services) == set(penpot.APP_SERVICES) | set(penpot.DATASTORE_IMAGES), 'PENPOT_COMPOSE_POLICY')
    require(set(composed['volumes']) == set(penpot.VOLUMES.values()), 'PENPOT_COMPOSE_POLICY')
    require(set(composed['networks']) == {'penpot', 'edge', 'egress'} and
            composed['networks']['penpot'].get('internal') is True and
            composed['networks']['edge'].get('external') is True and
            composed['networks']['edge'].get('name') == binding['edge_network'], 'PENPOT_COMPOSE_POLICY')
    for name, service in services.items():
        wanted_ref = refs[name.removeprefix('penpot-')] if name in penpot.APP_SERVICES else penpot.DATASTORE_IMAGES[name]
        require(service.get('image') == wanted_ref and service.get('container_name') == name and
                service.get('platform') == 'linux/arm64' and not service.get('ports'), 'PENPOT_COMPOSE_POLICY')
        live = penpot.container(name, wanted_ref, running=True)
        config = live['Config']
        host = live['HostConfig']
        require(not live['State'].get('Paused') and not live['State'].get('Restarting') and
                not host.get('CapAdd') and host.get('PidMode') != 'host' and host.get('IpcMode') != 'host' and
                host.get('NetworkMode') != 'host' and
                any(value in ('no-new-privileges', 'no-new-privileges:true')
                    for value in host.get('SecurityOpt') or []), 'PENPOT_CONTAINER_SECURITY')
        if name in penpot.APP_SERVICES:
            users = {'node', '1000', '1000:1000'} if name == 'penpot-mcp' else {'penpot', '1001', '1001:1001'}
            require(config.get('User') in users, 'PENPOT_CONTAINER_SECURITY')
        require(type(service.get('mem_limit')) is int and service['mem_limit'] > 0 and
                host.get('Memory') == service['mem_limit'], 'PENPOT_RESOURCE_PARITY')
        if 'shm_size' in service:
            require(host.get('ShmSize') == service['shm_size'], 'PENPOT_RESOURCE_PARITY')
        require(config.get('Healthcheck', {}).get('Test') == service.get('healthcheck', {}).get('test'),
                'PENPOT_HEALTHCHECK_PARITY')
        environment = dict(row.split('=', 1) for row in config.get('Env') or [] if '=' in row)
        defaults = penpot.inspect('image', wanted_ref).get('Config', {}).get('Env') or []
        expected_env = dict(row.split('=', 1) for row in defaults if '=' in row)
        expected_env.update({key: str(value) for key, value in service.get('environment', {}).items()})
        require(environment == expected_env, 'PENPOT_ENV_PARITY')
        wanted_mounts = set()
        for mount in service.get('volumes', []):
            require(mount.get('type') == 'volume' and mount.get('source') in composed['volumes'],
                    'PENPOT_COMPOSE_POLICY')
            volume = composed['volumes'][mount['source']]
            require(volume.get('external') is True and volume.get('name') == mount['source'],
                    'PENPOT_COMPOSE_POLICY')
            wanted_mounts.add((mount['target'], volume['name'], not mount.get('read_only', False)))
        actual_mounts = {(mount['Destination'], mount.get('Name'), mount['RW']) for mount in live.get('Mounts', [])}
        require(all(mount.get('Type') == 'volume' for mount in live.get('Mounts', [])) and
                wanted_mounts == actual_mounts, 'PENPOT_VOLUME_PARITY')
        networks = {composed['networks'][key]['name'] for key in service['networks']}
        require(networks == set(live['NetworkSettings']['Networks']), 'PENPOT_CONTAINER_NETWORKS')
    response = penpot.docker('exec', 'penpot-frontend', '/usr/bin/curl', '-fsS', '-w', '%{http_code}',
                             'http://127.0.0.1:8080/readyz', timeout=10)
    require(response == 'OK200', 'PENPOT_INTERNAL_READINESS')
    return composed
