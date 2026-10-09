"""Persist the one Penpot edge attachment without recreating shared Traefik.

Caller must hold install/app/Traefik locks. Failures retain owned resources for
operator diagnosis; this helper never disconnects existing networks.
"""
from pathlib import Path
import os
import tempfile
import re
import subprocess
import time
import yaml

from core import (Failure, atomic, container, docker, image_map, inspect, parse_yaml, require, trusted_path)

NETWORK = 'edge-penpot'
CONTAINER = 'edge-traefik'


def check(path):
    path = trusted_path(Path(path))
    require(path.stat().st_size <= 1024 * 1024, 'EDGE_COMPOSE_POLICY')
    before = path.read_bytes()
    value = parse_yaml(before)
    require(type(value) is dict and type(value.get('services')) is dict and
            type(value.get('networks')) is dict and type(value['services'].get('traefik')) is dict,
            'EDGE_COMPOSE_POLICY')
    live = container(CONTAINER, running=True)
    labels = live.get('Config', {}).get('Labels') or {}
    require(labels.get('com.docker.compose.project') == 'edge-traefik' and
            labels.get('com.docker.compose.service') == 'traefik' and
            labels.get('com.docker.compose.project.config_files') == str(path), 'EDGE_CONTAINER_OWNERSHIP')
    service = value['services']['traefik']
    networks = service.get('networks')
    require(type(networks) in (dict, list), 'EDGE_COMPOSE_POLICY')
    expected = {'external': True, 'name': NETWORK}
    require(NETWORK not in value['networks'] or value['networks'][NETWORK] == expected,
            'EDGE_NETWORK_CONFLICT')
    if type(networks) is dict:
        require(NETWORK not in networks or networks[NETWORK] in (None, {}), 'EDGE_NETWORK_CONFLICT')
        service['networks'] = dict(networks, **{NETWORK: {}})
    else:
        require(all(type(name) is str for name in networks) and len(networks) == len(set(networks)),
                'EDGE_COMPOSE_POLICY')
        service['networks'] = networks if NETWORK in networks else networks + [NETWORK]
    value['networks'][NETWORK] = expected
    after = yaml.safe_dump(value, sort_keys=False).encode('utf-8')
    return {'path': path, 'before': before, 'after': after, 'mode': path.stat().st_mode & 0o777}


def owned_network():
    value = inspect('network', NETWORK)
    require(value.get('Driver') == 'bridge' and value.get('Internal') is True and
            not value.get('Options') and (value.get('Labels') or {}).get('vps-deploy.app') == 'penpot' and
            {member.get('Name') for member in (value.get('Containers') or {}).values()} <=
            {CONTAINER, 'penpot-frontend'}, 'EDGE_NETWORK_OWNERSHIP')


def apply(plan):
    path = trusted_path(plan['path'])
    require(path.read_bytes() == plan['before'], 'EDGE_COMPOSE_CHANGED')
    current = check(path)
    require(current['after'] == plan['after'], 'EDGE_COMPOSE_CHANGED')
    owned_network()
    # Keep the validation file beside compose so relative includes resolve alike.
    fd, name = tempfile.mkstemp(prefix='.penpot-edge-', suffix='.yml', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(plan['after'])
        docker('compose', '-p', 'edge-traefik', '-f', name, 'config', '--quiet')
    finally:
        Path(name).unlink(missing_ok=True)
    require(path.read_bytes() == plan['before'], 'EDGE_COMPOSE_CHANGED')
    if plan['after'] != plan['before']:
        atomic(path, plan['after'], plan['mode'])
    live = container(CONTAINER, running=True)
    if NETWORK not in live['NetworkSettings']['Networks']:
        docker('network', 'connect', NETWORK, CONTAINER)


def origin_topology(profile, entry):
    require(profile['api_host'] == 'design.tuannguyenviet.site', 'PENPOT_ORIGIN_SCOPE')
    images = image_map(entry['images'], profile['registration']['manifest']['images'])
    ca = trusted_path(Path('/opt/platform/edge/cloudflare-ca/origin-ca.pem'))
    cloudflared = container('edge-cloudflared', running=True)
    traefik = container(CONTAINER, running=True)
    static_mounts = [item for item in traefik.get('Mounts', [])
                     if item.get('Destination') == '/etc/traefik/traefik.yml']
    require(len(static_mounts) == 1 and static_mounts[0].get('Type') == 'bind' and
            static_mounts[0].get('Source') == '/opt/platform/edge/traefik.yml' and
            static_mounts[0].get('RW') is False, 'PENPOT_ORIGIN_ENTRYPOINT_POLICY')
    mounts = [item for item in cloudflared.get('Mounts', []) if item.get('Destination') in
              ('/etc/cloudflare-origin-ca', '/etc/cloudflare-origin-ca/origin-ca.pem')]
    require(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and
            mounts[0].get('Source') == str(ca.parent) and
            mounts[0].get('Destination') == '/etc/cloudflare-origin-ca' and
            mounts[0].get('RW') is False, 'CLOUDFLARED_ORIGIN_CA_POLICY')
    networks = cloudflared.get('NetworkSettings', {}).get('Networks', {})
    peers = traefik.get('NetworkSettings', {}).get('Networks', {})
    matches = [name for name in networks.keys() & peers.keys()
               if networks[name].get('IPAddress') == '172.31.250.2' and
               peers[name].get('IPAddress') == '172.31.250.4' and
               networks[name].get('NetworkID') == peers[name].get('NetworkID')]
    require(len(matches) == 1, 'PENPOT_ORIGIN_NETWORK_POLICY')
    network = inspect('network', matches[0])
    members = network.get('Containers') or {}
    for live, address in ((cloudflared, '172.31.250.2'), (traefik, '172.31.250.4')):
        require(members.get(live['Id'], {}).get('IPv4Address', '').split('/')[0] == address,
                'PENPOT_ORIGIN_NETWORK_POLICY')
    static = parse_yaml(trusted_path(Path('/opt/platform/edge/traefik.yml')).read_bytes())
    web = static.get('entryPoints', {}).get('web', {})
    require(web.get('address') in (':8080', '172.31.250.4:8080') and
            type(web.get('http', {}).get('tls')) is dict, 'PENPOT_ORIGIN_ENTRYPOINT_POLICY')
    image = inspect('image', images['frontend'])
    user = image.get('Config', {}).get('User', '').split(':')[0]
    require(user not in ('', 'root', '0') and not re.fullmatch('0+', user), 'PENPOT_ORIGIN_HELPER_USER')
    return images['frontend'], ca


def origin_ack(profile, entry, generation=None, *, maintenance=False):
    """Probe the enrolled origin without DNS, preserving the tunnel source IP."""
    import penpot
    require(maintenance or type(generation) is str and re.fullmatch('[0-9a-f]{32}', generation),
            'PENPOT_PUBLIC_HEALTH')
    deadline, consecutive = time.monotonic() + 30, 0
    while time.monotonic() < deadline:
        frontend, ca = origin_topology(profile, entry)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        probe_timeout = min(8, remaining)
        process = subprocess.run([
            '/usr/bin/docker', 'run', '--rm', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--network', 'container:edge-cloudflared',
            '--mount', 'type=bind,src=' + str(ca) + ',dst=/ca.pem,readonly',
            '--entrypoint', '/usr/bin/curl', frontend, '--silent', '--show-error',
            '--cacert', '/ca.pem', '--connect-to',
            'design.tuannguyenviet.site:443:172.31.250.4:8080', '--proto', '=https',
            '--max-time', str(probe_timeout), '--max-redirs', '0', '--max-filesize', '65536',
            '--dump-header', '-', '--write-out', '\n%{http_code}',
            'https://design.tuannguyenviet.site/readyz'],
            env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'},
            capture_output=True, timeout=min(10, remaining))
        require(process.returncode not in (35, 51, 58, 60, 77, 80, 82, 83, 90, 91), 'PENPOT_ORIGIN_TLS')
        try:
            require(process.returncode == 0 and len(process.stdout) <= 131080, 'PENPOT_PUBLIC_HEALTH')
            response, separator, status = process.stdout.rpartition(b'\n')
            headers, boundary, body = response.partition(b'\r\n\r\n')
            require(separator and boundary, 'PENPOT_PUBLIC_HEALTH')
            penpot.health_response(profile, status, headers, body, generation, maintenance)
            consecutive += 1
            if consecutive == 2 and time.monotonic() <= deadline:
                return
        except Failure:
            consecutive = 0
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise Failure('PENPOT_ORIGIN_ROUTE_ACK')
