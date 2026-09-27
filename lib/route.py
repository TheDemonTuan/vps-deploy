import json
import os
import re
import stat
import time
from pathlib import Path

from core import Failure, command, digest, docker, fsync_dir, parse_yaml, require


def dynamic(profile):
    edge = json.loads(docker('container', 'inspect', 'edge-traefik'))[0]
    require(edge['State']['Running'], 'TRAEFIK_STOPPED')
    target = '/etc/traefik/dynamic'
    mounts = edge['Mounts']
    matches = [m for m in mounts if m['Destination'] == target]
    require(len(matches) == 1 and matches[0]['Type'] == 'bind' and not any(m['Destination'].startswith(target + '/') for m in mounts), 'TRAEFIK_MOUNT')
    directory = Path(profile['dynamic_dir'])
    require(not directory.is_symlink() and directory.is_dir() and str(directory.resolve()) == matches[0]['Source'] and os.access(directory, os.R_OK | os.W_OK), 'TRAEFIK_MOUNT')
    require('edge-traefik' in docker('network', 'inspect', profile['edge_network'], '--format', '{{range .Containers}}{{println .Name}}{{end}}').splitlines(), 'TRAEFIK_NETWORK')
    return directory


def checked_file(path):
    require(not path.is_symlink() and path.is_file(), 'ROUTE_FILE')
    mode = path.stat().st_mode
    require(stat.S_ISREG(mode) and mode & 0o444, 'ROUTE_UNREADABLE')
    return path.read_bytes()


def route_state(raw):
    obj = parse_yaml(raw)
    try:
        service = obj['http']['services']['9router-service']['loadBalancer']
        urls = service['servers']
        header = obj['http']['middlewares']['9router-route-generation']['headers']['customResponseHeaders']['X-9Router-Route-Generation']
        require(type(urls) is list and len(urls) == 1 and type(urls[0]) is dict and set(urls[0]) == {'url'}, 'ROUTE_SHAPE')
        url = urls[0]['url']
        found = re.fullmatch(r'http://9router-(blue|green):20128', url)
        require(found is not None and type(header) is str and re.fullmatch('[0-9a-f]{32}', header), 'ROUTE_SHAPE')
        return found.group(1), header
    except (KeyError, TypeError):
        raise Failure('ROUTE_SHAPE') from None


def preflight(directory, profile):
    target = directory / profile['route_name']
    require(not target.is_symlink(), 'ROUTE_SYMLINK')
    owned = ('9router-service', '9router-api-router', '9router-dashboard-router', '9router-route-generation')
    hashes = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'ROUTE_SYMLINK')
        if path.is_dir() or path.suffix.lower() not in ('.yml', '.yaml', '.toml'):
            continue
        raw = checked_file(path)
        if path != target:
            require(not any(token.encode() in raw for token in owned), 'ROUTE_COLLISION')
            if path.suffix.lower() in ('.yml', '.yaml'):
                parse_yaml(raw)
            hashes[str(path)] = digest(raw)
    raw = checked_file(target)
    route_state(raw)
    slot, generation = route_state(raw)
    observed = parse_yaml(raw)['http']
    expected = parse_yaml(render(profile, slot, generation))['http']
    require(observed == expected, 'ROUTE_SECURITY_SHAPE')
    require(docker('exec', 'edge-traefik', 'cat', '/etc/traefik/dynamic/' + profile['route_name']).encode() == raw, 'TRAEFIK_UNREADABLE')
    shared = b''.join(checked_file(Path(p)) for p in hashes if p.endswith(('.yml', '.yaml')))
    for name in (b'deny-internal:', b'tunnel-only:', b'public-api-rate-limit:', b'security-headers:'):
        require(name in shared, 'MIDDLEWARE_MISSING')
    return target, raw, hashes


def probe(profile):
    try:
        trust = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
        if profile.get('fixture_ci'):
            trust['CURL_CA_BUNDLE'] = profile['ca_bundle']
        line = command('/usr/bin/bash', str(Path(__file__).with_name('traefik.sh')), 'probe', profile['api_host'], timeout=8, env=trust)
        slot, generation = line.strip().split()
        require(slot in ('blue', 'green') and re.fullmatch('[0-9a-f]{32}', generation), 'PUBLIC_HEALTH')
        return slot, generation
    except (Failure, ValueError):
        raise Failure('PUBLIC_HEALTH') from None


def ack(profile, expected, timeout=30):
    deadline = time.monotonic() + timeout
    consecutive = 0
    while time.monotonic() < deadline:
        try:
            consecutive = consecutive + 1 if probe(profile) == expected else 0
            if consecutive == 2:
                return
        except Failure:
            consecutive = 0
        time.sleep(1)
    raise Failure('ROUTE_ACK_TIMEOUT')


def render(profile, slot, generation):
    adapter = Path(__file__).resolve().parent.parent / 'apps/9router/adapter.sh'
    raw = command('/usr/bin/bash', str(adapter), slot, generation, profile['dashboard_host'], profile['dashboard_alias_host'], profile['api_host']).encode()
    require(route_state(raw) == (slot, generation), 'ROUTE_SHAPE')
    return raw


def publish(path, raw, before):
    import tempfile
    require(digest(checked_file(path)) == before, 'ROUTE_CAS')
    expected_context = command('/usr/bin/stat', '-c', '%C', str(path)).strip()
    fd, name = tempfile.mkstemp(prefix='.9router-', suffix='.tmp', dir=str(path.parent))
    try:
        owner = path.stat()
        os.fchown(fd, owner.st_uid, owner.st_gid)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if expected_context != '?' and command('/usr/bin/stat', '-c', '%C', name).strip() != expected_context:
            command('/usr/bin/chcon', '--reference=' + str(path), name)
        require(command('/usr/bin/stat', '-c', '%C', name).strip() == expected_context, 'ROUTE_CONTEXT')
        require(digest(checked_file(path)) == before, 'ROUTE_CAS')
        os.replace(name, path)
        fsync_dir(path.parent)
        require(path.stat().st_mode & 0o777 == 0o644 and path.stat().st_uid == owner.st_uid and path.stat().st_gid == owner.st_gid and checked_file(path) == raw, 'ROUTE_PUBLISH')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def unchanged(hashes):
    require(all(digest(checked_file(Path(p))) == h for p, h in hashes.items()), 'SHARED_ROUTE_CHANGED')
if __name__ == '__main__':
    import sys
    if len(sys.argv) != 5 or sys.argv[1] != 'publish' or os.geteuid() != 0:
        sys.exit(2)
    try:
        path, source, previous = sys.argv[2:]
        require(Path(path).is_absolute() and Path(source).is_absolute() and re.fullmatch('[0-9a-f]{64}', previous), 'ROUTE_ARGUMENT')
        publish(Path(path), checked_file(Path(source)), previous)
    except (Failure, OSError):
        sys.exit(1)
