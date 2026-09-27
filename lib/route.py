import json
import os
import re
import stat
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
from core import Failure, command, digest, docker, fsync_dir, parse_yaml, require, trusted_path


def dynamic(profile):
    traefik = profile['host_registration']['traefik']
    edge = json.loads(docker('container', 'inspect', traefik['container']))[0]
    require(edge['State']['Running'], 'TRAEFIK_STOPPED')
    target = traefik['mount']
    mounts = edge['Mounts']
    matches = [m for m in mounts if m['Destination'] == target]
    require(len(matches) == 1 and matches[0]['Type'] == 'bind' and not any(m['Destination'].startswith(target + '/') for m in mounts), 'TRAEFIK_MOUNT')
    directory = trusted_path(Path(traefik['dynamic_dir']), directory=True)
    require(str(directory) == matches[0]['Source'] and os.access(directory, os.R_OK | os.W_OK), 'TRAEFIK_MOUNT')
    require(traefik['container'] in docker('network', 'inspect', profile['edge_network'], '--format', '{{range .Containers}}{{println .Name}}{{end}}').splitlines(), 'TRAEFIK_NETWORK')
    return directory


def checked_file(path, managed=False):
    trusted_path(path)
    mode = path.stat().st_mode & 0o777
    require(mode == 0o644 if managed else bool(mode & 0o044), 'ROUTE_UNREADABLE')
    return path.read_bytes()


def route_state(raw, profile):
    obj = parse_yaml(raw)
    app = profile['app']
    header_name = profile['registration']['route']['generation_header']
    try:
        service = obj['http']['services'][app + '-service']['loadBalancer']
        urls = service['servers']
        header = obj['http']['middlewares'][app + '-route-generation']['headers']['customResponseHeaders'][header_name]
        require(type(urls) is list and len(urls) == 1 and type(urls[0]) is dict and set(urls[0]) == {'url'}, 'ROUTE_SHAPE')
        url = urls[0]['url']
        expected = rf'http://{re.escape(app)}-(blue|green):{profile["registration"]["manifest"]["runtime"]["port"]}'
        found = re.fullmatch(expected, url) if type(url) is str else None
        require(found is not None and type(header) is str and re.fullmatch('[0-9a-f]{32}', header), 'ROUTE_SHAPE')
        return found.group(1), header
    except (KeyError, TypeError):
        raise Failure('ROUTE_SHAPE') from None


def route_files(directory):
    files = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'ROUTE_SYMLINK')
        if path.is_dir() or path.suffix.lower() not in ('.yml', '.yaml', '.toml'):
            continue
        files[path] = checked_file(path)
    return files


def preflight(directory, profile):
    trusted_path(directory, directory=True)
    target = directory / profile['route_name']
    files = route_files(directory)
    require(target in files, 'ROUTE_FILE')
    raw = checked_file(target, managed=True)
    slot, generation = route_state(raw, profile)
    observed = parse_yaml(raw)['http']
    expected = parse_yaml(render(profile, slot, generation))['http']
    require(observed == expected, 'ROUTE_SECURITY_SHAPE')
    owned = {name for category in ('routers', 'services', 'middlewares') for name in expected.get(category, {})}
    shared_middlewares = set()
    hashes = {}
    for path, content in files.items():
        if path == target:
            continue
        if path.suffix.lower() in ('.yml', '.yaml'):
            parsed = parse_yaml(content)
            http = parsed.get('http', {}) if type(parsed) is dict else {}
            require(type(http) is dict, 'ROUTE_SHAPE')
            for category in ('routers', 'services', 'middlewares'):
                definitions = http.get(category, {})
                require(type(definitions) is dict, 'ROUTE_SHAPE')
                require(not owned.intersection(definitions), 'ROUTE_COLLISION')
            shared_middlewares.update(name for name, definition in http.get('middlewares', {}).items() if type(definition) is dict and definition)
        else:
            require(not any(re.search(rb'(?<![A-Za-z0-9_-])' + re.escape(name.encode()) + rb'(?![A-Za-z0-9_-])', content) for name in owned), 'ROUTE_COLLISION')
        hashes[str(path)] = digest(content)
    require(set(profile['registration']['route']['required_middlewares']) <= shared_middlewares, 'MIDDLEWARE_MISSING')
    mount = profile['host_registration']['traefik']['mount']
    require(docker('exec', profile['host_registration']['traefik']['container'], 'cat', mount + '/' + profile['route_name']).encode() == raw, 'TRAEFIK_UNREADABLE')
    return target, raw, hashes


def probe(profile):
    try:
        trust = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
        if profile.get('fixture_ci'):
            trust['CURL_CA_BUNDLE'] = profile['ca_bundle']
        line = command('/usr/bin/bash', str(Path(__file__).with_name('traefik.sh')), 'probe', profile['api_host'], profile['registration']['manifest']['health']['path'], profile['registration']['route']['generation_header'], timeout=8, env=trust)
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
    adapter = Path('/opt/vps-deploy/releases') / profile['platform_ref'] / 'apps' / profile['app'] / 'adapter.sh'
    trusted_path(adapter)
    raw = command('/usr/bin/bash', str(adapter), slot, generation, profile['dashboard_host'], profile['dashboard_alias_host'], profile['api_host']).encode()
    require(route_state(raw, profile) == (slot, generation), 'ROUTE_SHAPE')
    return raw


def publish(path, raw, before):
    import tempfile
    require(digest(checked_file(path, managed=True)) == before, 'ROUTE_CAS')
    expected_context = command('/usr/bin/stat', '-c', '%C', str(path), check=False).strip()
    fd, name = tempfile.mkstemp(prefix='.vps-deploy-', suffix='.tmp', dir=str(path.parent))
    try:
        owner = path.stat()
        os.fchown(fd, owner.st_uid, owner.st_gid)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if expected_context and expected_context != '?':
            if command('/usr/bin/stat', '-c', '%C', name, check=False).strip() != expected_context:
                command('/usr/bin/chcon', '--reference=' + str(path), name)
            require(command('/usr/bin/stat', '-c', '%C', name, check=False).strip() == expected_context, 'ROUTE_CONTEXT')
        require(digest(checked_file(path, managed=True)) == before, 'ROUTE_CAS')
        os.replace(name, path)
        fsync_dir(path.parent)
        require(path.stat().st_mode & 0o777 == 0o644 and path.stat().st_uid == owner.st_uid and path.stat().st_gid == owner.st_gid and checked_file(path, managed=True) == raw, 'ROUTE_PUBLISH')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def unchanged(hashes, directory, own_route_name):
    current = route_files(directory)
    current.pop(directory / own_route_name, None)
    require({str(path): digest(raw) for path, raw in current.items()} == hashes, 'SHARED_ROUTE_CHANGED')
if __name__ == '__main__':
    import sys
    if len(sys.argv) != 5 or sys.argv[1] != 'publish' or os.geteuid() != 0:
        sys.exit(2)
    try:
        path, source, previous = sys.argv[2:]
        require(Path(path).is_absolute() and Path(source).is_absolute() and re.fullmatch('[0-9a-f]{64}', previous), 'ROUTE_ARGUMENT')
        publish(Path(path), checked_file(Path(source)), previous)
    except (Failure, OSError):
        if __import__('core').fixture_authorized():
            import traceback
            traceback.print_exc()
        sys.exit(1)
