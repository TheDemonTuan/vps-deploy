import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath

import yaml

SHA = re.compile(r'[0-9a-f]{40}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
REQUEST_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z')
DEFAULT_CONFIG = Path('/etc/vps-deploy/apps')
DEFAULT_STATE = Path('/var/lib/vps-deploy/apps')
DEFAULT_LOCKS = Path('/run/lock/vps-deploy')
APP_ID = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?\Z')
ENV_NAME = re.compile(r'[A-Z_][A-Z0-9_]*\Z')
HEADER = re.compile(r'[A-Za-z][A-Za-z0-9-]{0,63}\Z')
HEALTH_PATH = re.compile(r'/[A-Za-z0-9._/-]*\Z')



class Failure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(ok, code):
    if not ok:
        raise Failure(code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_KEY')
        result[key] = value
    return result


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def parse_json(raw):
    require(len(raw) <= 65536, 'REQUEST_TOO_LARGE')
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, TypeError):
        raise Failure('INVALID_JSON') from None
    require(type(value) is dict, 'INVALID_JSON')
    return value


class SafeLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node):
    loader.flatten_mapping(node)
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key)
        require(type(name) is str and name not in result, 'DUPLICATE_KEY')
        result[name] = loader.construct_object(value)
    return result


SafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def parse_yaml(raw):
    require(len(raw) <= 65536, 'MANIFEST_TOO_LARGE')
    try:
        text = raw.decode('utf-8')
        require(not any(isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)) for token in yaml.scan(text)), 'UNSAFE_YAML')
        value = yaml.load(text, Loader=SafeLoader)
    except (yaml.YAMLError, UnicodeError):
        raise Failure('INVALID_YAML') from None
    require(type(value) is dict, 'INVALID_YAML')
    return value


def fields(value, expected, required):
    require(type(value) is dict and required <= value.keys() and value.keys() <= expected, 'UNKNOWN_OR_MISSING_FIELD')

def registration_id(value):
    require(type(value) is str and APP_ID.fullmatch(value), 'APP_NOT_REGISTERED')
    return value


def exact(value, expected):
    if type(value) is dict and type(expected) is dict:
        require(value.keys() == expected.keys(), 'MANIFEST_POLICY')
        for key in value:
            exact(value[key], expected[key])
    else:
        require(type(value) is type(expected) and value == expected, 'MANIFEST_POLICY')


def hostname(value):
    require(type(value) is str and len(value) <= 253 and len(value.split('.')) >= 2 and all(0 < len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in value.split('.')), 'REGISTRY_POLICY')


def app_registration(release, app):
    registration_id(app)
    path = Path(release) / 'registry' / (app + '.yml')
    require(path.is_file() and not path.is_symlink(), 'APP_NOT_REGISTERED')
    value = parse_yaml(path.read_bytes())
    fields(value, {'version', 'app', 'host', 'caller', 'manifest', 'runtime', 'route'}, {'version', 'app', 'host', 'caller', 'manifest', 'runtime', 'route'})
    require(type(value['version']) is int and value['version'] == 1 and value['app'] == app, 'REGISTRY_POLICY')
    registration_id(value['host'])
    caller = value['caller']
    fields(caller, {'repository', 'ref', 'config', 'build_workflows', 'deploy_workflows'}, {'repository', 'ref', 'config', 'build_workflows', 'deploy_workflows'})
    require(type(caller['repository']) is str and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', caller['repository']) and type(caller['ref']) is str and re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+', caller['ref']) and type(caller['config']) is str and re.fullmatch(r'\.[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+\.yml', caller['config']), 'REGISTRY_POLICY')
    for key in ('build_workflows', 'deploy_workflows'):
        names = caller[key]
        require(type(names) is list and names and all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]+\.yml', name) for name in names) and len(names) == len(set(names)), 'REGISTRY_POLICY')
    policy = value['manifest']
    fields(policy, {'version', 'app', 'strategy', 'image', 'platform', 'runtime', 'health', 'route', 'rtk'}, {'version', 'app', 'strategy', 'image', 'platform', 'runtime', 'health', 'route'})
    fixture_image = fixture_authorized() and value['host'] == 'fixture-local' and app == 'demo' and policy['image'] == 'localhost:5000/demo'
    require(type(policy['version']) is int and policy['version'] == 1 and policy['app'] == app and policy['strategy'] == 'blue-green' and policy['platform'] == 'linux/arm64' and type(policy['image']) is str and (re.fullmatch(r'ghcr\.io/[a-z0-9./_-]+', policy['image']) or fixture_image), 'REGISTRY_POLICY')
    for section, keys in (('runtime', {'port'}), ('health', {'path', 'timeout_seconds'}), ('route', {'timeout_seconds'})):
        fields(policy[section], keys, keys)
    require(type(policy['runtime']['port']) is int and 1 <= policy['runtime']['port'] <= 65535, 'REGISTRY_POLICY')
    path_value = policy['health']['path']
    require(type(path_value) is str and HEALTH_PATH.fullmatch(path_value) and '..' not in path_value.split('/'), 'REGISTRY_POLICY')
    require(all(type(policy[section]['timeout_seconds']) is int and policy[section]['timeout_seconds'] == bound for section, bound in (('health', 60), ('route', 30))), 'REGISTRY_POLICY')
    if 'rtk' in policy:
        fields(policy['rtk'], {'image'}, {'image'})
        require(type(policy['rtk']['image']) is str and re.fullmatch(r'ghcr\.io/[a-z0-9./_-]+', policy['rtk']['image']), 'REGISTRY_POLICY')
    runtime = value['runtime']
    fields(runtime, {'allowed_env', 'required_env'}, {'allowed_env', 'required_env'})
    for key in ('allowed_env', 'required_env'):
        names = runtime[key]
        require(type(names) is list and all(type(name) is str and ENV_NAME.fullmatch(name) for name in names) and len(names) == len(set(names)), 'REGISTRY_POLICY')
    require(set(runtime['required_env']) <= set(runtime['allowed_env']), 'REGISTRY_POLICY')
    route = value['route']
    fields(route, {'generation_header', 'required_middlewares'}, {'generation_header', 'required_middlewares'})
    require(type(route['generation_header']) is str and HEADER.fullmatch(route['generation_header']), 'REGISTRY_POLICY')
    names = route['required_middlewares']
    require(type(names) is list and all(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]*', name) for name in names) and len(names) == len(set(names)), 'REGISTRY_POLICY')
    return value


def host_registration(release, host_id):
    require(type(host_id) is str and APP_ID.fullmatch(host_id), 'HOST_NOT_REGISTERED')
    path = Path(release) / 'hosts' / (host_id + '.yml')
    require(path.is_file() and not path.is_symlink(), 'HOST_NOT_REGISTERED')
    value = parse_yaml(path.read_bytes())
    fields(value, {'version', 'host', 'ssh', 'traefik', 'apps'}, {'version', 'host', 'ssh', 'traefik', 'apps'})
    require(type(value['version']) is int and value['version'] == 1 and value['host'] == host_id, 'REGISTRY_POLICY')
    ssh = value['ssh']
    fields(ssh, {'address', 'port', 'host_key', 'fingerprint'}, {'address', 'port', 'host_key', 'fingerprint'})
    import ipaddress
    try:
        ipaddress.ip_address(ssh['address'])
    except (ValueError, TypeError):
        if not (host_id == 'fixture-local' and fixture_authorized() and ssh['address'] == 'localhost'):
            hostname(ssh['address'])
    require(type(ssh['port']) is int and 1 <= ssh['port'] <= 65535 and type(ssh['host_key']) is str and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', ssh['host_key']) and type(ssh['fingerprint']) is str and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', ssh['fingerprint']), 'REGISTRY_POLICY')
    traefik = value['traefik']
    fields(traefik, {'container', 'dynamic_dir', 'mount'}, {'container', 'dynamic_dir', 'mount'})
    require(type(traefik['container']) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]*', traefik['container']), 'REGISTRY_POLICY')
    for key in ('dynamic_dir', 'mount'):
        require(type(traefik[key]) is str and PurePosixPath(traefik[key]).is_absolute() and str(PurePosixPath(traefik[key])) == traefik[key] and '..' not in PurePosixPath(traefik[key]).parts, 'REGISTRY_POLICY')
    require(type(value['apps']) is dict and value['apps'], 'REGISTRY_POLICY')
    for app, binding in value['apps'].items():
        registration_id(app)
        required = {'api_host', 'dashboard_host', 'dashboard_alias_host', 'work_dir', 'compose_project', 'edge_network', 'route_name'}
        fields(binding, required | {'rtk_network'}, required)
        hostname(binding['api_host'])
        for key in ('dashboard_host', 'dashboard_alias_host'):
            if binding[key]:
                hostname(binding[key])
            else:
                require(type(binding[key]) is str, 'REGISTRY_POLICY')
        require(type(binding['work_dir']) is str and PurePosixPath(binding['work_dir']).is_absolute() and str(PurePosixPath(binding['work_dir'])) == binding['work_dir'] and '..' not in PurePosixPath(binding['work_dir']).parts and binding['compose_project'] == app and binding['edge_network'] == 'edge-' + app and binding['route_name'] == app + '.yml', 'REGISTRY_POLICY')
        if 'rtk_network' in binding:
            require(binding['rtk_network'] == app + '-rtk', 'REGISTRY_POLICY')
    return resource_collisions(value)


def trusted_path(path, directory=False):
    path = Path(path)
    require(path.is_absolute(), 'UNTRUSTED_PATH')
    for entry in (*reversed(path.parents), path):
        try:
            mode = entry.lstat()
        except (OSError, ValueError):
            raise Failure('UNTRUSTED_PATH') from None
        require(mode.st_uid == 0 and not stat.S_ISLNK(mode.st_mode) and (stat.S_ISDIR(mode.st_mode) if entry != path or directory else stat.S_ISREG(mode.st_mode)), 'UNTRUSTED_PATH')
        sticky_fixture = entry == Path('/tmp') and fixture_authorized() and mode.st_mode & stat.S_ISVTX
        require(not mode.st_mode & 0o022 or sticky_fixture, 'UNTRUSTED_PATH')
    return path


def resource_collisions(host_record):
    occupied = set()
    def reserve(kind, value):
        key = kind, value
        require(key not in occupied, 'RESOURCE_COLLISION')
        occupied.add(key)
    for app, binding in host_record['apps'].items():
        for kind, value in (('user', 'deploy-' + app), ('work_dir', binding['work_dir']), ('project', binding['compose_project']), ('route', binding['route_name']), ('host', binding['api_host']), ('wrapper', 'vps-deploy-' + app), ('wrapper', 'vps-deploy-drain-' + app), ('container', app + '-blue'), ('container', app + '-green'), ('network', binding['edge_network'])):
            reserve(kind, value)
        for key in ('dashboard_host', 'dashboard_alias_host'):
            if binding[key]:
                reserve('host', binding[key])
        if 'rtk_network' in binding:
            reserve('network', binding['rtk_network'])
            reserve('container', app + '-rtk-rtk-1')
    return host_record

def fixture_authorized():
    marker = Path('/etc/vps-deploy/fixture-ci')
    if marker.is_symlink() or not marker.is_file():
        return False
    value = marker.stat()
    return value.st_uid == 0 and stat.S_ISREG(value.st_mode) and value.st_mode & 0o777 == 0o600

def fault(profile, label):
    if not (profile.get('fixture_ci') and fixture_authorized() and profile.get('fault_file')):
        return
    path = Path(profile['fault_file'])
    if not path.exists() or path.is_symlink():
        return
    value = path.stat()
    require(value.st_uid == 0 and stat.S_ISREG(value.st_mode) and value.st_mode & 0o777 == 0o600 and path.parent.stat().st_uid == 0 and path.parent.stat().st_mode & 0o777 == 0o700, 'FIXTURE_FAULT_POLICY')
    if path.read_text(encoding='ascii').strip() == label:
        os.kill(os.getpid(), 9)

def manifest(raw, registration):
    obj = parse_yaml(raw)
    exact(obj, registration['manifest'])
    return obj


def request(raw, profile):
    obj = parse_json(raw)
    op = obj.get('op')
    require(op in ('deploy', 'rollback', 'reconcile', 'status'), 'INVALID_OPERATION')
    common = {'version', 'op', 'app', 'request_id'}
    mutating = common | {'component', 'platform_ref', 'manifest_sha256', 'source_sha'}
    expected = common if op == 'status' else mutating | ({'image'} if op == 'deploy' else set())
    fields(obj, expected, {'version', 'op', 'app'} if op == 'status' else expected)
    require(type(obj['version']) is int and obj['version'] == 1, 'INVALID_REQUEST')
    require(type(obj['app']) is str and obj['app'] == profile['app'], 'APP_BINDING_MISMATCH')
    if 'request_id' in obj:
        require(type(obj['request_id']) is str and REQUEST_ID.fullmatch(obj['request_id']), 'INVALID_REQUEST_ID')
    if op != 'status':
        require(obj['component'] in (('app', 'rtk') if 'rtk' in profile['registration']['manifest'] else ('app',)) and (op != 'rollback' or obj['component'] == 'app'), 'INVALID_COMPONENT')
        require(all(type(obj[k]) is str and SHA.fullmatch(obj[k]) for k in ('platform_ref', 'source_sha')), 'INVALID_SHA')
        require(type(obj['manifest_sha256']) is str and HASH.fullmatch(obj['manifest_sha256']), 'INVALID_HASH')
        if op == 'deploy':
            repository = profile['image_repository'] if obj['component'] == 'app' else profile['rtk_image_repository']
            require(type(obj['image']) is str and re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', obj['image']), 'INVALID_IMAGE')
    return obj


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.write-', suffix='.tmp', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save(path, obj):
    atomic(path, json_bytes(obj))


def load(path):
    return parse_json(Path(path).read_bytes())


@contextlib.contextmanager
def lock(path, timeout=0):
    path = Path(path)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid == 0, 'UNSAFE_LOCK')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Failure('APP_BUSY' if timeout == 0 else 'TRAEFIK_BUSY') from None
                time.sleep(.1)
        yield
    finally:
        os.close(fd)


def command(*argv, env=None, timeout=30, check=True):
    proc = subprocess.run(argv, env=env, cwd='/', capture_output=True, timeout=timeout)
    if check and proc.returncode:
        raise Failure('COMMAND_FAILED')
    return proc.stdout.decode('utf-8')


def docker(*argv, timeout=30):
    return command('/usr/bin/docker', *argv, timeout=timeout)


def inspect(kind, name):
    output = docker(kind, 'inspect', name)
    result = json.loads(output)
    require(len(result) == 1, 'IDENTITY_MISMATCH')
    return result[0]


def image_id(ref):
    value = inspect('image', ref)
    architecture = os.uname().machine
    architecture = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(architecture, architecture)
    if ref.startswith('localhost:5000/') and fixture_authorized():
        require(value['Architecture'] == architecture, 'IDENTITY_MISMATCH')
    else:
        require(value['Architecture'] == 'arm64', 'IDENTITY_MISMATCH')
    require(value['Os'] == 'linux' and ref in value['RepoDigests'], 'IDENTITY_MISMATCH')
    return value['Id']


def container_digest(value, repository):
    image = inspect('image', value['Image'])
    require(image['Id'] == value['Image'] and image['Os'] == 'linux', 'IDENTITY_MISMATCH')
    candidates = [ref for ref in image.get('RepoDigests', []) if re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', ref)]
    require(len(candidates) == 1 and image_id(candidates[0]) == value['Image'], 'ADOPT_DIGEST_AMBIGUOUS')
    return candidates[0]

def container(name, ref=None, running=False):
    value = inspect('container', name)
    if ref:
        require(value['Image'] == image_id(ref), 'IDENTITY_MISMATCH')
    if running:
        require(value['State']['Running'], 'CONTAINER_STOPPED')
    return value


def paths(app, operator=False):
    registration_id(app)
    if operator and os.geteuid() == 0 and fixture_authorized():
        config = Path(os.environ.get('VPS_DEPLOY_CONFIG', str(DEFAULT_CONFIG / app)))
        state = Path(os.environ.get('VPS_DEPLOY_STATE', str(DEFAULT_STATE / app)))
        locks = Path(os.environ.get('VPS_DEPLOY_LOCKS', str(DEFAULT_LOCKS)))
        return config, state, locks
    return DEFAULT_CONFIG / app, DEFAULT_STATE / app, DEFAULT_LOCKS


def host(config, registration, host_record):
    trusted_path(config, directory=True)
    trusted_path(config / 'host.json')
    value = load(config / 'host.json')
    app = registration['app']
    require(registration['host'] == host_record['host'] and app in host_record['apps'], 'APP_BINDING_MISMATCH')
    binding = host_record['apps'][app]
    required = {'platform_ref', 'dynamic_dir', 'api_host', 'dashboard_host', 'dashboard_alias_host', 'work_dir', 'compose_project', 'edge_network', 'route_name'}
    if 'rtk' in registration['manifest']:
        required.add('rtk_network')
    else:
        require('rtk_network' not in binding, 'REGISTRY_POLICY')
    fixture = value.get('fixture_ci') is True
    require(not fixture or fixture_authorized(), 'FIXTURE_NOT_AUTHORIZED')
    extras = {'fixture_ci', 'image_repository', 'architecture', 'ca_bundle'} | ({'rtk_image_repository'} if 'rtk_network' in required else set()) if fixture else set()
    if fixture and 'fault_file' in value:
        extras.add('fault_file')
    fields(value, required | {'bridge_socket_root', 'bridge_socket_gid'} | extras, required | (extras - {'fault_file'}))
    require(type(value['platform_ref']) is str and SHA.fullmatch(value['platform_ref']), 'PLATFORM_MISMATCH')
    release = Path('/opt/vps-deploy/releases') / value['platform_ref']
    trusted_path(release, directory=True)
    trusted_path(release / 'registry', directory=True)
    trusted_path(release / 'hosts', directory=True)
    trusted_path(release / 'registry' / (app + '.yml'))
    trusted_path(release / 'hosts' / (host_record['host'] + '.yml'))
    require(app_registration(release, app) == registration and host_registration(release, host_record['host']) == host_record, 'REGISTRY_POLICY')
    require(all(type(value[key]) is str and value[key] == expected for key, expected in binding.items()) and type(value['dynamic_dir']) is str and value['dynamic_dir'] == host_record['traefik']['dynamic_dir'], 'APP_BINDING_MISMATCH')
    require(set(value) - extras - {'bridge_socket_root', 'bridge_socket_gid', 'platform_ref', 'dynamic_dir'} == set(binding), 'APP_BINDING_MISMATCH')
    trusted_path(value['work_dir'], directory=True)
    if fixture:
        require(Path(value['work_dir']).stat().st_mode & 0o777 == 0o700, 'FIXTURE_POLICY')
    require(('bridge_socket_gid' in value) == ('bridge_socket_root' in value), 'HOST_POLICY')
    if 'bridge_socket_gid' in value:
        require(type(value['bridge_socket_gid']) is int and value['bridge_socket_gid'] >= 0 and type(value['bridge_socket_root']) is str and value['bridge_socket_root'].startswith('/run/') and '..' not in Path(value['bridge_socket_root']).parts, 'HOST_POLICY')
        trusted_path(release / 'apps' / app / 'docker-compose.chatgpt-web.yml')
    if fixture:
        native = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine, os.uname().machine)
        fixture_image = 'localhost:5000/' + app
        fixture_rtk = 'localhost:5000/rtk-sidecar' if 'rtk' in registration['manifest'] else None
        require(value['architecture'] == native and value['image_repository'] == fixture_image and value.get('rtk_image_repository') == fixture_rtk, 'FIXTURE_POLICY')
        require(type(value['ca_bundle']) is str, 'FIXTURE_POLICY')
        trusted_path(value['ca_bundle'])
        if 'fault_file' in value:
            require(type(value['fault_file']) is str, 'FIXTURE_FAULT_POLICY')
            fault = Path(value['fault_file'])
            require(fault.is_absolute() and str(fault).startswith(value['work_dir'] + '/'), 'FIXTURE_FAULT_POLICY')
            trusted_path(fault.parent, directory=True)
            require(fault.parent.stat().st_mode & 0o777 == 0o700, 'FIXTURE_FAULT_POLICY')
            if fault.exists() or fault.is_symlink():
                trusted_path(fault)
    else:
        value['image_repository'] = registration['manifest']['image']
        value['rtk_image_repository'] = registration['manifest'].get('rtk', {}).get('image')
        value['architecture'] = 'arm64'
    trusted_path(config / 'app.yml')
    trusted_path(config / 'runtime.env')
    require((config / 'runtime.env').stat().st_mode & 0o777 == 0o600, 'UNSAFE_RUNTIME_ENV')
    trusted_path(value['dynamic_dir'], directory=True)
    value.update(app=app, registration=registration, host_registration=host_record)
    return value


def registered(config, registration):
    trusted_path(config / 'app.yml')
    raw = (config / 'app.yml').read_bytes()
    return manifest(raw, registration), digest(raw)


def verify_request(req, cfg, profile):
    _, manifest_hash = registered(cfg, profile['registration'])
    require(req['manifest_sha256'] == manifest_hash and req['platform_ref'] == profile['platform_ref'], 'PLATFORM_OR_MANIFEST_MISMATCH')
    release = Path('/opt/vps-deploy/releases') / req['platform_ref']
    trusted_path(release, directory=True)
    return release
