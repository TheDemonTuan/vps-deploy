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
from pathlib import Path

import yaml

APP = '9router'
APP_IMAGE = 'ghcr.io/thedemontuan/9router'
RTK_IMAGE = 'ghcr.io/thedemontuan/rtk-sidecar'
SHA = re.compile(r'[0-9a-f]{40}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
REQUEST_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z')
DEFAULT_CONFIG = Path('/etc/vps-deploy/apps/9router')
DEFAULT_STATE = Path('/var/lib/vps-deploy/apps/9router')
DEFAULT_LOCKS = Path('/run/lock/vps-deploy')


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

def manifest(raw):
    obj = parse_yaml(raw)
    fields(obj, {'version', 'app', 'strategy', 'image', 'platform', 'runtime', 'health', 'route', 'rtk'}, {'version', 'app', 'strategy', 'image', 'platform', 'runtime', 'health', 'route', 'rtk'})
    require(type(obj['version']) is int and obj['version'] == 1 and obj['app'] == APP and obj['strategy'] == 'blue-green' and obj['image'] == APP_IMAGE and obj['platform'] == 'linux/arm64', 'MANIFEST_POLICY')
    for section, specs in [('runtime', {'port': (int, 20128)}), ('health', {'path': (str, '/api/health'), 'timeout_seconds': (int, 60)}), ('route', {'timeout_seconds': (int, 30)}), ('rtk', {'image': (str, RTK_IMAGE)})]:
        fields(obj[section], set(specs), set(specs))
        for key, (kind, expected) in specs.items():
            require(type(obj[section][key]) is kind and obj[section][key] == expected, 'MANIFEST_POLICY')
    return obj


def request(raw, repositories=None):
    obj = parse_json(raw)
    op = obj.get('op')
    require(op in ('deploy', 'rollback', 'reconcile', 'status'), 'INVALID_OPERATION')
    common = {'version', 'op', 'app', 'request_id'}
    mutating = common | {'component', 'platform_ref', 'manifest_sha256', 'source_sha'}
    expected = common if op == 'status' else mutating | ({'image'} if op == 'deploy' else set())
    required = {'version', 'op', 'app'} if op == 'status' else expected
    fields(obj, expected, required)
    require(type(obj['version']) is int and obj['version'] == 1 and obj['app'] == APP, 'INVALID_APP')
    if 'request_id' in obj:
        require(type(obj['request_id']) is str and REQUEST_ID.fullmatch(obj['request_id']), 'INVALID_REQUEST_ID')
    if op != 'status':
        require(obj['component'] in ('app', 'rtk') and (op != 'rollback' or obj['component'] == 'app'), 'INVALID_COMPONENT')
        require(all(type(obj[k]) is str and SHA.fullmatch(obj[k]) for k in ('platform_ref', 'source_sha')), 'INVALID_SHA')
        require(type(obj['manifest_sha256']) is str and HASH.fullmatch(obj['manifest_sha256']), 'INVALID_HASH')
        if op == 'deploy':
            prefix = (repositories or (APP_IMAGE, RTK_IMAGE))[0 if obj['component'] == 'app' else 1]
            require(type(obj['image']) is str and re.fullmatch(re.escape(prefix) + r'@sha256:[0-9a-f]{64}', obj['image']), 'INVALID_IMAGE')
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


def paths(operator=False):
    # Operator fixture roots never accepted from SSH environment.
    if operator and os.geteuid() == 0:
        return (Path(os.environ.get('VPS_DEPLOY_CONFIG', str(DEFAULT_CONFIG))), Path(os.environ.get('VPS_DEPLOY_STATE', str(DEFAULT_STATE))), Path(os.environ.get('VPS_DEPLOY_LOCKS', str(DEFAULT_LOCKS))))
    return DEFAULT_CONFIG, DEFAULT_STATE, DEFAULT_LOCKS


def host(config):
    value = load(config / 'host.json')
    required = {'platform_ref', 'dynamic_dir', 'api_host', 'dashboard_host', 'dashboard_alias_host', 'work_dir', 'compose_project', 'edge_network', 'rtk_network', 'route_name'}
    fixture = value.get('fixture_ci') is True
    extras = {'fixture_ci', 'image_repository', 'rtk_image_repository', 'architecture', 'ca_bundle'} if fixture and fixture_authorized() else set()
    if fixture and fixture_authorized() and 'fault_file' in value:
        extras.add('fault_file')
    fields(value, required | {'bridge_socket_root', 'bridge_socket_gid'} | extras, required | (extras - {'fault_file'} if fixture else set()))
    require(type(value['platform_ref']) is str and SHA.fullmatch(value['platform_ref']), 'PLATFORM_MISMATCH')
    require(all(type(value[key]) is str for key in required - {'platform_ref'}), 'HOST_POLICY')
    require(value['compose_project'] == APP and value['route_name'] == '9router.yml', 'HOST_POLICY')
    if fixture:
        require(fixture_authorized(), 'FIXTURE_NOT_AUTHORIZED')
        native = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(os.uname().machine, os.uname().machine)
        require(value['architecture'] == native and value['image_repository'] == 'localhost:5000/9router' and value['rtk_image_repository'] == 'localhost:5000/rtk-sidecar', 'FIXTURE_POLICY')
        require(value['work_dir'].startswith('/tmp/') or value['work_dir'].startswith('/home/runner/work/'), 'FIXTURE_POLICY')
        require(value['edge_network'] == 'edge-9router' and value['rtk_network'] == '9router-rtk', 'FIXTURE_POLICY')
        require(type(value['ca_bundle']) is str and type(value['architecture']) is str, 'FIXTURE_POLICY')
        ca = Path(value['ca_bundle'])
        require(ca.is_file() and not ca.is_symlink() and ca.stat().st_uid == 0, 'FIXTURE_CA')
        if 'fault_file' in value:
            require(type(value['fault_file']) is str, 'FIXTURE_FAULT_POLICY')
            fault = Path(value['fault_file'])
            require(fault.is_absolute() and str(fault).startswith(value['work_dir'] + '/') and not fault.is_symlink(), 'FIXTURE_FAULT_POLICY')
            require(fault.parent.is_dir() and not fault.parent.is_symlink() and fault.parent.stat().st_uid == 0 and fault.parent.stat().st_mode & 0o777 == 0o700, 'FIXTURE_FAULT_POLICY')
    else:
        require(value['work_dir'] == '/opt/9router' and value['edge_network'] == 'edge-9router' and value['rtk_network'] == '9router-rtk', 'HOST_POLICY')
        value['image_repository'] = APP_IMAGE
        value['rtk_image_repository'] = RTK_IMAGE
        value['architecture'] = 'arm64'
    require(('bridge_socket_gid' in value) == ('bridge_socket_root' in value), 'HOST_POLICY')
    if 'bridge_socket_gid' in value:
        require(type(value['bridge_socket_gid']) is int and value['bridge_socket_gid'] >= 0 and type(value['bridge_socket_root']) is str and value['bridge_socket_root'].startswith('/run/') and '..' not in Path(value['bridge_socket_root']).parts, 'HOST_POLICY')
    import ipaddress
    for key in ('api_host', 'dashboard_host', 'dashboard_alias_host'):
        name = value[key]
        if key == 'dashboard_alias_host' and not name:
            continue
        labels = name.split('.')
        require(len(name) <= 253 and len(labels) >= 2 and all(0 < len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in labels), 'HOST_POLICY')
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise Failure('HOST_POLICY')
    for key in ('dynamic_dir', 'work_dir'):
        require(type(value[key]) is str and os.path.isabs(value[key]) and '..' not in Path(value[key]).parts, 'HOST_POLICY')
    return value


def registered(config):
    raw = (config / 'app.yml').read_bytes()
    return manifest(raw), digest(raw)


def verify_request(req, cfg, profile):
    _, manifest_hash = registered(cfg)
    require(req['manifest_sha256'] == manifest_hash and req['platform_ref'] == profile['platform_ref'], 'PLATFORM_OR_MANIFEST_MISMATCH')
    release = Path('/opt/vps-deploy/releases') / req['platform_ref']
    require(release.is_dir() and not release.is_symlink(), 'RELEASE_NOT_INSTALLED')
    return release
