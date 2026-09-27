#!/usr/bin/python3
"""Root-only, selected-app release activation. --check never writes host state."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import (Failure, SHA, app_registration, atomic, fixture_authorized,
                  host, host_registration, lock, manifest, registration_id,
                  require, trusted_path)
from preflight import check as preflight

AREAS = ('bin', 'lib', 'apps', 'schema', 'install', 'registry', 'hosts')
RELEASES = Path('/opt/vps-deploy/releases')
CONFIG = Path('/etc/vps-deploy/apps')
STATE = Path('/var/lib/vps-deploy/apps')
LOCKS = Path('/run/lock/vps-deploy')
SYSTEMD = Path('/etc/systemd/system')
LIBEXEC = Path('/usr/local/libexec')


def run(*args, timeout=30, check=True):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise Failure('COMMAND_FAILED')
    return result


def git(root, *args):
    result = run('/usr/bin/git', '-C', str(root), *args)
    return result.stdout.strip()


def optional_trusted(path, directory=False):
    if path.exists() or path.is_symlink():
        trusted_path(path, directory=directory)
        return True
    return False


def valid_key(path):
    trusted_path(path)
    data = path.read_bytes()
    lines = data.splitlines()
    require(data.endswith(b'\n') and len(lines) == 1 and re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?', lines[0]), 'INVALID_PUBLIC_KEY')
    require(run('/usr/bin/ssh-keygen', '-lf', str(path), check=False).returncode == 0, 'INVALID_PUBLIC_KEY')


def tree(root):
    require(root.is_dir() and not root.is_symlink(), 'UNTRUSTED_PATH')
    trusted_path(root, directory=True)
    result = {}
    for area in AREAS:
        base = root / area
        trusted_path(base, directory=True)
        result[area] = ('dir', stat.S_IMODE(base.stat().st_mode))
        for path in base.rglob('*'):
            trusted_path(path, directory=path.is_dir())
            if '__pycache__' in path.relative_to(base).parts or path.suffix == '.pyc':
                continue
            result[str(path.relative_to(root))] = ('dir', stat.S_IMODE(path.stat().st_mode)) if path.is_dir() else (hashlib.sha256(path.read_bytes()).digest(), stat.S_IMODE(path.stat().st_mode))
    return result


def release_copy(source, destination, expected):
    if destination.exists() or destination.is_symlink():
        require(destination.is_dir() and not destination.is_symlink() and tree(destination) == expected, 'RELEASE_MODIFIED')
        return
    temporary = Path(tempfile.mkdtemp(prefix='.install.', dir=RELEASES))
    try:
        for area in AREAS:
            shutil.copytree(source / area, temporary / area, symlinks=False, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for path in (temporary, *temporary.rglob('*')):
            os.chown(path, 0, 0)
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~0o022)
        require(tree(temporary) == expected, 'RELEASE_MODIFIED')
        for path in sorted(temporary.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            fd = os.open(path, os.O_RDONLY | (os.O_DIRECTORY if path.is_dir() else 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        os.replace(temporary, destination)
        fd = os.open(RELEASES, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def put(path, data, mode):
    if path.exists() or path.is_symlink():
        trusted_path(path)
    atomic(path, data, mode)


def profile_data(app, release, binding, host_record, previous):
    profile = dict(binding, platform_ref=release, dynamic_dir=host_record['traefik']['dynamic_dir'])
    if previous:
        previous = dict(previous)
        for name in ('bridge_socket_root', 'bridge_socket_gid', 'fixture_ci', 'image_repository',
                     'rtk_image_repository', 'architecture', 'ca_bundle', 'fault_file'):
            if name in previous:
                profile[name] = previous[name]
    return json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()


def enrolled_collisions(app, binding, host_record):
    # Compare selected host inventory against every already installed app, even
    # when a new release accidentally drops an old app from its host record.
    selected = host_record['apps']
    for config in CONFIG.iterdir() if CONFIG.exists() else ():
        if config.name == app or not config.is_dir():
            continue
        registration_id(config.name)
        path = config / 'host.json'
        if not optional_trusted(path):
            continue
        old = json.loads(path.read_bytes())
        require(type(old) is dict, 'HOST_POLICY')
        if config.name in selected:
            require(all(old.get(key) == value for key, value in selected[config.name].items()), 'APP_BINDING_MISMATCH')
        def identity(name, data):
            resources = {
                ('user', 'deploy-' + name), ('work_dir', data['work_dir']),
                ('project', data['compose_project']), ('route', data['route_name']),
                ('container', name + '-blue'), ('container', name + '-green'),
                ('wrapper', 'vps-deploy-' + name), ('wrapper', 'vps-deploy-drain-' + name),
                ('network', data['edge_network']),
            }
            if data.get('rtk_network'):
                resources.update({('network', data['rtk_network']), ('container', name + '-rtk-rtk-1')})
            resources.update(('host', data[key]) for key in ('api_host', 'dashboard_host', 'dashboard_alias_host') if data.get(key))
            return resources
        require(not identity(app, binding) & identity(config.name, old), 'RESOURCE_COLLISION')

@contextlib.contextmanager
def acquire(path):
    try:
        with lock(path, 120):
            yield
    except Failure as exc:
        if exc.code in ('APP_BUSY', 'TRAEFIK_BUSY'):
            raise Failure('INSTALL_BUSY') from exc
        raise

def busy(app, state_dir):
    if (state_dir / 'state.json').exists():
        trusted_path(state_dir / 'state.json')
        require(json.loads((state_dir / 'state.json').read_bytes()).get('operation') is None, 'INSTALL_BUSY')
    requests = state_dir / 'requests'
    if requests.exists():
        trusted_path(requests, directory=True)
        for entry in requests.iterdir():
            trusted_path(entry, directory=True)
            receipt = entry / 'result.json'
            if not receipt.is_file():
                raise Failure('INSTALL_BUSY')
            trusted_path(receipt)
            require(json.loads(receipt.read_bytes()).get('status') in ('complete', 'failed'), 'INSTALL_BUSY')
    patterns = ['vps-deploy-' + app + '@*.service']
    if app == '9router':
        patterns.append('vps-deploy-9router-*.service')
    output = run('/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-legend', '--no-pager', *patterns).stdout.decode()
    require(not any(row.split()[2:3] == ['active'] or row.split()[3:4] == ['running'] for row in output.splitlines()), 'INSTALL_BUSY')


def timer_enabled(name):
    return run('/usr/bin/systemctl', 'is-enabled', '--quiet', name, check=False).returncode == 0


def stop_drain(app, old=False):
    service = 'vps-deploy-9router-drain.service' if old else 'vps-deploy-drain@' + app + '.service'
    timer = service.replace('.service', '.timer')
    enabled = timer_enabled(timer)
    running = run('/usr/bin/systemctl', 'is-active', '--quiet', timer, check=False).returncode == 0
    run('/usr/bin/systemctl', 'stop', timer, check=False)
    deadline = time.monotonic() + 120
    while run('/usr/bin/systemctl', 'is-active', '--quiet', service, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            restore_timers([(timer, enabled, running)])
            raise Failure('INSTALL_BUSY')
        time.sleep(.2)
    return timer, enabled, running


def restore_timers(timers):
    for timer, enabled, running in timers:
        run('/usr/bin/systemctl', 'enable' if enabled else 'disable', timer, check=False)
        if running:
            run('/usr/bin/systemctl', 'start', timer, check=False)


def activation(args, root, raw, binding, host_record, previous, source_env, expected):
    app = args.app
    cfg = CONFIG / app
    state = STATE / app
    destination = RELEASES / args.release
    wrapper = LIBEXEC / ('vps-deploy-' + app)
    drain = LIBEXEC / ('vps-deploy-drain-' + app)
    sudo = Path('/etc/sudoers.d') / ('vps-deploy-' + app)
    originals = {}
    backup_dir = state / 'install-backups'
    def backup(path):
        original = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) if optional_trusted(path) else None
        originals[path] = original
        token = hashlib.sha256(str(path).encode()).hexdigest()
        if original is not None:
            atomic(snapshot / token, original[0], 0o600)
        atomic(snapshot / (token + '.json'), json.dumps({'path': str(path), 'mode': original[1] if original else None}).encode(), 0o600)
    def rollback():
        for path, content in originals.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                put(path, *content)
        sudo.with_suffix('.tmp').unlink(missing_ok=True)
        run('/usr/bin/systemctl', 'daemon-reload', check=False)

    for directory in (RELEASES.parent, RELEASES, CONFIG.parent, CONFIG, cfg, STATE.parent, STATE, state,
                      state / 'requests', LOCKS, LIBEXEC, Path('/etc/sudoers.d')):
        if directory.exists():
            trusted_path(directory, directory=True)
        else:
            directory.mkdir(mode=0o700)
    with acquire(LOCKS / 'install.lock'):
        with acquire(LOCKS / (app + '@submit.lock')):
            with contextlib.ExitStack() as stack:
                if app == '9router' and (LOCKS / '9router-submit.lock').exists():
                    stack.enter_context(acquire(LOCKS / '9router-submit.lock'))
                busy(app, state)
                timers = []
                try:
                    timers.append(stop_drain(app))
                    if app == '9router':
                        timers.append(stop_drain(app, old=True))
                    stack.enter_context(acquire(LOCKS / (app + '@operation.lock')))
                    if app == '9router' and (LOCKS / '9router.lock').exists():
                        stack.enter_context(acquire(LOCKS / '9router.lock'))
                    busy(app, state)
                    backup_dir.mkdir(mode=0o700, exist_ok=True)
                    trusted_path(backup_dir, directory=True)
                    snapshot = Path(tempfile.mkdtemp(prefix='activation-', dir=backup_dir))
                    os.chmod(snapshot, 0o700)
                    release_copy(root, destination, expected)
                    # Shared unit templates may not be overwritten by a later enrollment.
                    for name in ('vps-deploy-drain@.service', 'vps-deploy-drain@.timer'):
                        target = SYSTEMD / name
                        content = (destination / 'install' / name).read_bytes()
                        if optional_trusted(target):
                            require(target.read_bytes() == content and stat.S_IMODE(target.stat().st_mode) == 0o644, 'SHARED_UNIT_MISMATCH')
                        else:
                            put(target, content, 0o644)
                    key_file = Path('/home') / ('deploy-' + app) / '.ssh/authorized_keys'
                    old_units = (SYSTEMD / 'vps-deploy-9router-drain.service', SYSTEMD / 'vps-deploy-9router-drain.timer') if app == '9router' else ()
                    for path in (cfg / 'host.json', cfg / 'app.yml', cfg / 'runtime.env', wrapper, drain, sudo, key_file, *old_units):
                        backup(path)
                    if originals[cfg / 'runtime.env'] is None:
                        put(cfg / 'runtime.env', source_env.read_bytes(), 0o600)
                    put(cfg / 'app.yml', raw, 0o600)
                    put(cfg / 'host.json', profile_data(app, args.release, binding, host_record, previous), 0o600)
                    for target, action in ((wrapper, 'submit'), (drain, 'cleanup-drains')):
                        content = (destination / 'install/vps-deploy-app').read_text()
                        content = content.replace('@APP@', app).replace('@RELEASE@', args.release).replace('@ACTION@', action)
                        put(target, content.encode(), 0o755)
                    sudo_text = f'deploy-{app} ALL=(root) NOPASSWD: {wrapper} ""\n'.encode()
                    temporary = sudo.with_suffix('.tmp')
                    put(temporary, sudo_text, 0o440)
                    require(run('/usr/sbin/visudo', '-cf', str(temporary), check=False).returncode == 0, 'INVALID_SUDOERS')
                    os.replace(temporary, sudo)
                    run('/usr/bin/systemctl', 'daemon-reload')
                    if (state / 'state.json').exists():
                        run(str(destination / 'bin/deployctl'), 'status', '--app', app, '--strict')
                    run('/usr/bin/bash', str(destination / 'install/install-key.sh'), '--app', app, str(args.public_key))
                    was_enabled = any(enabled for _, enabled, _ in timers)
                    run('/usr/bin/systemctl', 'enable' if was_enabled else 'disable', 'vps-deploy-drain@' + app + '.timer')
                    if app == '9router':
                        run('/usr/bin/systemctl', 'disable', 'vps-deploy-9router-drain.timer', check=False)
                    if any(running for _, _, running in timers):
                        run('/usr/bin/systemctl', 'start', 'vps-deploy-drain@' + app + '.timer')
                    for old_unit in old_units:
                        old_unit.unlink(missing_ok=True)
                    if old_units:
                        run('/usr/bin/systemctl', 'daemon-reload')
                except Exception:
                    rollback()
                    restore_timers(timers)
                    raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--app', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--app-source', required=True, type=Path)
    parser.add_argument('--app-ref', required=True)
    parser.add_argument('--public-key', required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.uname().sysname == 'Linux', 'ROOT_REQUIRED')
    registration_id(args.app)
    registration_id(args.host)
    require(SHA.fullmatch(args.release) and SHA.fullmatch(args.app_ref), 'INVALID_SHA')
    require(args.app_source.is_absolute() and args.app_source.is_dir() and not args.app_source.is_symlink(), 'INVALID_APP_REF')
    require(not Path('/etc/vps-deploy/fixture-ci').exists() or args.fixture, 'FIXTURE_INSTALL_FORBIDDEN')
    require(not args.fixture or fixture_authorized() and args.host == 'fixture-local', 'FIXTURE_NOT_AUTHORIZED')
    root = Path(__file__).resolve().parents[1]
    expected = tree(root)
    require(args.fixture or git(root, 'rev-parse', 'HEAD').decode() == args.release and not git(root, 'status', '--porcelain', '--untracked-files=all'), 'RELEASE_NOT_REVIEWED')
    require(git(args.app_source, 'cat-file', '-t', args.app_ref) == b'commit', 'INVALID_APP_REF')
    registration = app_registration(root, args.app)
    host_record = host_registration(root, args.host)
    require(registration['host'] == args.host and args.app in host_record['apps'], 'APP_BINDING_MISMATCH')
    valid_key(args.public_key)
    manifest_path = registration['caller']['config']
    # Keep commit bytes: manifest SHA must not hash a normalized YAML representation.
    raw = run('/usr/bin/git', '-C', str(args.app_source), 'show', args.app_ref + ':' + manifest_path).stdout
    manifest(raw, registration)
    cfg = CONFIG / args.app
    profile_path = cfg / 'host.json'
    previous = json.loads(profile_path.read_bytes()) if optional_trusted(profile_path) else None
    binding = host_record['apps'][args.app]
    if previous:
        require(type(previous) is dict and type(previous.get('platform_ref')) is str and SHA.fullmatch(previous['platform_ref']), 'HOST_POLICY')
        installed = RELEASES / previous['platform_ref']
        trusted_path(installed, directory=True)
        if (installed / 'registry').exists():
            old_registration = app_registration(installed, args.app)
            old_host = host_registration(installed, old_registration['host'])
            host(cfg, old_registration, old_host)
        else:
            require(args.app == '9router' and (installed / 'bin/deployctl').is_file(), 'APP_NOT_REGISTERED')
            for name in ('api_host', 'dashboard_host', 'dashboard_alias_host', 'work_dir', 'compose_project', 'edge_network', 'rtk_network', 'route_name', 'dynamic_dir'):
                expected_value = host_record['traefik']['dynamic_dir'] if name == 'dynamic_dir' else binding[name]
                require(previous.get(name) == expected_value, 'APP_BINDING_MISMATCH')
    enrolled_collisions(args.app, binding, host_record)
    source_env = cfg / 'runtime.env' if optional_trusted(cfg / 'runtime.env') else Path(binding['work_dir']) / '.env'
    if source_env == cfg / 'runtime.env':
        require(optional_trusted(source_env), 'MISSING_RUNTIME_ENV')
    else:
        require(source_env.is_file() and not source_env.is_symlink() and source_env.parent.is_dir() and not source_env.parent.is_symlink(), 'MISSING_RUNTIME_ENV')
        trusted_path(source_env.parent.parent, directory=True)
        require(source_env.stat().st_uid in (0, source_env.parent.stat().st_uid) and not source_env.parent.stat().st_mode & 0o022, 'UNSAFE_RUNTIME_ENV')
    require(stat.S_IMODE(source_env.stat().st_mode) == 0o600, 'UNSAFE_RUNTIME_ENV')
    composed = preflight(root, args.app, registration, binding, source_env, previous)
    selected_volumes = {mount['source'] for service in composed['services'].values() for mount in service.get('volumes', []) if mount.get('type') == 'volume'}
    from core import container
    for enrolled in CONFIG.iterdir() if CONFIG.exists() else ():
        if enrolled.name == args.app or not (enrolled / 'host.json').is_file():
            continue
        for slot in ('blue', 'green'):
            try:
                value = container(enrolled.name + '-' + slot)
            except Failure as exc:
                if exc.code == 'COMMAND_FAILED':
                    continue
                raise
            require(not selected_volumes & {mount.get('Name') for mount in value['Mounts'] if mount.get('Type') == 'volume'}, 'RESOURCE_COLLISION')
    import route
    selected_profile = json.loads(profile_data(args.app, args.release, binding, host_record, previous))
    selected_profile.update(app=args.app, registration=registration, host_registration=host_record)
    route.preflight(Path(selected_profile['dynamic_dir']), selected_profile)
    for name in ('vps-deploy-drain@.service', 'vps-deploy-drain@.timer'):
        unit_file = SYSTEMD / name
        if optional_trusted(unit_file):
            require(unit_file.read_bytes() == (root / 'install' / name).read_bytes() and stat.S_IMODE(unit_file.stat().st_mode) == 0o644, 'SHARED_UNIT_MISMATCH')
    installed_release = RELEASES / args.release
    if installed_release.exists() or installed_release.is_symlink():
        require(installed_release.is_dir() and not installed_release.is_symlink() and tree(installed_release) == expected, 'RELEASE_MODIFIED')
    if args.check:
        print('CHECK_OK')
        return
    activation(args, root, raw, binding, host_record, previous, source_env, expected)
    print('INSTALLED', args.app, args.release)


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError, TypeError, KeyError, IndexError, subprocess.TimeoutExpired) as exc:
        print(exc.code if isinstance(exc, Failure) else 'INSTALL_IO_ERROR', file=sys.stderr)
        sys.exit(1)
