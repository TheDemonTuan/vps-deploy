#!/usr/bin/python3
"""Stdin-only, root-only activation of an already enrolled OpenDesign platform."""
import base64
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

sys.dont_write_bytecode = True
BASE = Path('/opt/vps-deploy')
CONFIG = Path('/etc/vps-deploy/apps/opendesign')
STATE = Path('/var/lib/vps-deploy/apps/opendesign')
AUTHORIZED = Path('/home/deploy-opendesign/.ssh/authorized_keys')
SHA = re.compile(r'[0-9a-f]{40}\Z')


class Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Failure(code)


def secure_path(path, directory=False):
    # The entry arrives over stdin, before any reviewed module can be imported.
    for entry in (*reversed(path.parents), path):
        value = entry.lstat()
        require(value.st_uid == 0 and not value.st_mode & 0o022 and
                (stat.S_ISDIR(value.st_mode) if entry != path or directory else stat.S_ISREG(value.st_mode)), 'UNTRUSTED_PATH')
    return path


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=kwargs.pop('timeout', 30), **kwargs)


def checked(argv, code, **kwargs):
    value = run(argv, **kwargs)
    require(value.returncode == 0, code)
    return value.stdout


def enrolled():
    require(CONFIG.is_dir() and STATE.is_dir() and (CONFIG / 'host.json').is_file() and
            (STATE / 'state.json').is_file(), 'NOT_ENROLLED')
    secure_path(CONFIG, directory=True)
    secure_path(STATE, directory=True)
    profile = json.loads(secure_path(CONFIG / 'host.json').read_bytes())
    state = json.loads(secure_path(STATE / 'state.json').read_bytes())
    require(type(profile) is dict and type(profile.get('platform_ref')) is str and SHA.fullmatch(profile['platform_ref']), 'INVALID_PROFILE')
    require(not profile.get('fixture_ci') and not Path('/etc/vps-deploy/fixture-ci').exists(), 'FIXTURE_INSTALL_FORBIDDEN')
    require(type(state) is dict and 'operation' in state and 'active' in state, 'INVALID_STATE')
    require(state.get('operation') is None and state.get('active') is not None, 'INSTALL_BUSY')
    requests = STATE / 'requests'
    secure_path(requests, directory=True)
    for entry in requests.iterdir():
        secure_path(entry, directory=True)
        receipt = entry / 'result.json'
        require(receipt.is_file(), 'INSTALL_BUSY')
        require(json.loads(secure_path(receipt).read_bytes()).get('status') in ('complete', 'failed'), 'INSTALL_BUSY')
    return profile


def checkout(destination, repository, ref):
    checked(['/usr/bin/git', 'init', '--quiet', str(destination)], 'FETCH_FAILED')
    checked(['/usr/bin/git', '-C', str(destination), 'fetch', '--quiet', '--no-tags', '--depth=1',
             'https://github.com/' + repository + '.git', ref], 'FETCH_FAILED', timeout=180)
    checked(['/usr/bin/git', '-C', str(destination), 'checkout', '--quiet', '--detach', ref], 'FETCH_FAILED')
    head = checked(['/usr/bin/git', '-C', str(destination), 'rev-parse', 'HEAD'], 'FETCH_FAILED')
    dirty = checked(['/usr/bin/git', '-C', str(destination), 'status', '--porcelain', '--untracked-files=all'], 'FETCH_FAILED')
    require(head.strip().decode() == ref and not dirty, 'CHECKOUT_NOT_REVIEWED')


def key_identity(raw):
    require(raw.endswith(b'\n') and len(raw.splitlines()) == 1 and
            re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\n', raw), 'INVALID_PUBLIC_KEY')
    return b' '.join(raw.splitlines()[0].split(b' ', 2)[:2])


def enrolled_key(raw, path):
    identity = key_identity(raw)
    path.write_bytes(raw)
    path.chmod(0o600)
    require(run(['/usr/bin/ssh-keygen', '-lf', str(path)]).returncode == 0, 'INVALID_PUBLIC_KEY')
    actual = secure_path(AUTHORIZED).read_bytes()
    expected = b'restrict,command="sudo -n /usr/local/libexec/vps-deploy-opendesign" ' + identity + b'\n'
    require(actual == expected, 'DEPLOY_KEY_MISMATCH')


def validate_checkout(platform, app, app_ref):
    sys.path.insert(0, str(platform / 'lib'))
    from core import app_registration, host_registration, manifest
    registration = app_registration(platform, 'opendesign')
    host_record = host_registration(platform, 'oracle-main')
    require(registration['host'] == 'oracle-main' and registration['caller']['repository'] == 'TheDemonTuan/open-design' and
            registration['caller']['ref'] == 'refs/heads/main' and 'opendesign' in host_record['apps'], 'APP_BINDING_MISMATCH')
    raw = checked(['/usr/bin/git', '-C', str(app), 'show', app_ref + ':' + registration['caller']['config']], 'INVALID_MANIFEST')
    manifest(raw, registration)
    return registration, host_record


def container_snapshot(value):
    require(value['State']['Running'] is True and not value['State'].get('Paused') and
            not value['State'].get('Restarting') and not value['State'].get('Dead'), 'CONTAINER_UNHEALTHY')
    require(not any(value.get('HostConfig', {}).get('PortBindings', {}).values()) and
            not any((value['NetworkSettings'].get('Ports') or {}).values()), 'PUBLISHED_PORTS')
    env = {}
    for item in value['Config']['Env']:
        key, separator, content = item.partition('=')
        require(separator and key not in env, 'INVALID_CONTAINER_ENV')
        env[key] = content
    require(env.get('OD_DISABLE_API_AUTH') == '1' and bool(env.get('OD_ALLOWED_ORIGINS')), 'API_AUTH_POLICY')
    state = value['State']
    return {'id': value['Id'], 'image': value['Image'],
            'state': {key: state.get(key) for key in ('Status', 'Running', 'Paused', 'Restarting', 'Dead', 'ExitCode')},
            'health': state.get('Health', {}).get('Status')}


def snapshot(profile, registration, host_record):
    require(all(profile.get(key) == content for key, content in host_record['apps']['opendesign'].items()) and
            profile.get('dynamic_dir') == host_record['traefik']['dynamic_dir'], 'APP_BINDING_MISMATCH')
    runtime = secure_path(CONFIG / 'runtime.env')
    meta = runtime.stat()
    require(meta.st_uid == 0 and meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o600, 'UNSAFE_RUNTIME_ENV')
    from operations import environment
    # Existing parser checks duplicate/disallowed variables without printing values.
    env = environment({'registration': registration, 'app': 'opendesign', **profile,
                       'rtk_image_repository': None}, CONFIG, '')
    require(env.get('OD_DISABLE_API_AUTH') == '1' and bool(env.get('OD_ALLOWED_ORIGINS')), 'API_AUTH_POLICY')
    route = Path(profile['dynamic_dir']) / profile['route_name']
    raw = checked(['/usr/bin/docker', 'container', 'inspect', 'opendesign-single'], 'CONTAINER_INSPECT_FAILED')
    values = json.loads(raw)
    require(type(values) is list and len(values) == 1, 'CONTAINER_INSPECT_FAILED')
    return {'platform_ref': profile['platform_ref'], 'container': container_snapshot(values[0]),
            'route': secure_path(route).read_bytes(),
            'runtime_env': (hashlib.sha256(runtime.read_bytes()).digest(), meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))}


def invariants(before, after, platform_ref):
    require(after['platform_ref'] == platform_ref, 'PROFILE_NOT_ACTIVATED')
    require(after['container'] == before['container'], 'CONTAINER_CHANGED')
    require(after['route'] == before['route'], 'ROUTE_CHANGED')
    require(after['runtime_env'] == before['runtime_env'], 'RUNTIME_ENV_CHANGED')


def installer(platform, app, platform_ref, app_ref, key, check):
    argv = ['/usr/bin/bash', str(platform / 'install/install.sh')]
    if check:
        argv.append('--check')
    argv += ['--app', 'opendesign', '--host', 'oracle-main', '--release', platform_ref,
             '--app-source', str(app), '--app-ref', app_ref, '--public-key', str(key)]
    value = run(argv, timeout=300)
    if value.returncode:
        # Installer's terminal error is a code; never forward arbitrary stderr.
        lines = value.stderr.decode(errors='replace').splitlines()
        code = lines[-1] if lines and re.fullmatch(r'[A-Z_]{1,64}', lines[-1]) else 'INSTALLER_FAILED'
        raise Failure(code)
    marker = 'CHECK_OK' if check else 'INSTALLED opendesign ' + platform_ref
    require(marker in value.stdout.decode().splitlines(), 'INSTALLER_PROOF_MISSING')


def strict_status(platform_ref):
    value = checked([str(BASE / 'releases' / platform_ref / 'bin/deployctl'), 'status',
                     '--app', 'opendesign', '--strict'], 'STRICT_STATUS_FAILED', timeout=60)
    require(json.loads(value).get('healthy') is True, 'STRICT_STATUS_FAILED')


def activate(platform_ref, app_ref, public_key):
    stage = 'preflight'
    staging = None
    try:
        require(os.geteuid() == 0 and os.uname().sysname == 'Linux', 'ROOT_REQUIRED')
        require(type(platform_ref) is str and SHA.fullmatch(platform_ref) and
                type(app_ref) is str and SHA.fullmatch(app_ref), 'INVALID_SHA')
        profile = enrolled()
        secure_path(BASE, directory=True)
        staging = Path(tempfile.mkdtemp(prefix='.reviewed-activation-', dir=BASE))
        staging.chmod(0o700)
        key = staging / 'deploy.pub'
        enrolled_key(public_key, key)
        stage = 'fetch'
        platform, app = staging / 'platform', staging / 'app'
        checkout(platform, 'TheDemonTuan/vps-deploy', platform_ref)
        checkout(app, 'TheDemonTuan/open-design', app_ref)
        stage = 'validation'
        registration, host_record = validate_checkout(platform, app, app_ref)
        before = snapshot(profile, registration, host_record)
        stage = 'installer_check'
        installer(platform, app, platform_ref, app_ref, key, True)
        # Recheck enrollment and snapshots after the potentially slow preflight.
        current = snapshot(enrolled(), registration, host_record)
        invariants(before, current, before['platform_ref'])
        stage = 'installer_apply'
        installer(platform, app, platform_ref, app_ref, key, False)
        stage = 'postcheck'
        strict_status(platform_ref)
        after = snapshot(enrolled(), registration, host_record)
        invariants(before, after, platform_ref)
        return {'app': 'opendesign', 'host': 'oracle-main', 'platform_ref': platform_ref, 'app_ref': app_ref,
                'previous_platform_ref': before['platform_ref'], 'healthy': True,
                'container_unchanged': True, 'runtime_env_unchanged': True}
    except Exception as exc:
        code = getattr(exc, 'code', 'ACTIVATION_IO_ERROR')
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z_]{1,64}', code):
            code = 'ACTIVATION_IO_ERROR'
        raise Failure(stage + ':' + code) from None
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 3, 'INVALID_ARGUMENTS')
        raw = base64.b64decode(argv[2], validate=True)
        receipt = activate(argv[0], argv[1], raw)
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else 'ACTIVATION_IO_ERROR'
        stage, separator, error = code.partition(':')
        if not separator:
            stage, error = 'preflight', code
        print(json.dumps({'stage': stage, 'error_code': error}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
