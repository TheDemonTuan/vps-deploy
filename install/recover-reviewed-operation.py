#!/usr/bin/python3
"""Recover only the fixed real transaction using reviewed logic and installed contracts."""
import base64
import importlib.machinery
import importlib.util
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
LOCKS = Path('/run/lock/vps-deploy')
REQUEST_ID = 'gh-37424292784-1-app'
SHA = re.compile(r'[0-9a-f]{40}\Z')


class Failure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Failure(code)


def secure_path(path, directory=False):
    # Trust bootstrap paths before importing any fetched code.
    for entry in (*reversed(path.parents), path):
        value = entry.lstat()
        require(value.st_uid == 0 and not value.st_mode & 0o022 and
                (stat.S_ISDIR(value.st_mode) if entry != path or directory else stat.S_ISREG(value.st_mode)),
                'UNTRUSTED_PATH')
    return path


def checkout(destination, repository, ref):
    commands = [(['/usr/bin/git', 'init', '--quiet', str(destination)], 30),
                (['/usr/bin/git', '-C', str(destination), 'fetch', '--quiet', '--no-tags', '--depth=1',
                  'https://github.com/' + repository + '.git', ref], 180),
                (['/usr/bin/git', '-C', str(destination), 'checkout', '--quiet', '--detach', ref], 30)]
    for argv, timeout in commands:
        require(subprocess.run(argv, capture_output=True, timeout=timeout).returncode == 0, 'FETCH_FAILED')
    head = subprocess.run(['/usr/bin/git', '-C', str(destination), 'rev-parse', 'HEAD'], capture_output=True, timeout=30)
    clean = subprocess.run(['/usr/bin/git', '-C', str(destination), 'status', '--porcelain', '--untracked-files=all'],
                           capture_output=True, timeout=30)
    require(head.returncode == clean.returncode == 0 and head.stdout.strip().decode() == ref and not clean.stdout,
            'CHECKOUT_NOT_REVIEWED')


def read_enrollment():
    secure_path(CONFIG, directory=True)
    secure_path(STATE, directory=True)
    profile = json.loads(secure_path(CONFIG / 'host.json').read_bytes())
    state = json.loads(secure_path(STATE / 'state.json').read_bytes())
    require(type(profile) is dict and type(profile.get('platform_ref')) is str and
            SHA.fullmatch(profile['platform_ref']), 'INVALID_PROFILE')
    require(not profile.get('fixture_ci') and not Path('/etc/vps-deploy/fixture-ci').exists(), 'FIXTURE_INSTALL_FORBIDDEN')
    pending(state)
    return profile


def pending(state, completing=False):
    require(type(state) is dict and state.get('version') == 1 and type(state.get('active')) is dict,
            'INVALID_STATE')
    intent = state.get('operation')
    require(type(intent) is dict and intent.get('request_id') == REQUEST_ID and
            intent.get('component') == 'app' and intent.get('target') == 'single' and
            state['active'].get('slot') == 'single' and intent.get('old_entry') == state['active'], 'UNEXPECTED_OPERATION')
    if completing:
        require(intent.get('phase') == 'recovery_required' and
                intent.get('error_code') == 'RECREATE_CANDIDATE_FAILED', 'UNEXPECTED_RECOVERY_PHASE')
    else:
        require(intent.get('phase') == 'candidate_started', 'UNEXPECTED_RECOVERY_PHASE')
    return intent


def request_contract(state, profile, core, deployctl):
    intent = pending(state)
    directory = STATE / 'requests' / REQUEST_ID
    core.trusted_path(directory, directory=True)
    req = core.request(core.trusted_path(directory / 'request.json').read_bytes(), profile)
    require(req['request_id'] == REQUEST_ID and req['op'] == 'deploy' and req['component'] == 'app' and
            req['image'] == intent['image'] and intent['target_entry']['image'] == req['image'], 'UNEXPECTED_REQUEST')
    release = core.verify_request(req, CONFIG, profile)
    snapshot = directory / 'route.snapshot'
    backup = STATE / 'backups' / REQUEST_ID / 'data.tar'
    require(intent.get('snapshot') == str(snapshot) and intent.get('data_snapshot') == str(backup), 'UNEXPECTED_SNAPSHOT')
    require(core.digest(core.trusted_path(snapshot).read_bytes()) == intent['old_hash'] and
            core.digest(core.trusted_path(backup).read_bytes()) == intent['data_checksum'] and
            state['generation'] == intent['old_generation'], 'SNAPSHOT_MISMATCH')
    requests = STATE / 'requests'
    core.trusted_path(requests, directory=True)
    for entry in requests.iterdir():
        core.trusted_path(entry, directory=True)
        require(not deployctl.unit_active('opendesign', entry.name), 'REQUEST_RUNNING')
        result = core.load(core.trusted_path(entry / 'result.json'))
        allowed = ('complete', 'failed', 'recovery_required') if entry.name == REQUEST_ID else ('complete', 'failed')
        require(result.get('status') in allowed, 'REQUEST_RUNNING')
    return req, release


def admission(recreate, profile, core, image, operation_id):
    core.container('opendesign-single', image, running=True)
    status, value = recreate.internal_call('opendesign-single', 'GET', '/api/deployment/status')
    require(status == 200 and value.get('accepting') is True and value.get('operationId') in (None, operation_id),
            'RESTORED_NOT_ACCEPTING')


def reconcile_fixed(state, req, release, profile, core, recreate):
    old_image = state['active']['image']
    pending(state)
    try:
        recreate.reconcile(req, state, STATE, CONFIG, release, profile, LOCKS)
    except Exception as exc:
        # A successful rollback has a deliberate intermediate recovery-required state.
        # This is one bounded continuation, never a retry after a transport/restore error.
        require(isinstance(exc, core.Failure) and exc.code == 'RECOVERY_REQUIRED',
                getattr(exc, 'code', 'RECONCILIATION_FAILED'))
        current = core.load(core.trusted_path(STATE / 'state.json'))
        pending(current, completing=True)
        require(current['active']['image'] == old_image, 'RESTORED_IMAGE_CHANGED')
        admission(recreate, profile, core, old_image, REQUEST_ID)
        recreate.reconcile(req, current, STATE, CONFIG, release, profile, LOCKS)
    current = core.load(core.trusted_path(STATE / 'state.json'))
    require(current.get('operation') is None and current['active']['image'] == old_image, 'RECOVERY_INCOMPLETE')
    admission(recreate, profile, core, old_image, REQUEST_ID)
    return old_image


def recover(platform_ref, app_ref, public_key):
    staging = None
    stage = 'preflight'
    try:
        require(os.geteuid() == 0 and os.uname().sysname == 'Linux', 'ROOT_REQUIRED')
        require(type(platform_ref) is str and SHA.fullmatch(platform_ref) and
                type(app_ref) is str and SHA.fullmatch(app_ref), 'INVALID_SHA')
        selected = read_enrollment()
        secure_path(BASE, directory=True)
        staging = Path(tempfile.mkdtemp(prefix='.reviewed-recovery-', dir=BASE))
        staging.chmod(0o700)
        stage = 'fetch'
        platform, app = staging / 'platform', staging / 'app'
        checkout(platform, 'TheDemonTuan/vps-deploy', platform_ref)
        checkout(app, 'TheDemonTuan/open-design', app_ref)
        spec = importlib.util.spec_from_file_location('reviewed_activation', platform / 'install/activate-reviewed-release.py')
        helpers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helpers)
        stage = 'validation'
        helpers.enrolled_key(public_key, staging / 'deploy.pub')
        registration, host_record = helpers.validate_checkout(platform, app, app_ref)
        import core
        import recreate
        # load_profile enforces the real installed path/registry/manifest/env contract.
        # Imported dependencies remain reviewed modules, while Compose uses installed release bytes.
        installed = BASE / 'releases' / selected['platform_ref']
        core.trusted_path(installed, directory=True)
        deployctl = importlib.machinery.SourceFileLoader('installed_deployctl',
                    str(core.trusted_path(installed / 'bin/deployctl'))).load_module()
        sys.path.insert(0, str(platform / 'lib'))
        core.trusted_path(LOCKS, directory=True)
        with core.lock(LOCKS / 'opendesign@submit.lock', 10):
            with core.lock(LOCKS / 'opendesign@operation.lock'):
                profile = deployctl.load_profile(CONFIG, 'opendesign')
                require(profile['platform_ref'] == selected['platform_ref'] and
                        profile['registration']['manifest']['strategy'] == 'recreate', 'PROFILE_CHANGED')
                state = core.load(core.trusted_path(STATE / 'state.json'))
                req, release = request_contract(state, profile, core, deployctl)
                before = helpers.snapshot(profile, registration, host_record)
                core.container('opendesign-single', state['active']['image'], running=True)
                require(core.digest(before['route']) == state['operation']['old_hash'], 'ROUTE_DRIFT')
                status, value = recreate.internal_call('opendesign-single', 'GET', '/api/deployment/status')
                require(status == 200 and value.get('operationId') == REQUEST_ID and
                        value.get('phase') == 'quiesced' and value.get('accepting') is False and
                        value.get('idle') is True, 'UNEXPECTED_DEPLOYMENT_FENCE')
                # recreate reconciliation restores route snapshots; serialize with all route writers.
                with core.lock(LOCKS / 'traefik.lock', 60):
                    require(helpers.snapshot(profile, registration, host_record) == before, 'RECOVERY_INVARIANT_CHANGED')
                    stage = 'reconciliation'
                    image = reconcile_fixed(state, req, release, profile, core, recreate)
                    stage = 'postcheck'
                    after = helpers.snapshot(profile, registration, host_record)
                    require(after['platform_ref'] == before['platform_ref'] and
                            after['route'] == before['route'] and after['runtime_env'] == before['runtime_env'],
                            'RECOVERY_INVARIANT_CHANGED')
                    require(core.load(CONFIG / 'host.json') == selected, 'PROFILE_CHANGED')
                    status = deployctl.state_status(STATE, None, CONFIG, profile)
                    require(status.get('healthy') is True and status.get('image') == image and
                            status.get('configured_generation') == status.get('observed_generation'), 'STRICT_STATUS_FAILED')
                    # Preserve original request semantics: its candidate failed; recovery succeeded.
                    core.save(STATE / 'requests' / REQUEST_ID / 'result.json',
                              deployctl.result(REQUEST_ID, 'failed', 'failed', 'RECREATE_CANDIDATE_FAILED'))
                return {'app': 'opendesign', 'host': 'oracle-main', 'platform_ref': platform_ref,
                        'app_ref': app_ref, 'request_id': REQUEST_ID, 'healthy': True, 'accepting': True,
                        'operation_cleared': True, 'restored_image': image}
    except Exception as exc:
        code = getattr(exc, 'code', 'RECOVERY_IO_ERROR')
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z_]{1,64}', code):
            code = 'RECOVERY_IO_ERROR'
        raise Failure(stage + ':' + code) from None
    finally:
        if staging is not None:
            shutil.rmtree(staging)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        require(len(argv) == 3, 'INVALID_ARGUMENTS')
        receipt = recover(argv[0], argv[1], base64.b64decode(argv[2], validate=True))
        print(json.dumps(receipt, sort_keys=True), flush=True)
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else 'RECOVERY_IO_ERROR'
        stage, separator, error = code.partition(':')
        if not separator:
            stage, error = 'preflight', code
        print(json.dumps({'stage': stage, 'error_code': error}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
