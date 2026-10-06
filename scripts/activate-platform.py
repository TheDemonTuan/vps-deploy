#!/usr/bin/env python3
"""Validate reviewed commits, then perform one non-retrying admin activation."""
import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import Failure, SHA, app_registration, host_registration, manifest, require

PLATFORM_REPOSITORY = 'TheDemonTuan/vps-deploy'
APP_REPOSITORY = 'TheDemonTuan/open-design'
RECEIPT_FIELDS = {'app', 'host', 'platform_ref', 'app_ref', 'previous_platform_ref',
                  'healthy', 'container_unchanged', 'runtime_env_unchanged'}


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=kwargs.pop('timeout', 30), **kwargs)


def github(path):
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def validate_sha(value):
    require(type(value) is str and SHA.fullmatch(value), 'INVALID_SHA')


def main_membership(repository, sha):
    result = github('repos/' + repository + '/compare/' + sha + '...main')
    require(result.get('status') in ('ahead', 'identical') and
            result.get('merge_base_commit', {}).get('sha') == sha, 'COMMIT_NOT_ON_MAIN')


def latest_ci(sha):
    # Do not filter status/event: a newer queued or failed main run must veto an older success.
    query = urllib.parse.urlencode({'head_sha': sha, 'branch': 'main', 'per_page': 100})
    runs = []
    page = 1
    while True:
        answer = github('repos/' + PLATFORM_REPOSITORY + '/actions/workflows/ci.yml/runs?' + query + '&page=' + str(page))
        batch = answer['workflow_runs']
        require(type(batch) is list, 'CI_INVALID')
        runs.extend(item for item in batch if item.get('head_sha') == sha and
                    item.get('head_branch') == 'main' and item.get('event') in ('push', 'workflow_dispatch') and
                    item.get('path') == '.github/workflows/ci.yml')
        if len(batch) < 100:
            break
        page += 1
    require(runs, 'CI_MISSING')
    newest = max(runs, key=lambda item: (item['id'], item.get('run_attempt', 1)))
    require(newest.get('status') == 'completed' and newest.get('conclusion') == 'success', 'CI_NOT_SUCCESSFUL')


def check_inputs(platform_ref, app_ref):
    validate_sha(platform_ref)
    validate_sha(app_ref)
    head = run(['/usr/bin/git', '-C', str(ROOT), 'rev-parse', 'HEAD'])
    clean = run(['/usr/bin/git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all'])
    require(head.returncode == 0 and head.stdout.strip().decode() == platform_ref and
            clean.returncode == 0 and not clean.stdout, 'CHECKOUT_NOT_REVIEWED')
    main_membership(PLATFORM_REPOSITORY, platform_ref)
    main_membership(APP_REPOSITORY, app_ref)
    latest_ci(platform_ref)
    registration = app_registration(ROOT, 'opendesign')
    host_record = host_registration(ROOT, 'oracle-main')
    require(registration['host'] == 'oracle-main' and 'opendesign' in host_record['apps'] and
            registration['caller']['repository'] == APP_REPOSITORY and
            registration['caller']['ref'] == 'refs/heads/main', 'APP_BINDING_MISMATCH')
    config = registration['caller']['config']
    content = github('repos/' + APP_REPOSITORY + '/contents/' + config + '?ref=' + app_ref)
    require(content.get('encoding') == 'base64' and content.get('type') == 'file', 'INVALID_MANIFEST')
    raw = base64.b64decode(content['content'].replace('\n', ''), validate=True)
    manifest(raw, registration)
    return host_record


def public_key(path):
    require(path.is_file() and not path.is_symlink(), 'INVALID_PUBLIC_KEY')
    raw = path.read_bytes()
    require(raw.endswith(b'\n') and len(raw.splitlines()) == 1 and
            re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\n', raw), 'INVALID_PUBLIC_KEY')
    require(run(['/usr/bin/ssh-keygen', '-lf', str(path)]).returncode == 0, 'INVALID_PUBLIC_KEY')
    return raw


def host_key(identity):
    address = identity.get('address', '')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', address), 'INVALID_HOST')
    raw = identity.get('host_key')
    if not raw:
        scan = run(['/usr/bin/ssh-keyscan', '-p', str(identity['port']), '-t', 'ed25519', address], timeout=15)
        lines = [line.split() for line in scan.stdout.decode().splitlines() if line and not line.startswith('#')]
        require(scan.returncode == 0 and len(lines) == 1 and len(lines[0]) == 3, 'HOST_KEY_SCAN_FAILED')
        raw = ' '.join(lines[0][1:])
    parts = raw.split()
    require(len(parts) == 2 and parts[0] == 'ssh-ed25519', 'HOST_KEY_INVALID')
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(parts[1], validate=True)).digest()).decode().rstrip('=')
    require(fingerprint == identity['fingerprint'], 'HOST_KEY_MISMATCH')
    return raw


def validate_receipt(value, platform_ref, app_ref):
    require(type(value) is dict and set(value) == RECEIPT_FIELDS and value['app'] == 'opendesign' and
            value['host'] == 'oracle-main' and value['platform_ref'] == platform_ref and value['app_ref'] == app_ref and
            type(value['previous_platform_ref']) is str and SHA.fullmatch(value['previous_platform_ref']) and
            all(value[field] is True for field in ('healthy', 'container_unchanged', 'runtime_env_unchanged')), 'INVALID_RECEIPT')
    return value


def activate(platform_ref, app_ref, admin_key, deploy_key, host_record):
    require(admin_key.is_file() and not admin_key.is_symlink() and
            stat.S_IMODE(admin_key.stat().st_mode) == 0o600, 'UNSAFE_ADMIN_KEY')
    encoded = base64.b64encode(public_key(deploy_key)).decode('ascii')
    identity = host_record['ssh']
    key = host_key(identity)
    with tempfile.TemporaryDirectory(prefix='platform-activation-') as temporary:
        known = Path(temporary) / 'known_hosts'
        address, port = identity['address'], identity['port']
        name = address if port == 22 else '[' + address + ']:' + str(port)
        known.write_text(name + ' ' + key + '\n', encoding='ascii')
        known.chmod(0o600)
        ssh = ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(admin_key), '-p', str(port),
               '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
               '-o', 'ClearAllForwardings=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known),
               '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4',
               '-T', 'opc@' + address,
               'sudo -n /usr/bin/python3 - ' + platform_ref + ' ' + app_ref + ' ' + encoded]
        answer = run(ssh, input=(ROOT / 'install/activate-reviewed-release.py').read_bytes(), timeout=960)
        if answer.returncode:
            # Only expose a bounded stage/code from our remote entry, never SSH stderr or env output.
            try:
                failure = json.loads(answer.stdout)
                stage, code = failure['stage'], failure['error_code']
                require(re.fullmatch(r'[a-z_]{1,40}', stage) and re.fullmatch(r'[A-Z_]{1,64}', code), 'REMOTE_FAILED')
            except (ValueError, KeyError, TypeError, Failure):
                raise Failure('SSH_ACTIVATION_FAILED') from None
            raise Failure(stage.upper() + ':' + code)
        return validate_receipt(json.loads(answer.stdout), platform_ref, app_ref)


def summary(stage, code):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a', encoding='utf-8') as stream:
            stream.write('\nPlatform activation: stage `' + stage + '`, code `' + code + '`.\n')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform-ref', required=True)
    parser.add_argument('--app-ref', required=True)
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--admin-key-file', type=Path)
    parser.add_argument('--public-key-file', type=Path)
    args = parser.parse_args(argv)
    stage = 'validation'
    try:
        require((args.check_inputs and args.admin_key_file is None and args.public_key_file is None) or
                (not args.check_inputs and args.admin_key_file is not None and args.public_key_file is not None), 'INVALID_ARGUMENTS')
        host_record = check_inputs(args.platform_ref, args.app_ref)
        if args.check_inputs:
            print(json.dumps({'platform_ref': args.platform_ref, 'app_ref': args.app_ref}, sort_keys=True))
            output = os.environ.get('GITHUB_OUTPUT')
            if output:
                with open(output, 'a', encoding='ascii') as stream:
                    stream.write('platform_ref=' + args.platform_ref + '\napp_ref=' + args.app_ref + '\n')
        else:
            stage = 'transport'
            value = activate(args.platform_ref, args.app_ref, args.admin_key_file, args.public_key_file, host_record)
            print(json.dumps(value, sort_keys=True))
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, Failure) else 'ACTIVATION_IO_ERROR'
        summary(stage, code)
        print(json.dumps({'stage': stage, 'error_code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
