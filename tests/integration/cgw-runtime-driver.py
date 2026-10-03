#!/usr/bin/python3
"""Real runtime/Docker lifecycle fixture. Called only by the guarded VM script."""
import argparse
import json
import os
import re
import stat
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'lib'))
import cgw
import core
import operations
from core import Failure, fixture_authorized, load, lock, require, save

def configure_loopback_fixture(directory):
    """Inject only fixture image identity; all lifecycle/HTTP code remains real."""
    if os.environ.get('CGW_CI_LOOPBACK') != '1':
        require(not os.environ.get('CGW_CI_REPOSITORY'), 'FIXTURE_REPOSITORY')
        return
    require(os.environ.get('CI') == 'true' and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and fixture_authorized(), 'FIXTURE_NOT_AUTHORIZED')
    marker = directory / 'loopback-fixture.json'
    require(not marker.is_symlink() and marker.is_file(), 'FIXTURE_NOT_AUTHORIZED')
    info = marker.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'FIXTURE_NOT_AUTHORIZED')
    repository = os.environ.get('CGW_CI_REPOSITORY', '')
    match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})/cgw-fixture/[0-9a-f]{40}', repository)
    require(match and 1024 <= int(match[1]) <= 65535, 'FIXTURE_REPOSITORY')
    require(load(marker) == {'repository': repository, 'disposable': True}, 'FIXTURE_REPOSITORY')
    original_image_id = core.image_id
    def native_image_id(ref):
        if not ref.startswith(repository + '@'):
            return original_image_id(ref)
        require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', ref), 'INVALID_IMAGE')
        value = core.inspect('image', ref)
        architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(os.uname().machine)
        require(value['Architecture'] == architecture and value['Os'] == 'linux' and
                ref in value.get('RepoDigests', []), 'IDENTITY_MISMATCH')
        return value['Id']
    original_anonymous = operations.anonymous_image
    def anonymous_fixture(ref):
        if ref.startswith(repository + '@'):
            require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', ref), 'INVALID_IMAGE')
            return  # No GHCR probe: compose still pulls the actual loopback OCI digest.
        return original_anonymous(ref)
    cgw.REPOSITORY = repository
    core.image_id = cgw.image_id = native_image_id
    operations.anonymous_image = anonymous_fixture


def assert_single_writer():
    ids = core.docker('ps', '-q', '--filter', 'volume=' + cgw.VOLUME).split()
    require(len(ids) <= 1, 'CGW_WRITER_ACTIVE')
    if ids:
        require(core.inspect('container', ids[0])['Name'] == '/' + cgw.NAME, 'CGW_WRITER_ACTIVE')


FENCE_PROBE = """const fs=require('node:fs');
const token=fs.readFileSync('/run/secrets/cgw-admin-token','utf8').trim();
const r=await fetch('http://127.0.0.1:17841/admin/profiles',{method:'POST',
headers:{authorization:'Bearer '+token,'content-type':'application/json'},
body:JSON.stringify({profileId:'must-not-be-created'}),signal:AbortSignal.timeout(8000)});
const v=await r.json();console.log(JSON.stringify({status:r.status,code:v.error?.code}));"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['adopt', 'deploy', 'reconcile', 'assert'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--operation-id', default='cgw-vm-upgrade')
    parser.add_argument('--crash-phase', default='')
    args = parser.parse_args()
    require(os.geteuid() == 0 and fixture_authorized(), 'FIXTURE_NOT_AUTHORIZED')
    configure_loopback_fixture(args.directory)
    cfg, state_dir = args.directory / 'config', args.directory / 'state'
    profile = dict(cgw_image_repository=cgw.REPOSITORY, cgw_network='9router-cgw')
    req = dict(component='cgw', request_id=args.operation_id, image=args.image)
    def interrupt(signum, frame):
        raise Failure('CGW_TERMINATED')
    signal.signal(signal.SIGTERM, interrupt)
    def fault(profile, phase):
        assert_single_writer()
        if phase == args.crash_phase:
            persisted = load(state_dir / 'state.json')['operation']
            require(persisted['phase'] == phase, 'CGW_INTENT_NOT_DURABLE')
            if phase in ('cgw_quiescing', 'cgw_quiesced', 'cgw_candidate', 'cgw_committed'):
                ref = persisted['image'] if phase in ('cgw_candidate', 'cgw_committed') else persisted['previous']
                fence = 'draining' if phase == 'cgw_quiescing' else 'quiesced'
                proof = cgw.diagnostics(profile, ref, persisted['operationId'], fence)
                require(proof['idle'], 'CGW_NOT_IDLE')
                # Exercise real server admission while fenced, not a fake readyz.
                response = core.docker('exec', cgw.NAME, 'bun', '-e', FENCE_PROBE)
                require(json.loads(response) == {'status': 503, 'code': 'runtime_draining'}, 'CGW_CANDIDATE_ADMITTED')
            if phase in ('cgw_stopped', 'cgw_snapshot_verified', 'cgw_switching'):
                cgw.writers_gone(cgw.Budget())
            if phase in ('cgw_snapshot_verified', 'cgw_switching', 'cgw_candidate', 'cgw_committed'):
                cgw.verified_snapshot(persisted, cgw.Budget())
            os.kill(os.getpid(), signal.SIGKILL)
    cgw.fault = fault
    with lock(args.directory / 'operation.lock'):
        if args.action == 'adopt':
            deadline = time.time() + 120
            while True:
                try:
                    proof = cgw.diagnostics(profile, args.image)
                    break
                except Failure:
                    require(time.time() < deadline, 'CGW_RUNTIME_BOOT')
                    time.sleep(2)
            require(proof.get('operationFence') is None, 'CGW_FENCE')
            sys.path.insert(0, str(ROOT / 'install'))
            from preflight import runtime_parity
            runtime_parity(ROOT, cfg, profile)
            state_dir.mkdir(mode=0o700, exist_ok=True)
            require(not (state_dir / 'state.json').exists(), 'ALREADY_ADOPTED')
            save(state_dir / 'state.json', dict(version=1, revision=1, operation=None, cgw=dict(current=args.image, previous=None)))
            # Nonempty private synthetic state must survive every snapshot/restore.
            core.docker('exec', cgw.NAME, 'bun', '-e', "await Bun.write('/data/cgw-fixture-state','private synthetic lifecycle state\\n')")
        else:
            state = load(state_dir / 'state.json')
            if args.action == 'deploy':
                cgw.deploy(req, state, state_dir, cfg, ROOT, profile)
            elif args.action == 'reconcile':
                cgw.reconcile(req, state, state_dir, cfg, ROOT, profile)
            else:
                require(state['operation'] is None and state['cgw']['current'] == args.image, 'CGW_STATE')
                proof = cgw.diagnostics(profile, args.image)
                require(proof['operationFence'] is None and proof['idle'], 'CGW_FENCE')
                assert_single_writer()
                private_state = core.docker('exec', cgw.NAME, 'bun', '-e', "process.stdout.write(await Bun.file('/data/cgw-fixture-state').text())")
                require(private_state == 'private synthetic lifecycle state\n', 'CGW_PRIVATE_STATE_LOST')
    print(json.dumps({'action': args.action, 'protocolVersion': 1, 'stateSchemaVersion': 1, 'liveFullHarness': False}))


if __name__ == '__main__':
    main()
