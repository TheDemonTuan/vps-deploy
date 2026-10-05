#!/usr/bin/python3
"""Operator-only initial bootstrap for recreate-strategy singleton applications."""
import argparse
import json
import os
import sys
import uuid
import stat
import subprocess
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import (
    Failure,
    SHA,
    app_registration,
    atomic,
    command,
    container,
    container_digest,
    digest,
    docker,
    host,
    host_registration,
    image_id,
    inspect,
    lock,
    paths,
    require,
    save,
    trusted_path,
)
from operations import environment, compose
import route
from recreate import get_volume_mountpoint, verify_no_writers, internal_call

CONFIG = Path('/etc/vps-deploy/apps')
STATE = Path('/var/lib/vps-deploy/apps')
LOCKS = Path('/run/lock/vps-deploy')

def main():
    parser = argparse.ArgumentParser(description="Bootstrap recreate-strategy application")
    parser.add_argument('--check', action='store_true', help="Read-only validation")
    parser.add_argument('--app', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--release', required=True)
    parser.add_argument('--app-source', required=True)
    parser.add_argument('--app-ref', required=True)
    parser.add_argument('--image', required=True)

    args = parser.parse_args()
    require(os.geteuid() == 0, 'ROOT_REQUIRED')

    require(type(args.release) is str and SHA.fullmatch(args.release), 'INVALID_RELEASE_SHA')
    require(type(args.app_ref) is str and SHA.fullmatch(args.app_ref), 'INVALID_APP_REF')

    root = Path(__file__).resolve().parents[1]
    registration = app_registration(root, args.app)
    manifest = registration['manifest']
    require(manifest['strategy'] == 'recreate', 'STRATEGY_MISMATCH')
    require(args.image.startswith(manifest['image'] + '@sha256:'), 'IMAGE_MISMATCH')

    host_record = host_registration(root, args.host)
    require(args.app in host_record['apps'], 'APP_NOT_ON_HOST')
    binding = host_record['apps'][args.app]

    cfg = CONFIG / args.app
    state_dir = STATE / args.app

    # Verify app is not already adopted
    if (state_dir / 'state.json').exists():
        raise Failure('ALREADY_ENROLLED')

    source_env = cfg / 'runtime.env' if (cfg / 'runtime.env').exists() else Path(binding['work_dir']) / '.env'
    require(source_env.is_file() and not source_env.is_symlink(), 'MISSING_RUNTIME_ENV')
    require(stat.S_IMODE(source_env.stat().st_mode) == 0o600, 'UNSAFE_RUNTIME_ENV')

    # Verify target image exists and matches architecture
    image_id(args.image)

    # Ingress inventory record check
    ingress_record = root / 'hosts' / args.host / f"{args.app}-ingress.yml"
    require(ingress_record.is_file() and not ingress_record.is_symlink(), 'INGRESS_CONFIG_MISSING')

    if args.check:
        print('CHECK_OK')
        return 0

    profile = host(cfg, registration, host_record)
    profile['platform_ref'] = args.release

    cname = args.app + '-single'
    vol_name = args.app + '-data'
    edge_net = binding['edge_network']

    for d in (CONFIG, cfg, STATE, state_dir, state_dir / 'requests', state_dir / 'backups', LOCKS):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)

    with lock(LOCKS / 'install.lock', 30), \
         lock(LOCKS / f"{args.app}@submit.lock", 30), \
         lock(LOCKS / f"{args.app}@operation.lock", 30), \
         lock(LOCKS / 'traefik.lock', 60):

        # 1. Create named volume if absent, set ownership 1001:1001
        try:
            inspect('volume', vol_name)
        except Failure:
            docker('volume', 'create', vol_name)
        mountpoint = get_volume_mountpoint(vol_name)
        os.chown(mountpoint, 1001, 1001)

        # 2. Create internal bridge network if absent
        try:
            inspect('network', edge_net)
        except Failure:
            docker('network', 'create', '--internal', edge_net)

        # 3. Connect Traefik container to edge network if not connected
        traefik_container = host_record['traefik']['container']
        net_containers = docker('network', 'inspect', edge_net, '--format', '{{range .Containers}}{{println .Name}}{{end}}').splitlines()
        if traefik_container not in net_containers:
            docker('network', 'connect', edge_net, traefik_container)

        # 4. Start singleton container via compose
        compose(root, profile, cfg, args.image, 'single', False, 'up', '-d', '--no-deps', '--pull', 'never', cname)

        # Wait for direct health
        c_info = container(cname, args.image, running=True)
        require(edge_net in c_info['NetworkSettings']['Networks'], 'EDGE_NETWORK')

        # 5. Create first route file
        generation = uuid.uuid4().hex
        route_bytes = route.render(profile, 'single', generation, release_root=root)
        route_path = Path(profile['dynamic_dir']) / profile['route_name']
        require(not route_path.exists(), 'ROUTE_ALREADY_EXISTS')
        atomic(route_path, route_bytes, mode=0o644)

        # 6. Verify local Traefik ACK
        route.ack(profile, ('single', generation))

    print('BOOTSTRAP_OK')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, TypeError, KeyError) as exc:
        code = exc.code if isinstance(exc, Failure) else 'BOOTSTRAP_FAILED'
        print(code, file=sys.stderr)
        sys.exit(1)
