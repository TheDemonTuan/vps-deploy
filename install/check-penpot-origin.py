#!/usr/bin/python3
"""Read-only root origin proof for the central Cloudflare apply workflow."""
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

sys.dont_write_bytecode = True


def trusted(path, directory=False):
    for parent in [path, *path.parents]:
        value = parent.lstat()
        sticky_lock_parent = parent == Path('/run/lock') and value.st_mode & stat.S_ISVTX
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022 and not sticky_lock_parent:
            raise RuntimeError('UNTRUSTED_ORIGIN_PATH')
    if directory and not path.is_dir() or not directory and not path.is_file():
        raise RuntimeError('UNTRUSTED_ORIGIN_PATH')
    return path


def check(platform):
    if os.geteuid() != 0 or not re.fullmatch(r'[0-9a-f]{40}', platform):
        raise RuntimeError('ORIGIN_SCOPE_POLICY')
    release = trusted(Path('/opt/vps-deploy/releases') / platform, directory=True)
    sys.path.insert(0, str(trusted(release / 'lib', directory=True)))
    sys.path.insert(0, str(trusted(release / 'install', directory=True)))
    from core import inspect, load, lock, require
    controller = runpy.run_path(str(trusted(release / 'bin/deployctl')))
    bootstrap = runpy.run_path(str(trusted(release / 'install/bootstrap-penpot.py')))
    cfg = trusted(Path('/etc/vps-deploy/apps/penpot'), directory=True)
    state_dir = trusted(Path('/var/lib/vps-deploy/apps/penpot'), directory=True)
    locks = trusted(Path('/run/lock/vps-deploy'), directory=True)
    with lock(locks / 'penpot@operation.lock', 60), lock(locks / 'traefik.lock', 60):
        profile = controller['load_profile'](cfg, 'penpot')
        controller['ready_engine'](profile)
        state = load(trusted(state_dir / 'state.json'))
        import penpot
        penpot.matching(state, profile)
        bootstrap['edge_policy']()
        live = inspect('container', 'edge-cloudflared')
        require(live.get('State', {}).get('Running') is True, 'CLOUDFLARED_STOPPED')
        mounts = [item for item in live.get('Mounts', []) if item.get('Destination') in
                  ('/etc/cloudflare-origin-ca', '/etc/cloudflare-origin-ca/origin-ca.pem')]
        require(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and
                mounts[0].get('Source') == '/opt/platform/edge/cloudflare-ca' and
                mounts[0].get('Destination') == '/etc/cloudflare-origin-ca' and mounts[0].get('RW') is False,
                'CLOUDFLARED_ORIGIN_CA_POLICY')
        trusted(Path('/opt/platform/edge/cloudflare-ca'), directory=True)
        trusted(Path('/opt/platform/edge/cloudflare-ca/origin-ca.pem'))
        import penpot_edge
        penpot_edge.origin_ack(profile, state['active'], state['generation'])
        return dict(app='penpot', host='oracle-main', platformRef=platform,
                    sourceSha=state['active']['source_sha'], images=state['active']['images'],
                    generation=state['generation'], healthy=True, origin_tls_verified=True)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise RuntimeError('ORIGIN_SCOPE_POLICY')
        print(json.dumps(check(sys.argv[1]), sort_keys=True))
    except Exception:
        # Neither runtime secrets nor arbitrary subprocess/SSH stderr are receipts.
        print('PENPOT_ORIGIN_NOT_READY', file=sys.stderr)
        sys.exit(1)
