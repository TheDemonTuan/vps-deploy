#!/usr/bin/python3
"""Root-only source-free Penpot bootstrap, gated by engine runtime activation.

Failures retain owned volumes/secrets. A durable bootstrap record allows retries
only for the same source/platform/digest set; it is not an app restore command.
"""
import argparse
import os
from pathlib import Path
import runpy
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'install'))
from core import (Failure, SHA, app_registration, atomic, command, digest, docker,
                  fsync_dir, image_id, image_map, inspect, json_bytes, lock, manifest,
                  parse_json, parse_yaml, require, save, trusted_path)
import installer
import penpot
import penpot_edge
import penpot_preflight
import penpot_secrets
import route


def edge_policy():
    live = inspect('container', 'edge-traefik')
    require(live.get('State', {}).get('Running') is True, 'TRAEFIK_STOPPED')
    for source, destination in (('/opt/platform/edge/traefik.yml', '/etc/traefik/traefik.yml'),
                                ('/opt/platform/edge/dynamic', '/etc/traefik/dynamic'),
                                ('/opt/platform/edge/certs', '/certs')):
        mounts = [value for value in live.get('Mounts', []) if value.get('Destination') == destination]
        require(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and
                mounts[0].get('Source') == source and mounts[0].get('RW') is False, 'EDGE_ORIGIN_TLS_POLICY')
    static = parse_yaml(trusted_path(Path('/opt/platform/edge/traefik.yml')).read_bytes())
    query = static.get('accessLog', {}).get('fields', {}).get('queryParameters', {})
    require(query.get('defaultMode') == 'drop' and not any(value != 'drop' for value in query.get('names', {}).values()),
            'EDGE_QUERY_LOG_POLICY')
    tls = parse_yaml(trusted_path(Path('/opt/platform/edge/dynamic/00-tls-origin.yml')).read_bytes())
    certificates = tls.get('tls', {}).get('certificates')
    require(type(certificates) is list and certificates, 'EDGE_ORIGIN_TLS_POLICY')
    ca = trusted_path(Path('/opt/platform/edge/cloudflare-ca/origin-ca.pem'))
    valid = False
    for record in certificates:
        require(type(record) is dict and type(record.get('certFile')) is str, 'EDGE_ORIGIN_TLS_POLICY')
        path = Path(record['certFile'])
        require(path.parent == Path('/certs'), 'EDGE_ORIGIN_TLS_POLICY')
        source = trusted_path(Path('/opt/platform/edge/certs') / path.name)
        checked = installer.run('/usr/bin/openssl', 'verify', '-CAfile', str(ca),
                                '-verify_hostname', 'design.tuannguyenviet.site', str(source), check=False)
        expires = installer.run('/usr/bin/openssl', 'x509', '-in', str(source), '-noout', '-checkend', '86400', check=False)
        valid = valid or checked.returncode == expires.returncode == 0
    require(valid, 'EDGE_ORIGIN_TLS_POLICY')


def check(args):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(args.app == 'penpot' and args.host == 'oracle-main', 'PENPOT_BOOTSTRAP_SCOPE')
    require(SHA.fullmatch(args.release) and SHA.fullmatch(args.app_ref), 'INVALID_RELEASE_SHA')
    require(os.uname().machine == 'aarch64', 'ARM64_REQUIRED')
    root = trusted_path(ROOT, directory=True)
    require(installer.git(root, 'rev-parse', 'HEAD').decode() == args.release and
            not installer.git(root, 'status', '--porcelain', '--untracked-files=all'), 'PLATFORM_DIRTY')
    registration = app_registration(root, 'penpot')
    from core import host_registration
    host_record = host_registration(root, args.host)
    require('penpot' in host_record['apps'], 'APP_NOT_ON_HOST')
    binding = host_record['apps']['penpot']
    require(binding['work_dir'] == '/opt/penpot' and binding['edge_network'] == 'edge-penpot' and
            binding['compose_project'] == 'penpot' and binding['route_name'] == 'penpot.yml' and
            binding['api_host'] == 'design.tuannguyenviet.site', 'PENPOT_BOOTSTRAP_SCOPE')
    source = trusted_path(Path(args.app_source), directory=True)
    require(installer.git(source, 'rev-parse', 'HEAD').decode() == args.app_ref and
            not installer.git(source, 'status', '--porcelain', '--untracked-files=all'), 'APP_SOURCE_DIRTY')
    raw = installer.git(source, 'show', args.app_ref + ':.deploy/app.yml')
    manifest(raw, registration)
    installer.valid_key(trusted_path(Path(args.public_key)))
    images = image_map(parse_json(args.images), registration['manifest']['images'])
    cfg, state, locks = installer.CONFIG / 'penpot', installer.STATE / 'penpot', installer.LOCKS
    require(not os.path.lexists(state / 'state.json'), 'ALREADY_ENROLLED')
    profile = dict(binding, app='penpot', registration=registration, host_registration=host_record,
                   platform_ref=args.release, dynamic_dir=host_record['traefik']['dynamic_dir'],
                   architecture='arm64', image_repositories=registration['manifest']['images'])
    entry = dict(slot='single', images=images, source_sha=args.app_ref, platform_ref=args.release, manifest_sha256=digest(raw))
    for role, ref in images.items():
        penpot.anonymous_image(ref)
        image_id(ref)
        labels = inspect('image', ref).get('Config', {}).get('Labels') or {}
        require(labels.get('org.opencontainers.image.source') == 'https://github.com/TheDemonTuan/penpot' and
                labels.get('org.opencontainers.image.revision') == args.app_ref, 'PENPOT_IMAGE_REVISION')
    for ref in penpot.DATASTORE_IMAGES.values():
        image_id(ref)
    checkpoint = state / 'bootstrap.json'
    record = dict(version=1, sourceSha=args.app_ref, platformRef=args.release, images=images, generation=uuid.uuid4().hex)
    if os.path.lexists(checkpoint):
        old = parse_json(penpot.bounded_file(checkpoint))
        require(type(old) is dict and set(old) == set(record) and type(old.get('version')) is int and old['version'] == 1 and
                all(old[key] == record[key] for key in ('sourceSha', 'platformRef', 'images')) and
                type(old.get('generation')) is str and len(old['generation']) == 32 and
                all(char in '0123456789abcdef' for char in old['generation']), 'PENPOT_BOOTSTRAP_RESUME_MISMATCH')
        record = old
    shared = {}
    middlewares = set()
    directory = trusted_path(Path(profile['dynamic_dir']), directory=True)
    for path, content in route.route_files(directory).items():
        if path.name == profile['route_name']:
            continue
        shared[str(path)] = digest(content)
        require(b'design.tuannguyenviet.site' not in content, 'PENPOT_HOST_ROUTE_COLLISION')
        if path.suffix.lower() in ('.yaml', '.yml'):
            parsed = parse_yaml(content)
            http = parsed.get('http', {}) if type(parsed) is dict else {}
            middlewares.update(http.get('middlewares', {}))
            for category in ('routers', 'services', 'middlewares'):
                require(not any(name.startswith('penpot-') for name in http.get(category, {})), 'ROUTE_COLLISION')
    require(set(registration['route']['required_middlewares']) <= middlewares, 'MIDDLEWARE_MISSING')
    normal = route.render(profile, 'single', record['generation'], release_root=root)
    maintenance = penpot.maintenance_route(normal, profile)
    target = trusted_path(Path(profile['dynamic_dir']), directory=True) / profile['route_name']
    if os.path.lexists(target):
        require(checkpoint.exists() and route.checked_file(target, managed=True) in (normal, maintenance), 'ROUTE_ALREADY_EXISTS')
    runtime = None
    for path in (Path(binding['work_dir']) / '.env', cfg / 'runtime.env'):
        if os.path.lexists(path):
            values = penpot.runtime_values(penpot.bounded_file(path), registration)
            require(runtime is None or values == runtime, 'PENPOT_RUNTIME_MISMATCH')
            runtime = values
    edge_policy()
    edge = penpot_edge.check(Path('/opt/platform/edge/compose.yml'))
    names = set(docker('ps', '-a', '--format', '{{.Names}}').splitlines())
    for name in set(penpot.APP_SERVICES) | set(penpot.DATASTORE_IMAGES):
        if name in names:
            ref = images[name.removeprefix('penpot-')] if name in penpot.APP_SERVICES else penpot.DATASTORE_IMAGES[name]
            labels = penpot.container(name, ref).get('Config', {}).get('Labels') or {}
            require(checkpoint.exists() and labels.get('com.docker.compose.project') == 'penpot' and
                    labels.get('com.docker.compose.service') == name and labels.get('vps-deploy.app') == 'penpot',
                    'PENPOT_BOOTSTRAP_CONTAINER_COLLISION')
    volumes = set(docker('volume', 'ls', '--format', '{{.Name}}').splitlines())
    for name in penpot.VOLUMES.values():
        if name in volumes:
            value = inspect('volume', name)
            require(value.get('Driver') == 'local' and not value.get('Options') and
                    (value.get('Labels') or {}).get('vps-deploy.app') == 'penpot' and
                    checkpoint.exists() and (cfg / 'runtime.env').exists(), 'PENPOT_BOOTSTRAP_VOLUME_COLLISION')
            consumers = set(docker('ps', '-a', '--filter', 'volume=' + name, '--format', '{{.Names}}').splitlines())
            wanted = {'penpot-postgres'} if name == 'penpot_postgres_v15' else {'penpot-backend', 'penpot-frontend'}
            require(consumers <= wanted, 'PENPOT_BOOTSTRAP_VOLUME_COLLISION')
    networks = set(docker('network', 'ls', '--format', '{{.Name}}').splitlines())
    if 'edge-penpot' in networks:
        penpot_edge.owned_network()
    for name, internal in (('penpot_penpot', True), ('penpot-egress', False)):
        if name in networks:
            value = inspect('network', name)
            members = set(penpot.APP_SERVICES) | set(penpot.DATASTORE_IMAGES) if internal else {'penpot-backend', 'penpot-exporter'}
            require(checkpoint.exists() and value.get('Driver') == 'bridge' and value.get('Internal') is internal and
                    not value.get('Options') and (value.get('Labels') or {}).get('vps-deploy.app') == 'penpot' and
                    {member.get('Name') for member in (value.get('Containers') or {}).values()} <= members,
                    'PENPOT_NETWORK_OWNERSHIP')
    return dict(profile=profile, entry=entry, cfg=cfg, state=state, locks=locks, raw=raw, record=record,
                target=target, normal=normal, maintenance=maintenance, edge=edge, volumes=volumes, networks=networks, shared=shared)


def exclusive_route(path, raw):
    """Publish a first route atomically, without replacing an existing filename."""
    fd, name = tempfile.mkstemp(prefix='.penpot-bootstrap-', suffix='.tmp', dir=path.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(name, path)
        except FileExistsError:
            raise Failure('ROUTE_ALREADY_EXISTS') from None
        fsync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def quarantine(plan, profile):
    route.unchanged(plan['shared'], Path(profile['dynamic_dir']), profile['route_name'])
    if route.checked_file(plan['target'], managed=True) == plan['normal']:
        route.publish(plan['target'], plan['maintenance'], digest(plan['normal']))
        penpot_edge.origin_ack(profile, plan['entry'], maintenance=True)


def apply(args):
    plan = check(args)
    # This same fence protects controller dispatch. Remove only after native
    # source/stack/migration evidence, never because mock unit tests passed.
    controller = runpy.run_path(str(ROOT / 'bin/deployctl'))
    controller['ready_engine'](plan['profile'])
    cfg, state, locks = plan['cfg'], plan['state'], plan['locks']
    for path in (installer.RELEASES.parent, installer.RELEASES, installer.CONFIG, installer.STATE, locks):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        trusted_path(path, directory=True)
    with lock(locks / 'install.lock', 60), lock(locks / 'penpot@operation.lock', 60), lock(locks / 'traefik.lock', 60):
        plan = check(args)
        destination = installer.RELEASES / args.release
        installer.release_copy(ROOT, destination, installer.tree(ROOT))
        work = Path(plan['profile']['work_dir'])
        for path in (work, cfg, state, state / 'requests', state / 'backups'):
            path.mkdir(mode=0o700, exist_ok=True)
            trusted_path(path, directory=True)
            require(path.stat().st_mode & 0o777 == 0o700, 'PENPOT_RUNTIME_DIRECTORY')
        save(state / 'bootstrap.json', plan['record'])
        penpot_secrets.runtime(work, cfg, plan['profile']['registration'])
        from core import host
        binding = dict(plan['profile']['host_registration']['apps']['penpot'], platform_ref=args.release,
                       dynamic_dir=plan['profile']['dynamic_dir'])
        for path, raw in ((cfg / 'app.yml', plan['raw']), (cfg / 'host.json', json_bytes(binding))):
            if os.path.lexists(path):
                require(penpot.bounded_file(path) == raw, 'PENPOT_BOOTSTRAP_CONFIG_MISMATCH')
            else:
                atomic(path, raw)
        profile = host(cfg, plan['profile']['registration'], plan['profile']['host_registration'])
        for name in penpot.VOLUMES.values():
            if name not in plan['volumes']:
                docker('volume', 'create', '--label', 'vps-deploy.app=penpot', name)
        penpot.owned_volumes(profile)
        if 'penpot_assets' not in plan['volumes']:
            value = inspect('volume', 'penpot_assets')
            mount = trusted_path(Path(value['Mountpoint']), directory=True)
            os.chown(mount, 1001, 1001)
        if 'edge-penpot' not in plan['networks']:
            docker('network', 'create', '--internal', '--label', 'vps-deploy.app=penpot', 'edge-penpot')
        penpot_edge.apply(plan['edge'])
        before = route.checked_file(plan['target'], managed=True) if plan['target'].exists() else None
        route.unchanged(plan['shared'], Path(profile['dynamic_dir']), profile['route_name'])
        if before is None:
            exclusive_route(plan['target'], plan['maintenance'])
        else:
            route.publish(plan['target'], plan['maintenance'], digest(before))
        penpot_edge.origin_ack(profile, plan['entry'], maintenance=True)
        values = penpot.runtime_values(penpot.bounded_file(cfg / 'runtime.env'), profile['registration'])
        values.update({'PENPOT_' + role.upper() + '_IMAGE': ref for role, ref in plan['entry']['images'].items()})
        command('/usr/bin/docker', 'compose', '--env-file', str(cfg / 'runtime.env'), '-p', 'penpot',
                '-f', str(destination / 'apps/penpot/docker-compose.prod.yml'), 'up', '-d', '--pull', 'never',
                '--wait', '--wait-timeout', '180', env=dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', **values), timeout=240)
        penpot.stack_health(profile, plan['entry'])
        penpot_preflight.check(destination, profile['registration'], binding, cfg / 'runtime.env', args.app_ref, args.release)
        response = docker('exec', 'penpot-frontend', '/usr/bin/curl', '-fsS', '-w', '%{http_code}',
                          'http://127.0.0.1:8080/readyz', timeout=10)
        require(response == 'OK200', 'PENPOT_INTERNAL_READINESS')
        route.unchanged(plan['shared'], Path(profile['dynamic_dir']), profile['route_name'])
        try:
            route.publish(plan['target'], plan['normal'], digest(plan['maintenance']))
            route.ack(profile, ('single', plan['record']['generation']))
            penpot_edge.origin_ack(profile, plan['entry'], plan['record']['generation'])
        except Exception:
            quarantine(plan, profile)
            raise
    # Installer takes its own app/install locks; never invoke it under those locks.
    flags = ['--app', 'penpot', '--host', args.host, '--release', args.release, '--app-source', args.app_source,
             '--app-ref', args.app_ref, '--public-key', args.public_key]
    try:
        command('/usr/bin/python3', str(ROOT / 'install/installer.py'), *flags, '--check', timeout=120)
        command('/usr/bin/python3', str(ROOT / 'install/installer.py'), *flags, timeout=240)
    except Exception:
        with lock(locks / 'traefik.lock', 60):
            quarantine(plan, profile)
        raise
    require((state / 'state.json').exists(), 'PENPOT_ENROLLMENT_INCOMPLETE')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', required=True, choices=['penpot'])
    parser.add_argument('--host', required=True, choices=['oracle-main'])
    for name in ('release', 'app-source', 'app-ref', 'images', 'public-key'):
        parser.add_argument('--' + name, required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--check', action='store_true')
    operation.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.check:
        check(args)
        print('CHECK_OK')
    else:
        apply(args)
        print('BOOTSTRAP_OK')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(error.code if isinstance(error, Failure) else 'PENPOT_BOOTSTRAP_FAILED', file=sys.stderr)
        sys.exit(1)
