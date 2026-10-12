#!/usr/bin/env python3
"""Restore one origin-bound production snapshot on a disposable hosted ARM64 VM.

The download/admin credential boundary is deliberately outside this root helper.
Only synthetic acceptance data may be transferred to this VM. No snapshot, raw
query, runtime environment, or Docker inspection is printed or uploaded. The
preparation fence on the production installer is not involved in this rehearsal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'cloudflare'))
import core
import penpot
import penpot_origin
import penpot_restore

FILES = frozenset(('manifest.json', *penpot.SNAPSHOT_FILES))
AREAS = ('bin', 'lib', 'apps', 'schema', 'install', 'registry', 'hosts')
BASE = Path('/var/lib/penpot-restore-rehearsal')
NETWORKS = ('edge-penpot', 'penpot_penpot', 'penpot-egress')
SERVICES = (*penpot.APP_SERVICES, *penpot.DATASTORE_IMAGES)
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}


def extract_snapshot(archive, destination):
    """Validate the entire six-file header closure before exclusive private writes."""
    destination = Path(destination)
    try:
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as source:
            core.require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'PENPOT_REHEARSAL_ARCHIVE')
            with tarfile.open(fileobj=source, mode='r:') as bundle:
                members, names = [], set()
                for member in bundle:
                    core.require(member.name in FILES and member.name not in names and
                                 member.isreg() and not member.issparse() and not member.linkname and
                                 member.size > 0, 'PENPOT_REHEARSAL_ARCHIVE')
                    if member.name in ('manifest.json', 'runtime.env', 'app.yml', 'route.yml'):
                        core.require(member.size <= 65536, 'PENPOT_REHEARSAL_ARCHIVE')
                    names.add(member.name)
                    members.append(member)
                core.require(names == FILES, 'PENPOT_REHEARSAL_ARCHIVE')
                if destination.exists() or destination.is_symlink():
                    core.require(not destination.is_symlink() and destination.is_dir() and
                                 not any(destination.iterdir()), 'PENPOT_REHEARSAL_ARCHIVE')
                else:
                    destination.mkdir(mode=0o700)
                for member in members:
                    with bundle.extractfile(member) as data:
                        output_fd = os.open(destination / member.name,
                                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(output_fd, 'wb') as output:
                            os.fchmod(output.fileno(), 0o600)
                            shutil.copyfileobj(data, output, 1024 * 1024)
                            core.require(output.tell() == member.size, 'PENPOT_REHEARSAL_ARCHIVE')
                            output.flush()
                            os.fsync(output.fileno())
                core.fsync_dir(destination)
    except (tarfile.TarError, OSError, ValueError):
        raise core.Failure('PENPOT_REHEARSAL_ARCHIVE') from None
    return destination


def host_policy():
    platform = os.environ.get('GITHUB_SHA', '')
    core.require(os.geteuid() == 0 and os.uname().machine == 'aarch64' and
                 all(os.environ.get(key) == value for key, value in {
                     'CI': 'true', 'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                     'PENPOT_DISPOSABLE_VM': '1', 'GITHUB_REPOSITORY': 'TheDemonTuan/vps-deploy',
                     'GITHUB_REF': 'refs/heads/main',
                 }.items()) and core.SHA.fullmatch(platform) and
                 os.environ.get('PLATFORM_REF') == platform, 'PENPOT_REHEARSAL_HOST_POLICY')
    core.require(core.command('/usr/bin/git', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT),
                              'rev-parse', 'HEAD', env=ENV).strip() == platform,
                 'PENPOT_REHEARSAL_HOST_POLICY')
    core.require(not any(os.environ.get(key) for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')),
                 'PENPOT_REHEARSAL_HOST_POLICY')
    endpoint = core.command('/usr/bin/docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', env=ENV).strip()
    core.require(endpoint == 'unix:///var/run/docker.sock', 'PENPOT_REHEARSAL_HOST_POLICY')
    for path in (Path('/etc/vps-deploy/apps'), Path('/opt/penpot'), Path('/opt/platform/edge'), BASE):
        core.require(not path.exists() and not path.is_symlink(), 'PENPOT_REHEARSAL_HOST_POLICY')
    info = json.loads(core.command('/usr/bin/docker', 'info', '--format', '{{json .}}', env=ENV))
    core.require(info.get('Architecture') in ('aarch64', 'arm64') and info.get('OSType') == 'linux',
                 'PENPOT_REHEARSAL_HOST_POLICY')
    for kind in ('container', 'network', 'volume'):
        arguments = ('ps', '-a') if kind == 'container' else (kind, 'ls')
        names = core.docker(*arguments, '--format', '{{.Names}}' if kind == 'container' else '{{.Name}}').splitlines()
        core.require(not any('penpot' in name.lower() for name in names), 'PENPOT_REHEARSAL_HOST_POLICY')
        labels = core.docker(*arguments, '--filter', 'label=vps-deploy.app=penpot', '--format', '{{.ID}}' if kind != 'volume' else '{{.Name}}')
        projects = core.docker(*arguments, '--filter', 'label=com.docker.compose.project=penpot', '--format', '{{.ID}}' if kind != 'volume' else '{{.Name}}')
        core.require(not labels.strip() and not projects.strip(), 'PENPOT_REHEARSAL_HOST_POLICY')
    return platform


def stage_engine(platform):
    """Copy engine areas, preserving bytes/modes, but never links or bytecode."""
    parent = Path('/opt/vps-deploy/releases')
    # Hosted runners use a group-writable /opt. Admission already proved this
    # is a disposable VM; normalize its ancestor just as the native harness does.
    opt = Path('/opt')
    core.require(opt.is_dir() and not opt.is_symlink() and opt.stat().st_uid == 0,
                 'PENPOT_REHEARSAL_HOST_POLICY')
    opt.chmod(stat.S_IMODE(opt.stat().st_mode) & ~0o022)
    for path in (Path('/opt'), parent.parent, parent):
        if not path.exists():
            path.mkdir(mode=0o755)
        core.trusted_path(path, directory=True)
    release = parent / platform
    core.require(not release.exists() and not release.is_symlink(), 'PENPOT_REHEARSAL_HOST_POLICY')
    release.mkdir(mode=0o755)
    try:
        for area in AREAS:
            source = ROOT / area
            core.require(source.is_dir() and not source.is_symlink(), 'PENPOT_REHEARSAL_HOST_POLICY')
            for directory, children, files in os.walk(source, followlinks=False):
                children[:] = [name for name in children if name != '__pycache__']
                relative = Path(directory).relative_to(ROOT)
                target = release / relative
                core.require(not Path(directory).is_symlink(), 'PENPOT_REHEARSAL_HOST_POLICY')
                target.mkdir(mode=stat.S_IMODE(Path(directory).stat().st_mode))
                for name in children:
                    core.require(not (Path(directory) / name).is_symlink(), 'PENPOT_REHEARSAL_HOST_POLICY')
                for name in files:
                    if name.endswith(('.pyc', '.pyo')):
                        continue
                    original = Path(directory) / name
                    core.require(stat.S_ISREG(original.lstat().st_mode), 'PENPOT_REHEARSAL_HOST_POLICY')
                    shutil.copyfile(original, target / name, follow_symlinks=False)
                    os.chmod(target / name, stat.S_IMODE(original.stat().st_mode))
                    core.trusted_path(target / name)
        return core.trusted_path(release, directory=True)
    except Exception:
        shutil.rmtree(release)
        raise


def origin_identity(receipt_path, metadata, platform, profile):
    with open(receipt_path, 'rb') as stream:
        raw = stream.read(65537)
    try:
        origin = penpot_origin.receipt(core.parse_json(raw), platform)
    except (penpot_origin.Failure, core.Failure, TypeError, ValueError):
        raise core.Failure('PENPOT_REHEARSAL_IDENTITY') from None
    core.image_map(origin['images'], profile['image_repositories'])
    core.require(metadata.get('sourceSha') == origin['sourceSha'] and
                 metadata.get('platformRef') == platform and metadata.get('images') == origin['images'],
                 'PENPOT_REHEARSAL_IDENTITY')
    return penpot.validate_entry(penpot_restore.snapshot_entry(metadata), profile)


def compose(release, cfg, profile, entry, *arguments):
    values = penpot.runtime_values(penpot.bounded_file(cfg / 'runtime.env'), profile['registration'])
    values.update({'PENPOT_' + role.upper() + '_IMAGE': ref for role, ref in entry['images'].items()})
    return core.command('/usr/bin/docker', 'compose', '--env-file', str(cfg / 'runtime.env'),
                        '-p', 'penpot', '-f', str(release / 'apps/penpot/docker-compose.prod.yml'),
                        '--ansi=never', '--progress=plain', *arguments, env=dict(ENV, **values), timeout=240)


def database_matches(file_id, fingerprint):
    """Use the acceptance query verbatim before any application writer starts."""
    sql = ("SELECT jsonb_build_object(\n"
           "  'file', (SELECT to_jsonb(f) FROM file f WHERE f.id = '" + file_id + "'::uuid),\n"
           "  'file_data', COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY d.id)\n"
           "                         FROM file_data d WHERE d.file_id = '" + file_id + "'::uuid), '[]'::jsonb)\n"
           ")::text;\n")
    process = subprocess.run(['/usr/bin/docker', 'exec', '-i', 'penpot-postgres', 'psql', '-X', '-At',
                              '-U', 'penpot', '-d', 'penpot', '--set=ON_ERROR_STOP=1'], input=sql.encode(),
                             capture_output=True, env=ENV, timeout=120)
    core.require(process.returncode == 0, 'PENPOT_REHEARSAL_DATABASE')
    raw = process.stdout.rstrip(b'\n')
    try:
        core.require(len(raw.splitlines()) == 1, 'PENPOT_REHEARSAL_DATABASE')
        row = json.loads(raw.decode('utf-8'))
        core.require(type(row) is dict and set(row) == {'file', 'file_data'} and
                     type(row['file']) is dict and row['file'].get('id') == file_id and
                     type(row['file_data']) is list, 'PENPOT_REHEARSAL_DATABASE')
    except (ValueError, UnicodeError):
        raise core.Failure('PENPOT_REHEARSAL_DATABASE') from None
    core.require(hashlib.sha256(raw).hexdigest() == fingerprint, 'PENPOT_REHEARSAL_DATABASE')


def asset_catalog(path):
    penpot.safe_assets(path)
    result = {}
    with tarfile.open(path, 'r|') as archive:
        for member in archive:
            if not member.isreg():
                continue
            name = PurePosixPath(member.name).as_posix()
            checksum, size = hashlib.sha256(), 0
            with archive.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    checksum.update(chunk)
                    size += len(chunk)
            core.require(size == member.size, 'PENPOT_REHEARSAL_ASSETS')
            result[name] = (checksum.hexdigest(), size)
    return dict(sorted(result.items()))


def assets_match(expected, restored):
    core.require(asset_catalog(expected) == asset_catalog(restored), 'PENPOT_REHEARSAL_ASSETS')


class Resources:
    """Track only resources admitted on this initially Penpot-free VM."""
    def __init__(self):
        self.created = []
        self.token = uuid.uuid4().hex
        self.compose_started = False
        self.backend = None
        self.baseline = set(core.docker('ps', '-aq', '--no-trunc').splitlines())

    def volume(self, name):
        # Register the intended name first so a timed-out create is still cleaned.
        self.created.append(('volume', name, name))
        core.docker('volume', 'create', '--label', 'vps-deploy.app=penpot',
                    '--label', 'penpot-rehearsal=' + self.token, name)

    def edge(self):
        self.created.append(('network', 'edge-penpot', 'edge-penpot'))
        core.docker('network', 'create', '--internal', '--label', 'vps-deploy.app=penpot',
                    '--label', 'penpot-rehearsal=' + self.token, 'edge-penpot')

    def helper_owned(self, value):
        # restore_data's --rm tar helper can survive a client timeout. Bind it to
        # a newly created volume and the exact backend digest, never its name.
        host = value.get('HostConfig') or {}
        mounts = value.get('Mounts') or []
        return (self.backend is not None and value.get('Id') not in self.baseline and
                value.get('Config', {}).get('Image') == self.backend and
                host.get('NetworkMode') == 'none' and host.get('AutoRemove') is True and
                len(mounts) == 1 and mounts[0].get('Type') == 'volume' and
                mounts[0].get('Name') == penpot.VOLUMES['assets'] and
                mounts[0].get('Destination') == '/opt/data/assets')

    def capture_compose(self):
        if not self.compose_started:
            return
        for kind, names in (('container', SERVICES), ('network', NETWORKS[1:])):
            existing = core.docker('ps', '-a', '--format', '{{.Names}}') if kind == 'container' else core.docker('network', 'ls', '--format', '{{.Name}}')
            for name in set(existing.splitlines()) & set(names):
                value = core.inspect(kind, name)
                labels = (value.get('Config', {}).get('Labels') if kind == 'container' else value.get('Labels')) or {}
                core.require(labels.get('vps-deploy.app') == 'penpot' and
                             labels.get('com.docker.compose.project') == 'penpot', 'PENPOT_REHEARSAL_HOST_POLICY')
                item = (kind, value['Id'], name)
                if item not in self.created:
                    self.created.append(item)
        for identity in set(core.docker('ps', '-aq', '--no-trunc').splitlines()) - self.baseline:
            value = core.inspect('container', identity)
            if self.helper_owned(value):
                item = ('container', identity, value.get('Name', ''))
                if item not in self.created:
                    self.created.append(item)

    def teardown(self):
        error = None
        try:
            self.capture_compose()
        except Exception as caught:
            error = caught
        for kind, identity, name in sorted(self.created, key=lambda item: {'container': 0, 'network': 1, 'volume': 2}[item[0]]):
            try:
                # --rm helpers may already be gone; absence is not a cleanup error.
                present = core.docker('ps', '-aq', '--no-trunc') if kind == 'container' else core.docker(kind, 'ls', '--format', '{{.Name}}')
                if (identity if kind == 'container' else name) not in present.splitlines():
                    continue
                value = core.inspect(kind, identity)
                labels = (value.get('Config', {}).get('Labels') if kind == 'container' else value.get('Labels')) or {}
                labelled = (labels.get('vps-deploy.app') == 'penpot' and
                            (labels.get('penpot-rehearsal') == self.token or
                             kind != 'volume' and labels.get('com.docker.compose.project') == 'penpot'))
                core.require(labelled or kind == 'container' and self.helper_owned(value),
                             'PENPOT_REHEARSAL_HOST_POLICY')
                core.docker('rm', '-f', identity) if kind == 'container' else core.docker(kind, 'rm', identity)
            except Exception as caught:
                if error is None:
                    error = caught
        if error is not None:
            if isinstance(error, core.Failure):
                raise error
            raise core.Failure('PENPOT_REHEARSAL_FAILED') from None


def rehearse(args):
    try:
        file_id = str(uuid.UUID(args.file_id))
    except (ValueError, AttributeError):
        raise core.Failure('PENPOT_REHEARSAL_DATABASE') from None
    core.require(args.file_id == file_id and re.fullmatch(r'[0-9a-f]{64}', args.file_sha256),
                 'PENPOT_REHEARSAL_DATABASE')
    platform = host_policy()
    core.trusted_path(BASE.parent, directory=True)
    resources = Resources()
    BASE.mkdir(mode=0o700)
    os.chmod(BASE, 0o700)
    error, report, release = None, None, None
    try:
        backup = extract_snapshot(args.archive, BASE / 'backup')
        penpot.private_directory(backup)
        release = stage_engine(platform)
        registration = core.app_registration(release, 'penpot')
        host = core.host_registration(release, 'oracle-main')
        core.require(registration['host'] == 'oracle-main', 'PENPOT_REHEARSAL_IDENTITY')
        profile = dict(host['apps']['penpot'], app='penpot', registration=registration,
                       image_repositories=registration['manifest']['images'], platform_ref=platform)
        metadata = core.parse_json(penpot.bounded_file(backup / 'manifest.json'))
        entry = origin_identity(args.origin_receipt, metadata, platform, profile)
        resources.backend = entry['images']['backend']
        cfg = BASE / 'config'
        cfg.mkdir(mode=0o700)
        for name in ('runtime.env', 'app.yml'):
            core.atomic(cfg / name, penpot.bounded_file(backup / name))
        core.manifest(penpot.bounded_file(cfg / 'app.yml'), registration)
        penpot.runtime_values(penpot.bounded_file(cfg / 'runtime.env'), registration)
        penpot.prepare_images(entry, profile)
        for ref in penpot.DATASTORE_IMAGES.values():
            core.docker('pull', ref, timeout=650)
            core.image_id(ref)
        for name in penpot.VOLUMES.values():
            resources.volume(name)
        penpot.owned_volumes(profile)
        resources.edge()
        resources.compose_started = True
        compose(release, cfg, profile, entry, 'create', '--pull', 'never', *SERVICES)
        resources.capture_compose()
        penpot.writers_stopped(profile, entry['images'])
        compose(release, cfg, profile, entry, 'up', '-d', '--no-deps', '--pull', 'never',
                '--wait', '--wait-timeout', '180', *penpot.DATASTORE_IMAGES)
        verified = penpot.verify_snapshot(backup, registration)
        core.require(verified == metadata, 'PENPOT_REHEARSAL_IDENTITY')
        penpot.restore_data(profile, cfg, backup, entry)
        penpot.writers_stopped(profile, entry['images'])
        database_matches(file_id, args.file_sha256)
        restored = cfg / 'restored-assets.tar'
        penpot.stream_file(restored, ['/usr/bin/docker', 'run', '--rm', '--network', 'none',
                                     '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                                     '--mount', 'type=volume,src=penpot_assets,dst=/opt/data/assets,readonly',
                                     '--entrypoint', '/bin/tar', entry['images']['backend'],
                                     '--numeric-owner', '-cf', '-', '-C', '/opt/data/assets', '.'])
        assets_match(backup / 'assets.tar', restored)
        penpot.writers_stopped(profile, entry['images'])
        penpot.start_applications(release, profile, cfg, entry)
        penpot.stack_health(profile, entry)
        readiness = core.command('/usr/bin/docker', 'exec', 'penpot-frontend', 'curl', '-fsS',
                                 '--max-time', '10', '-w', '%{http_code}', 'http://127.0.0.1:8080/readyz', env=ENV)
        core.require(readiness == 'OK200', 'PENPOT_STACK_UNHEALTHY')
        report = {'status': 'passed', 'snapshotVerified': True, 'databaseMatches': True,
                  'assetsMatch': True, 'readiness': True, 'sourceSha': metadata['sourceSha'],
                  'platformRef': platform, 'dataTimestamp': metadata['createdAt']}
    except Exception as caught:
        error = caught
    finally:
        try:
            resources.teardown()
        except Exception as caught:
            if error is None:
                error = caught
        # Both paths are created here after an absence check; never erase other VM data.
        for path in (BASE, release):
            if path is None:
                continue
            try:
                shutil.rmtree(core.trusted_path(path, directory=True))
            except Exception as caught:
                if error is None:
                    error = caught
    if error is not None:
        raise error
    return report


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise core.Failure('PENPOT_REHEARSAL_FAILED')


def main():
    try:
        parser = Parser(description=__doc__)
        for name in ('archive', 'origin-receipt', 'file-id', 'file-sha256'):
            parser.add_argument('--' + name, required=True)
        report = rehearse(parser.parse_args())
    except Exception as error:
        code = error.code if isinstance(error, core.Failure) else 'PENPOT_REHEARSAL_FAILED'
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', code):
            code = 'PENPOT_REHEARSAL_FAILED'
        print(json.dumps({'status': 'failed', 'error_code': code}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
