#!/usr/bin/python3
"""Offline, root-only enrollment of the dedicated forced-command browser probe."""
import argparse
import base64
import binascii
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
ACCOUNT = 'probe-uptimeflare'
HOME = Path('/home/probe-uptimeflare')
BASE = Path('/opt/vps-deploy-probe')
ENTRY = Path('/usr/local/libexec/vps-deploy-uptimeflare-probe-entry')
WRAPPER = Path('/usr/local/libexec/vps-deploy-uptimeflare-probe')
SUDOERS = Path('/etc/sudoers.d/vps-deploy-uptimeflare-probe')
INSTALL_LOCK = Path('/run/vps-deploy-probe-install.lock')
RESTORECON = Path('/usr/sbin/restorecon')
NODE_VERSION = '24.21.0'
NODE_DIGESTS = {
    'arm64': '6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2',
    'x64': 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6',
}
SOURCE_FILES = ('cloudflare/uptimeflare-http.mjs', 'cloudflare/package-lock.json',
                'install/install-uptimeflare-probe.py')


class Failure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def trusted(path, directory=False):
    """All ancestors must be root-owned, non-writable by other users, no links."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'UNTRUSTED_PATH')
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and
                (stat.S_ISDIR(info.st_mode) if item != path or directory else stat.S_ISREG(info.st_mode)),
                'UNTRUSTED_PATH')
    return path


def trusted_executable(path):
    """Allow root-owned OS executable links, never staged/resource symlinks."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'UNTRUSTED_PATH')
    seen = set()
    for _ in range(40):
        require(path not in seen, 'UNTRUSTED_EXECUTABLE_LINK')
        seen.add(path)
        trusted(path.parent, directory=True)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            # A symlink's 0777 mode is not a write grant; its parent controls it.
            require(info.st_uid == 0, 'UNTRUSTED_EXECUTABLE_LINK')
            path = Path(os.path.abspath(path.parent / os.readlink(path)))
            continue
        trusted(path)
        require(os.access(path, os.X_OK), 'EXECUTABLE_REQUIRED')
        return path
    raise Failure('UNTRUSTED_EXECUTABLE_LINK')


def tree_trusted(path):
    trusted(path, directory=True)
    for child in path.iterdir():
        trusted(child, directory=stat.S_ISDIR(child.lstat().st_mode))
        if child.is_dir():
            tree_trusted(child)


def existing(path, directory=False, mode=None):
    if os.path.lexists(path):
        trusted(path, directory=directory)
        if mode is not None:
            require(stat.S_IMODE(path.stat().st_mode) == mode, 'RESOURCE_MODE_CONFLICT')
        return True
    parent = path.parent
    while not os.path.lexists(parent):
        parent = parent.parent
    trusted(parent, directory=True)
    return False


def public_key(path):
    raw = trusted(path).read_bytes()
    require(len(raw) <= 1024 and re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?\n', raw),
            'INVALID_PUBLIC_KEY')
    token = raw.split()[1]
    try:
        blob = base64.b64decode(token, validate=True)
    except (ValueError, binascii.Error):
        raise Failure('INVALID_PUBLIC_KEY') from None
    require(len(blob) == 51 and blob[:4] == struct.pack('>I', 11) and
            blob[4:15] == b'ssh-ed25519' and blob[15:19] == struct.pack('>I', 32), 'INVALID_PUBLIC_KEY')
    return b'ssh-ed25519 ' + token


def package(archive, name, record):
    """Verify the lock's SRI before parsing; never execute npm or extract links."""
    raw = trusted(archive).read_bytes()
    integrity = record.get('integrity', '')
    require(type(integrity) is str and integrity.startswith('sha512-'), 'PACKAGE_INTEGRITY_POLICY')
    require(integrity == 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode(),
            'PACKAGE_DIGEST_MISMATCH')
    files = {}
    with tarfile.open(archive, 'r:gz') as tar:
        seen = set()
        for member in tar:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts and
                    path.parts[0] == 'package' and member.name not in seen and
                    (member.isdir() or member.isfile()) and not member.mode & 0o7022,
                    'UNSAFE_PACKAGE_ARCHIVE')
            seen.add(member.name)
            if member.isdir():
                continue
            require(len(path.parts) > 1, 'UNSAFE_PACKAGE_ARCHIVE')
            relative = str(Path('cloudflare/node_modules') / name / Path(*path.parts[1:]))
            require(relative not in files, 'UNSAFE_PACKAGE_ARCHIVE')
            files[relative] = (tar.extractfile(member).read(), 0o755 if member.mode & 0o111 else 0o644)
    metadata_path = 'cloudflare/node_modules/' + name + '/package.json'
    require(metadata_path in files, 'PACKAGE_METADATA_MISSING')
    metadata = json.loads(files[metadata_path][0])
    require(metadata.get('name') == name and metadata.get('version') == record.get('version'),
            'PACKAGE_METADATA_MISMATCH')
    return files


def node_binary(archive, architecture):
    path = trusted(archive)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    require(digest.hexdigest() == NODE_DIGESTS[architecture], 'NODE_DIGEST_MISMATCH')
    with tarfile.open(path, 'r:xz') as tar:
        name = 'node-v' + NODE_VERSION + '-linux-' + architecture + '/bin/node'
        members = [member for member in tar if member.name == name]
        require(len(members) == 1 and members[0].isfile(), 'NODE_ARCHIVE_INVALID')
        return tar.extractfile(members[0]).read()


def account_state():
    try:
        user = pwd.getpwnam(ACCOUNT)
    except KeyError:
        user = None
    try:
        group = grp.getgrnam(ACCOUNT)
    except KeyError:
        group = None
    require((user is None) == (group is None), 'ACCOUNT_CONFLICT')
    if user is not None:
        require(0 < user.pw_uid < 1000 and user.pw_gid == group.gr_gid and
                user.pw_dir == str(HOME) and user.pw_shell == '/bin/sh' and
                user.pw_gecos == 'vps-deploy uptimeflare probe' and not group.gr_mem and
                not any(ACCOUNT in item.gr_mem for item in grp.getgrall()) and
                not any(item.pw_gid == group.gr_gid and item.pw_name != ACCOUNT for item in pwd.getpwall()),
                'ACCOUNT_CONFLICT')
        shadow = trusted(Path('/etc/shadow')).read_text().splitlines()
        records = [line.split(':') for line in shadow if line.split(':', 1)[0] == ACCOUNT]
        require(len(records) == 1 and records[0][1] == '*', 'ACCOUNT_PASSWORD_POLICY')
    return user is not None


def scripts(release):
    runtime = BASE / 'releases' / release
    entry = '''#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ "${SSH_ORIGINAL_COMMAND-}" = probe ] || exit 64
exec /usr/bin/sudo -n -- /usr/local/libexec/vps-deploy-uptimeflare-probe
'''
    # No caller-controlled command, paths, environment, unit properties or arguments.
    wrapper = '''#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ "$(/usr/bin/id -u)" -eq 0 ] || exit 64
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C /usr/bin/flock -n /run/vps-deploy-uptimeflare-probe.lock \\
 /usr/bin/systemd-run --quiet --pipe --wait --collect \\
 --property=User=probe-uptimeflare --property=Group=probe-uptimeflare \\
 --property=RuntimeMaxSec=90 --property=MemoryMax=768M --property=CPUQuota=100% --property=TasksMax=256 \\
 --property=PrivateTmp=yes --property=ProtectSystem=strict --property=ProtectHome=yes \\
 --property=PrivateDevices=yes --property=ReadOnlyPaths=RUNTIME \\
 '--property=InaccessiblePaths=-/etc/vps-deploy -/var/lib/vps-deploy -/opt/platform -/opt/9router -/opt/penpot -/opt/tuan-portfolio' \\
 --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=AmbientCapabilities= \\
 --property=UMask=0077 --property=WorkingDirectory=/tmp \\
 /usr/bin/env -i PATH=/usr/bin:/bin LANG=C HOME=/tmp UPTIMEFLARE_BROWSER_EXECUTABLE=/usr/bin/chromium-browser \\
 RUNTIME/node/bin/node RUNTIME/cloudflare/uptimeflare-http.mjs
'''.replace('RUNTIME', str(runtime))
    sudoers = (ACCOUNT + ' ALL=(root) NOPASSWD: ' + str(WRAPPER) + ' ""\n')
    return entry.encode(), wrapper.encode(), sudoers.encode()


def expected_directories(files):
    result = set()
    for name in files:
        result.update(str(parent) for parent in Path(name).parents if parent != Path('.'))
    return result


def release_matches(path, files):
    require(existing(path, directory=True, mode=0o755), 'RELEASE_MISSING')
    directories = expected_directories(files)
    found_files, found_directories = set(), set()
    for child in path.rglob('*'):
        relative = str(child.relative_to(path))
        if child.is_dir() and not child.is_symlink():
            trusted(child, directory=True)
            require(stat.S_IMODE(child.stat().st_mode) == 0o755, 'IMMUTABLE_RELEASE_CONFLICT')
            found_directories.add(relative)
        else:
            trusted(child)
            require(relative in files and child.read_bytes() == files[relative][0] and
                    stat.S_IMODE(child.stat().st_mode) == files[relative][1], 'IMMUTABLE_RELEASE_CONFLICT')
            found_files.add(relative)
    require(found_files == set(files) and found_directories == directories, 'IMMUTABLE_RELEASE_CONFLICT')


def check(args):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', args.release), 'INVALID_RELEASE_SHA')
    architecture = {'aarch64': 'arm64', 'x86_64': 'x64'}.get(os.uname().machine)
    require(architecture is not None, 'UNSUPPORTED_ARCHITECTURE')
    source = Path(args.source)
    tree_trusted(source)
    require((source / '.probe-source-sha').read_bytes() == (args.release + '\n').encode(), 'SOURCE_SHA_MISMATCH')
    source_raw = {name: trusted(source / name).read_bytes() for name in SOURCE_FILES}
    require(source_raw[SOURCE_FILES[2]] == trusted(Path(__file__).absolute()).read_bytes(), 'INSTALLER_SOURCE_MISMATCH')
    lock = json.loads(source_raw['cloudflare/package-lock.json'])
    require(lock.get('lockfileVersion') == 3, 'LOCKFILE_POLICY')
    records = {name: lock['packages']['node_modules/' + name] for name in ('playwright', 'playwright-core')}
    require(records['playwright'].get('dependencies') == {'playwright-core': records['playwright-core']['version']} and
            not records['playwright-core'].get('dependencies'), 'PACKAGE_DEPENDENCY_POLICY')
    files = {'cloudflare/uptimeflare-http.mjs': (source_raw['cloudflare/uptimeflare-http.mjs'], 0o644),
             'node/bin/node': (node_binary(Path(args.node_archive), architecture), 0o755)}
    for name, archive in (('playwright', args.playwright_archive), ('playwright-core', args.playwright_core_archive)):
        files.update(package(Path(archive), name, records[name]))
    manifest = {'version': 1, 'release': args.release, 'architecture': architecture,
                'node': {'version': NODE_VERSION, 'sha256': NODE_DIGESTS[architecture]},
                'source_sha256': {name: sha(raw) for name, raw in source_raw.items()},
                'package_integrity': {name: record['integrity'] for name, record in records.items()},
                'files': {name: {'sha256': sha(raw), 'mode': format(mode, '04o')}
                          for name, (raw, mode) in sorted(files.items())}}
    files['manifest.json'] = (encoded(manifest), 0o644)
    entry, wrapper, sudoers = scripts(args.release)
    key = public_key(Path(args.public_key))
    resources = {ENTRY: (entry, 0o755), WRAPPER: (wrapper, 0o755), SUDOERS: (sudoers, 0o440),
                 HOME / '.ssh/authorized_keys':
                     (b'restrict,command="' + str(ENTRY).encode() + b'" ' + key + b'\n', 0o644)}
    # sshd opens public authorized_keys as the login UID; root retains write ownership.
    directories = {BASE: 0o755, BASE / 'releases': 0o755, HOME: 0o755, HOME / '.ssh': 0o755,
                   ENTRY.parent: 0o755}
    for path, mode in directories.items():
        existing(path, directory=True, mode=mode)
    for path, (raw, mode) in resources.items():
        if existing(path, mode=mode):
            require(path.read_bytes() == raw, 'IMMUTABLE_RESOURCE_CONFLICT')
    if existing(HOME, directory=True):
        require(set(HOME.iterdir()) <= {HOME / '.ssh'}, 'HOME_CONFLICT')
    if existing(HOME / '.ssh', directory=True):
        require(set((HOME / '.ssh').iterdir()) <= {HOME / '.ssh/authorized_keys'}, 'HOME_CONFLICT')
    release_path = BASE / 'releases' / args.release
    reused = existing(release_path, directory=True)
    if reused:
        release_matches(release_path, files)
    installed_account = account_state()
    for executable in ('/usr/bin/sudo', '/usr/bin/systemd-run', '/usr/bin/flock', '/usr/bin/env',
                       '/usr/bin/id', '/usr/sbin/useradd', '/usr/sbin/visudo', '/usr/bin/chromium-browser'):
        trusted_executable(Path(executable))
    existing(INSTALL_LOCK, mode=0o600)
    restorecon = os.path.lexists(RESTORECON)
    if restorecon:
        trusted_executable(RESTORECON)
    return dict(files=files, resources=resources, directories=directories, release_path=release_path,
                reused=reused, installed_account=installed_account, manifest=manifest, restorecon=restorecon)


def exclusive_file(path, raw, mode):
    if existing(path, mode=mode):
        require(path.read_bytes() == raw, 'IMMUTABLE_RESOURCE_CONFLICT')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def apply(plan):
    for path, mode in plan['directories'].items():
        if not existing(path, directory=True, mode=mode):
            path.mkdir(mode=mode)
            path.chmod(mode)
    if not plan['reused']:
        temporary = Path(tempfile.mkdtemp(prefix='.install-', dir=BASE / 'releases'))
        try:
            for name in sorted(expected_directories(plan['files']), key=lambda value: (len(Path(value).parts), value)):
                (temporary / name).mkdir(mode=0o755)
                (temporary / name).chmod(0o755)
            for name, (raw, mode) in plan['files'].items():
                exclusive_file(temporary / name, raw, mode)
            temporary.chmod(0o755)
            require(not os.path.lexists(plan['release_path']), 'IMMUTABLE_RELEASE_CONFLICT')
            temporary.rename(plan['release_path'])
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    if not plan['installed_account']:
        subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                        '--no-log-init',
                        '--home-dir', str(HOME), '--shell', '/bin/sh', '--password', '*',
                        '--comment', 'vps-deploy uptimeflare probe', ACCOUNT],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    # Validate sudo grammar before making the grant visible; no file/network/scripts.
    subprocess.run(['/usr/sbin/visudo', '-cf', '-'], input=plan['resources'][SUDOERS][0],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    for path in (WRAPPER, ENTRY, SUDOERS, HOME / '.ssh/authorized_keys'):
        exclusive_file(path, *plan['resources'][path])
    if plan['restorecon']:
        subprocess.run([str(RESTORECON), '-RF', str(HOME)], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'release', 'public-key', 'node-archive', 'playwright-archive', 'playwright-core-archive'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--check', action='store_true', help='validate all inputs/conflicts without any mutation')
    args = parser.parse_args(argv)
    try:
        plan = check(args)
        if not args.check:
            fd = os.open(INSTALL_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'rb') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Recheck after acquiring the installation lock, including immutable bytes.
                plan = check(args)
                apply(plan)
        print(json.dumps({'status': 'checked' if args.check else 'installed',
                          'release': args.release, 'reused_release': plan['reused'],
                          'manifest_sha256': sha(encoded(plan['manifest']))}, sort_keys=True))
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps({'error_code': str(error) if isinstance(error, Failure) else 'PROBE_INSTALL_FAILED'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
