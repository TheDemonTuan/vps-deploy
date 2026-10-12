#!/usr/bin/env python3
"""Read one production snapshot over verified admin SSH; never mutate the VPS."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'cloudflare'))
from core import Failure, REQUEST_ID, SHA
import penpot_origin
from penpot_ingress import Failure as OriginFailure

# The remote reader uses descriptor-relative, no-follow opens for the entire
# trusted path. All six files are admitted before the first archive byte leaves.
REMOTE_READER = r'''
import os
import re
import stat
import sys
import tarfile

FILES = ('manifest.json', 'database.dump', 'assets.tar', 'runtime.env', 'app.yml', 'route.yml')


def stream_snapshot(base, backup_id, output):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', backup_id):
        raise ValueError()
    if not base.startswith('/'):
        raise ValueError()
    descriptors = []
    streams = []
    try:
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        parts = base.strip('/').split('/') + [backup_id]
        root = os.fstat(directory)
        if root.st_uid != 0 or stat.S_IMODE(root.st_mode) & 0o022:
            raise ValueError()
        for index, component in enumerate(parts):
            if not component or component in ('.', '..'):
                raise ValueError()
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            descriptors.append(directory)
            info = os.fstat(directory)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != 0 or mode & 0o022 or (index >= len(parts) - 2 and mode != 0o700):
                raise ValueError()
        if set(os.listdir(directory)) != set(FILES):
            raise ValueError()
        for name in FILES:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            stream = os.fdopen(fd, 'rb')
            streams.append((name, stream, os.fstat(fd)))
            info = streams[-1][2]
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError()
        with tarfile.open(fileobj=output, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
            for name, stream, info in streams:
                member = tarfile.TarInfo(name)
                member.size = info.st_size
                member.mode = 0o600
                member.mtime = int(info.st_mtime)
                archive.addfile(member, stream)
    finally:
        for _, stream, _ in streams:
            stream.close()
        for fd in reversed(descriptors):
            os.close(fd)


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or len(sys.argv) != 2:
            raise ValueError()
        stream_snapshot('/var/lib/vps-deploy/apps/penpot/backups', sys.argv[1], sys.stdout.buffer)
    except Exception:
        sys.exit(1)
'''


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure('PENPOT_BACKUP_DOWNLOAD_ARGUMENT')


def private_output(path):
    path = Path(path)
    parent = path.parent
    info = parent.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or \
            stat.S_IMODE(info.st_mode) != 0o700:
        raise Failure('PENPOT_BACKUP_DOWNLOAD_PRIVATE_PATH')
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')


def transport(directory, value):
    """Mirror penpot_origin.verify's pinned admin-only transport, not deploy SSH."""
    key = directory / 'admin.key'
    with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        output.write(value.rstrip('\n') + '\n')
    scan = penpot_origin.run(['/usr/bin/ssh-keyscan', '-p', '22', '-t', 'ed25519', penpot_origin.ADDRESS], timeout=15)
    lines = [line.split() for line in scan.stdout.decode('ascii').splitlines() if line and not line.startswith('#')]
    if scan.returncode or len(lines) != 1 or len(lines[0]) != 3 or lines[0][1] != 'ssh-ed25519':
        raise OriginFailure('PENPOT_ORIGIN_HOST_KEY_SCAN_FAILED')
    try:
        actual = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(lines[0][2], validate=True)).digest()).decode().rstrip('=')
    except ValueError:
        raise OriginFailure('PENPOT_ORIGIN_HOST_KEY_INVALID') from None
    if actual != penpot_origin.FINGERPRINT:
        raise OriginFailure('PENPOT_ORIGIN_HOST_KEY_MISMATCH')
    known = directory / 'known_hosts'
    known.write_text(penpot_origin.ADDRESS + ' ' + ' '.join(lines[0][1:]) + '\n', encoding='ascii')
    known.chmod(0o600)
    return ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(key), '-p', '22',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', '-T', 'opc@' + penpot_origin.ADDRESS]


def download(backup_id, archive, origin_receipt):
    platform = os.environ.get('GITHUB_SHA', '')
    if not SHA.fullmatch(platform) or os.environ.get('PLATFORM_REF') != platform:
        raise Failure('PENPOT_BACKUP_DOWNLOAD_IDENTITY')
    if not REQUEST_ID.fullmatch(backup_id) or archive == origin_receipt:
        raise Failure('PENPOT_BACKUP_DOWNLOAD_ARGUMENT')
    value = os.environ.get('VPS_PLATFORM_ADMIN_SSH_KEY', '')
    # verifier pops the key from the environment and proves installed origin first.
    receipt = penpot_origin.verifier()()
    created = []
    try:
        with tempfile.TemporaryDirectory(prefix='penpot-backup-admin-') as temporary:
            ssh = transport(Path(temporary), value)
            with private_output(archive) as output:
                created.append(archive)
                result = subprocess.run(ssh + ['sudo -n /usr/bin/python3 - ' + backup_id],
                                        input=REMOTE_READER.encode(), stdout=output, stderr=subprocess.DEVNULL,
                                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=900)
                if result.returncode:
                    raise Failure('PENPOT_BACKUP_DOWNLOAD_FAILED')
                output.flush()
                os.fsync(output.fileno())
        with private_output(origin_receipt) as output:
            created.append(origin_receipt)
            output.write((json.dumps(receipt, sort_keys=True) + '\n').encode())
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('--backup-id', required=True)
        parser.add_argument('--archive', type=Path, required=True)
        parser.add_argument('--origin-receipt', type=Path, required=True)
        args = parser.parse_args()
        download(args.backup_id, args.archive, args.origin_receipt)
        print(json.dumps({'status': 'downloaded'}))
        return 0
    except (Failure, OriginFailure) as error:
        code = error.code if isinstance(error, Failure) else str(error)
        if not isinstance(code, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', code):
            code = 'PENPOT_BACKUP_DOWNLOAD_FAILED'
    except Exception:
        code = 'PENPOT_BACKUP_DOWNLOAD_FAILED'
    print(json.dumps({'status': 'failed', 'error_code': code}))
    return 1


if __name__ == '__main__':
    sys.exit(main())
