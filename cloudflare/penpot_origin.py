"""Verify the installed origin over pinned admin SSH before Cloudflare writes."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from penpot_ingress import Failure

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = '134.185.89.192'
FINGERPRINT = 'SHA256:e3LV9csFdtQi0+fs+GkRX1T8RFCYNy7afFgSm8nyfc4'
SHA = re.compile(r'[0-9a-f]{40}\Z')


def run(argv, **kwargs):
    try:
        return subprocess.run(argv, capture_output=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure('PENPOT_ORIGIN_TRANSPORT_FAILED') from None


def receipt(value, platform):
    fields = {'app', 'host', 'platformRef', 'sourceSha', 'images', 'generation', 'healthy', 'origin_tls_verified'}
    if type(value) is not dict or set(value) != fields or value.get('app') != 'penpot' or value.get('host') != 'oracle-main' or \
            value.get('platformRef') != platform or not SHA.fullmatch(value.get('sourceSha', '')) or \
            value.get('healthy') is not True or value.get('origin_tls_verified') is not True or \
            not re.fullmatch(r'[0-9a-f]{32}', value.get('generation', '')):
        raise Failure('PENPOT_ORIGIN_RECEIPT_POLICY')
    images = value.get('images')
    if type(images) is not dict or set(images) != {'frontend', 'backend', 'exporter', 'mcp'} or any(
            type(images[role]) is not str or not re.fullmatch(
                r'ghcr\.io/thedemontuan/penpot-' + role + r'@sha256:[0-9a-f]{64}', images[role]) for role in images):
        raise Failure('PENPOT_ORIGIN_RECEIPT_POLICY')
    return value


def verifier():
    platform = os.environ.get('GITHUB_SHA', '')
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'TheDemonTuan/vps-deploy' or \
            os.environ.get('GITHUB_REF') != 'refs/heads/main' or not SHA.fullmatch(platform):
        raise Failure('PENPOT_INGRESS_CALLER_POLICY')
    value = os.environ.pop('VPS_PLATFORM_ADMIN_SSH_KEY', '')
    if not value.strip():
        raise Failure('PENPOT_ORIGIN_ADMIN_KEY_REQUIRED')
    # Rechecks reuse this in-memory key, not the environment or an artifact.
    return lambda: verify(platform, value)


def verify(platform, value):
    # The key is removed from the environment and never sent to the origin.
    with tempfile.TemporaryDirectory(prefix='penpot-ingress-admin-') as temporary:
        path = Path(temporary)
        key = path / 'admin.key'
        fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(value.rstrip('\n') + '\n')
        scan = run(['/usr/bin/ssh-keyscan', '-p', '22', '-t', 'ed25519', ADDRESS], timeout=15)
        lines = [line.split() for line in scan.stdout.decode('ascii').splitlines() if line and not line.startswith('#')]
        if scan.returncode or len(lines) != 1 or len(lines[0]) != 3 or lines[0][1] != 'ssh-ed25519':
            raise Failure('PENPOT_ORIGIN_HOST_KEY_SCAN_FAILED')
        try:
            actual = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(lines[0][2], validate=True)).digest()).decode().rstrip('=')
        except ValueError:
            raise Failure('PENPOT_ORIGIN_HOST_KEY_INVALID') from None
        if actual != FINGERPRINT:
            raise Failure('PENPOT_ORIGIN_HOST_KEY_MISMATCH')
        known = path / 'known_hosts'
        known.write_text(ADDRESS + ' ' + ' '.join(lines[0][1:]) + '\n', encoding='ascii')
        known.chmod(0o600)
        ssh = ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(key), '-p', '22',
               '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
               '-o', 'ClearAllForwardings=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=10',
               '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', '-T', 'opc@' + ADDRESS,
               'sudo -n /usr/bin/python3 - ' + platform]
        result = run(ssh, input=(ROOT / 'install/check-penpot-origin.py').read_bytes(), timeout=120)
        if result.returncode:
            raise Failure('PENPOT_ORIGIN_NOT_READY')
        if len(result.stdout) > 65536:
            raise Failure('PENPOT_ORIGIN_RECEIPT_TOO_LARGE')
        try:
            return receipt(json.loads(result.stdout), platform)
        except (ValueError, TypeError):
            raise Failure('PENPOT_ORIGIN_RECEIPT_POLICY') from None
