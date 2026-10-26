"""Credential-isolated SSH transport to the fixed, forced-command public probe."""
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

# The oracle-main registration; tests keep this pin aligned with hosts/oracle-main.yml.
HOST = '134.185.89.192'
FINGERPRINT = 'SHA256:e3LV9csFdtQi0+fs+GkRX1T8RFCYNy7afFgSm8nyfc4'
USER = 'probe-uptimeflare'
MAX_RESPONSE = 16 * 1024 * 1024
_KEY = None


class ProbeError(RuntimeError):
    pass


def invoke(request):
    global _KEY
    if not isinstance(request, bytes) or len(request) > 2048:
        raise ProbeError('Dedicated probe request exceeds size limit')
    if _KEY is None:
        _KEY = os.environ.pop('UPTIMEFLARE_PROBE_SSH_KEY', '')
    if not _KEY or len(_KEY) > 16384:
        raise ProbeError('Dedicated uptimeflare probe SSH key is required')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C'}
    try:
        with tempfile.TemporaryDirectory(prefix='uptimeflare-probe-') as temporary:
            directory = Path(temporary)
            key = directory / 'identity'
            key.write_text(_KEY.rstrip('\n') + '\n')
            key.chmod(0o600)
            scan = subprocess.run(['/usr/bin/ssh-keyscan', '-p', '22', '-t', 'ed25519', HOST],
                                  capture_output=True, timeout=15, env=env, check=False)
            lines = [line.split() for line in scan.stdout.splitlines() if line and not line.startswith(b'#')]
            if scan.returncode or len(lines) != 1 or len(lines[0]) != 3 or lines[0][1] != b'ssh-ed25519':
                raise ProbeError('Dedicated probe host-key scan failed')
            fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(lines[0][2], validate=True)).digest()).decode().rstrip('=')
            if fingerprint != FINGERPRINT:
                raise ProbeError('Dedicated probe host-key fingerprint mismatch')
            known = directory / 'known_hosts'
            known.write_bytes(b' '.join(lines[0]) + b'\n')
            known.chmod(0o600)
            command = ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(key), '-p', '22',
                       '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
                       '-o', 'ClearAllForwardings=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                       '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UserKnownHostsFile=' + str(known),
                       '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                       '-T', USER + '@' + HOST, 'probe']
            result = subprocess.run(command, input=request, capture_output=True, timeout=105, env=env, check=False)
            if len(result.stdout) > MAX_RESPONSE or len(result.stderr) > 8192:
                raise ProbeError('Dedicated probe response exceeds size limit')
            return result
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ProbeError('Dedicated public probe transport failed; no fallback accepted') from None
