import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location('uptimeflare_probe', Path(__file__).parents[1] / 'uptimeflare_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTransportTests(unittest.TestCase):
    def setUp(self):
        self.key = b'public-host-key'
        self.scan = SimpleNamespace(returncode=0, stdout=probe.HOST.encode() + b' ssh-ed25519 ' + base64.b64encode(self.key) + b'\n')
        self.fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(self.key).digest()).decode().rstrip('=')
        self.previous = probe._KEY
        probe._KEY = None
        self.addCleanup(setattr, probe, '_KEY', self.previous)

    def test_pin_matches_registered_oracle_host(self):
        host = yaml.safe_load((Path(__file__).parents[2] / 'hosts/oracle-main.yml').read_text())['ssh']
        self.assertEqual(probe.HOST, host['address'])
        self.assertEqual(probe.FINGERPRINT, host['fingerprint'])
        self.assertEqual(host['port'], 22)

    def test_repeated_calls_isolate_secret_and_enforce_fixed_command(self):
        identities = []
        def run(command, **kwargs):
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            if command[0].endswith('ssh-keyscan'):
                return self.scan
            self.assertEqual(command[-2:], [probe.USER + '@' + probe.HOST, 'probe'])
            self.assertIn('ClearAllForwardings=yes', command)
            self.assertIn('StrictHostKeyChecking=yes', command)
            identity = Path(command[command.index('-i') + 1])
            identities.append(identity)
            self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            self.assertEqual(identity.read_text(), 'private-canary\n')
            self.assertNotIn('private-canary', repr(command))
            self.assertEqual(json.loads(kwargs['input']), {'web_sha': '', 'monitor_sha': ''})
            return SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')
        with patch.dict(os.environ, {'UPTIMEFLARE_PROBE_SSH_KEY': 'private-canary', 'CLOUDFLARE_API_TOKEN': 'cf-canary', 'GH_TOKEN': 'gh-canary'}, clear=True), patch.object(probe, 'FINGERPRINT', self.fingerprint), patch.object(probe.subprocess, 'run', side_effect=run):
            for _ in range(2):
                probe.invoke(b'{"web_sha":"","monitor_sha":""}')
            self.assertNotIn('UPTIMEFLARE_PROBE_SSH_KEY', os.environ)
        self.assertTrue(identities)
        self.assertTrue(all(not identity.exists() for identity in identities))

    def test_changed_host_key_fails_before_ssh(self):
        with patch.dict(os.environ, {'UPTIMEFLARE_PROBE_SSH_KEY': 'private-canary'}, clear=True), patch.object(probe.subprocess, 'run', return_value=self.scan) as run:
            with self.assertRaisesRegex(probe.ProbeError, 'fingerprint mismatch'):
                probe.invoke(b'{}')
            self.assertEqual(run.call_count, 1)

    def test_missing_key_never_contacts_host(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(probe.subprocess, 'run') as run:
            with self.assertRaises(probe.ProbeError):
                probe.invoke(b'{}')
            run.assert_not_called()

    def test_oversized_request_never_contacts_host(self):
        with patch.object(probe.subprocess, 'run') as run:
            with self.assertRaisesRegex(probe.ProbeError, 'size limit'):
                probe.invoke(b'x' * 2049)
            run.assert_not_called()

    def test_oversized_remote_evidence_fails_closed(self):
        result = SimpleNamespace(returncode=0, stdout=b'x' * (probe.MAX_RESPONSE + 1), stderr=b'')
        with patch.dict(os.environ, {'UPTIMEFLARE_PROBE_SSH_KEY': 'private-canary'}, clear=True), patch.object(probe, 'FINGERPRINT', self.fingerprint), patch.object(probe.subprocess, 'run', side_effect=[self.scan, result]):
            with self.assertRaisesRegex(probe.ProbeError, 'size limit'):
                probe.invoke(b'{}')

    def test_transport_exception_never_leaks_sensitive_details(self):
        with patch.dict(os.environ, {'UPTIMEFLARE_PROBE_SSH_KEY': 'private-canary'}, clear=True), patch.object(probe.subprocess, 'run', side_effect=OSError('private-error')):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.invoke(b'{}')
        self.assertNotIn('private-', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
