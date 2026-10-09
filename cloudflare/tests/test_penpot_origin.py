import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import penpot_origin
from penpot_ingress import Failure


class PenpotOriginTests(unittest.TestCase):
    def evidence(self):
        return {'app': 'penpot', 'host': 'oracle-main', 'platformRef': 'a' * 40, 'sourceSha': 'b' * 40,
                'generation': 'c' * 32, 'healthy': True, 'origin_tls_verified': True,
                'images': {role: 'ghcr.io/thedemontuan/penpot-' + role + '@sha256:' + 'd' * 64
                           for role in ('frontend', 'backend', 'exporter', 'mcp')}}

    def environment(self):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'TheDemonTuan/vps-deploy',
                'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'a' * 40,
                'VPS_PLATFORM_ADMIN_SSH_KEY': 'secret-canary-key'}

    def test_repeated_checks_use_pinned_ssh_and_remove_temporary_identity(self):
        evidence = self.evidence()
        blob = b'fake-ed25519-public-blob'
        key = base64.b64encode(blob).decode()
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        files = []
        def run(argv, **kwargs):
            if argv[0].endswith('ssh-keyscan'):
                return types.SimpleNamespace(returncode=0, stdout=('host ssh-ed25519 ' + key + '\n').encode())
            private = Path(argv[argv.index('-i') + 1])
            files.append(private)
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('UpdateHostKeys=no', argv)
            self.assertIn('HostKeyAlgorithms=ssh-ed25519', argv)
            self.assertNotIn('secret-canary-key', str(argv))
            self.assertEqual(kwargs['input'], (ROOT.parent / 'install/check-penpot-origin.py').read_bytes())
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(evidence).encode())
        with mock.patch.dict(penpot_origin.os.environ, self.environment(), clear=True), \
                mock.patch.object(penpot_origin, 'FINGERPRINT', fingerprint), mock.patch.object(penpot_origin, 'run', run):
            check = penpot_origin.verifier()
            self.assertNotIn('VPS_PLATFORM_ADMIN_SSH_KEY', penpot_origin.os.environ)
            self.assertEqual(check(), evidence)
            self.assertEqual(check(), evidence)
        self.assertEqual(len(files), 2)
        self.assertTrue(all(not path.exists() for path in files))

    def test_caller_and_wrong_host_key_fail_before_ssh(self):
        env = self.environment()
        env['GITHUB_REF'] = 'refs/heads/develop'
        with mock.patch.dict(penpot_origin.os.environ, env, clear=True), mock.patch.object(penpot_origin, 'run') as run:
            with self.assertRaisesRegex(Failure, 'CALLER_POLICY'):
                penpot_origin.verifier()
            run.assert_not_called()
        calls = []
        def scan(argv, **kwargs):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0, stdout=b'host ssh-ed25519 YWJj\n')
        with mock.patch.dict(penpot_origin.os.environ, self.environment(), clear=True), mock.patch.object(penpot_origin, 'run', scan):
            with self.assertRaisesRegex(Failure, 'HOST_KEY_MISMATCH'):
                penpot_origin.verifier()()
        self.assertEqual(len(calls), 1)

    def test_receipt_rejects_unhealthy_foreign_and_mixed_release(self):
        for field, value in [('healthy', False), ('origin_tls_verified', False), ('platformRef', 'f' * 40),
                             ('app', '9router'), ('generation', 'not-a-generation')]:
            evidence = self.evidence()
            evidence[field] = value
            with self.subTest(field=field), self.assertRaises(Failure):
                penpot_origin.receipt(evidence, 'a' * 40)
        evidence = self.evidence()
        evidence['images']['mcp'] = 'ghcr.io/foreign/mcp@sha256:' + 'd' * 64
        with self.assertRaises(Failure):
            penpot_origin.receipt(evidence, 'a' * 40)

    def test_root_checker_rejects_nonroot_without_loading_engine(self):
        spec = importlib.util.spec_from_file_location('origin_check', ROOT.parent / 'install/check-penpot-origin.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module.os, 'geteuid', return_value=1000), mock.patch.object(module.runpy, 'run_path') as load:
            with self.assertRaisesRegex(RuntimeError, 'ORIGIN_SCOPE_POLICY'):
                module.check('a' * 40)
            load.assert_not_called()

    def test_workflow_main_only_dispatch_and_apply_requires_admin_environment(self):
        import yaml
        text = (ROOT.parent / '.github/workflows/penpot-ingress.yml').read_text()
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(workflow['on']['workflow_dispatch']['inputs']['operation']['options'], ['survey', 'apply'])
        self.assertEqual(workflow['jobs']['apply']['environment'], 'platform-admin')
        for name in ('survey', 'apply'):
            self.assertIn("github.ref == 'refs/heads/main'", workflow['jobs'][name]['if'])
            self.assertIn("github.repository == 'TheDemonTuan/vps-deploy'", workflow['jobs'][name]['if'])
        self.assertNotIn('push', workflow['on'])
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], 'false')


if __name__ == '__main__':
    unittest.main()
