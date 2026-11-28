"""Preflight live Compose parity and installer command error boundaries."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
sys.path.insert(0, str(ROOT / 'install'))
import preflight
import installer
from core import Failure, app_registration, host_registration


class PreflightParity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)
        self.runtime = self.config / 'runtime.env'
        self.runtime.write_text('INITIAL_PASSWORD=fixture-only\nJWT_SECRET=x\nAPI_KEY_SECRET=y\nPUBLIC_URL=https://omni.test\nPUBLIC_API_URL=https://api.omni.test\n')
        self.registration = app_registration(ROOT, 'omniroute')
        self.binding = host_registration(ROOT, 'n1-oci-sin1-arm-4c24g')['apps']['omniroute']
        self.base = {
            'services': {name: {'container_name': name, 'environment': {'INITIAL_PASSWORD': 'fixture-only'},
                               'networks': ['edge'], 'volumes': [{'type': 'volume', 'target': '/app/data', 'source': 'data'}]}
                         for name in ('omniroute-blue', 'omniroute-green')},
            'networks': {'edge': {'name': 'edge-omniroute'}}, 'volumes': {'data': {'name': 'omniroute-data'}},
        }
        self.live = {'State': {'Running': True}, 'Config': {'Env': ['INITIAL_PASSWORD=fixture-only']},
                     'NetworkSettings': {'Networks': {'edge-omniroute': {}}},
                     'Mounts': [{'Type': 'volume', 'Destination': '/app/data', 'Name': 'omniroute-data'}]}

    def test_missing_runtime_env_fails(self):
        self.runtime.write_text('')
        with self.assertRaisesRegex(Failure, 'MISSING_RUNTIME_ENV'):
            preflight.check(ROOT, 'omniroute', self.registration, self.binding, self.runtime, None)

    def test_compose_parity(self):
        with mock.patch('preflight.container', return_value=self.live), \
             mock.patch('preflight.container_digest', return_value='fixture@sha256:' + 'a' * 64), \
             mock.patch('preflight.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(self.base).encode())):
            composed = preflight.check(ROOT, 'omniroute', self.registration, self.binding, self.runtime, None)
            self.assertEqual(set(composed['services']), {'omniroute-blue', 'omniroute-green'})


class InstallerCommandErrors(unittest.TestCase):
    def test_controller_error_survives_without_forwarding_secret_output(self):
        report = json.dumps({'status': 'failed', 'error_code': 'PUBLIC_HEALTH',
                             'detail': 'private credential'}).encode()
        result = SimpleNamespace(returncode=1, stdout=report, stderr=b'private credential')
        with mock.patch.object(installer.subprocess, 'run', return_value=result):
            with self.assertRaises(Failure) as caught:
                installer.run('/fixture/bin/deployctl', 'adopt', '--app', 'demo')
        self.assertEqual(caught.exception.code, 'PUBLIC_HEALTH')
        self.assertNotIn('private credential', str(caught.exception))

    def test_unstructured_or_foreign_command_output_stays_private(self):
        for command, output in (
                ('/fixture/bin/deployctl', b'private credential'),
                ('/fixture/bin/deployctl', b'[]'),
                ('/fixture/bin/deployctl', b'{"status":"failed","error_code":"private credential"}'),
                ('/bin/bash', b'{"status":"failed","error_code":"PUBLIC_HEALTH"}')):
            with self.subTest(command=command, output=output):
                result = SimpleNamespace(returncode=1, stdout=output, stderr=b'private credential')
                with mock.patch.object(installer.subprocess, 'run', return_value=result):
                    with self.assertRaises(Failure) as caught:
                        installer.run(command)
                self.assertEqual(caught.exception.code, 'COMMAND_FAILED')


class InstallerBusy(unittest.TestCase):
    def busy(self, operation, status):
        with tempfile.TemporaryDirectory() as name:
            state = Path(name)
            (state / 'state.json').write_text(json.dumps({'operation': operation}))
            (state / 'requests/gh-1').mkdir(parents=True)
            (state / 'requests/gh-1/result.json').write_text(json.dumps({'status': status}))
            with mock.patch.object(installer, 'trusted_path'), \
                    mock.patch.object(installer, 'run', return_value=SimpleNamespace(stdout=b'')):
                installer.busy('demo', state)

    def test_a_receipt_a_later_reconcile_settled_does_not_block(self):
        self.busy(None, 'recovery_required')

    def test_a_pending_intent_or_running_request_blocks(self):
        for operation, status in (({'phase': 'prepared'}, 'complete'), (None, 'running'), (None, 'queued')):
            with self.subTest(operation=operation, status=status), self.assertRaisesRegex(Failure, 'INSTALL_BUSY'):
                self.busy(operation, status)


if __name__ == '__main__':
    unittest.main()
