import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

from test_penpot_contract import ROOT, deploy_request, registration


class PenpotCaller(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        (self.directory / 'platform/registry').mkdir(parents=True)
        (self.directory / 'platform/hosts').mkdir()
        (self.directory / 'platform/registry/penpot.yml').write_text(yaml.safe_dump(registration()))
        (self.directory / 'platform/hosts/oracle-main.yml').write_bytes((ROOT / 'hosts/oracle-main.yml').read_bytes())
        self.env = {
            **os.environ, 'APP': 'penpot', 'HOST': 'oracle-main',
            'CALLER_REPO': 'TheDemonTuan/penpot', 'CALLER_REF': 'refs/heads/main',
            'CALLER_SHA': 'a' * 40, 'SOURCE_SHA': 'a' * 40,
            'ACTION_REF': 'b' * 40, 'PLATFORM_REF': 'b' * 40,
            'CONFIG': '.deploy/app.yml', 'COMPONENT': 'app', 'OPERATION': 'deploy',
            'IMAGE_REF': '', 'IMAGES': json.dumps(deploy_request()['images']),
        }

    def check(self, workflow='deploy/action.yml', **changes):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/check-caller.py'), workflow, '--preflight'],
                              cwd=self.directory, env={**self.env, **changes}, capture_output=True, text=True)

    def test_complete_release_passes_and_invalid_map_fails_before_checkout(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = deploy_request()['images']
        for changes in ({'IMAGE_REF': value['frontend']}, {'IMAGES': '{}'},
                        {'IMAGES': json.dumps({**value, 'admin': value['frontend']})},
                        {'IMAGES': json.dumps({**value, 'mcp': value['frontend']})},
                        {'IMAGES': '{"mcp":"a","mcp":"b"}'},
                        {'CALLER_REF': 'refs/heads/develop'}, {'CALLER_REPO': 'attacker/penpot'},
                        {'SOURCE_SHA': 'c' * 40}, {'ACTION_REF': 'c' * 40}):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.check(**changes).returncode, 0)

    def test_only_status_and_reconcile_accept_no_images(self):
        for operation in ('status', 'reconcile'):
            result = self.check(OPERATION=operation, IMAGES='')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotEqual(self.check(OPERATION=operation).returncode, 0)
        self.assertNotEqual(self.check(OPERATION='rollback', IMAGES='').returncode, 0)

    def test_native_builder_accepts_only_registered_penpot_inputs(self):
        result = self.check('build-penpot.yml', OPERATION='build', IMAGES='')
        self.assertEqual(result.returncode, 0, result.stderr)
        for changes in ({'COMPONENT': 'cgw'}, {'COMPONENT': 'rtk'}, {'IMAGES': self.env['IMAGES']}):
            self.assertNotEqual(self.check('build-penpot.yml', OPERATION='build', **changes).returncode, 0)
        self.assertNotEqual(self.check('build-docker.yml', OPERATION='build', IMAGES='').returncode, 0)

    def test_scans_bind_each_role_to_its_registered_repository(self):
        for role, image in deploy_request()['images'].items():
            result = self.check('security-trivy.yml', SCAN_MODE='image', IMAGE_REF=image, IMAGE_ROLE=role, IMAGES='')
            self.assertEqual(result.returncode, 0, result.stderr)
            wrong = 'mcp' if role != 'mcp' else 'frontend'
            self.assertNotEqual(self.check('security-trivy.yml', SCAN_MODE='image', IMAGE_REF=image, IMAGE_ROLE=wrong, IMAGES='').returncode, 0)
        self.assertNotEqual(self.check('security-trivy.yml', SCAN_MODE='image', IMAGE_REF=deploy_request()['images']['mcp'], IMAGE_ROLE='', IMAGES='').returncode, 0)
        self.assertEqual(self.check('security-trivy.yml', SCAN_MODE='source', IMAGE_REF='', IMAGE_ROLE='', IMAGES='').returncode, 0)


class PenpotReceipt(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('penpot_transport', ROOT / 'scripts/ssh-request.py')
        self.transport = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.transport)
        self.payload = deploy_request()
        self.args = SimpleNamespace(operation='deploy', component='app', app='penpot',
                                    request_id=self.payload['request_id'], source_sha=self.payload['source_sha'],
                                    platform_ref=self.payload['platform_ref'], images=self.payload['images'], image='')
        self.answer = {'status': 'complete', 'healthy': True, 'images': self.payload['images'],
                       'source_sha': self.payload['source_sha'], 'platform_ref': self.payload['platform_ref'],
                       'active': 'single', 'configured_generation': 'generation', 'draining': None}

    def run_dispatch(self, answer):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        responder = root / 'responder.py'
        responder.write_text('import json,sys\njson.load(sys.stdin)\nprint(' + repr(json.dumps(answer)) + ')\n')
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(root / 'summary')}):
            with mock.patch('builtins.print'):
                self.transport.dispatch(self.args, self.payload, [sys.executable, str(responder)])
        return (root / 'summary').read_text()

    def test_receipt_proves_entire_map_and_source(self):
        summary = self.run_dispatch(self.answer)
        self.assertIn('penpot-frontend@sha256:', summary)
        self.assertIn(self.payload['source_sha'], summary)

    def test_wrong_missing_or_extra_digest_or_source_is_rejected(self):
        for mutation in ('missing', 'extra', 'foreign', 'source'):
            answer = copy.deepcopy(self.answer)
            if mutation == 'missing':
                del answer['images']['mcp']
            elif mutation == 'extra':
                answer['images']['admin'] = 'foreign'
            elif mutation == 'foreign':
                answer['images']['backend'] = answer['images']['frontend']
            else:
                answer['source_sha'] = 'e' * 40
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.run_dispatch(answer)


if __name__ == '__main__':
    unittest.main()
