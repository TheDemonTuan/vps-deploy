import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import core

ROOT = Path(__file__).resolve().parents[1]
ROLES = ('frontend', 'backend', 'exporter', 'mcp')
REPOSITORIES = {role: 'ghcr.io/thedemontuan/penpot-' + role for role in ROLES}
MANIFEST = {
    'version': 1, 'app': 'penpot', 'strategy': 'penpot', 'images': REPOSITORIES,
    'platform': 'linux/arm64', 'runtime': {'port': 8080},
    'health': {'path': '/readyz', 'timeout_seconds': 180},
    'route': {'timeout_seconds': 30},
}


def registration():
    return {
        'version': 1, 'app': 'penpot', 'host': 'oracle-main',
        'caller': {
            'repository': 'TheDemonTuan/penpot', 'ref': 'refs/heads/main',
            'refs': ['refs/heads/main'], 'config': '.deploy/app.yml',
            'build_workflows': ['fork-deploy.yml'],
            'security_workflows': ['fork-deploy.yml'],
            'deploy_workflows': ['fork-deploy.yml', 'fork-ops.yml'],
        },
        'manifest': copy.deepcopy(MANIFEST),
        'runtime': {
            'allowed_env': ['PENPOT_SECRET_KEY', 'PENPOT_DB_PASSWORD'],
            'required_env': ['PENPOT_SECRET_KEY', 'PENPOT_DB_PASSWORD'],
        },
        'route': {
            'generation_header': 'X-Penpot-Route-Generation',
            'required_middlewares': ['tunnel-only', 'crowdsec-ip'],
        },
    }


def profile():
    return {'app': 'penpot', 'registration': registration(), 'image_repositories': REPOSITORIES}


def deploy_request():
    return {
        'version': 1, 'op': 'deploy', 'app': 'penpot', 'component': 'app',
        'request_id': 'gh-123-1-app', 'platform_ref': 'a' * 40,
        'source_sha': 'b' * 40, 'manifest_sha256': 'c' * 64,
        'images': {role: repo + '@sha256:' + 'd' * 64 for role, repo in REPOSITORIES.items()},
    }


class PenpotContract(unittest.TestCase):
    def checked_registration(self, value):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / 'registry'
            directory.mkdir()
            (directory / 'penpot.yml').write_text(yaml.safe_dump(value))
            return core.app_registration(directory.parent, 'penpot')

    def test_registered_manifest_has_four_repositories_and_no_primary_image(self):
        self.assertEqual(self.checked_registration(registration())['manifest'], MANIFEST)

    def test_production_registry_matches_fork_manifest_exactly(self):
        value = core.app_registration(ROOT, 'penpot')
        self.assertEqual(value['manifest'], MANIFEST)

    def test_registry_rejects_missing_extra_foreign_or_primary_images(self):
        mutations = []
        value = registration()
        del value['manifest']['images']['mcp']
        mutations.append(value)
        value = registration()
        value['manifest']['images']['admin'] = 'ghcr.io/thedemontuan/admin'
        mutations.append(value)
        value = registration()
        value['manifest']['images']['backend'] = 'ghcr.io/other/backend'
        mutations.append(value)
        for forbidden in ('image', 'build', 'rtk', 'cgw'):
            value = registration()
            value['manifest'][forbidden] = {'image': 'ghcr.io/other/image'}
            mutations.append(value)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(core.Failure):
                self.checked_registration(value)

    def test_penpot_strategy_cannot_be_assigned_to_another_app(self):
        value = registration()
        value['app'] = value['manifest']['app'] = '9router'
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name) / 'registry'
            directory.mkdir()
            (directory / '9router.yml').write_text(yaml.safe_dump(value))
            with self.assertRaises(core.Failure):
                core.app_registration(directory.parent, '9router')

    def test_complete_digest_map_is_preserved(self):
        value = deploy_request()
        self.assertEqual(core.request(core.json_bytes(value), profile()), value)

    def test_request_rejects_incomplete_extra_tagged_mixed_and_foreign_maps(self):
        mutations = []
        value = deploy_request()
        del value['images']['mcp']
        mutations.append(value)
        value = deploy_request()
        value['images']['admin'] = 'ghcr.io/thedemontuan/admin@sha256:' + 'd' * 64
        mutations.append(value)
        for image in ('ghcr.io/thedemontuan/penpot-backend:latest',
                      'ghcr.io/thedemontuan/penpot-backend:sha-abcd@sha256:' + 'd' * 64,
                      'ghcr.io/other/backend@sha256:' + 'd' * 64,
                      REPOSITORIES['frontend'] + '@sha256:' + 'd' * 64, None, 3):
            value = deploy_request()
            value['images']['backend'] = image
            mutations.append(value)
        value = deploy_request()
        value['image'] = value['images']['frontend']
        mutations.append(value)
        value = deploy_request()
        value['component'] = 'rtk'
        mutations.append(value)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(core.Failure):
                core.request(core.json_bytes(value), profile())

    def test_duplicate_role_is_rejected_before_validation(self):
        raw = json.dumps(deploy_request()).replace('"images": {', '"images": {"mcp": "bad", ')
        with self.assertRaisesRegex(core.Failure, 'DUPLICATE_KEY'):
            core.request(raw.encode(), profile())

    def test_status_and_reconcile_reject_image_maps(self):
        for op in ('status', 'reconcile'):
            value = deploy_request()
            value['op'] = op
            if op == 'status':
                value = {key: value[key] for key in ('version', 'op', 'app', 'request_id', 'images')}
            with self.subTest(op=op), self.assertRaises(core.Failure):
                core.request(core.json_bytes(value), profile())

    def test_image_only_rollback_is_rejected_at_request_boundary(self):
        value = deploy_request()
        del value['images']
        value['op'] = 'rollback'
        with self.assertRaisesRegex(core.Failure, 'PENPOT_ROLLBACK_REQUIRES_OFFLINE_RESTORE'):
            core.request(core.json_bytes(value), profile())

    def test_blue_green_still_rejects_image_maps(self):
        existing = core.app_registration(ROOT, '9router')
        value = deploy_request()
        value['app'] = '9router'
        with self.assertRaises(core.Failure):
            core.request(core.json_bytes(value), {'app': '9router', 'registration': existing,
                                                 'image_repository': existing['manifest']['image']})


if __name__ == '__main__':
    unittest.main()
