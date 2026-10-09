"""Retired automation stays absent; the gateway remains registered unchanged."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import Failure, app_registration, host_registration
import route
import operations

RETIRED = (
    'registry/opendesign.yml',
    'apps/opendesign/adapter.sh',
    'apps/opendesign/docker-compose.prod.yml',
    'apps/opendesign/rollback-compatibility.json',
    'hosts/oracle-main/opendesign-edge.override.yml',
    'hosts/oracle-main/opendesign-ingress.yml',
    'lib/recreate.py',
    'install/bootstrap-recreate.py',
    'install/activate-reviewed-release.py',
    'install/recover-reviewed-operation.py',
    'install/tune-reviewed-opendesign-waf.py',
    'install/smoke-opendesign-appsec.py',
    'scripts/activate-platform.py',
    'scripts/recover-opendesign.py',
    'scripts/tune-opendesign-waf.py',
    '.github/workflows/activate-platform.yml',
    '.github/workflows/recover-opendesign.yml',
    '.github/workflows/tune-opendesign-waf.yml',
    'security/crowdsec/opendesign-scope-smoke.json',
    'security/crowdsec/opendesign-message-body-config.yaml',
    'security/crowdsec/opendesign-crs-scope.yaml',
    'security/crowdsec/opendesign-cloudflare-cookie-rule.yaml',
    'security/crowdsec/opendesign-cloudflare-cookie-config.yaml',
)


class RetiredDeployment(unittest.TestCase):
    def test_retired_controllers_and_assets_are_not_in_new_releases(self):
        self.assertEqual([path for path in RETIRED if (ROOT / path).exists()], [])
        with self.assertRaisesRegex(Failure, 'APP_NOT_REGISTERED'):
            app_registration(ROOT, 'opendesign')

    def test_host_replaces_retired_app_without_changing_gateway(self):
        apps = host_registration(ROOT, 'oracle-main')['apps']
        self.assertEqual(set(apps), {'9router', 'penpot'})
        self.assertEqual(apps['9router'], {
            'api_host': '9router-api.tuannguyenviet.site',
            'dashboard_host': '9router.tuannguyenviet.site',
            'dashboard_alias_host': '9router-admin.tuannguyenviet.site',
            'work_dir': '/opt/9router', 'compose_project': '9router',
            'edge_network': 'edge-9router', 'rtk_network': '9router-rtk',
            'cgw_network': '9router-cgw', 'route_name': '9router.yml',
        })
        self.assertEqual(apps['penpot'], {
            'api_host': 'design.tuannguyenviet.site',
            'dashboard_host': '', 'dashboard_alias_host': '',
            'work_dir': '/opt/penpot', 'compose_project': 'penpot',
            'edge_network': 'edge-penpot', 'route_name': 'penpot.yml',
        })

    def test_retired_strategy_is_rejected_by_registry_and_schema(self):
        value = copy.deepcopy(app_registration(ROOT, '9router'))
        for key in ('rtk', 'cgw'):
            value['manifest'].pop(key, None)
        value['manifest']['strategy'] = 'recreate'
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'registry').mkdir()
            (root / 'registry/9router.yml').write_text(json.dumps(value))
            with self.assertRaisesRegex(Failure, 'REGISTRY_POLICY'):
                app_registration(root, '9router')
        schema = json.loads((ROOT / 'schema/app.schema.json').read_text())
        self.assertEqual(schema['properties']['strategy']['enum'], ['blue-green', 'penpot'])

    def test_retired_strategy_never_falls_through_to_gateway_route_or_probe(self):
        profile = {'app': 'demo', 'registration': {
            'manifest': {'strategy': 'recreate', 'runtime': {'port': 8080}},
            'route': {'generation_header': 'X-Demo-Generation'},
        }}
        raw = json.dumps({'http': {
            'services': {'demo-service': {'loadBalancer': {'servers': [{'url': 'http://demo-blue:8080'}]}}},
            'middlewares': {'demo-route-generation': {'headers': {
                'customResponseHeaders': {'X-Demo-Generation': 'a' * 32}}}},
        }}).encode()
        with self.assertRaisesRegex(Failure, 'ROUTE_SHAPE'):
            route.route_state(raw, profile)
        with mock.patch.object(route, 'command') as command, \
             mock.patch.object(route.subprocess, 'run') as run:
            with self.assertRaisesRegex(Failure, 'STRATEGY_MISMATCH'):
                route.probe(profile)
        command.assert_not_called()
        run.assert_not_called()

    def test_gateway_matching_rejects_singleton_before_inspection(self):
        state = {'active': {'slot': 'single', 'image': 'fixture'}, 'generation': 'a' * 32}
        with mock.patch.object(route, 'dynamic') as dynamic, \
             mock.patch.object(operations, 'container') as container, \
             mock.patch.object(operations, 'health') as health:
            with self.assertRaisesRegex(Failure, 'INVALID_STATE'):
                operations.matching(state, {'app': 'demo'})
        dynamic.assert_not_called()
        container.assert_not_called()
        health.assert_not_called()


if __name__ == '__main__':
    unittest.main()
