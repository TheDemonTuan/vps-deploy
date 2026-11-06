import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import app_registration, host_registration, parse_yaml, resource_collisions
from route import route_state

ROOT = Path(__file__).resolve().parents[1]


class OmniRoute(unittest.TestCase):
    def test_registration_has_no_resource_overlap(self):
        registration = app_registration(ROOT, 'omniroute')
        host = host_registration(ROOT, 'oracle-main')
        resource_collisions(host)
        self.assertEqual(registration['manifest']['image'], 'ghcr.io/thedemontuan/omniroute')
        self.assertNotIn('rtk', registration['manifest'])
        self.assertNotIn('cgw', registration['manifest'])

    def test_route_slot_identity_and_api_management_boundary(self):
        registration = app_registration(ROOT, 'omniroute')
        host = host_registration(ROOT, 'oracle-main')['apps']['omniroute']
        generation = 'a' * 32
        profile = dict(app='omniroute', registration=registration)
        for slot in ('blue', 'green'):
            raw = subprocess.check_output(['bash', str(ROOT / 'apps/omniroute/adapter.sh'),
                slot, generation, host['dashboard_host'], '', host['api_host']])
            self.assertEqual(route_state(raw, profile), (slot, generation))
            http = parse_yaml(raw)['http']
            routers = http['routers']
            self.assertEqual(routers['omniroute-api-fallback']['middlewares'], ['deny-internal'])
            self.assertEqual(routers['omniroute-deny-internal']['middlewares'], ['deny-internal'])
            self.assertIn('public-api-rate-limit', routers['omniroute-api-router']['middlewares'])
            self.assertIn('tunnel-only', routers['omniroute-dashboard-router']['middlewares'])
            self.assertEqual(http['services']['omniroute-service']['loadBalancer']['servers'],
                             [{'url': f'http://omniroute-{slot}:20128'}])

    def test_adapter_rejects_untrusted_route_arguments(self):
        valid = ['blue', 'a' * 32, 'omni.example.test', '', 'api.example.test']
        for position, value in ((0, 'red'), (1, 'not-a-generation'),
                                (2, 'bad` || Host(`foreign.test'), (3, 'foreign.test'),
                                (4, '127.0.0.1'), (4, 'omni.example.test')):
            arguments = valid.copy()
            arguments[position] = value
            result = subprocess.run(['bash', str(ROOT / 'apps/omniroute/adapter.sh'), *arguments],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')


if __name__ == '__main__':
    unittest.main()
