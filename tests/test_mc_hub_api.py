import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import app_registration, host_registration, parse_yaml
from route import route_state

ROOT = Path(__file__).resolve().parents[1]


class McHubApi(unittest.TestCase):
    def test_api_host_routes_only_ssr_reads(self):
        registration = app_registration(ROOT, 'mc-hub-api')
        host = host_registration(ROOT, 'oracle-main')['apps']['mc-hub-api']
        profile = dict(app='mc-hub-api', registration=registration)
        for slot in ('blue', 'green'):
            raw = subprocess.check_output(['bash', str(ROOT / 'apps/mc-hub-api/adapter.sh'),
                                           slot, 'a' * 32, '', '', host['api_host']])
            self.assertEqual(route_state(raw, profile), (slot, 'a' * 32))
            routers = parse_yaml(raw)['http']['routers']
            allowed = routers['mc-hub-api-router']
            # Admin and login exist only on the site host, behind Cloudflare Access.
            self.assertEqual(set(re.findall(r'Path(?:Prefix)?\(`([^`]*)`\)', allowed['rule'])),
                             {'/healthz', '/api/posts', '/api/posts/', '/api/pages/', '/api/settings', '/api/stats', '/api/auth/me'})
            self.assertIn('tunnel-only', allowed['middlewares'])
            fallback = routers['mc-hub-api-fallback']
            self.assertEqual((fallback['rule'], fallback['middlewares']), ('Host(`' + host['api_host'] + '`)', ['deny-internal']))
            self.assertLess(fallback['priority'], allowed['priority'])
            site = host_registration(ROOT, 'oracle-main')['apps']['mc-hub']['api_host']
            self.assertIn('Host(`' + site + '`)', routers['mc-hub-api-site-router']['rule'])


if __name__ == '__main__':
    unittest.main()
