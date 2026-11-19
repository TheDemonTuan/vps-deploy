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
            hosts = '(Host(`' + site + '`) || Host(`thedemontuan.dev`))'
            self.assertTrue(routers['mc-hub-api-site-router']['rule'].startswith(hosts + ' && '))
            # SSR reads all come from the VPS: a per-IP limit there would throttle every reader at once.
            self.assertFalse({'mc-hub-api-rate-limit', 'mc-hub-api-inflight'} & set(allowed['middlewares']))
            reads, writes = routers['mc-hub-api-site-router'], routers['mc-hub-api-site-write']
            self.assertIn('mc-hub-api-rate-limit', reads['middlewares'])
            self.assertEqual(writes['rule'], hosts + ' && Method(`POST`) && PathPrefix(`/api/`) && !PathPrefix(`/api/admin/`)')
            self.assertGreater(writes['priority'], reads['priority'])
            self.assertEqual(writes['middlewares'][:3], ['mc-hub-api-route-generation', 'tunnel-only', 'mc-hub-api-write-rate-limit'])
            self.assertIn('mc-hub-api-write-body-limit', writes['middlewares'])
            limiters = parse_yaml(raw)['http']['middlewares']
            for name in ('mc-hub-api-rate-limit', 'mc-hub-api-write-rate-limit', 'mc-hub-api-inflight'):
                key = next(iter(limiters[name].values()))['sourceCriterion']
                self.assertEqual(key, {'requestHeaderName': 'CF-Connecting-IP'})

    def test_site_pages_are_rate_limited_per_visitor(self):
        site = host_registration(ROOT, 'oracle-main')['apps']['mc-hub']['api_host']
        raw = subprocess.check_output(['bash', str(ROOT / 'apps/mc-hub/adapter.sh'), 'blue', 'a' * 32, '', '', site])
        http = parse_yaml(raw)['http']
        router = http['routers']['mc-hub-router']
        self.assertEqual(router['rule'], 'Host(`' + site + '`) || Host(`thedemontuan.dev`)')
        self.assertEqual(router['middlewares'][:4], ['mc-hub-route-generation', 'tunnel-only', 'mc-hub-rate-limit', 'mc-hub-inflight'])
        self.assertEqual(http['middlewares']['mc-hub-rate-limit']['rateLimit']['sourceCriterion'], {'requestHeaderName': 'CF-Connecting-IP'})
        # /internal stays denied on both domains.
        self.assertEqual(http['routers']['mc-hub-deny-internal']['rule'], '(Host(`' + site + '`) || Host(`thedemontuan.dev`)) && PathPrefix(`/internal`)')


if __name__ == '__main__':
    unittest.main()
