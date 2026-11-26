import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import app_registration, host_registration, parse_yaml
from route import route_state

ROOT = Path(__file__).resolve().parents[1]


def render(app, slot='blue'):
    binding = host_registration(ROOT, 'oracle-main')['apps'][app]
    return subprocess.check_output(['bash', str(ROOT / 'apps' / app / 'adapter.sh'), slot, 'a' * 32,
                                    binding['dashboard_host'], binding['dashboard_alias_host'], binding['api_host']])


def host_rule(app):
    # A host's domain, then its fallback alias (the previous domain) when the registry names one.
    binding = host_registration(ROOT, 'oracle-main')['apps'][app]
    return ' || '.join('Host(`' + host + '`)' for host in (binding['api_host'], binding['dashboard_alias_host']) if host)


class McHubApi(unittest.TestCase):
    def test_api_host_routes_only_ssr_reads(self):
        registration = app_registration(ROOT, 'mc-hub-api')
        profile = dict(app='mc-hub-api', registration=registration)
        api = host_rule('mc-hub-api')
        for slot in ('blue', 'green'):
            raw = render('mc-hub-api', slot)
            self.assertEqual(route_state(raw, profile), (slot, 'a' * 32))
            routers = parse_yaml(raw)['http']['routers']
            allowed = routers['mc-hub-api-router']
            self.assertTrue(allowed['rule'].startswith('(' + api + ') && ('))
            # Admin and login exist only on the site host, behind Cloudflare Access.
            self.assertEqual(set(re.findall(r'Path(?:Prefix)?\(`([^`]*)`\)', allowed['rule'])),
                             {'/healthz', '/api/posts', '/api/posts/', '/api/pages/', '/api/settings', '/api/stats', '/api/auth/me'})
            self.assertIn('tunnel-only', allowed['middlewares'])
            fallback = routers['mc-hub-api-fallback']
            self.assertEqual((fallback['rule'], fallback['middlewares']), (api, ['deny-internal']))
            self.assertLess(fallback['priority'], allowed['priority'])
            self.assertEqual(routers['mc-hub-api-deny-internal']['rule'], '(' + api + ') && PathPrefix(`/internal`)')
            sites = '(Host(`thedemontuan.dev`) || Host(`tuannguyenviet.site`))'
            self.assertTrue(routers['mc-hub-api-site-router']['rule'].startswith(sites + ' && '))
            # SSR reads all come from the VPS: a per-IP limit there would throttle every reader at once.
            self.assertFalse({'mc-hub-api-rate-limit', 'mc-hub-api-inflight'} & set(allowed['middlewares']))
            # SSR on the same node: plain HTTP on "internal", the same reads, loopback/mc-hub only.
            internal = routers['mc-hub-api-internal']
            self.assertEqual((internal['entryPoints'], internal['middlewares'][0]), (['internal'], 'internal-only'))
            self.assertEqual(set(re.findall(r'Path(?:Prefix)?\(`([^`]*)`\)', internal['rule'])),
                             set(re.findall(r'Path(?:Prefix)?\(`([^`]*)`\)', allowed['rule'])) - {'/healthz'})
            self.assertNotIn('Host(', internal['rule'])
            reads, writes = routers['mc-hub-api-site-router'], routers['mc-hub-api-site-write']
            self.assertIn('mc-hub-api-rate-limit', reads['middlewares'])
            self.assertEqual(writes['rule'], sites + ' && Method(`POST`) && PathPrefix(`/api/`) && !PathPrefix(`/api/admin/`)')
            self.assertGreater(writes['priority'], reads['priority'])
            self.assertEqual(writes['middlewares'][:3], ['mc-hub-api-route-generation', 'tunnel-only', 'mc-hub-api-write-rate-limit'])
            self.assertIn('mc-hub-api-write-body-limit', writes['middlewares'])
            limiters = parse_yaml(raw)['http']['middlewares']
            for name in ('mc-hub-api-rate-limit', 'mc-hub-api-write-rate-limit', 'mc-hub-api-inflight'):
                key = next(iter(limiters[name].values()))['sourceCriterion']
                self.assertEqual(key, {'requestHeaderName': 'CF-Connecting-IP'})

    def test_site_pages_are_rate_limited_per_visitor(self):
        http = parse_yaml(render('mc-hub'))['http']
        router = http['routers']['mc-hub-router']
        self.assertEqual(router['rule'], host_rule('mc-hub'))
        self.assertEqual(router['middlewares'][:4], ['mc-hub-route-generation', 'tunnel-only', 'mc-hub-rate-limit', 'mc-hub-inflight'])
        self.assertEqual(http['middlewares']['mc-hub-rate-limit']['rateLimit']['sourceCriterion'], {'requestHeaderName': 'CF-Connecting-IP'})
        # /internal stays denied on every domain the site answers.
        self.assertEqual(http['routers']['mc-hub-deny-internal']['rule'], '(' + host_rule('mc-hub') + ') && PathPrefix(`/internal`)')

    def test_adapters_refuse_malformed_hosts(self):
        for app in ('mc-hub', 'mc-hub-api'):
            for alias, api in (('', 'bad host'), ('`) || Host(`x.y', 'a.b'), ('', 'nodot')):
                with self.subTest(app=app, api=api, alias=alias):
                    result = subprocess.run(['bash', str(ROOT / 'apps' / app / 'adapter.sh'), 'blue', 'a' * 32, '', alias, api],
                                            capture_output=True)
                    self.assertEqual(result.returncode, 2)

    def test_domain_copies_follow_the_registry(self):
        # Moving domains edits hosts/oracle-main.yml; these few literal copies must cover it.
        apps = host_registration(ROOT, 'oracle-main')['apps']
        site_hosts = {apps['mc-hub']['api_host'], apps['mc-hub']['dashboard_alias_host']} - {''}
        routers = parse_yaml(render('mc-hub-api'))['http']['routers']
        api_site_hosts = set(re.findall(r'Host\(`([^`]*)`\)', routers['mc-hub-api-site-router']['rule']))
        self.assertLessEqual(site_hosts, api_site_hosts)
        scope = (ROOT / 'platform/crowdsec/config/appsec-configs/local-mc-hub-bot-scope.yaml').read_text()
        self.assertLessEqual(site_hosts, set(re.findall(r'"([a-z0-9.-]+\.[a-z]+)"', scope.split('ExemptFromChallenge("not-mc-hub")')[0])))
        # Compose files use anchors, which parse_yaml refuses; read the one line instead.
        def env(app, key):
            return re.search(r'^  ' + key + r': (\S+)$', (ROOT / 'apps' / app / 'docker-compose.prod.yml').read_text(), re.M).group(1)
        self.assertIn(env('mc-hub-api', 'SITE_URL').removeprefix('https://'), api_site_hosts)
        self.assertEqual(env('mc-hub', 'API_URL'), 'http://edge-traefik:8082')
        tofu = (ROOT / 'cloudflare/tofu/rulesets.tf').read_text()
        waf = {name: re.search(r'\b' + name + r'\s*=\s*"([^"]*)"', tofu).group(1) for name in ('mc_hub_site', 'mc_hub_api_host', 'mc_hub_api_alias')}
        self.assertEqual(waf, {'mc_hub_site': apps['mc-hub']['api_host'], 'mc_hub_api_host': apps['mc-hub-api']['api_host'],
                               'mc_hub_api_alias': apps['mc-hub-api']['dashboard_alias_host']})

    def test_edge_waf_admits_every_api_host_read(self):
        # Cloudflare blocks the rest of an API host (cloudflare/tofu/rulesets.tf): a read added to the
        # router but not there would be refused at the edge.
        tofu = (ROOT / 'cloudflare/tofu/rulesets.tf').read_text()
        def waf(name):
            return set(re.findall(r'"([^"]*)"', re.search(r'\b' + name + r'\s*=\s*\[([^\]]*)\]', tofu).group(1)))
        rule = parse_yaml(render('mc-hub-api'))['http']['routers']['mc-hub-api-router']['rule']
        self.assertEqual(waf('api_host_paths'), set(re.findall(r'Path\(`([^`]*)`\)', rule)))
        self.assertEqual(waf('api_host_prefixes'), set(re.findall(r'PathPrefix\(`([^`]*)`\)', rule)))


if __name__ == '__main__':
    unittest.main()
