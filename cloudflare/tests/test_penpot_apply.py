import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from penpot_ingress import Failure, HOST, TUNNEL


class CloudflareFixture:
    account = 'a' * 32
    zone = 'b' * 32

    def __init__(self):
        self.writes = []
        self.dns = []
        self.apps = []
        self.tunnel = {'version': 3, 'config': {'warp-routing': {'enabled': False}, 'ingress': [
            {'hostname': '9router.tuannguyenviet.site', 'service': 'https://other'},
            {'service': 'http_status:404'}]}}
        self.cache = {'id': 'c' * 32, 'kind': 'zone', 'name': 'cache',
                      'phase': 'http_request_cache_settings', 'version': '1', 'rules': [
                          {'id': 'other-rule', 'description': '9router', 'expression': '(http.host eq "other")',
                           'action': 'set_cache_settings', 'action_parameters': {'cache': True}, 'enabled': True}]}
        self.drift = False
        self.connected = True

    def get(self, path):
        if path.startswith('/zones?'):
            result = [{'id': self.zone, 'name': 'tuannguyenviet.site', 'account': {'id': self.account}}]
        elif '/dns_records?' in path:
            result = self.dns
        elif path.endswith('/connections'):
            result = [{'is_pending_reconnect': False}] if self.connected else []
        elif path.endswith('/configurations'):
            result = self.tunnel
        elif '/access/apps?' in path:
            result = self.apps
        elif '/access/apps/' in path:
            result = next(app for app in self.apps if path.endswith('/' + app['id']))
        elif '/rulesets?' in path:
            result = [{key: value for key, value in self.cache.items() if key != 'rules'}] if self.cache else []
        elif '/rulesets/' in path:
            result = self.cache
        else:
            raise AssertionError(path)
        return copy.deepcopy(result)

    def request(self, method, path, body=None):
        self.writes.append((method, path, copy.deepcopy(body)))
        if path.endswith('/configurations'):
            if self.drift:
                raise AssertionError('Drift must be detected before write')
            self.tunnel = {'version': self.tunnel['version'] + 1, 'config': copy.deepcopy(body['config'])}
            return copy.deepcopy(self.tunnel)
        if '/dns_records' in path:
            record = dict(body, id='dns-id')
            self.dns = [record]
            return copy.deepcopy(record)
        if '/rulesets/' in path:
            self.cache = dict(body, id='c' * 32, version='2')
            return copy.deepcopy(self.cache)
        if '/access/apps/' in path:
            identity = path.rsplit('/', 1)[1]
            if method == 'DELETE':
                self.apps = [app for app in self.apps if app['id'] != identity]
                return {'id': identity}
            self.apps = [dict(body, id=identity) if app['id'] == identity else app for app in self.apps]
            return next(copy.deepcopy(app) for app in self.apps if app['id'] == identity)
        raise AssertionError(path)


class PenpotApplyTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('penpot_apply', ROOT / 'penpot_apply.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_apply_preserves_shared_tunnel_and_cache_and_is_idempotent(self):
        module = self.module()
        api = CloudflareFixture()
        other_route = copy.deepcopy(api.tunnel['config']['ingress'][0])
        other_rule = copy.deepcopy(api.cache['rules'][0])
        result = module.apply(api, api.account, lambda: None)
        self.assertEqual(result['status'], 'applied')
        self.assertEqual(api.tunnel['config']['ingress'][0], other_route)
        self.assertEqual(api.tunnel['config']['ingress'][-1], {'service': 'http_status:404'})
        self.assertEqual(api.tunnel['config']['warp-routing'], {'enabled': False})
        design = api.tunnel['config']['ingress'][1]
        self.assertEqual(design['originRequest']['noTLSVerify'], False)
        self.assertEqual(api.cache['rules'][0], other_rule)
        self.assertEqual(api.cache['rules'][1]['action_parameters'], {'cache': False})
        self.assertEqual(api.dns[0]['content'], TUNNEL + '.cfargotunnel.com')
        before = len(api.writes)
        module.apply(api, api.account, lambda: None)
        self.assertEqual(len(api.writes), before)

    def test_unverified_origin_and_conflicts_perform_zero_writes(self):
        module = self.module()
        for fault in ('origin', 'wildcard', 'dns', 'connector', 'cache'):
            api = CloudflareFixture()
            def origin():
                if fault == 'origin':
                    raise Failure('PENPOT_ORIGIN_NOT_READY')
            if fault == 'wildcard':
                api.apps = [{'id': 'access-id', 'domain': '*.tuannguyenviet.site'}]
            elif fault == 'dns':
                api.dns = [{'id': 'dns', 'name': HOST, 'type': 'CNAME', 'proxied': True, 'content': 'foreign'}]
            elif fault == 'connector':
                api.connected = False
            elif fault == 'cache':
                api.cache['rules'].append({'description': 'penpot-bypass-cache', 'expression': 'true',
                                           'action': 'set_cache_settings', 'action_parameters': {'cache': False}})
            with self.subTest(fault=fault), self.assertRaises(Failure):
                module.apply(api, api.account, origin)
            self.assertEqual(api.writes, [])

    def test_access_removes_only_design_and_preserves_other_domains_and_policy(self):
        module = self.module()
        api = CloudflareFixture()
        api.apps = [{'id': 'access-shared', 'name': 'shared', 'type': 'self_hosted', 'domain': HOST,
                     'self_hosted_domains': [HOST, 'other.tuannguyenviet.site'],
                     'session_duration': '24h', 'policies': [{'id': 'policy', 'decision': 'allow'}]},
                    {'id': 'dedicated', 'name': 'old-design', 'type': 'self_hosted', 'domain': HOST}]
        module.apply(api, api.account, lambda: None)
        self.assertEqual(len(api.apps), 1)
        self.assertEqual(api.apps[0]['domain'], 'other.tuannguyenviet.site')
        self.assertEqual(api.apps[0]['self_hosted_domains'], ['other.tuannguyenviet.site'])
        self.assertEqual(api.apps[0]['policies'], [{'id': 'policy', 'decision': 'allow'}])

    def test_drift_detected_before_tunnel_put(self):
        module = self.module()
        api = CloudflareFixture()
        reads = 0
        original = api.get
        def get(path):
            nonlocal reads
            if path.endswith('/configurations'):
                reads += 1
                if reads == 3:
                    api.tunnel['version'] += 1
                    api.drift = True
            return original(path)
        api.get = get
        with self.assertRaisesRegex(Failure, 'DRIFT'):
            module.apply(api, api.account, lambda: None)
        self.assertEqual(api.writes, [])

    def test_existing_design_ingress_retains_options_and_gets_tls_policy(self):
        module = self.module()
        api = CloudflareFixture()
        api.tunnel['config']['ingress'].insert(1, {'hostname': HOST, 'service': 'https://old',
                                                  'originRequest': {'connectTimeout': 10, 'noTLSVerify': True}})
        module.apply(api, api.account, lambda: None)
        self.assertEqual(api.tunnel['config']['ingress'][1]['originRequest']['connectTimeout'], 10)
        self.assertEqual(api.tunnel['config']['ingress'][1]['originRequest']['originServerName'], HOST)

    def test_partial_write_failure_can_resume_without_rewriting_shared_routes(self):
        module = self.module()
        api = CloudflareFixture()
        request = api.request
        failed = False
        def flaky(method, path, body=None):
            nonlocal failed
            value = request(method, path, body)
            if '/dns_records' in path and not failed:
                failed = True
                raise Failure('LOST_DNS_RESPONSE')
            return value
        api.request = flaky
        with self.assertRaisesRegex(Failure, 'LOST_DNS_RESPONSE'):
            module.apply(api, api.account, lambda: None)
        first_tunnel = copy.deepcopy(api.tunnel)
        result = module.apply(api, api.account, lambda: None)
        self.assertEqual(api.tunnel, first_tunnel)
        self.assertEqual(result['changes'], ['cache'])

    def test_cache_and_access_drift_do_not_overwrite_external_changes(self):
        module = self.module()
        for fault in ('cache', 'access'):
            api = CloudflareFixture()
            api.apps = [{'id': 'dedicated', 'name': 'old-design', 'type': 'self_hosted', 'domain': HOST}]
            original = api.get
            reads = 0
            def get(path):
                nonlocal reads
                selected = '/rulesets/' in path if fault == 'cache' else '/access/apps/' in path
                if selected:
                    reads += 1
                    # Cache is read once by survey and once by prepare.
                    if reads == (3 if fault == 'cache' else 2):
                        if fault == 'cache':
                            api.cache['rules'][0]['enabled'] = False
                        else:
                            api.apps[0]['name'] = 'changed-by-operator'
                return original(path)
            api.get = get
            with self.subTest(fault=fault), self.assertRaisesRegex(Failure, 'DRIFT'):
                module.apply(api, api.account, lambda: None)
            if fault == 'cache':
                self.assertFalse(api.cache['rules'][0]['enabled'])
                self.assertTrue(all('/rulesets/' not in path for _, path, _ in api.writes))
            else:
                self.assertEqual(api.apps[0]['name'], 'changed-by-operator')
                self.assertTrue(all('/access/apps/' not in path for _, path, _ in api.writes))

    def test_public_readiness_rejects_redirects_and_cloudflare_errors(self):
        from unittest import mock
        import urllib.error
        module = self.module()
        for code in (302, 403, 530):
            opener = mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError('https://' + HOST, code, 'failed', {}, None)
            with self.subTest(code=code), mock.patch.object(module.urllib.request, 'build_opener', return_value=opener), \
                    self.assertRaisesRegex(Failure, 'PUBLIC_READINESS_FAILED'):
                module.public_ready(timeout=0)
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'OK'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(module.urllib.request, 'build_opener', return_value=opener):
            module.public_ready(timeout=0)
        handler = module.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, '', {}, 'https://access.example'))

    def test_missing_catchall_or_foreign_access_type_fail_without_writes(self):
        module = self.module()
        for fault in ('catchall', 'access'):
            api = CloudflareFixture()
            if fault == 'catchall':
                api.tunnel['config']['ingress'].pop()
            else:
                api.apps = [{'id': 'id', 'domain': HOST, 'type': 'saas'}]
            with self.subTest(fault=fault), self.assertRaises(Failure):
                module.apply(api, api.account, lambda: None)
            self.assertEqual(api.writes, [])


if __name__ == '__main__':
    unittest.main()
