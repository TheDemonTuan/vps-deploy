import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'penpot_ingress.py'


class PenpotIngressSurvey(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('penpot_ingress', PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def survey(self, fault=None):
        module = self.module()
        account = 'a' * 32
        calls = []
        def api(path):
            calls.append(path)
            if path.startswith('/zones?'):
                return [{'id': 'b' * 32, 'name': module.ZONE, 'account': {'id': account}}]
            if '/dns_records?' in path:
                return [{'id': 'dns-id', 'name': module.HOST, 'type': 'CNAME', 'proxied': True,
                         'content': ('foreign.example' if fault == 'dns' else module.TUNNEL + '.cfargotunnel.com')}]
            if path.endswith('/connections'):
                return [] if fault == 'connector' else [{'id': 'connector-id', 'is_pending_reconnect': False}]
            if path.endswith('/configurations'):
                return {'version': 7, 'config': {'ingress': [{'service': 'http_status:404'}]}}
            if '/access/apps?' in path:
                return [{'id': 'access-id', 'domain': '*.tuannguyenviet.site'}] if fault == 'access' else []
            if '/rulesets?' in path:
                return []
            raise AssertionError(path)
        result = module.survey(api, account)
        self.assertTrue(all(path.startswith(('/zones', '/accounts')) for path in calls))
        return result

    def test_survey_is_sanitized_and_read_only(self):
        value = self.survey()
        self.assertEqual(value['status'], 'read_only')
        self.assertEqual(value['tunnel_version'], 7)
        self.assertEqual(value['conflicts'], [])
        self.assertNotIn('config', value)

    def test_foreign_dns_inactive_connector_and_wildcard_access_are_conflicts(self):
        for fault, expected in [('dns', 'DNS_OWNERSHIP_CONFLICT'), ('connector', 'ACTIVE_CONNECTOR_REQUIRED'),
                                ('access', 'ACCESS_SCOPE_CONFLICT')]:
            with self.subTest(fault=fault):
                self.assertIn(expected, self.survey(fault)['conflicts'])

    def test_incomplete_paginated_and_oversized_responses_fail_closed(self):
        import json
        from unittest import mock
        module = self.module()
        for raw, error in [(json.dumps({'success': True, 'result': [], 'result_info': {'total_pages': 2}}).encode(),
                            'CLOUDFLARE_PAGINATION_REQUIRED'),
                           (b'x' * (4 * 1024 * 1024 + 1), 'CLOUDFLARE_RESPONSE_TOO_LARGE')]:
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = raw
            with self.subTest(error=error), mock.patch.dict(module.os.environ, {
                    'CLOUDFLARE_API_TOKEN': 'secret-canary', 'CLOUDFLARE_ACCOUNT_ID': 'a' * 32}), \
                 mock.patch.object(module.urllib.request, 'build_opener') as opener:
                opener.return_value.open.return_value = response
                with self.assertRaisesRegex(module.Failure, error):
                    module.Client().get('/zones')

    def test_api_redirects_cannot_forward_credentials(self):
        module = self.module()
        with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_REDIRECT_FORBIDDEN'):
            module.NoApiRedirect().redirect_request(None, None, 302, '', {}, 'https://foreign.example')

    def test_write_permission_error_reports_resource_without_token(self):
        import urllib.error
        from unittest import mock
        module = self.module()
        with mock.patch.dict(module.os.environ, {'CLOUDFLARE_API_TOKEN': 'secret-canary',
                                                 'CLOUDFLARE_ACCOUNT_ID': 'a' * 32}), \
             mock.patch.object(module.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError(
                'https://api.cloudflare.com', 403, 'denied', {}, None)
            with self.assertRaises(module.Failure) as caught:
                module.Client().request('PUT', '/accounts/' + 'a' * 32 + '/cfd_tunnel/test/configurations', {'config': {}})
        self.assertIn('Cloudflare Tunnel: Edit', str(caught.exception))
        self.assertNotIn('secret-canary', str(caught.exception))

    def test_wildcards_match_parent_domains_but_not_other_hosts(self):
        module = self.module()
        for pattern in ('*', '*.site', '*.tuannguyenviet.site'):
            self.assertTrue(module.wildcard_matches(pattern))
        for pattern in ('*.foreign.site', '*.other.tuannguyenviet.site', module.HOST):
            self.assertFalse(module.wildcard_matches(pattern))

    def test_http_errors_report_resource_permission_without_token(self):
        import urllib.error
        from unittest import mock
        module = self.module()
        with mock.patch.dict(module.os.environ, {'CLOUDFLARE_API_TOKEN': 'secret-canary',
                                                 'CLOUDFLARE_ACCOUNT_ID': 'a' * 32}), \
             mock.patch.object(module.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError(
                'https://api.cloudflare.com', 403, 'denied', {}, None)
            with self.assertRaises(module.Failure) as caught:
                module.Client().get('/accounts/' + 'a' * 32 + '/cfd_tunnel/test/connections')
        self.assertIn('Cloudflare Tunnel: Read', str(caught.exception))
        self.assertNotIn('secret-canary', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
