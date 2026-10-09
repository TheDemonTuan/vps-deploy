import importlib.util
import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock

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

    @contextlib.contextmanager
    def client(self, module, responses):
        values = [io.BytesIO(value if type(value) is bytes else json.dumps(value).encode())
                  if not isinstance(value, Exception) else value for value in responses]
        with mock.patch.dict(module.os.environ, {'CLOUDFLARE_API_TOKEN': 'secret-canary',
                                                'CLOUDFLARE_ACCOUNT_ID': 'a' * 32}), \
             mock.patch.object(module.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = values
            yield module.Client(), opener.return_value.open

    def page(self, items, page=1, per_page=2, total_count=1, total_pages=1):
        return {'success': True, 'result': items, 'result_info': {
            'page': page, 'per_page': per_page, 'count': len(items),
            'total_count': total_count, 'total_pages': total_pages}}

    def test_all_get_pages_are_aggregated_with_filters_preserved(self):
        module = self.module()
        items = [{'id': str(number)} for number in range(5)]
        responses = [self.page(items[:2], total_count=5, total_pages=3),
                     self.page(items[2:4], page=2, total_count=5, total_pages=3),
                     self.page(items[4:], page=3, total_count=5, total_pages=3)]
        path = '/accounts/' + 'a' * 32 + '/access/apps?domain=design.example%2Fpath&per_page=2&page=1'
        with self.client(module, responses) as (client, opened):
            self.assertEqual(client.get(path), items)
            requests = [call.args[0] for call in opened.call_args_list]
            for number, request in enumerate(requests, 1):
                url = module.urllib.parse.urlsplit(request.full_url)
                self.assertEqual(module.urllib.parse.parse_qs(url.query), {
                    'domain': ['design.example/path'], 'per_page': ['2'], 'page': [str(number)]})

    def test_total_count_can_prove_completion_without_total_pages(self):
        module = self.module()
        responses = [self.page([{'id': 'first'}, {'id': 'second'}], total_count=3, total_pages=2),
                     self.page([{'id': 'third'}], page=2, total_count=3, total_pages=2)]
        for response in responses:
            del response['result_info']['total_pages']
        with self.client(module, responses) as (client, opened):
            self.assertEqual(client.get('/zones?per_page=2'), [
                {'id': 'first'}, {'id': 'second'}, {'id': 'third'}])
            self.assertEqual(opened.call_count, 2)

    def test_empty_inventory_accepts_consistent_zero_or_one_page(self):
        module = self.module()
        for pages in (0, 1, None):
            response = self.page([], total_count=0, total_pages=pages)
            if pages is None:
                del response['result_info']['total_pages']
            with self.subTest(pages=pages), self.client(module, [response]) as (client, opened):
                self.assertEqual(client.get('/accounts/' + 'a' * 32 + '/access/apps?per_page=100'), [])
                self.assertEqual(opened.call_count, 1)

    def test_missing_malformed_and_truncated_metadata_fail_closed(self):
        module = self.module()
        cases = [{'success': True, 'result': []},
                 {'success': True, 'result': [], 'result_info': {'total_pages': 2}}]
        valid = self.page([{'id': 'one'}])
        for field in ('page', 'per_page', 'count', 'total_count'):
            value = json.loads(json.dumps(valid))
            del value['result_info'][field]
            cases.append(value)
        for field, malformed in [('page', 0), ('page', 2), ('page', True), ('per_page', 0),
                                 ('per_page', '2'), ('count', -1), ('count', True), ('total_count', -1),
                                 ('total_count', 0), ('total_count', 2), ('total_pages', False),
                                 ('total_pages', 0), ('total_pages', 2), ('total_pages', '1')]:
            value = json.loads(json.dumps(valid))
            value['result_info'][field] = malformed
            cases.append(value)
        for info in (None, [], 'pagination'):
            cases.append({'success': True, 'result': [], 'result_info': info})
        cases.extend([self.page([{'id': 'short'}], total_count=3, total_pages=2),
                      self.page([], total_count=1), self.page([], total_count=0, total_pages=2),
                      self.page([{'id': 'one'}], per_page=1, total_count=module.MAX_INVENTORY_PAGES + 1,
                                total_pages=module.MAX_INVENTORY_PAGES + 1)])
        for value in cases:
            with self.subTest(value=value), self.client(module, [value]) as (client, opened):
                with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_PAGINATION_REQUIRED'):
                    client.get('/zones')
                self.assertEqual(opened.call_count, 1)

    def test_later_page_drift_and_missing_metadata_fail_closed(self):
        module = self.module()
        first = self.page([{'id': 'one'}, {'id': 'two'}], total_count=3, total_pages=2)
        final = self.page([{'id': 'three'}], page=2, total_count=3, total_pages=2)
        cases = [{'success': True, 'result': [{'id': 'three'}]},
                 {'success': True, 'result': {}, 'result_info': final['result_info']},
                 self.page([], page=2, total_count=3, total_pages=2),
                 self.page([{'id': 'one'}], page=2, total_count=3, total_pages=2)]
        for field, value in [('page', 1), ('per_page', 3), ('count', 0), ('total_count', 4), ('total_pages', 3)]:
            changed = json.loads(json.dumps(final))
            changed['result_info'][field] = value
            cases.append(changed)
        changed = json.loads(json.dumps(final))
        del changed['result_info']['total_count']
        cases.append(changed)
        cases.extend([self.page([{'id': 'three'}, {'id': 'four'}], page=2, total_count=4, total_pages=2),
                      self.page([{'id': 'two'}], page=2, per_page=1, total_count=2, total_pages=2)])
        for response in cases:
            with self.subTest(response=response), self.client(module, [first, response]) as (client, opened):
                with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_PAGINATION_REQUIRED'):
                    client.get('/zones?per_page=2')
                self.assertEqual(opened.call_count, 2)

    def test_noninitial_or_duplicate_page_parameters_cannot_return_partial_inventory(self):
        module = self.module()
        for query in ('page=2', 'page=0', 'page=1&page=1', 'per_page=1&per_page=2'):
            with self.subTest(query=query), self.client(module, [self.page([{'id': 'one'}])]) as (client, opened):
                with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_PAGINATION_REQUIRED'):
                    client.get('/zones?' + query)
                self.assertEqual(opened.call_count, 1)

    def test_later_page_transport_failure_keeps_credentials_private_and_never_retries(self):
        module = self.module()
        first = self.page([{'id': 'one'}], per_page=1, total_count=2, total_pages=2)
        errors = [module.urllib.error.HTTPError('https://foreign.example?token=secret-canary', 403,
                                               'secret-canary', {}, None),
                  module.urllib.error.URLError('secret-canary'),
                  module.Failure('CLOUDFLARE_REDIRECT_FORBIDDEN')]
        for error in errors:
            with self.subTest(error=type(error).__name__), self.client(module, [first, error]) as (client, opened):
                with self.assertRaises(module.Failure) as caught:
                    client.get('/accounts/' + 'a' * 32 + '/access/apps?per_page=1')
                self.assertNotIn('secret-canary', str(caught.exception))
                self.assertNotIn('foreign.example', str(caught.exception))
                self.assertEqual(opened.call_count, 2)
                if isinstance(error, module.urllib.error.HTTPError):
                    self.assertIn('Access: Apps and Policies: Read', str(caught.exception))

    def test_page_and_aggregate_response_limits_are_bounded(self):
        module = self.module()
        with self.client(module, [b'x' * (module.MAX_RESPONSE_BYTES + 1)]) as (client, opened):
            with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_RESPONSE_TOO_LARGE'):
                client.get('/zones')
            self.assertEqual(opened.call_count, 1)
        responses = [self.page([{'id': 'one'}], per_page=1, total_count=2, total_pages=2),
                     self.page([{'id': 'two'}], page=2, per_page=1, total_count=2, total_pages=2)]
        limit = max(len(json.dumps(value).encode()) for value in responses)
        with mock.patch.object(module, 'MAX_RESPONSE_BYTES', limit), \
             self.client(module, responses) as (client, opened):
            with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_RESPONSE_TOO_LARGE'):
                client.get('/zones?per_page=1')
            self.assertEqual(opened.call_count, 2)

    def test_ruleset_cursor_pages_include_late_cache_entrypoint(self):
        module = self.module()
        responses = [
            {'success': True, 'result': [{'id': 'foreign'}], 'result_info': {'cursors': {'after': 'next+/='}}},
            {'success': True, 'result': [{'id': 'cache', 'phase': 'http_request_cache_settings'}],
             'result_info': {'cursors': {}}}]
        with self.client(module, responses) as (client, opened):
            result = client.get('/zones/' + 'b' * 32 + '/rulesets?per_page=50')
            self.assertEqual([item['id'] for item in result], ['foreign', 'cache'])
            query = module.urllib.parse.parse_qs(module.urllib.parse.urlsplit(opened.call_args.args[0].full_url).query)
            self.assertEqual(query, {'per_page': ['50'], 'cursor': ['next+/=']})

    def test_ruleset_cursor_inventory_rejects_missing_and_repeated_metadata(self):
        module = self.module()
        path = '/zones/' + 'b' * 32 + '/rulesets?per_page=50'
        for responses in (
                [{'success': True, 'result': []}],
                [{'success': True, 'result': [], 'result_info': {'cursors': {'after': 'next'}}}],
                [{'success': True, 'result': [{'id': 'one'}], 'result_info': {'cursors': {'after': 'next'}}},
                 {'success': True, 'result': [{'id': 'two'}], 'result_info': {'cursors': {'after': 'next'}}}]):
            with self.subTest(responses=responses), self.client(module, responses) as (client, opened):
                with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_PAGINATION_REQUIRED'):
                    client.get(path)
        with self.client(module, [{'success': True, 'result': [], 'result_info': {'cursors': {}}}]) as (client, opened):
            self.assertEqual(client.get(path), [])

    def test_cursor_metadata_diagnostic_never_discloses_response_values(self):
        import json
        module = self.module()
        response = {'success': True, 'result': [{'id': 'private-resource-canary'}],
                    'result_info': {'page': 'secret-page-canary', 'cursors': 'secret-cursor-canary',
                                    'private-field-canary': 'secret-value-canary'}}
        with self.client(module, [response]) as (client, opened):
            with self.assertRaises(module.Failure) as caught:
                client.get('/zones/' + 'b' * 32 + '/rulesets?per_page=50')
        message = str(caught.exception)
        for secret in ('private-resource-canary', 'secret-page-canary', 'secret-cursor-canary',
                       'private-field-canary', 'secret-value-canary', 'secret-canary'):
            self.assertNotIn(secret, message)
        diagnostic = json.loads(message.split('; metadata_shape=', 1)[1])
        self.assertEqual(diagnostic, {'result_info_type': 'dict', 'fields': {'page': 'str', 'cursors': 'str'},
                                      'items': 1, 'page': 1})

    def test_nonpaginated_endpoints_and_object_responses_keep_contract(self):
        module = self.module()
        for path, result in [('/accounts/' + 'a' * 32 + '/cfd_tunnel/test/connections', [{'id': 'connector'}]),
                             ('/accounts/' + 'a' * 32 + '/cfd_tunnel/test/configurations', {'version': 7})]:
            with self.subTest(path=path), self.client(module, [{'success': True, 'result': result}]) as (client, opened):
                self.assertEqual(client.get(path), result)
                self.assertEqual(opened.call_count, 1)

    def test_writes_never_paginate_or_retry(self):
        module = self.module()
        for method in ('PUT', 'POST', 'PATCH', 'DELETE'):
            with self.subTest(method=method), self.client(module, [self.page([], total_count=3, total_pages=2)]) as (client, opened):
                with self.assertRaisesRegex(module.Failure, 'CLOUDFLARE_PAGINATION_REQUIRED'):
                    client.request(method, '/zones', {'record': 'value'})
                self.assertEqual(opened.call_count, 1)
                self.assertEqual(opened.call_args.args[0].get_method(), method)
        for method in ('GET', 'PUT'):
            error = module.urllib.error.URLError('secret-canary')
            with self.subTest(method=method), self.client(module, [error]) as (client, opened):
                with self.assertRaisesRegex(module.Failure, '^CLOUDFLARE_READ_FAILED$'):
                    client.request(method, '/zones')
                self.assertEqual(opened.call_count, 1)

    def test_access_conflicts_on_last_page_are_not_omitted(self):
        module = self.module()
        zone = 'b' * 32
        responses = [self.page([{'id': zone, 'name': module.ZONE, 'account': {'id': 'a' * 32}}]),
                     self.page([], total_count=0, total_pages=0),
                     {'success': True, 'result': [{'id': 'connector', 'is_pending_reconnect': False}]},
                     {'success': True, 'result': {'version': 7, 'config': {'ingress': [{'service': 'http_status:404'}]}}},
                     self.page([{'id': 'foreign', 'domain': 'other.example'}], per_page=1, total_count=2, total_pages=2),
                     self.page([{'id': 'wildcard', 'domain': '*.tuannguyenviet.site',
                                 'self_hosted_domains': [module.HOST]}], page=2, per_page=1,
                               total_count=2, total_pages=2),
                     {'success': True, 'result': [], 'result_info': {'cursors': {}}}]
        with self.client(module, responses) as (client, opened):
            receipt = module.survey(client.get, client.account)
            self.assertIn('ACCESS_SCOPE_CONFLICT', receipt['conflicts'])
            self.assertEqual(receipt['access_apps'], [{'id': 'wildcard', 'dedicated': False}])
            self.assertEqual(opened.call_count, 7)

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
