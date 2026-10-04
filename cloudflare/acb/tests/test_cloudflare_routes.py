import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cloudflare_routes', Path(__file__).parents[1] / 'cloudflare-routes.py')
routes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routes)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.writes = []
        self.sequence = 0
        self.failure = None
        self.fail_confirm = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, result, success=True, status=200, info=None):
                body = json.dumps({'success': success, 'result': result, 'result_info': info or {}}).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if fixture.fail_confirm and any(record.get('script') == routes.WORKER for record in fixture.records):
                    fixture.fail_confirm = False
                    return self.reply([], success=False)
                self.reply(fixture.records, info={'total_pages': 1})

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fixture.writes.append(('POST', data))
                if fixture.failure == 'http':
                    fixture.failure = None
                    return self.reply(None, False, 503)
                if fixture.failure == 'json':
                    fixture.failure = None
                    return self.reply(None, False)
                if data.get('script') == routes.WORKER:
                    host = data['pattern'][:-2]
                    exceptions = dict(routes.patterns(host)[:-1])
                    actual = {record['pattern']: record.get('script') for record in fixture.records}
                    if any(pattern not in actual or actual[pattern] is not None for pattern in exceptions):
                        return self.reply(None, False)
                fixture.sequence += 1
                record = dict(data, id=str(fixture.sequence))
                fixture.records.append(record)
                if fixture.failure == 'catchall-ack' and data.get('script') == routes.WORKER:
                    fixture.failure = None
                    return self.reply(None, False)
                self.reply(record)

            def do_DELETE(self):
                record_id = self.path.rsplit('/', 1)[1]
                fixture.writes.append(('DELETE', record_id))
                fixture.records[:] = [record for record in fixture.records if record['id'] != record_id]
                self.reply({'id': record_id})

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env = patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': 'test-only', 'CLOUDFLARE_ZONE_ID': 'a' * 32})
        self.env.start()
        self.base = patch.object(routes, 'API_BASE', f'http://127.0.0.1:{self.server.server_port}')
        self.base.start()
        self.temp = tempfile.TemporaryDirectory()
        self.snapshot = Path(self.temp.name) / 'routes.json'
        self.api = routes.API()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.base.stop()
        self.env.stop()
        self.temp.cleanup()

    def test_exceptions_confirmed_before_switch_and_restore_preserves_other_host(self):
        foreign = {'id': 'foreign', 'pattern': 'elsewhere.example/*', 'script': 'other'}
        self.records.append(foreign)
        routes.apply(self.api, routes.HOSTS['viewer'], self.snapshot)
        self.assertEqual(self.writes[-1][1]['script'], routes.WORKER)
        for _, body in self.writes[:-1]:
            self.assertNotIn('script', body)
        routes.inspect(self.api.routes(), routes.HOSTS['viewer'], require=True)
        catchall_id = next(record['id'] for record in self.records if record.get('script') == routes.WORKER)
        delete_start = len(self.writes)
        routes.restore(self.api, self.snapshot)
        self.assertEqual(self.records, [foreign])
        self.assertEqual(self.writes[delete_start], ('DELETE', catchall_id))

    def test_http_and_json_errors_keep_old_origin(self):
        for failure in ('http', 'json'):
            with self.subTest(failure=failure):
                self.failure = failure
                path = Path(self.temp.name) / (failure + '.json')
                with self.assertRaises(routes.RouteError):
                    routes.apply(self.api, routes.HOSTS['bank'], path)
                self.assertFalse(any(record.get('script') == routes.WORKER for record in self.records))

    def test_conflict_does_not_overwrite(self):
        for pattern in (routes.HOSTS['bank'] + '/*', '*.tuannguyenviet.site/api*', routes.HOSTS['bank'] + '/api/other*'):
            self.records[:] = [{'id': 'foreign', 'pattern': pattern, 'script': 'other'}]
            with self.assertRaises(routes.RouteError):
                routes.apply(self.api, routes.HOSTS['bank'], self.snapshot)
            self.assertEqual(self.writes, [])
            self.assertFalse(self.snapshot.exists())

    def test_restore_refuses_drift_before_any_mutation(self):
        routes.apply(self.api, routes.HOSTS['viewer'], self.snapshot)
        self.records[0]['script'] = 'someone-else'
        writes_before = len(self.writes)
        with self.assertRaises(routes.RouteError):
            routes.restore(self.api, self.snapshot)
        self.assertEqual(len(self.writes), writes_before)
        self.assertTrue(any(record.get('script') == routes.WORKER for record in self.records))

    def test_failure_after_switch_restores_static_origin_leaving_exceptions(self):
        self.fail_confirm = True
        with self.assertRaises(routes.RouteError):
            routes.apply(self.api, routes.HOSTS['bank'], self.snapshot)
        self.assertFalse(any(record.get('script') == routes.WORKER for record in self.records))
        self.assertEqual({record['pattern'] for record in self.records}, set(dict(routes.patterns(routes.HOSTS['bank'])[:-1])))
        routes.restore(self.api, self.snapshot)
        self.assertEqual(self.records, [])

    def test_lost_catchall_ack_is_journaled_and_restored(self):
        self.failure = 'catchall-ack'
        with self.assertRaises(routes.RouteError):
            routes.apply(self.api, routes.HOSTS['bank'], self.snapshot)
        self.assertFalse(any(record.get('script') == routes.WORKER for record in self.records))
        routes.restore(self.api, self.snapshot)
        self.assertEqual(self.records, [])

    def test_existing_identical_noop_and_snapshot_exclusive(self):
        routes.apply(self.api, routes.HOSTS['bank'], self.snapshot)
        writes_before = len(self.writes)
        second = Path(self.temp.name) / 'second.json'
        routes.apply(self.api, routes.HOSTS['bank'], second)
        self.assertEqual(len(self.writes), writes_before)
        with self.assertRaises(FileExistsError):
            routes.apply(self.api, routes.HOSTS['bank'], self.snapshot)
        self.assertEqual(len(self.writes), writes_before)

    def test_prefix_routes_cover_bare_namespace_and_query(self):
        routes.apply(self.api, routes.HOSTS['viewer'], self.snapshot)
        for suffix in ('/api', '/api?x=1', '/api/unknown', '/internal?x=1', '/admin?x=1', '/health-anything', '/ready-anything'):
            url = routes.HOSTS['viewer'] + suffix
            matching = [record for record in self.records if __import__('fnmatch').fnmatchcase(url, record['pattern'])]
            selected = max(matching, key=lambda record: len(record['pattern']))
            self.assertIsNone(selected.get('script'), suffix)
        self.records.pop(0)
        with self.assertRaises(routes.RouteError):
            routes.inspect(self.api.routes(), routes.HOSTS['viewer'], require=True)


if __name__ == '__main__':
    unittest.main()
