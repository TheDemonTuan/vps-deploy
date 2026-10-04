import hashlib
import importlib.util
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('cutover_controller', Path(__file__).parents[1] / 'deploy.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
SHA = 'b' * 40
OLD = 'a' * 40
ZONE = 'c' * 32


def archive(values):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        for name, value in values.items():
            output.writestr(name, value)
    raw = stream.getvalue()
    return raw, 'sha256:' + hashlib.sha256(raw).hexdigest()


class SnapshotAPI:
    def __init__(self):
        self.run = {'id': 42, 'workflow_id': 7, 'head_sha': SHA, 'status': 'completed',
                    'conclusion': 'failure', 'event': 'workflow_dispatch', 'head_branch': 'main',
                    'head_repository': {'full_name': 'TheDemonTuan/vps-deploy'}}
        self.workflow = {'path': '.github/workflows/cloudflare-deploy.yml'}
        self.values = {
            host + '-routes.json': json.dumps({'schema': 1, 'host': hostname, 'zone_id': ZONE,
                                               'changes': [], 'existing_records': []})
            for host, hostname in [('bank', 'bank.tuannguyenviet.site'),
                                   ('viewer', 'transactions.tuannguyenviet.site')]
        }
        self.refresh()

    def refresh(self):
        self.raw, self.digest = archive(self.values)
        self.artifact = {'id': 11, 'name': 'cloudflare-receipt-acb-42', 'expired': False,
                         'workflow_run': {'head_sha': SHA}, 'digest': self.digest}

    def get(self, path, binary=False):
        if path.endswith('/actions/runs/42'):
            return self.run
        if path.endswith('/actions/workflows/7'):
            return self.workflow
        if '/actions/runs/42/artifacts?' in path:
            return {'total_count': 1, 'artifacts': [self.artifact]}
        if path.endswith('/actions/artifacts/11/zip'):
            return self.raw
        raise AssertionError(path)


class CutoverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.summary = self.root / 'receipt.json'
        self.config = controller.registration('acb')
        self.selection = {'app': 'acb', 'mode': 'cutover', 'sha': SHA, 'run_id': 42,
                          'artifact_id': 11, 'archive_digest': ''}
        values = {'manifest.json': json.dumps({'app': 'acb', 'source_repository': self.config['repository'], 'source_sha': SHA}),
                  'dist/__release': SHA + '\n', 'dist/index.html': '<div>verified application</div>'}
        values['SHA256SUMS'] = ''.join(hashlib.sha256(value.encode()).hexdigest() + '  ' + name + '\n'
                                     for name, value in values.items())
        raw, digest = archive(values)
        self.selection['archive_digest'] = digest
        self.api = type('ArtifactAPI', (), {'get': lambda api, path, binary=False: raw})()
        self.active_sha = OLD
        self.routes = {'bank': False, 'viewer': False}
        self.fail_surface = None
        self.drift_host = None
        self.observed = []
        self.restored = []

    def tearDown(self):
        self.temporary.cleanup()

    def run_command(self, command, **kwargs):
        name = Path(command[1]).name
        if name == 'release-frontend.py':
            mode = command[command.index('--mode') + 1]
            if mode == 'bootstrap':
                if any(self.routes.values()):
                    raise subprocess.CalledProcessError(1, command)
                self.active_sha = command[command.index('--sha') + 1]
                controller.save(self.summary, {'status': 'bootstrapped_no_traffic', 'public_checks_passed': False})
            else:
                if not all(self.routes.values()) or self.active_sha != SHA:
                    raise subprocess.CalledProcessError(1, command)
                controller.save(self.summary, {'status': 'already_current', 'public_checks_passed': True,
                                               'active_deployment': {'version_id': 'candidate'}})
        elif name == 'cloudflare-routes.py':
            snapshot = Path(command[command.index('--snapshot') + 1])
            host = snapshot.name.split('-')[0]
            if command[2] == 'apply':
                controller.save(snapshot, {'host': host, 'previous': self.routes[host]})
                self.routes[host] = True
            elif host == self.drift_host:
                return subprocess.CompletedProcess(command, 1)
            else:
                self.routes[host] = json.loads(snapshot.read_text())['previous']
                self.restored.append(host)
        elif name == 'verify-frontend.py':
            host = 'viewer' if '--surface' in command else 'bank'
            self.observed.append((host, self.active_sha, self.routes.copy()))
            if self.active_sha != SHA or not self.routes[host] or self.fail_surface == host:
                raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    def execute(self):
        with patch.object(controller, 'account_zone', return_value=ZONE), \
                patch.object(controller, 'resolve', return_value=self.selection), \
                patch.object(controller, 'wait_static_release', return_value={'ready': True}), \
                patch.object(controller.subprocess, 'run', side_effect=self.run_command):
            controller.execute(self.api, self.config, self.selection, self.summary)

    def test_new_artifact_precedes_viewer_and_bank_is_not_switched_until_viewer_passes(self):
        self.execute()
        self.assertEqual(self.observed, [('viewer', SHA, {'bank': False, 'viewer': True}),
                                         ('bank', SHA, {'bank': True, 'viewer': True})])
        receipt = json.loads(self.summary.read_text())
        self.assertEqual(receipt['status'], 'pending_owner_acceptance')
        self.assertTrue(receipt['public_checks_passed'])
        self.assertFalse(receipt['metadata_migration_authorized'])
        self.assertFalse(receipt['owner_browser_checks_passed'])
        self.assertFalse((self.root / 'proof.json').exists())

    def test_viewer_failure_restores_only_viewer_without_switching_bank(self):
        self.fail_surface = 'viewer'
        with self.assertRaises(controller.Failure):
            self.execute()
        self.assertEqual(self.routes, {'bank': False, 'viewer': False})
        self.assertEqual(self.restored, ['viewer'])
        self.assertEqual([row[0] for row in self.observed], ['viewer'])

    def test_bank_failure_restores_both_hosts_in_reverse_order(self):
        self.fail_surface = 'bank'
        with self.assertRaises(controller.Failure):
            self.execute()
        self.assertEqual(self.routes, {'bank': False, 'viewer': False})
        self.assertEqual(self.restored, ['bank', 'viewer'])

    def test_restore_drift_is_retained_as_failure_not_false_success(self):
        self.fail_surface = 'bank'
        self.drift_host = 'bank'
        with self.assertRaises(controller.Failure):
            self.execute()
        self.assertTrue(self.routes['bank'])
        receipt = json.loads(self.summary.read_text())
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['route_restoration'][0], {'snapshot': 'bank-routes.json', 'restored': False})

    def test_already_exposed_bootstrap_refuses_to_mutate_existing_routes(self):
        self.routes['viewer'] = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.routes, {'bank': False, 'viewer': True})
        self.assertEqual(self.active_sha, OLD)


class EdgeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name) / 'readiness.json'
        self.count = 0
        self.unready_at = {1, 2}
        self.stale = False
        self.cacheable = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.count += 1
                converged = owner.count not in owner.unready_at or owner.stale or owner.cacheable
                body = ((OLD if owner.stale else SHA) + '\n').encode() if converged else b'<html>CrowdSec Challenge</html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain' if converged else 'text/html')
                self.send_header('Cache-Control', 'public' if owner.cacheable else 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_control_plane_success_waits_for_actual_release_not_html_challenge(self):
        with patch.object(controller.time, 'sleep'):
            result = controller.wait_static_release(self.origin, SHA, self.evidence)
        self.assertEqual(self.count, 5)
        self.assertTrue(result['ready'])
        self.assertEqual([item['mime'] for item in result['observations']], ['text/html', 'text/html', 'text/plain', 'text/plain', 'text/plain'])

    def test_origin_challenge_after_correct_identity_resets_convergence(self):
        self.unready_at = {1, 2, 4}
        with patch.object(controller.time, 'sleep'):
            result = controller.wait_static_release(self.origin, SHA, self.evidence)
        self.assertTrue(result['ready'])
        self.assertEqual([item['mime'] for item in result['observations']],
                         ['text/html', 'text/html', 'text/plain', 'text/html', 'text/plain', 'text/plain', 'text/plain'])

    def test_stale_release_or_cacheable_identity_never_passes_at_deadline(self):
        for kind in ('stale', 'cacheable'):
            self.stale, self.cacheable = kind == 'stale', kind == 'cacheable'
            with self.subTest(kind=kind), self.assertRaises(controller.Failure):
                controller.wait_static_release(self.origin, SHA, self.evidence, timeout=0)
            self.assertFalse(json.loads(self.evidence.read_text())['ready'])


class RouteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.api = SnapshotAPI()
        self.config = controller.registration('acb')

    def test_failed_central_dispatch_is_valid_recovery_source(self):
        selected = controller.resolve(self.api, self.config, 'restore-routes', 42)
        self.assertEqual(selected['archive_digest'], self.api.digest)
        self.assertEqual(selected['run_id'], 42)

    def test_foreign_workflow_branch_expired_artifact_and_missing_digest_refuse(self):
        for target, key, value in [(self.api.workflow, 'path', '.github/workflows/other.yml'),
                                   (self.api.run, 'head_branch', 'attacker'),
                                   (self.api.artifact, 'expired', True),
                                   (self.api.artifact, 'digest', '')]:
            original = target[key]
            target[key] = value
            with self.subTest(key=key), self.assertRaises(controller.Failure):
                controller.resolve(self.api, self.config, 'restore-routes', 42)
            target[key] = original

    def test_wrong_snapshot_host_fails_before_either_restore(self):
        self.api.values['viewer-routes.json'] = json.dumps({'schema': 1, 'host': 'other.example', 'zone_id': ZONE})
        self.api.refresh()
        selection = controller.resolve(self.api, self.config, 'restore-routes', 42)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(controller, 'account_zone', return_value=ZONE), \
                patch.object(controller.subprocess, 'run') as runner, self.assertRaises(controller.Failure):
            controller.execute(self.api, self.config, selection, Path(temporary) / 'receipt.json')
        runner.assert_not_called()


if __name__ == '__main__':
    unittest.main()
