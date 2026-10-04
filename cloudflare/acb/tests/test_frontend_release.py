import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs
import zipfile

spec = importlib.util.spec_from_file_location('frontend_release', Path(__file__).parents[1] / 'release-frontend.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

OLD = 'a' * 40
NEW = 'b' * 40
PREVIOUS = '11111111-1111-4111-8111-111111111111'
CANDIDATE = '22222222-2222-4222-8222-222222222222'
FOREIGN = '33333333-3333-4333-8333-333333333333'
CONFIG = {'name': 'acb-web', 'workers_dev': False, 'preview_urls': False, 'routes': [],
          'compatibility_date': '2026-10-04',
          'assets': {'directory': './dist', 'not_found_handling': 'single-page-application',
                     'html_handling': 'none', 'run_worker_first': False}}


def artifact(directory, sha):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'dist').mkdir()
    (directory / 'dist/index.html').write_text('<div id="root"></div>')
    (directory / 'dist/__release').write_bytes((sha + '\n').encode())
    (directory / 'wrangler.jsonc').write_text(json.dumps(CONFIG))
    (directory / 'release-sha').write_text(sha + '\n')
    files = sorted(path for path in directory.rglob('*') if path.is_file())
    (directory / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.relative_to(directory).as_posix() + '\n'
        for path in files))


class FrontendReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        artifact(self.root / 'web', NEW)
        artifact(self.root / 'old', OLD)
        self.summary_path = self.root / 'summary.json'
        self.commands = []
        self.requests = []
        self.versions = {PREVIOUS: self.version(PREVIOUS, OLD)}
        self.deployment = self.deployed(PREVIOUS, 1)
        self.exists = True
        self.routes = [{'id': 'route', 'pattern': host + '/*', 'script': 'acb-web'} for host in release.HOSTS]
        self.domains = []
        self.subdomain = {'enabled': False, 'previews_enabled': False}
        self.failure = None
        self.verify_failure = False
        self.route_failure = False
        self.drift_on_verify = False
        self.drift_after_upload = False
        self.cli_failure_after_switch = False
        self.deployment_override = None
        self.upload_output = None
        self.list_override = None
        self.artifacts = []
        self.artifact_bytes = b''
        self.same_version_drift = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, result, success=True, status=200, info=None, errors=None):
                data = {'success': success, 'result': result}
                if info:
                    data['result_info'] = info
                if errors:
                    data['errors'] = errors
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fixture.requests.append(self.path)
                parsed = urlsplit(self.path)
                path = parsed.path
                if fixture.failure:
                    failure = fixture.failure
                    fixture.failure = None
                    return self.reply(None, False, 503 if failure == 'http' else 200)
                if '/actions/artifacts' in path:
                    if path.endswith('/zip'):
                        self.send_response(200)
                        self.send_header('Content-Length', str(len(fixture.artifact_bytes)))
                        self.end_headers()
                        self.wfile.write(fixture.artifact_bytes)
                        return
                    body = json.dumps({'artifacts': fixture.artifacts, 'total_count': len(fixture.artifacts)}).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if path == '/zones/' + 'b' * 32:
                    return self.reply({'name': 'tuannguyenviet.site', 'account': {'id': 'a' * 32}})
                if path.endswith('/workers/routes'):
                    return self.reply(fixture.routes, info={'total_pages': 1})
                if path.endswith('/workers/domains'):
                    return self.reply(fixture.domains, info={'total_pages': 1})
                if path.endswith('/settings'):
                    if not fixture.exists:
                        return self.reply(None, False, 404, errors=[{'code': 10007}])
                    return self.reply({'bindings': []})
                if path.endswith('/script-settings'):
                    return self.reply({})
                if path.endswith('/subdomain'):
                    return self.reply(fixture.subdomain)
                if path.endswith('/deployments'):
                    return self.reply({'deployments': [fixture.deployment]})
                if path.endswith('/versions'):
                    return self.reply({'items': list(fixture.versions.values())})
                if '/versions/' in path:
                    version_id = path.rsplit('/', 1)[1]
                    if version_id not in fixture.versions:
                        return self.reply(None, False, 404)
                    return self.reply(fixture.versions[version_id])
                self.reply(None, False, 404)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        base = f'http://127.0.0.1:{self.server.server_port}'
        self.patches = [patch.object(release, 'API_BASE', base), patch.object(release, 'GH_BASE', base),
                        patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': 'test-only',
                            'CLOUDFLARE_ACCOUNT_ID': 'a' * 32, 'CLOUDFLARE_ZONE_ID': 'b' * 32,
                            'GH_TOKEN': 'test-only', 'GITHUB_REPOSITORY': 'owner/repo'})]
        for item in self.patches:
            item.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def version(self, version_id, sha, bootstrap=False):
        return {'id': version_id, 'annotations': {'workers/tag': sha,
                'workers/message': ('bootstrap ' if bootstrap else 'frontend ') + sha},
                'metadata': {'hasPreview': False}, 'resources': {'bindings': [], 'script': {'handlers': []}}}

    def deployed(self, version_id, sequence):
        return {'id': f'00000000-0000-4000-8000-{sequence:012d}',
                'versions': [{'version_id': version_id, 'percentage': 100}]}

    def runner(self, command, cwd):
        self.commands.append(command)
        if command[0] == 'node':
            self.assertEqual(Path(cwd), self.root / 'web')
            args = command[2:]
            if args[:2] == ['versions', 'upload'] or args[0] == 'deploy':
                self.exists = True
                self.versions[CANDIDATE] = self.version(CANDIDATE, NEW, args[0] == 'deploy')
                if args[0] == 'deploy':
                    self.deployment = self.deployed(CANDIDATE, 2)
                if self.drift_after_upload:
                    self.deployment = self.deployed(FOREIGN, 3)
                return self.upload_output or 'Worker Version ID: ' + CANDIDATE + '\n'
            if args[:2] == ['versions', 'list']:
                return json.dumps(self.list_override if self.list_override is not None else list(self.versions.values()))
            if args[:2] == ['versions', 'deploy']:
                self.assertEqual(args[2], CANDIDATE + '@100')
                self.deployment = self.deployed(self.deployment_override or CANDIDATE, 2)
                if self.cli_failure_after_switch:
                    self.cli_failure_after_switch = False
                    raise release.ReleaseError('Injected transport failure after accepted deployment')
                return ''
            if args[0] == 'rollback':
                self.assertNotIn('--yes', args)
                self.assertIn('--message', args)
                self.assertIn(args[1], self.versions)
                self.deployment = self.deployed(args[1], 4)
                return ''
            self.fail('Unexpected Wrangler command')
        if 'cloudflare-routes.py' in command[1]:
            if self.route_failure and self.deployment['versions'][0]['version_id'] == CANDIDATE:
                self.route_failure = False
                raise release.ReleaseError('Injected missing exception route')
            return ''
        if 'verify-frontend.py' in command[1]:
            sha = command[command.index('--sha') + 1]
            mode = command[command.index('--mode') + 1]
            if mode == 'static':
                self.assertTrue(Path(command[command.index('--artifact') + 1], '__release').is_file())
            if self.verify_failure and sha == NEW:
                self.verify_failure = False
                if self.drift_on_verify:
                    self.deployment = self.deployed(CANDIDATE if self.same_version_drift else FOREIGN, 3)
                raise release.ReleaseError('Injected HTML/challenge release verification failure')
            return ''
        self.fail('Unexpected consumer command')

    def execute(self, mode='publish', version_id=None):
        publisher = release.Publisher(self.root, runner=self.runner)
        publisher.execute(OLD if mode == 'rollback' else NEW, mode, version_id, self.summary_path)
        return json.loads(self.summary_path.read_text())

    def test_already_current_publish_does_not_create_or_switch_a_version(self):
        self.versions[PREVIOUS] = self.version(PREVIOUS, NEW)
        summary = self.execute()
        self.assertEqual(summary['status'], 'already_current')
        self.assertTrue(summary['public_checks_passed'])
        self.assertEqual(self.mutations(), [])

    def test_rollback_sha_mismatch_does_not_switch_traffic(self):
        publisher = release.Publisher(self.root, runner=self.runner)
        with self.assertRaises(release.ReleaseError):
            publisher.execute(NEW, 'rollback', PREVIOUS, self.summary_path)
        self.assertEqual(self.mutations(), [])

    def failed(self, mode='publish', version_id=None):
        with self.assertRaises(release.ReleaseError):
            self.execute(mode, version_id)
        return json.loads(self.summary_path.read_text())

    def mutations(self):
        return [command[2:] for command in self.commands if command[0] == 'node' and
                command[2:4] != ['versions', 'list']]

    def serve_artifact(self, sha=OLD, corrupt=False):
        source = self.root / ('old' if sha == OLD else 'web')
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as stream:
            for path in source.rglob('*'):
                if path.is_file():
                    stream.writestr(path.relative_to(source).as_posix(), b'corrupt' if corrupt and path.name == '__release' else path.read_bytes())
        self.artifact_bytes = archive.getvalue()
        self.artifacts = [{'id': 42, 'name': 'frontend-dist-' + sha, 'expired': False,
                           'created_at': '2026-10-04T00:00:00Z', 'workflow_run': {'head_sha': sha}}]

    def test_publish_uses_current_upload_id_with_duplicate_tags(self):
        self.versions[FOREIGN] = self.version(FOREIGN, NEW)
        summary = self.execute()
        self.assertEqual(summary['status'], 'passed')
        self.assertEqual(summary['candidate_version_id'], CANDIDATE)
        self.assertEqual(summary['previous_sha'], OLD)
        self.assertEqual(summary['frontend_sha'], NEW)
        self.assertTrue(summary['public_checks_passed'])
        self.assertEqual(len(summary['artifact_checksum']), 64)
        self.assertEqual([args[:2] for args in self.mutations()], [['versions', 'upload'], ['versions', 'deploy']])
        route_commands = [command for command in self.commands if 'cloudflare-routes.py' in command[1]]
        self.assertEqual(len(route_commands), 2)
        self.assertTrue(Path(str(self.summary_path) + '.upload.json').is_file())

    def test_ambiguous_upload_output_never_deploys(self):
        self.upload_output = 'Version ID: ' + CANDIDATE + '\nVersion ID: ' + FOREIGN
        self.failed()
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.deployment['versions'][0]['version_id'], PREVIOUS)

    def test_upload_tag_mismatch_never_deploys(self):
        self.list_override = [self.version(CANDIDATE, OLD)]
        self.failed()
        self.assertEqual(len(self.mutations()), 1)

    def test_gradual_rollout_rejected_before_upload(self):
        self.deployment['versions'] = [{'version_id': PREVIOUS, 'percentage': 50}, {'version_id': FOREIGN, 'percentage': 50}]
        self.failed()
        self.assertEqual(self.mutations(), [])

    def test_http_and_json_errors_prevent_mutation(self):
        for error in ('http', 'json'):
            with self.subTest(error=error):
                self.failure = error
                self.failed()
                self.assertEqual(self.mutations(), [])

    def test_missing_credentials_prevent_commands_and_api(self):
        with patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN': ''}):
            with self.assertRaises(release.ReleaseError):
                release.Publisher(self.root, runner=self.runner)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.commands, [])

    def test_corrupt_artifact_prevents_upload(self):
        (self.root / 'web/dist/__release').write_text(OLD)
        self.failed()
        self.assertEqual(self.mutations(), [])

    def test_public_failure_restores_previous_with_verified_artifact(self):
        self.serve_artifact()
        self.verify_failure = True
        summary = self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], PREVIOUS)
        self.assertEqual(self.mutations()[-1][:2], ['rollback', PREVIOUS])
        self.assertTrue(summary['rollback']['checksum_verified'])
        self.assertTrue(summary['rollback']['public_checks_passed'])
        self.assertFalse(summary['public_checks_passed'])

    def test_absent_previous_artifact_uses_explicit_rollback_verifier(self):
        self.verify_failure = True
        summary = self.failed()
        self.assertFalse(summary['rollback']['checksum_verified'])
        self.assertFalse(summary['rollback']['artifact_available'])
        rollback_checks = [command for command in self.commands if 'verify-frontend.py' in command[1]
                           and command[command.index('--mode') + 1] == 'rollback']
        self.assertEqual(len(rollback_checks), 1)
        self.assertNotIn('--artifact', rollback_checks[0])

    def test_invalid_previous_artifact_does_not_claim_checksum_or_skip_restore(self):
        self.serve_artifact(corrupt=True)
        self.verify_failure = True
        summary = self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], PREVIOUS)
        self.assertNotIn('checksum_verified', summary['rollback'])
        self.assertNotIn('public_checks_passed', summary['rollback'])

    def test_deployment_drift_during_verification_refuses_rollback(self):
        self.verify_failure = True
        self.drift_on_verify = True
        summary = self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], FOREIGN)
        self.assertFalse(any(args[0] == 'rollback' for args in self.mutations()))
        self.assertIn('deployment_drift', summary)

    def test_same_version_new_deployment_is_still_drift(self):
        self.verify_failure = True
        self.drift_on_verify = True
        self.same_version_drift = True
        summary = self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], CANDIDATE)
        self.assertFalse(any(args[0] == 'rollback' for args in self.mutations()))
        self.assertIn('deployment_drift', summary)

    def test_deployment_drift_after_upload_refuses_deploy(self):
        self.drift_after_upload = True
        self.failed()
        self.assertEqual(len(self.mutations()), 1)

    def test_foreign_deployment_confirmation_never_rolls_back_foreign_version(self):
        self.deployment_override = FOREIGN
        summary = self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], FOREIGN)
        self.assertNotIn('rollback', summary)
        self.assertFalse(any(args[0] == 'rollback' for args in self.mutations()))

    def test_cli_failure_after_acceptance_restores_confirmed_candidate(self):
        self.cli_failure_after_switch = True
        self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], PREVIOUS)

    def test_route_postcheck_failure_restores_previous(self):
        self.route_failure = True
        self.failed()
        self.assertEqual(self.deployment['versions'][0]['version_id'], PREVIOUS)

    def test_intentional_rollback_reads_version_sha_not_checkout_sha(self):
        summary = self.execute('rollback', PREVIOUS)
        self.assertEqual(summary['frontend_sha'], OLD)
        self.assertEqual(self.mutations()[0][:2], ['rollback', PREVIOUS])
        self.assertFalse(any(args[:2] == ['versions', 'upload'] for args in self.mutations()))
        self.assertFalse(summary['rollback_artifact']['checksum_verified'])
        self.assertTrue(any('/versions/' + PREVIOUS in request for request in self.requests))

    def test_intentional_rollback_missing_version_refused(self):
        self.failed('rollback', FOREIGN)
        self.assertEqual(self.mutations(), [])

    def test_intentional_rollback_artifact_checked_when_available(self):
        self.serve_artifact()
        summary = self.execute('rollback', PREVIOUS)
        self.assertTrue(summary['rollback_artifact']['checksum_verified'])

    def test_intentional_rollback_older_than_cli_list_window(self):
        for sequence in range(15):
            version_id = f'99999999-9999-4999-8999-{sequence:012d}'
            self.versions[version_id] = self.version(version_id, NEW)
        self.list_override = list(self.versions.values())[-10:]
        summary = self.execute('rollback', PREVIOUS)
        self.assertEqual(summary['frontend_sha'], OLD)
        self.assertFalse(any(command[2:4] == ['versions', 'list'] for command in self.commands))

    def test_bootstrap_new_service_never_claims_public_success(self):
        self.exists = False
        self.routes = []
        summary = self.execute('bootstrap')
        self.assertEqual(summary['status'], 'bootstrapped_no_traffic')
        self.assertFalse(summary['public_checks_passed'])
        self.assertEqual(self.mutations()[0][0], 'deploy')
        self.assertFalse(any('verify-frontend.py' in command[1] for command in self.commands))
        self.assertEqual(self.routes, [])

    def test_bootstrap_can_replace_prior_unexposed_bootstrap_only(self):
        self.routes = []
        self.versions[PREVIOUS] = self.version(PREVIOUS, OLD, bootstrap=True)
        self.execute('bootstrap')
        self.assertEqual(self.deployment['versions'][0]['version_id'], CANDIDATE)

    def test_bootstrap_refuses_existing_foreign_worker_and_bound_script(self):
        self.routes = []
        self.failed('bootstrap')
        self.assertEqual(self.mutations(), [])
        self.versions[PREVIOUS] = self.version(PREVIOUS, OLD, bootstrap=True)
        self.versions[PREVIOUS]['resources']['bindings'] = [{'type': 'secret_text', 'name': 'foreign'}]
        self.failed('bootstrap')
        self.assertEqual(self.mutations(), [])

    def test_bootstrap_refuses_existing_routes_and_custom_domains(self):
        cases = [([{'id': 'foreign', 'pattern': release.HOSTS[0] + '/*', 'script': 'other'}], []),
                 ([{'id': 'other-zone', 'pattern': 'elsewhere.example/*', 'script': 'acb-web'}], []),
                 ([], [{'hostname': release.HOSTS[1], 'service': 'other'}]),
                 ([], [{'hostname': 'elsewhere.example', 'service': 'acb-web'}])]
        for routes, domains in cases:
            with self.subTest(routes=routes, domains=domains):
                self.routes = routes
                self.domains = domains
                self.failed('bootstrap')
                self.assertEqual(self.mutations(), [])

    def test_public_workers_dev_or_preview_refused(self):
        for settings in ({'enabled': True, 'previews_enabled': False}, {'enabled': False, 'previews_enabled': True}):
            with self.subTest(settings=settings):
                self.subdomain = settings
                self.failed()
                self.assertEqual(self.mutations(), [])

    def test_unsafe_archive_rejected_without_extraction(self):
        self.serve_artifact()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('../escaped', 'secret')
        self.artifact_bytes = archive.getvalue()
        summary = {}
        with self.assertRaises(release.ReleaseError):
            release.previous_artifact(OLD, self.root / 'download', summary)
        self.assertFalse((self.root / 'escaped').exists())
        self.assertNotIn('checksum_verified', summary)

    def test_corrupt_retrieval_never_falls_back_to_unverified_success(self):
        self.serve_artifact(corrupt=True)
        summary = {}
        with self.assertRaises(release.ReleaseError):
            release.previous_artifact(OLD, self.root / 'download', summary)
        self.assertNotIn('checksum_verified', summary)

    def test_artifact_must_cover_extra_public_file(self):
        (self.root / 'web/dist/unlisted.js').write_text('x')
        with self.assertRaises(release.ReleaseError):
            release.artifact_checksum(self.root / 'web', NEW)


if __name__ == '__main__':
    unittest.main()
