import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_penpot_contract
import core
import penpot_publish as publish


ROOT = Path(__file__).resolve().parents[1]


def script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PenpotPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / 'images.tar.zst'
        self.archive.write_bytes(b'disposable-archive')
        self.source = 'a' * 40
        self.platform = 'b' * 40
        self.metadata = {'schemaVersion': 1, 'sourceSha': self.source, 'platformRef': self.platform,
                         'platform': 'linux/arm64', 'archiveSha256': publish.archive_hash(self.archive)}
        self.digests = {role: repo + '@sha256:' + 'd' * 64 for role, repo in core.PENPOT_REPOSITORIES.items()}

    def image(self, role):
        return {'Architecture': 'arm64', 'Os': 'linux', 'Config': {'User': 'penpot', 'Labels': {
            'org.opencontainers.image.source': 'https://github.com/TheDemonTuan/penpot',
            'org.opencontainers.image.revision': self.source}}, 'RepoDigests': [self.digests[role]]}

    def inspect(self, kind, ref):
        role = next(role for role, repo in core.PENPOT_REPOSITORIES.items() if ref.startswith(repo + ':'))
        return self.image(role)

    def test_hash_caller_and_exact_metadata_gate_docker_load(self):
        for fault in ('hash', 'source', 'platform', 'architecture', 'extra', 'bool'):
            value = copy.deepcopy(self.metadata)
            if fault == 'hash':
                value['archiveSha256'] = 'e' * 64
            elif fault == 'source':
                value['sourceSha'] = 'f' * 40
            elif fault == 'platform':
                value['platformRef'] = 'f' * 40
            elif fault == 'architecture':
                value['platform'] = 'linux/amd64'
            elif fault == 'extra':
                value['images'] = {}
            else:
                value['schemaVersion'] = True
            with self.subTest(fault=fault), mock.patch.object(publish, 'docker') as docker, self.assertRaises(core.Failure):
                publish.publish(self.archive, value, self.source, self.platform)
            docker.assert_not_called()

    def test_four_images_publish_only_after_all_local_identities_pass(self):
        events = []
        def anonymous(ref):
            self.assertEqual([event[0] for event in events], ['load'] + ['push'] * 4 + ['anonymous'] * (len(events) - 5))
            events.append(('anonymous', ref))
        with mock.patch.object(publish, 'docker', side_effect=lambda *args, **kw: events.append(args)), mock.patch.object(publish, 'inspect', side_effect=self.inspect), mock.patch.object(publish, 'anonymous_image', side_effect=anonymous) as anonymous_check:
            result = publish.publish(self.archive, self.metadata, self.source, self.platform)
        self.assertEqual(events[0][0], 'load')
        self.assertEqual([args[0] for args in events[1:5]], ['push'] * 4)
        self.assertEqual(result['images'], self.digests)
        self.assertEqual(anonymous_check.call_count, 4)
        self.assertEqual(set(result), {'schemaVersion', 'sourceSha', 'platformRef', 'platform', 'images'})

    def test_wrong_image_revision_or_user_prevents_every_push(self):
        for fault in ('revision', 'root', 'architecture'):
            def inspect(kind, ref):
                value = self.inspect(kind, ref)
                if not ref.startswith(core.PENPOT_REPOSITORIES['mcp'] + ':'):
                    return value
                if fault == 'revision':
                    value['Config']['Labels']['org.opencontainers.image.revision'] = 'e' * 40
                elif fault == 'root':
                    value['Config']['User'] = '0:0'
                else:
                    value['Architecture'] = 'amd64'
                return value
            events = []
            with self.subTest(fault=fault), mock.patch.object(publish, 'docker', side_effect=lambda *args, **kw: events.append(args)), mock.patch.object(publish, 'inspect', side_effect=inspect), self.assertRaises(core.Failure):
                publish.publish(self.archive, self.metadata, self.source, self.platform)
            self.assertEqual([args[0] for args in events], ['load'])

    def test_ambiguous_or_foreign_digest_never_emits_release(self):
        for fault in ('foreign', 'ambiguous'):
            def inspect(kind, ref):
                value = self.inspect(kind, ref)
                if fault == 'foreign':
                    value['RepoDigests'] = ['foreign/image@sha256:' + 'd' * 64]
                else:
                    value['RepoDigests'].append(ref.split(':sha-', 1)[0] + '@sha256:' + 'e' * 64)
                return value
            with self.subTest(fault=fault), mock.patch.object(publish, 'docker'), mock.patch.object(publish, 'inspect', side_effect=inspect), mock.patch.object(publish, 'anonymous_image') as anonymous:
                with self.assertRaisesRegex(core.Failure, 'PENPOT_PUBLISHED_DIGEST'):
                    publish.publish(self.archive, self.metadata, self.source, self.platform)
                anonymous.assert_not_called()

    def test_same_run_release_evidence_must_match_all_build_outputs(self):
        record = {'schemaVersion': 1, 'sourceSha': self.source, 'platformRef': self.platform,
                  'platform': 'linux/arm64', 'images': self.digests}
        self.assertEqual(publish.release_record(record, self.source, self.platform, self.digests), self.digests)
        for fault in ('sourceSha', 'platformRef', 'platform', 'images', 'schemaVersion', 'extra'):
            value = copy.deepcopy(record)
            if fault in ('sourceSha', 'platformRef'):
                value[fault] = 'f' * 40
            elif fault == 'platform':
                value[fault] = 'linux/amd64'
            elif fault == 'images':
                value[fault]['mcp'] = core.PENPOT_REPOSITORIES['mcp'] + '@sha256:' + 'f' * 64
            elif fault == 'schemaVersion':
                value[fault] = True
            else:
                value[fault] = 1
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                publish.release_record(value, self.source, self.platform, self.digests)

    def test_malformed_registry_digest_is_rejected_before_anonymous_network(self):
        def inspect(kind, ref):
            value = self.image('frontend')
            value['RepoDigests'] = [core.PENPOT_REPOSITORIES['frontend'] + '@sha256:invalid']
            return value
        with mock.patch.object(publish, 'docker'), mock.patch.object(publish, 'inspect', side_effect=inspect), mock.patch.object(publish, 'anonymous_image') as anonymous:
            with self.assertRaisesRegex(core.Failure, 'PENPOT_PUBLISHED_DIGEST'):
                publish.publish(self.archive, self.metadata, self.source, self.platform)
            anonymous.assert_not_called()

    def test_push_and_visibility_errors_keep_their_original_codes(self):
        for stage in ('push', 'visibility'):
            events = []
            def docker(*args, **kwargs):
                events.append(args[0])
                if stage == 'push' and events.count('push') == 3:
                    raise core.Failure('COMMAND_FAILED')
            def anonymous(ref):
                self.assertEqual(events.count('push'), 4)
                raise core.Failure('ANONYMOUS_IMAGE_REQUIRED')
            code = 'COMMAND_FAILED' if stage == 'push' else 'ANONYMOUS_IMAGE_REQUIRED'
            with self.subTest(stage=stage), mock.patch.object(publish, 'docker', side_effect=docker), mock.patch.object(publish, 'inspect', side_effect=self.inspect), mock.patch.object(publish, 'anonymous_image', side_effect=anonymous) as visibility:
                with self.assertRaisesRegex(core.Failure, code):
                    publish.publish(self.archive, self.metadata, self.source, self.platform)
                if stage == 'push':
                    visibility.assert_not_called()

    def test_cli_never_writes_release_or_images_on_failed_publication(self):
        cli = script('publish-penpot')
        metadata = Path(self.temp.name) / 'build.json'
        metadata.write_text(json.dumps(self.metadata))
        output = Path(self.temp.name) / 'release.json'
        github_output = Path(self.temp.name) / 'github-output'
        github_output.write_text('')
        environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'TheDemonTuan/penpot',
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': self.source,
                       'PLATFORM_REF': self.platform, 'GITHUB_OUTPUT': str(github_output)}
        argv = ['publish-penpot.py', '--archive', str(self.archive), '--metadata', str(metadata), '--output', str(output)]
        for code in ('COMMAND_FAILED', 'PENPOT_PUBLISHED_DIGEST', 'ANONYMOUS_IMAGE_REQUIRED'):
            with self.subTest(code=code), mock.patch.dict(os.environ, environment), mock.patch('sys.argv', argv), mock.patch.object(cli, 'publish', side_effect=core.Failure(code)):
                with self.assertRaisesRegex(core.Failure, code):
                    cli.main()
            self.assertFalse(output.exists())
            self.assertEqual(github_output.read_text(), '')
        with mock.patch.dict(os.environ, dict(environment, GITHUB_OUTPUT=self.temp.name)), mock.patch('sys.argv', argv), mock.patch.object(cli, 'publish', return_value={'images': self.digests}):
            with self.assertRaises(OSError):
                cli.main()
        self.assertFalse(output.exists())

    def test_visibility_hint_preserves_error_without_exception_or_credential_text(self):
        cli = script('publish-penpot')
        summary = Path(self.temp.name) / 'summary'
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            cli.failure_report(core.Failure('ANONYMOUS_IMAGE_REQUIRED'))
            self.assertEqual(json.loads(stdout.getvalue())['error_code'], 'ANONYMOUS_IMAGE_REQUIRED')
        self.assertIn('does not prove the packages are private', summary.read_text())
        self.assertIn('same run', summary.read_text())
        summary.unlink()
        with mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            cli.failure_report(core.Failure('COMMAND_FAILED'))
            self.assertEqual(json.loads(stdout.getvalue())['error_code'], 'COMMAND_FAILED')
        self.assertFalse(summary.exists())


class PenpotBuildProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.writer = script('write-penpot-proof')
        self.identity = {'schemaVersion': 1, 'sourceSha': 'a' * 40, 'platformRef': 'b' * 40,
                         'runId': '123', 'runAttempt': '2', 'platform': 'linux/arm64'}
        self.smoke = {'sourceSha': self.identity['sourceSha'], 'platform': 'linux/arm64',
                      **{key: True for key in self.writer.SMOKE_CHECKS}}
        self.lifecycle = dict(self.identity, status='passed', cases=[{'name': 'happy', 'status': 'passed',
                                                                    'evidence': {'dataPreserved': True}}])
        self.reports()
        (self.directory / 'logs').mkdir()
        (self.directory / 'logs' / 'runtime.log').write_text('ERROR upstream refused path=/mcp/ws status=502\n')

    def reports(self):
        (self.directory / 'smoke.json').write_text(json.dumps(self.smoke))
        (self.directory / 'lifecycle.json').write_text(json.dumps(self.lifecycle))

    def write(self):
        return self.writer.write_proof(self.directory, self.identity['sourceSha'], self.identity['platformRef'],
                                       self.identity['runId'], self.identity['runAttempt'])

    def test_every_evidence_byte_is_bound_to_exact_run_identity(self):
        result = self.write()
        self.assertEqual({key: result[key] for key in self.identity}, self.identity)
        self.assertEqual(set(result['files']), {'smoke.json', 'lifecycle.json', 'logs/runtime.log'})
        for name, digest in result['files'].items():
            self.assertEqual(digest, hashlib.sha256((self.directory / name).read_bytes()).hexdigest())
        (self.directory / 'logs' / 'runtime.log').write_text('ERROR timeout path=/mcp/ws status=504\n')
        replacement = self.write()
        self.assertNotEqual(result['files']['logs/runtime.log'], replacement['files']['logs/runtime.log'])
        self.assertEqual(result['files']['smoke.json'], replacement['files']['smoke.json'])
        self.assertEqual(json.loads((self.directory / 'proof.json').read_text()), replacement)

    def test_identity_or_report_mismatch_cannot_leave_stale_proof(self):
        for field in ('sourceSha', 'platformRef', 'runId', 'runAttempt', 'platform', 'schemaVersion'):
            self.write()
            before = self.lifecycle[field]
            self.lifecycle[field] = True if field == 'schemaVersion' else 'foreign'
            self.reports()
            with self.subTest(field=field), self.assertRaisesRegex(core.Failure, 'PENPOT_PROOF_LIFECYCLE'):
                self.write()
            self.assertFalse((self.directory / 'proof.json').exists())
            self.lifecycle[field] = before
            self.reports()
        self.smoke['assetPersistence'] = False
        self.reports()
        with self.assertRaisesRegex(core.Failure, 'PENPOT_PROOF_SMOKE'):
            self.write()
        self.assertFalse((self.directory / 'proof.json').exists())

    def test_secret_artifacts_symlinks_and_raw_credentials_are_rejected(self):
        forbidden = self.directory / 'runtime.env'
        forbidden.write_text('PENPOT_DB_PASSWORD=do-not-upload\n')
        with self.assertRaisesRegex(core.Failure, 'PENPOT_PROOF_FILES'):
            self.write()
        forbidden.unlink()
        log = self.directory / 'logs' / 'runtime.log'
        log.unlink()
        log.symlink_to(self.directory / 'smoke.json')
        with self.assertRaisesRegex(core.Failure, 'PENPOT_PROOF_FILES'):
            self.write()
        log.unlink()
        for raw in ('userToken=synthetic-secret', 'userToken%3Dsynthetic-secret',
                    'https://example.invalid/readyz?opaque=secret', 'https://user:secret@example.invalid/',
                    '-----BEGIN OPENSSH PRIVATE KEY-----', 'inspect={"Env":["NAME=secret"]}',
                    '\x00binary', '{"Env":["NAME=secret"]}'):
            with self.subTest(raw=raw):
                if raw.startswith('{'):
                    log.write_text('ERROR refused status=502\n')
                    self.lifecycle['raw'] = json.loads(raw)
                    self.reports()
                else:
                    log.write_text(raw)
                with self.assertRaisesRegex(core.Failure, 'PENPOT_PROOF_SECRET'):
                    self.write()
                self.assertFalse((self.directory / 'proof.json').exists())

    def test_failed_lifecycle_is_preserved_as_diagnostics_not_release(self):
        self.lifecycle['status'] = 'failed'
        self.lifecycle['cases'][0]['status'] = 'failed'
        self.lifecycle['errorCode'] = 'PENPOT_FIXTURE_MIGRATION_FAILURE'
        self.reports()
        result = self.write()
        self.assertEqual(result['files']['lifecycle.json'],
                         hashlib.sha256((self.directory / 'lifecycle.json').read_bytes()).hexdigest())
        self.assertNotIn('images', result)
        self.assertEqual(set(path.name for path in self.directory.iterdir()),
                         {'smoke.json', 'lifecycle.json', 'logs', 'proof.json'})


if __name__ == '__main__':
    unittest.main()
