import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('controller', Path(__file__).parents[1] / 'deploy.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
SHA = 'a' * 40
NEW = 'b' * 40


class SourceAPI:
    def __init__(self):
        self.config = controller.registration('acb')
        self.run = {'id': 42, 'workflow_id': 7, 'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
                    'event': 'push', 'head_branch': 'main', 'head_repository': {'full_name': self.config['repository']}}
        self.workflow = {'path': '.github/workflows/deploy.yml'}
        self.head = SHA
        self.comparison = {'status': 'ahead', 'total_commits': 1, 'files': [{'filename': 'internal/acb/client.go'}]}
        self.artifact = {'id': 11, 'name': 'frontend-dist-' + SHA, 'expired': False,
                         'workflow_run': {'head_sha': SHA}, 'digest': 'sha256:' + 'c' * 64}

    def get(self, path, binary=False):
        if '/actions/runs/42/artifacts?' in path:
            return {'artifacts': [self.artifact]}
        if path.endswith('/actions/runs/42'):
            return self.run
        if path.endswith('/actions/workflows/7'):
            return self.workflow
        if '/git/ref/heads/' in path:
            return {'object': {'sha': self.head}}
        if '/compare/' in path:
            return self.comparison
        if '/actions/workflows/deploy.yml/runs?' in path:
            return {'workflow_runs': [self.run]}
        raise AssertionError(path)


class SourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.api = SourceAPI()
        self.config = self.api.config

    def test_backend_only_successor_keeps_frontend_artifact_eligible(self):
        self.api.head = NEW
        result = controller.resolve(self.api, self.config, 'publish')
        self.assertEqual((result['sha'], result['run_id'], result['artifact_id']), (SHA, 42, 11))

    def test_changed_frontend_or_rename_refuses_stale_artifact(self):
        self.api.head = NEW
        for change in ({'filename': 'web/src/app.tsx'}, {'filename': 'internal/moved', 'previous_filename': 'web/app.tsx'}):
            self.api.comparison['files'] = [change]
            with self.subTest(change=change):
                with self.assertRaises(controller.Failure):
                    controller.resolve(self.api, self.config, 'publish', 42)

    def test_partial_ci_success_and_foreign_workflow_cannot_publish(self):
        for field, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('event', 'pull_request')]:
            original = self.api.run[field]
            self.api.run[field] = value
            with self.subTest(field=field):
                with self.assertRaises(controller.Failure):
                    controller.resolve(self.api, self.config, 'publish', 42)
            self.api.run[field] = original
        self.api.workflow['path'] = '.github/workflows/untrusted.yml'
        with self.assertRaises(controller.Failure):
            controller.resolve(self.api, self.config, 'publish', 42)

    def test_manual_branch_is_not_automatic_and_fork_identity_is_rejected(self):
        self.api.run['event'] = 'workflow_dispatch'
        self.api.run['head_branch'] = 'migration/cloudflare-static-assets'
        self.assertIsNone(controller.resolve(self.api, self.config, 'publish'))
        self.assertEqual(controller.resolve(self.api, self.config, 'bootstrap', 42)['run_id'], 42)
        self.api.run['head_repository']['full_name'] = 'attacker/fork'
        with self.assertRaises(controller.Failure):
            controller.resolve(self.api, self.config, 'publish', 42)

    def test_expired_or_wrong_artifact_identity_never_substitutes_another_run(self):
        self.api.artifact['expired'] = True
        with self.assertRaises(controller.Failure):
            controller.resolve(self.api, self.config, 'publish', 42)
        self.api.artifact['expired'] = False
        self.api.artifact['workflow_run']['head_sha'] = NEW
        with self.assertRaises(controller.Failure):
            controller.resolve(self.api, self.config, 'publish', 42)


class ArtifactBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = controller.registration('acb')

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, value in entries:
                archive.writestr(name, value)
        raw = stream.getvalue()
        return raw, 'sha256:' + hashlib.sha256(raw).hexdigest()

    def artifact(self):
        values = {'manifest.json': json.dumps({'app': 'acb', 'source_repository': self.config['repository'], 'source_sha': SHA}),
                  'dist/index.html': '<div>actual output</div>', 'dist/__release': SHA + '\n'}
        checksums = ''.join(hashlib.sha256(value.encode()).hexdigest() + '  ' + name + '\n' for name, value in values.items())
        return self.archive([*values.items(), ('SHA256SUMS', checksums)])

    def test_real_archive_digest_and_exhaustive_source_identity(self):
        raw, digest = self.artifact()
        controller.extract(raw, self.root, digest)
        controller.checksum(self.root, self.config, SHA)
        self.assertEqual((self.root / 'dist/__release').read_text(), SHA + '\n')
        (self.root / 'dist/extra.js').write_text('unlisted code')
        with self.assertRaises(controller.Failure):
            controller.checksum(self.root, self.config, SHA)

    def test_corrupt_download_does_not_extract(self):
        raw, digest = self.artifact()
        with self.assertRaises(controller.Failure):
            controller.extract(raw + b'corruption', self.root, digest)
        self.assertFalse((self.root / 'manifest.json').exists())

    def test_traversal_links_and_case_collisions_reject_before_writing(self):
        link = zipfile.ZipInfo('link')
        link.external_attr = 0o120777 << 16
        cases = [[('safe.txt', 'safe'), ('../escape', 'malicious')],
                 [('safe.txt', 'safe'), (link, '../escape')],
                 [('same.js', 'one'), ('Same.js', 'two')]]
        for entries in cases:
            raw, digest = self.archive(entries)
            with self.subTest(entries=entries):
                with self.assertRaises(controller.Failure):
                    controller.extract(raw, self.root, digest)
                self.assertFalse((self.root / 'safe.txt').exists())
                self.assertFalse((self.root.parent / 'escape').exists())

    def test_verified_bytes_cannot_claim_a_different_source_sha(self):
        raw, digest = self.artifact()
        controller.extract(raw, self.root, digest)
        with self.assertRaises(controller.Failure):
            controller.checksum(self.root, self.config, NEW)
        (self.root / 'dist/index.html').write_text('tampered bytes')
        with self.assertRaises(controller.Failure):
            controller.checksum(self.root, self.config, SHA)


if __name__ == '__main__':
    unittest.main()
