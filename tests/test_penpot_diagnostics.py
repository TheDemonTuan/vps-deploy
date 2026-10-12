import copy
import hashlib
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

import test_penpot_publication
import core


diagnostic = test_penpot_publication.script('diagnose-penpot')


class NativeDiagnostics(unittest.TestCase):
    def setUp(self):
        self.source = 'a' * 40
        self.platform = 'b' * 40
        self.run = {'id': 123, 'run_attempt': 2, 'path': '.github/workflows/fork-deploy.yml',
                    'event': 'push', 'head_branch': 'main', 'head_sha': self.source, 'status': 'completed',
                    'conclusion': 'failure', 'repository': {'full_name': diagnostic.REPOSITORY, 'id': 456},
                    'head_repository': {'full_name': diagnostic.REPOSITORY, 'id': 456},
                    'referenced_workflows': [{'path': diagnostic.BUILD_WORKFLOW + self.platform,
                                              'sha': self.platform}]}
        self.artifact = {'id': 789, 'name': 'penpot-built-unverified-' + self.source + '-123-2',
                         'expired': False, 'expires_at': '2099-01-01T00:00:00Z', 'size_in_bytes': 100,
                         'digest': 'sha256:' + 'c' * 64,
                         'workflow_run': {'id': 123, 'head_sha': self.source, 'head_branch': 'main',
                                          'repository_id': 456, 'head_repository_id': 456}}
        self.api = mock.Mock()
        self.api.get.side_effect = lambda path: self.artifact if '/artifacts/' in path else self.run
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def provenance(self):
        return diagnostic.provenance(self.api, 123, 789, self.source)

    def test_failed_push_build_is_reusable_not_required_to_be_a_release(self):
        self.assertEqual(self.provenance(), (self.platform, self.artifact['digest']))

    def test_repository_workflow_branch_source_builder_and_attempt_must_match(self):
        mutations = [
            ('run', 'path', '.github/workflows/foreign.yml'), ('run', 'event', 'pull_request'),
            ('run', 'event', 'workflow_dispatch'), ('run', 'head_branch', 'foreign'),
            ('run', 'head_sha', 'd' * 40), ('run', 'status', 'in_progress'),
            ('run', 'repository', {'full_name': 'foreign/penpot', 'id': 456}),
            ('run', 'head_repository', {'full_name': diagnostic.REPOSITORY, 'id': 999}),
            ('run', 'referenced_workflows', [{'path': diagnostic.BUILD_WORKFLOW + self.platform, 'sha': 'd' * 40}]),
            ('artifact', 'name', 'penpot-native-' + self.source + '-123-2'),
            ('artifact', 'name', 'penpot-built-unverified-' + self.source + '-123-3'),
            ('artifact', 'expired', True), ('artifact', 'expires_at', '2000-01-01T00:00:00Z'),
            ('artifact', 'digest', None),
            ('artifact', 'workflow_run', dict(self.artifact['workflow_run'], head_repository_id=999)),
        ]
        for target, key, value in mutations:
            original = copy.deepcopy(getattr(self, target))
            getattr(self, target)[key] = value
            with self.subTest(target=target, key=key), self.assertRaises(core.Failure):
                self.provenance()
            setattr(self, target, original)

    def test_exact_older_attempt_resolves_its_original_builder(self):
        self.artifact['name'] = 'penpot-built-unverified-' + self.source + '-123-1'
        earlier_platform = 'd' * 40
        earlier = dict(self.run, run_attempt=1,
                       referenced_workflows=[{'path': diagnostic.BUILD_WORKFLOW + earlier_platform,
                                              'sha': earlier_platform}])
        self.api.get.side_effect = lambda path: (self.artifact if '/artifacts/' in path else
                                                earlier if '/attempts/' in path else self.run)
        self.assertEqual(self.provenance()[0], earlier_platform)

    def archive(self, entries):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as bundle:
            for name, value in entries:
                bundle.writestr(name, value)
        return raw.getvalue()

    def download(self, raw, directory, digest=None):
        self.api.open.side_effect = lambda path: io.BytesIO(raw)
        diagnostic.download(self.api, 789, directory, digest or 'sha256:' + hashlib.sha256(raw).hexdigest())

    def test_download_checks_digest_and_extracts_only_two_fixed_regular_files(self):
        raw = self.archive([('build.json', b'{}'), ('images.tar.zst', b'images')])
        directory = Path(self.temp.name) / 'valid'
        self.download(raw, directory)
        self.assertEqual({path.name for path in directory.iterdir()}, {'build.json', 'images.tar.zst'})
        self.assertEqual((directory / 'images.tar.zst').read_bytes(), b'images')
        with self.assertRaisesRegex(core.Failure, 'PENPOT_ARTIFACT_DIGEST'):
            self.download(raw, Path(self.temp.name) / 'wrong-digest', 'sha256:' + 'd' * 64)
        for index, entries in enumerate([
                [('build.json', b'{}'), ('../images.tar.zst', b'images')],
                [('build.json', b'{}'), ('images.tar.zst', b'images'), ('extra.sh', b'script')],
                [('build.json', b'{}'), ('build.json', b'duplicate')]]):
            with self.subTest(entries=entries), self.assertRaisesRegex(core.Failure, 'PENPOT_ARTIFACT_FILES'):
                self.download(self.archive(entries), Path(self.temp.name) / str(index))
        symlink = zipfile.ZipInfo('images.tar.zst')
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(core.Failure, 'PENPOT_ARTIFACT_FILES'):
            self.download(self.archive([('build.json', b'{}'), (symlink, b'/etc/passwd')]),
                          Path(self.temp.name) / 'symlink')

    def test_diagnostic_loader_validates_images_but_never_pushes_or_checks_published_digests(self):
        publication = test_penpot_publication.PenpotPublication()
        publication.setUp()
        self.addCleanup(publication.doCleanups)
        with mock.patch.object(test_penpot_publication.publish, 'docker') as docker, \
                mock.patch.object(test_penpot_publication.publish, 'inspect', side_effect=publication.inspect), \
                mock.patch.object(test_penpot_publication.publish, 'anonymous_image') as anonymous:
            tags = diagnostic.load_bundle(publication.archive, publication.metadata,
                                          publication.source, publication.platform)
        self.assertEqual(set(tags), set(core.PENPOT_ROLES))
        self.assertEqual([call.args[0] for call in docker.call_args_list], ['load'])
        anonymous.assert_not_called()



if __name__ == '__main__':
    unittest.main()
