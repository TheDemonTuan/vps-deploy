import copy
import unittest
from unittest import mock

from test_penpot_contract import deploy_request, profile
import core
import penpot


class PenpotImageIdentity(unittest.TestCase):
    def setUp(self):
        self.request = deploy_request()
        self.profile = profile()

    def inspected(self, kind, ref):
        self.assertEqual(kind, 'image')
        return {'Id': ref, 'Config': {'Labels': {
            'org.opencontainers.image.source': 'https://github.com/TheDemonTuan/penpot',
            'org.opencontainers.image.revision': self.request['source_sha'],
        }}}

    def test_all_four_images_are_bound_to_one_source_before_downtime(self):
        with mock.patch.object(penpot, 'image_id', side_effect=lambda ref: ref) as identities, mock.patch.object(penpot, 'inspect', side_effect=self.inspected), mock.patch.object(penpot, 'docker') as docker:
            penpot.prepare_images(self.request, self.profile)
        self.assertEqual({call.args[0] for call in identities.call_args_list}, set(self.request['images'].values()))
        docker.assert_not_called()

    def test_wrong_source_revision_or_missing_label_is_rejected(self):
        for bad in ('source', 'revision', 'missing'):
            def inspect(kind, ref):
                value = self.inspected(kind, ref)
                if ref == self.request['images']['mcp']:
                    labels = value['Config']['Labels']
                    if bad == 'missing':
                        del labels['org.opencontainers.image.revision']
                    elif bad == 'source':
                        labels['org.opencontainers.image.source'] = 'https://github.com/attacker/penpot'
                    else:
                        labels['org.opencontainers.image.revision'] = 'f' * 40
                return value
            with self.subTest(bad=bad), mock.patch.object(penpot, 'image_id', side_effect=lambda ref: ref), mock.patch.object(penpot, 'inspect', side_effect=inspect), self.assertRaisesRegex(core.Failure, 'PENPOT_IMAGE_REVISION'):
                penpot.prepare_images(self.request, self.profile)

    def test_missing_digest_requires_anonymous_pull_and_then_identity_check(self):
        cache = set()
        def identity(ref):
            if ref not in cache:
                raise core.Failure('COMMAND_FAILED')
            return ref
        def pull(*args, **kwargs):
            self.assertEqual(args[0], 'pull')
            cache.add(args[1])
        with mock.patch.object(penpot, 'image_id', side_effect=identity), mock.patch.object(penpot, 'inspect', side_effect=self.inspected), mock.patch.object(penpot, 'anonymous_image') as anonymous, mock.patch.object(penpot, 'docker', side_effect=pull):
            penpot.prepare_images(self.request, self.profile)
        self.assertEqual({call.args[0] for call in anonymous.call_args_list}, set(self.request['images'].values()))

    def test_identity_failure_is_not_treated_as_a_missing_image(self):
        with mock.patch.object(penpot, 'image_id', side_effect=core.Failure('IDENTITY_MISMATCH')), mock.patch.object(penpot, 'docker') as docker, self.assertRaisesRegex(core.Failure, 'IDENTITY_MISMATCH'):
            penpot.prepare_images(self.request, self.profile)
        docker.assert_not_called()

    def test_release_entry_contains_map_and_source_not_a_fake_primary(self):
        value = penpot.release_entry(self.request, self.profile)
        self.assertEqual(set(value), {'slot', 'images', 'source_sha', 'platform_ref', 'manifest_sha256'})
        self.assertEqual(value['images'], self.request['images'])
        self.assertEqual(value['source_sha'], self.request['source_sha'])
        for key in ('slot', 'source_sha', 'manifest_sha256'):
            invalid = copy.deepcopy(value)
            invalid[key] = 'bad'
            with self.subTest(key=key), self.assertRaises(core.Failure):
                penpot.validate_entry(invalid, self.profile)
        invalid = {**value, 'image': value['images']['frontend']}
        with self.assertRaises(core.Failure):
            penpot.validate_entry(invalid, self.profile)


if __name__ == '__main__':
    unittest.main()
