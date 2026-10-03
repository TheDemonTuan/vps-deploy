import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, app_registration, host_registration, manifest, parse_yaml

ACTIVATION = Path(__file__).resolve().parents[1] / 'tests/fixtures/activation'


class ActivationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'registry').mkdir()
        (self.root / 'hosts').mkdir()
        shutil.copyfile(ACTIVATION / 'registry/9router.yml', self.root / 'registry/9router.yml')
        shutil.copyfile(ACTIVATION / 'hosts/oracle-main.yml', self.root / 'hosts/oracle-main.yml')
        self.manifest_raw = (ACTIVATION / 'app.yml').read_bytes()

    def test_expanded_registration_validates_cgw_image_and_network(self):
        reg = app_registration(self.root, '9router')
        host = host_registration(self.root, 'oracle-main')
        self.assertEqual(reg['manifest']['cgw']['image'], 'ghcr.io/thedemontuan/9router-cgw-runtime')
        self.assertEqual(host['apps']['9router']['cgw_network'], '9router-cgw')
        parsed = manifest(self.manifest_raw, reg)
        self.assertEqual(parsed['cgw']['image'], 'ghcr.io/thedemontuan/9router-cgw-runtime')

    def test_unregistered_app_cannot_claim_cgw(self):
        raw = parse_yaml((ACTIVATION / 'registry/9router.yml').read_bytes())
        raw['app'] = 'other'
        (self.root / 'registry/other.yml').write_bytes(json.dumps(raw).encode())
        with self.assertRaisesRegex(Failure, 'REGISTRY_POLICY'):
            app_registration(self.root, 'other')

    def test_non_canonical_cgw_image_fails_registration(self):
        raw = parse_yaml((ACTIVATION / 'registry/9router.yml').read_bytes())
        raw['manifest']['cgw']['image'] = 'ghcr.io/other/runtime'
        (self.root / 'registry/9router.yml').write_bytes(json.dumps(raw).encode())
        with self.assertRaisesRegex(Failure, 'REGISTRY_POLICY'):
            app_registration(self.root, '9router')


if __name__ == '__main__':
    unittest.main()
