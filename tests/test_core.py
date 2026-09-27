import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from core import Failure, atomic, digest, manifest, parse_json, parse_yaml, request

GOOD = b'''version: 1
app: 9router
strategy: blue-green
image: ghcr.io/thedemontuan/9router
platform: linux/arm64
runtime: {port: 20128}
health: {path: /api/health, timeout_seconds: 60}
route: {timeout_seconds: 30}
rtk: {image: ghcr.io/thedemontuan/rtk-sidecar}
'''
BASE = '{"version":1,"op":"deploy","app":"9router","request_id":"canary-1","component":"app","platform_ref":"%s","manifest_sha256":"%s","source_sha":"%s","image":"ghcr.io/thedemontuan/9router@sha256:%s"}' % ('a'*40, 'b'*64, 'c'*40, 'd'*64)
REGISTRATION = {'manifest': parse_yaml(GOOD), 'runtime': {'allowed_env': ['INITIAL_PASSWORD'], 'required_env': ['INITIAL_PASSWORD']}}
PROFILE = {'app': '9router', 'registration': REGISTRATION, 'image_repository': 'ghcr.io/thedemontuan/9router', 'rtk_image_repository': 'ghcr.io/thedemontuan/rtk-sidecar'}
DEMO = dict(PROFILE, app='demo', registration={'manifest': {'version': 1, 'app': 'demo', 'strategy': 'blue-green', 'image': 'localhost:5000/demo', 'platform': 'linux/arm64', 'runtime': {'port': 18081}, 'health': {'path': '/healthz', 'timeout_seconds': 60}, 'route': {'timeout_seconds': 30}}}, image_repository='localhost:5000/demo', rtk_image_repository=None)


class Validation(unittest.TestCase):
    def test_manifest_rejects_unknown_duplicate_alias_and_bool(self):
        self.assertEqual(manifest(GOOD, REGISTRATION)['runtime']['port'], 20128)
        for bad in (GOOD+b'unknown: true\n', GOOD.replace(b'port: 20128', b'port: true'), GOOD.replace(b'app: 9router', b'app: 9router\napp: 9router'), GOOD.replace(b'port: 20128', b'port: &x 20128'), GOOD+b'---\napp: 9router\n', GOOD+b' '*65536):
            with self.subTest(bad=bad[:30]), self.assertRaises(Failure):
                manifest(bad, REGISTRATION)

    def test_quoted_rule_negation_is_not_yaml_tag(self):
        self.assertEqual(parse_yaml(b'rule: "Host(`example.test`) && !PathPrefix(`/internal`)"\n')['rule'], 'Host(`example.test`) && !PathPrefix(`/internal`)')
        for bad in (b'item: &anchor value\n', b'item: *anchor\n', b'item: !custom value\n'):
            with self.subTest(bad=bad), self.assertRaisesRegex(Failure, 'UNSAFE_YAML'):
                parse_yaml(bad)

    def test_request_rejects_boundary_mutations(self):
        self.assertEqual(request(BASE.encode(), PROFILE)['request_id'], 'canary-1')
        for bad in (BASE.replace('canary-1','../canary'), BASE.replace('9router@sha256:', '9router:latest@sha256:'), BASE.replace('"app":"9router"','"app":"acb"'), BASE.replace('"version":1', '"version":true'), BASE.replace('"request_id":"canary-1"', '"request_id":"canary-1","request_id":"canary-2"'), BASE.replace('"component":"app"', '"component":"app","shell":"id"')):
            with self.subTest(bad=bad[:80]), self.assertRaises(Failure):
                request(bad.encode(), PROFILE)
        with self.assertRaises(Failure):
            request(BASE.encode()+b' '*65536, PROFILE)
        demo_raw = b'version: 1\napp: demo\nstrategy: blue-green\nimage: localhost:5000/demo\nplatform: linux/arm64\nruntime: {port: 18081}\nhealth: {path: /healthz, timeout_seconds: 60}\nroute: {timeout_seconds: 30}\n'
        self.assertEqual(manifest(demo_raw, DEMO['registration'])['health']['path'], '/healthz')
        with self.assertRaisesRegex(Failure, 'INVALID_COMPONENT'):
            request(BASE.replace('"app":"9router"', '"app":"demo"').replace('"component":"app"', '"component":"rtk"').encode(), DEMO)

    def test_atomic_replacement_and_mode(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home)/'state.json'
            atomic(path, b'old')
            atomic(path, b'new')
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(home).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
