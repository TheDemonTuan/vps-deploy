import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import route
from core import Failure, digest

ROOT = Path(__file__).resolve().parents[1]
GENERATION = '0123456789abcdef0123456789abcdef'
PROFILE = {
    'app': '9router', 'route_name': '9router.yml', 'platform_ref': 'a' * 40,
    'api_host': 'api.test.invalid', 'dashboard_host': 'dashboard.test.invalid',
    'dashboard_alias_host': 'legacy.test.invalid',
    'registration': {'manifest': {'runtime': {'port': 20128}, 'health': {'path': '/api/health'}},
                     'route': {'generation_header': 'X-9Router-Route-Generation',
                               'required_middlewares': ['security-headers', 'deny-internal']}},
    'host_registration': {'traefik': {'container': 'edge-traefik', 'mount': '/etc/traefik/dynamic'}},
}


def rendered():
    return subprocess.check_output(['bash', str(ROOT / 'apps/9router/adapter.sh'), 'blue', GENERATION,
                                    PROFILE['dashboard_host'], PROFILE['dashboard_alias_host'], PROFILE['api_host']])


class RoutePolicy(unittest.TestCase):
    def test_registered_identity_and_exact_url(self):
        raw = rendered()
        self.assertEqual(route.route_state(raw, PROFILE), ('blue', GENERATION))
        for bad in (raw.replace(b'20128', b'18081'), raw.replace(b'X-9Router-Route-Generation', b'X-Demo-Route-Generation')):
            with self.subTest(bad=bad[:40]), self.assertRaises(Failure):
                route.route_state(bad, PROFILE)

    def test_preflight_checks_definitions_collision_permissions_and_file_set(self):
        with tempfile.TemporaryDirectory() as root, patch.object(route, 'trusted_path', side_effect=lambda path, directory=False: path), patch.object(route, 'render', return_value=rendered()):
            directory = Path(root)
            target = directory / PROFILE['route_name']
            target.write_bytes(rendered())
            target.chmod(0o644)
            shared = directory / 'shared.yml'
            shared.write_bytes(b'http:\n  middlewares:\n    security-headers: {headers: {}}\n    deny-internal: {headers: {}}\n')
            shared.chmod(0o644)
            def mock_docker(*args):
                if len(args) >= 4 and args[:3] == ('exec', 'edge-traefik', 'cat'):
                    rel = args[3].replace('/etc/traefik/dynamic/', '')
                    return (directory / rel).read_text()
                return ''
            with patch.object(route, 'docker', side_effect=mock_docker):
                _, raw, hashes = route.preflight(directory, PROFILE)
                self.assertEqual(digest(raw), digest(rendered()))
                route.unchanged(hashes, directory, PROFILE['route_name'])
                other = directory / 'other.yml'
                other.write_bytes(b'http: {routers: {unrelated: {rule: "Host(`other.test`)"}}}\n')
                other.chmod(0o644)
                with self.assertRaisesRegex(Failure, 'SHARED_ROUTE_CHANGED'):
                    route.unchanged(hashes, directory, PROFILE['route_name'])
                other.unlink()
                shared.chmod(0o600)
                with self.assertRaisesRegex(Failure, 'ROUTE_UNREADABLE'):
                    route.preflight(directory, PROFILE)
                shared.chmod(0o644)
                shared.write_bytes(b'# deny-internal: security-headers:\nhttp: {middlewares: {}}\n')
                with self.assertRaisesRegex(Failure, 'MIDDLEWARE_MISSING'):
                    route.preflight(directory, PROFILE)
                shared.write_bytes(b'http: {middlewares: {security-headers: {}, deny-internal: {}}, routers: {9router-api-fallback: {}}}\n')
                with self.assertRaisesRegex(Failure, 'ROUTE_COLLISION'):
                    route.preflight(directory, PROFILE)
                shared.unlink()
                target.chmod(0o600)
                with self.assertRaisesRegex(Failure, 'ROUTE_UNREADABLE'):
                    route.preflight(directory, PROFILE)
                target.chmod(0o644)
                shared = directory / 'shared.yml'
                shared.write_bytes(b'http:\n  middlewares:\n    security-headers: {headers: {}}\n    deny-internal: {headers: {}}\n')
                shared.chmod(0o644)
            with patch.object(route, 'docker', return_value='corrupted'):
                with self.assertRaisesRegex(Failure, 'TRAEFIK_UNREADABLE'):
                    route.preflight(directory, PROFILE)

    def test_custom_probe_and_duplicate_or_cached_ack(self):
        helper = ROOT / 'lib/traefik.sh'
        with tempfile.TemporaryDirectory() as root:
            curl = Path(root) / 'curl'
            curl.write_text('''#!/usr/bin/env bash
set -eu
while (( $# )); do
  case "$1" in
    --dump-header) headers="$2"; shift 2 ;;
    --output) body="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
[[ $url == https://demo.fixture.test/healthz\\?deploy_probe=* ]] || exit 1
printf 'HTTP/2 200\\r\\ncache-control: no-store\\r\\nX-Demo-Route-Generation: 0123456789abcdef0123456789abcdef\\r\\n%s\\r\\n' "${EXTRA_HEADER:-}" > "$headers"
printf '{"ok":true,"deployment_slot":"green"}' > "$body"
printf 200
''')
            curl.chmod(0o755)
            args = ['bash', str(helper), 'probe', 'demo.fixture.test', '/healthz', 'X-Demo-Route-Generation']
            env = dict(os.environ, PATH=root + os.pathsep + os.environ['PATH'])
            result = subprocess.run(args, env=env, capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'green ' + GENERATION))
            for extra in ('X-Demo-Route-Generation: ' + GENERATION, 'Age: 1'):
                with self.subTest(extra=extra):
                    result = subprocess.run(args, env=dict(env, EXTRA_HEADER=extra), capture_output=True)
                    self.assertNotEqual(result.returncode, 0)

    def test_probe_input_rejected_before_network(self):
        helper = ROOT / 'lib/traefik.sh'
        for path, header in (('/healthz?unsafe=1', 'X-Demo-Route-Generation'), ('/a/../healthz', 'X-Demo-Route-Generation'), ('/healthz', 'Bad:Header')):
            with self.subTest(path=path, header=header):
                result = subprocess.run(['bash', str(helper), 'probe', 'demo.fixture.test', path, header], capture_output=True)
                self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
