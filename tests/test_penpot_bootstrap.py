from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_penpot_contract import profile
import core

ROOT = Path(__file__).resolve().parents[1]


class PenpotBootstrap(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('penpot_bootstrap', ROOT / 'install/bootstrap-penpot.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def checked_fixture(self, module, home, stack):
        import yaml
        item = profile()
        registration = item['registration']
        work = Path(home) / 'source'
        dynamic = Path(home) / 'dynamic'
        dynamic.mkdir()
        (dynamic / 'middleware.yml').write_text('http:\n  middlewares:\n    tunnel-only: {}\n    crowdsec-ip: {}\n')
        binding = {'api_host': 'design.tuannguyenviet.site', 'dashboard_host': '', 'dashboard_alias_host': '',
                   'work_dir': '/opt/penpot', 'compose_project': 'penpot', 'edge_network': 'edge-penpot', 'route_name': 'penpot.yml'}
        host = {'host': 'oracle-main', 'apps': {'penpot': binding}, 'traefik': {'dynamic_dir': str(dynamic)}}
        args = SimpleNamespace(app='penpot', host='oracle-main', release='a' * 40, app_ref='b' * 40,
            app_source=str(work), public_key='/unused.pub', images=json.dumps({role: repository + '@sha256:' + 'c' * 64
                    for role, repository in registration['manifest']['images'].items()}))
        def git(path, *arguments):
            if arguments[0] == 'rev-parse':
                return (args.release if path == module.ROOT else args.app_ref).encode()
            if arguments[0] == 'show':
                self.assertEqual(arguments[1], args.app_ref + ':.deploy/app.yml')
                return yaml.safe_dump(registration['manifest']).encode()
            return b''
        for patch in (
            mock.patch.object(module.os, 'geteuid', return_value=0),
            mock.patch.object(module.os, 'uname', return_value=SimpleNamespace(machine='aarch64')),
            mock.patch.object(module, 'trusted_path', side_effect=lambda path, **kw: Path(path)),
            mock.patch.object(module.route, 'trusted_path', side_effect=lambda path, **kw: Path(path)),
            mock.patch.object(module, 'app_registration', return_value=registration),
            mock.patch.object(core, 'host_registration', return_value=host),
            mock.patch.object(module.installer, 'CONFIG', Path(home) / 'config'),
            mock.patch.object(module.installer, 'STATE', Path(home) / 'state'),
            mock.patch.object(module.installer, 'RELEASES', Path(home) / 'releases'),
            mock.patch.object(module.installer, 'git', side_effect=git),
            mock.patch.object(module.installer, 'valid_key'),
            mock.patch.object(module, 'image_id', return_value='image'),
            mock.patch.object(module, 'inspect', return_value={'Config': {'Labels': {
                'org.opencontainers.image.source': 'https://github.com/TheDemonTuan/penpot',
                'org.opencontainers.image.revision': args.app_ref}}}),
            mock.patch.object(module.penpot, 'anonymous_image'),
            mock.patch.object(module, 'edge_policy'),
            mock.patch.object(module.penpot_edge, 'check', return_value={}),
            mock.patch.object(module.route, 'render', return_value=b'normal'),
            mock.patch.object(module.penpot, 'maintenance_route', return_value=b'maintenance'),
            mock.patch.object(module, 'docker', return_value=''),
        ):
            stack.enter_context(patch)
        return args

    def test_bootstrap_check_is_nonmutating_and_validates_all_four_source_images(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            args = self.checked_fixture(module, home, stack)
            with mock.patch.object(module, 'save') as save, mock.patch.object(module, 'atomic') as atomic:
                plan = module.check(args)
            self.assertEqual(plan['entry']['source_sha'], args.app_ref)
            self.assertEqual(len(plan['entry']['images']), 4)
            self.assertEqual(module.penpot.anonymous_image.call_count, 4)
            self.assertTrue(all(call.args[0] in ('ps', 'volume', 'network') for call in module.docker.call_args_list))
            save.assert_not_called()
            atomic.assert_not_called()
            self.assertFalse((Path(home) / 'state').exists())
            module.inspect.return_value['Config']['Labels']['org.opencontainers.image.revision'] = 'd' * 40
            with self.assertRaisesRegex(core.Failure, 'PENPOT_IMAGE_REVISION'):
                module.check(args)

    def test_dirty_source_or_existing_host_route_fail_before_bootstrap(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            args = self.checked_fixture(module, home, stack)
            (Path(home) / 'dynamic' / 'old.yml').write_text('design.tuannguyenviet.site')
            with self.assertRaisesRegex(core.Failure, 'PENPOT_HOST_ROUTE_COLLISION'):
                module.check(args)
            (Path(home) / 'dynamic' / 'old.yml').unlink()
            original = module.installer.git.side_effect
            def dirty(path, *arguments):
                return b' M local' if path != module.ROOT and arguments[0] == 'status' else original(path, *arguments)
            module.installer.git.side_effect = dirty
            with self.assertRaisesRegex(core.Failure, 'APP_SOURCE_DIRTY'):
                module.check(args)
            self.assertFalse((Path(home) / 'state').exists())

    def test_cli_rejects_nonroot_without_mutating_host(self):
        import os
        if os.geteuid() == 0:
            self.skipTest('nonroot CLI assertion')
        result = subprocess.run([sys.executable, str(ROOT / 'install/bootstrap-penpot.py'), '--app', 'penpot',
            '--host', 'oracle-main', '--release', 'a' * 40, '--app-source', '/absent', '--app-ref', 'b' * 40,
            '--images', '{}', '--public-key', '/absent', '--check'], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), b'ROOT_REQUIRED')
        self.assertEqual(result.stdout, b'')

    def test_activation_fence_precedes_every_mutating_action(self):
        module = self.module()
        with mock.patch.object(module, 'check', return_value={'profile': profile()}), \
             mock.patch.object(module.installer, 'release_copy') as copy, \
             mock.patch.object(module, 'docker') as docker, \
             mock.patch.object(module, 'atomic') as atomic, \
             mock.patch.object(module.penpot_secrets, 'runtime') as secrets:
            with self.assertRaisesRegex(core.Failure, 'PENPOT_RELEASE_ENGINE_NOT_READY'):
                module.apply(SimpleNamespace())
        copy.assert_not_called()
        docker.assert_not_called()
        atomic.assert_not_called()
        secrets.assert_not_called()

    def test_guarded_apply_stages_secrets_and_keeps_maintenance_after_ack_failure(self):
        from contextlib import nullcontext
        import yaml
        module = self.module()
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            args = self.checked_fixture(module, home, stack)
            plan = module.check(args)
            work = Path(home) / 'work'
            assets = Path(home) / 'assets'
            assets.mkdir(mode=0o700)
            plan['profile']['work_dir'] = str(work)
            plan['profile']['host_registration']['apps']['penpot']['work_dir'] = str(work)
            plan['profile']['route_name'] = 'penpot.yml'
            plan['locks'] = Path(home) / 'locks'
            plan['record']['platformRef'] = args.release
            for patch in (
                mock.patch.object(module, 'check', return_value=plan),
                mock.patch.object(module.runpy, 'run_path', return_value={'ready_engine': lambda p: None}),
                mock.patch.object(module.installer, 'release_copy'),
                mock.patch.object(module.installer, 'tree', return_value={}),
                mock.patch.object(module, 'lock', side_effect=lambda *a, **kw: nullcontext()),
                mock.patch.object(module.os, 'chown'),
                mock.patch.object(core, 'host', return_value=plan['profile']),
                mock.patch.object(module.penpot, 'trusted_path', side_effect=lambda p, **kw: Path(p)),
                mock.patch.object(module.penpot_secrets, 'trusted_path', side_effect=lambda p, **kw: Path(p)),
                mock.patch.object(module.penpot, 'owned_volumes'),
                mock.patch.object(module.penpot, 'stack_health'),
                mock.patch.object(module.penpot_preflight, 'check'),
                mock.patch.object(module.penpot_edge, 'origin_ack'),
                mock.patch.object(module.penpot_edge, 'apply'),
                mock.patch.object(module.route, 'unchanged'),
                mock.patch.object(module.route, 'ack', side_effect=core.Failure('ACK_FAILED')),
                mock.patch.object(module, 'command'),
            ):
                stack.enter_context(patch)
            def publish(path, raw, before):
                self.assertEqual(core.digest(path.read_bytes()), before)
                path.write_bytes(raw)
            stack.enter_context(mock.patch.object(module.route, 'publish', side_effect=publish))
            module.inspect.return_value = {'Mountpoint': str(assets)}
            module.docker.side_effect = lambda *a, **kw: 'OK200' if a[0] == 'exec' else ''
            with self.assertRaisesRegex(core.Failure, 'ACK_FAILED'):
                module.apply(args)
            self.assertEqual(plan['target'].read_bytes(), b'maintenance')
            self.assertFalse((plan['state'] / 'state.json').exists())
            self.assertTrue((plan['state'] / 'bootstrap.json').exists())
            self.assertEqual((work / '.env').read_bytes(), (plan['cfg'] / 'runtime.env').read_bytes())

    def test_first_route_is_atomic_readable_and_cannot_replace_any_file(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / 'penpot.yml'
            module.exclusive_route(path, b'first\n')
            self.assertEqual(path.read_bytes(), b'first\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            with self.assertRaisesRegex(core.Failure, 'ROUTE_ALREADY_EXISTS'):
                module.exclusive_route(path, b'second\n')
            self.assertEqual(path.read_bytes(), b'first\n')
            self.assertEqual({p.name for p in Path(home).iterdir()}, {'penpot.yml'})
            path.unlink()
            path.symlink_to(Path(home) / 'missing')
            with self.assertRaises(core.Failure):
                module.exclusive_route(path, b'no\n')
            self.assertTrue(path.is_symlink())


    def test_tls_and_query_logs_fail_closed(self):
        module = self.module()
        static = {'accessLog': {'fields': {'queryParameters': {'defaultMode': 'drop'}}}}
        cert = {'tls': {'certificates': [{'certFile': '/certs/certificate.pem'}]}}
        live = {'State': {'Running': True}, 'Mounts': [
            {'Type': 'bind', 'Source': source, 'Destination': destination, 'RW': False}
            for source, destination in (('/opt/platform/edge/traefik.yml', '/etc/traefik/traefik.yml'),
                                        ('/opt/platform/edge/dynamic', '/etc/traefik/dynamic'),
                                        ('/opt/platform/edge/certs', '/certs'))]}
        with mock.patch.object(module, 'inspect', return_value=live), mock.patch.object(module, 'trusted_path', return_value=SimpleNamespace(read_bytes=lambda: b'x')), \
             mock.patch.object(module, 'parse_yaml', side_effect=[static, cert]), \
             mock.patch.object(module.installer, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            module.edge_policy()
        self.assertIn('-verify_hostname', run.call_args_list[0].args)
        self.assertIn('design.tuannguyenviet.site', run.call_args_list[0].args)
        self.assertEqual(run.call_args_list[1].args[-2:], ('-checkend', '86400'))
        static['accessLog']['fields']['queryParameters']['names'] = {'capability': 'keep'}
        with mock.patch.object(module, 'inspect', return_value=live), \
             mock.patch.object(module, 'trusted_path', return_value=SimpleNamespace(read_bytes=lambda: b'x')), \
             mock.patch.object(module, 'parse_yaml', return_value=static), \
             mock.patch.object(module.installer, 'run') as run, \
             self.assertRaisesRegex(core.Failure, 'EDGE_QUERY_LOG_POLICY'):
            module.edge_policy()
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
