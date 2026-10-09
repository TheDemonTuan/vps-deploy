import copy
from contextlib import ExitStack, nullcontext
import importlib.machinery
import signal
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from test_penpot_contract import deploy_request, profile
import core
import penpot


ROOT = Path(__file__).resolve().parents[1]
DEPLOYCTL = importlib.machinery.SourceFileLoader('penpot_state_deployctl', str(ROOT / 'bin/deployctl')).load_module()


class PenpotState(unittest.TestCase):
    def setUp(self):
        self.profile = dict(profile(), edge_network='edge-penpot', compose_project='penpot')
        self.entry = penpot.release_entry(deploy_request(), self.profile)
        self.profile['platform_ref'] = self.entry['platform_ref']
        self.state = {'version': 1, 'revision': 1, 'active': self.entry,
                      'previous': None, 'generation': 'a' * 32,
                      'operation': None, 'draining': None, 'rtk': None}

    def test_state_preserves_the_complete_map_without_a_primary_image(self):
        self.assertEqual(penpot.validate_state(self.state, self.profile), self.state)
        for field, value in (('version', True), ('revision', 0), ('generation', 'bad'),
                             ('rtk', {}), ('draining', 'single'), ('previous', {'image': 'bad'})):
            invalid = copy.deepcopy(self.state)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(core.Failure):
                penpot.validate_state(invalid, self.profile)
        invalid = dict(self.state, cgw={})
        with self.assertRaises(core.Failure):
            penpot.validate_state(invalid, self.profile)

    def live_container(self, name, ref, running):
        self.assertTrue(running)
        networks = {'penpot_penpot': {}}
        if name == 'penpot-frontend':
            networks['edge-penpot'] = {}
        if name in ('penpot-backend', 'penpot-exporter'):
            networks['penpot-egress'] = {}
        return {'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                'Config': {'Labels': {'vps-deploy.app': 'penpot',
                                      'com.docker.compose.project': 'penpot',
                                      'com.docker.compose.service': name}},
                'HostConfig': {'PortBindings': {}, 'PublishAllPorts': False},
                'NetworkSettings': {'Networks': networks, 'Ports': {}}}

    def test_health_requires_all_six_owned_services_with_exact_image_identities(self):
        refs = {}
        def container(name, ref=None, running=False):
            refs[name] = ref
            return self.live_container(name, ref, running)
        with mock.patch.object(penpot, 'container', side_effect=container):
            penpot.stack_health(self.profile, self.entry)
        self.assertEqual(set(refs), set(penpot.APP_SERVICES) | {'penpot-postgres', 'penpot-valkey'})
        for role, ref in self.entry['images'].items():
            self.assertEqual(refs['penpot-' + role], ref)
        import yaml
        compose = yaml.safe_load((ROOT / 'apps/penpot/docker-compose.prod.yml').read_text())
        for name in ('penpot-postgres', 'penpot-valkey'):
            self.assertEqual(refs[name], compose['services'][name]['image'])

    def test_unhealthy_foreign_published_or_wrong_network_service_is_not_healthy(self):
        for fault in ('health', 'owner', 'port', 'network', 'edge', 'privileged'):
            def container(name, ref=None, running=False):
                value = self.live_container(name, ref, running)
                if name == 'penpot-mcp':
                    if fault == 'health':
                        value['State']['Health']['Status'] = 'starting'
                    elif fault == 'owner':
                        value['Config']['Labels']['vps-deploy.app'] = 'other'
                    elif fault == 'port':
                        value['HostConfig']['PortBindings'] = {'4401/tcp': [{'HostPort': '4401'}]}
                    elif fault == 'network':
                        value['NetworkSettings']['Networks'] = {'foreign': {}}
                    elif fault == 'edge':
                        value['NetworkSettings']['Networks']['edge-penpot'] = {}
                    else:
                        value['HostConfig']['Privileged'] = True
                return value
            with self.subTest(fault=fault), mock.patch.object(penpot, 'container', side_effect=container), self.assertRaises(core.Failure):
                penpot.stack_health(self.profile, self.entry)

    def test_matching_rejects_configured_or_observed_generation_drift(self):
        import route
        for configured, observed in ((('single', 'f' * 32), ('single', 'a' * 32)),
                                     (('single', 'a' * 32), ('single', 'f' * 32))):
            with self.subTest(configured=configured, observed=observed), mock.patch.object(route, 'dynamic', return_value=Path('/unused')), mock.patch.object(route, 'preflight', return_value=(Path('/unused'), b'route', {})), mock.patch.object(route, 'route_state', return_value=configured), mock.patch.object(route, 'probe', return_value=observed), mock.patch.object(penpot, 'container', side_effect=self.live_container), self.assertRaises(core.Failure):
                penpot.matching(self.state, self.profile)

    def test_pending_operation_cannot_be_reported_as_healthy(self):
        self.state['operation'] = {'phase': 'checking', 'request_id': 'b' * 32}
        with self.assertRaisesRegex(core.Failure, 'RECOVERY_REQUIRED'):
            penpot.matching(self.state, self.profile)

    def test_incomplete_engine_is_rejected_before_creating_a_request_receipt(self):
        with mock.patch.object(DEPLOYCTL, 'lock'), mock.patch.object(DEPLOYCTL, 'load_profile', return_value=self.profile), mock.patch.object(DEPLOYCTL, 'verify_request') as verify, self.assertRaisesRegex(core.Failure, 'PENPOT_RELEASE_ENGINE_NOT_READY'):
            DEPLOYCTL.submit(deploy_request(), Path('/unused'), Path('/unused'), Path('/unused'))
        verify.assert_not_called()

    def test_adoption_requires_all_four_images_share_one_source(self):
        def lookup(live, repository):
            role = live['Config']['Labels']['com.docker.compose.service'].removeprefix('penpot-')
            return self.entry['images'][role]
        def inspect(kind, ref):
            return {'Config': {'Labels': {'org.opencontainers.image.source': 'https://github.com/TheDemonTuan/penpot',
                                          'org.opencontainers.image.revision': self.entry['source_sha']}}}
        with mock.patch.object(penpot, 'container', side_effect=lambda name, ref=None, **kw: self.live_container(name, ref, True)), mock.patch.object(core, 'container_digest', side_effect=lookup), mock.patch.object(penpot, 'inspect', side_effect=inspect), mock.patch.object(penpot, 'prepare_images') as prepare:
            adopted = penpot.adopt_state(self.profile, self.entry['manifest_sha256'], 'a' * 32)
            self.assertEqual(adopted, self.state)
            prepare.assert_called_once()
        def mixed(kind, ref):
            value = inspect(kind, ref)
            if ref == self.entry['images']['mcp']:
                value['Config']['Labels']['org.opencontainers.image.revision'] = 'f' * 40
            return value
        with mock.patch.object(penpot, 'container', side_effect=lambda name, ref=None, **kw: self.live_container(name, ref, True)), mock.patch.object(core, 'container_digest', side_effect=lookup), mock.patch.object(penpot, 'inspect', side_effect=mixed), mock.patch.object(penpot, 'prepare_images') as prepare, self.assertRaisesRegex(core.Failure, 'PENPOT_IMAGE_REVISION'):
            penpot.adopt_state(self.profile, self.entry['manifest_sha256'], 'a' * 32)
        prepare.assert_not_called()

    def test_guarded_worker_dispatches_only_the_penpot_handler_with_one_app_lock(self):
        for operation in ('deploy', 'reconcile'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as home, ExitStack() as stack:
                home = Path(home)
                req = deploy_request()
                req['op'] = operation
                if operation == 'reconcile':
                    req.pop('images')
                receipt = home / 'requests' / req['request_id']
                receipt.mkdir(parents=True)
                core.save(receipt / 'request.json', req)
                core.save(home / 'state.json', self.state)
                for name, kwargs in [('ready_engine', {}), ('load_profile', {'return_value': self.profile}),
                                     ('verify_request', {'return_value': ROOT}),
                                     ('trusted_path', {'side_effect': lambda path, **kw: path}),
                                     ('lock', {'side_effect': lambda *args: nullcontext()}),
                                     ('state_status', {'return_value': {'status': 'complete'}})]:
                    stack.enter_context(mock.patch.object(DEPLOYCTL, name, **kwargs))
                stack.enter_context(mock.patch.object(signal, 'signal'))
                deploy = stack.enter_context(mock.patch.object(penpot, 'transaction'))
                reconcile = stack.enter_context(mock.patch.object(penpot, 'reconcile_transaction'))
                old = stack.enter_context(mock.patch.object(DEPLOYCTL, 'transaction'))
                old_reconcile = stack.enter_context(mock.patch.object(DEPLOYCTL, 'reconcile'))
                result = DEPLOYCTL.run(req['request_id'], home, home, home, self.profile)
                self.assertEqual(result['status'], 'complete')
                called = deploy if operation == 'deploy' else reconcile
                self.assertTrue(called.call_args.kwargs['_locked'])
                self.assertEqual(called.call_count, 1)
                old.assert_not_called()
                old_reconcile.assert_not_called()
                self.assertEqual(core.load(receipt / 'result.json')['status'], 'complete')

    def test_status_returns_the_whole_map_and_source_without_a_fake_primary(self):
        with mock.patch.object(DEPLOYCTL, 'trusted_path', side_effect=lambda path, **kwargs: path), mock.patch.object(DEPLOYCTL, 'load', return_value=self.state), mock.patch.object(Path, 'exists', return_value=True), mock.patch.object(penpot, 'matching'), mock.patch.object(DEPLOYCTL.route, 'probe', return_value=('single', 'a' * 32)):
            value = DEPLOYCTL.state_status(Path('/unused'), None, Path('/unused'), self.profile)
        self.assertTrue(value['healthy'])
        self.assertEqual(value['images'], self.entry['images'])
        self.assertEqual(value['source_sha'], self.entry['source_sha'])
        self.assertNotIn('image', value)


if __name__ == '__main__':
    unittest.main()
