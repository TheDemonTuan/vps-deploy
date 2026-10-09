import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import yaml

from test_penpot_contract import profile
import core

ROOT = Path(__file__).resolve().parents[1]


class PenpotEdgePersistence(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('penpot_edge', ROOT / 'install/penpot_edge.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'compose.yml'
        self.base = {'services': {'traefik': {'image': 'traefik:3', 'networks': {'existing': {}},
                                              'ports': ['8080:8080']}},
                     'networks': {'existing': {'external': True, 'name': 'edge-9router'}}}
        self.path.write_text(yaml.safe_dump(self.base))
        self.live = {'Config': {'Labels': {'com.docker.compose.project': 'edge-traefik',
                      'com.docker.compose.service': 'traefik',
                      'com.docker.compose.project.config_files': str(self.path)}},
                     'NetworkSettings': {'Networks': {'edge-9router': {}}}}

    def patches(self, module):
        return mock.patch.multiple(module, trusted_path=mock.Mock(side_effect=lambda path, **kw: Path(path)),
            container=mock.Mock(return_value=self.live),
            inspect=mock.Mock(return_value={'Driver': 'bridge', 'Internal': True, 'Options': {},
                            'Labels': {'vps-deploy.app': 'penpot'}, 'Containers': {}}))

    def test_read_only_plan_retains_all_existing_service_and_network_settings(self):
        module = self.module()
        before = self.path.read_bytes()
        with self.patches(module):
            plan = module.check(self.path)
        after = yaml.safe_load(plan['after'])
        self.assertEqual(after['services']['traefik']['ports'], self.base['services']['traefik']['ports'])
        self.assertEqual(after['networks']['existing'], self.base['networks']['existing'])
        self.assertEqual(after['networks']['edge-penpot'], {'external': True, 'name': 'edge-penpot'})
        self.assertEqual(self.path.read_bytes(), before)

    def test_foreign_project_service_file_or_network_is_rejected(self):
        module = self.module()
        for key, value in [('com.docker.compose.project', 'other'),
                           ('com.docker.compose.service', 'other'),
                           ('com.docker.compose.project.config_files', '/foreign.yml')]:
            original = copy.deepcopy(self.live)
            self.live['Config']['Labels'][key] = value
            with self.subTest(key=key), self.patches(module), self.assertRaises(core.Failure):
                module.check(self.path)
            self.live = original

    def test_noninternal_or_foreign_edge_is_rejected_before_compose_change(self):
        module = self.module()
        before = self.path.read_bytes()
        with self.patches(module), mock.patch.object(module, 'docker') as docker:
            plan = module.check(self.path)
            module.inspect.return_value['Internal'] = False
            with self.assertRaisesRegex(core.Failure, 'EDGE_NETWORK_OWNERSHIP'):
                module.apply(plan)
        self.assertEqual(self.path.read_bytes(), before)
        docker.assert_not_called()

    def test_apply_requires_unchanged_compose_and_never_restarts_traefik(self):
        module = self.module()
        with self.patches(module), mock.patch.object(module, 'docker') as docker:
            plan = module.check(self.path)
            module.apply(plan)
        self.assertIn('edge-penpot', yaml.safe_load(self.path.read_bytes())['networks'])
        calls = [call.args for call in docker.call_args_list]
        self.assertEqual(calls[-1], ('network', 'connect', 'edge-penpot', 'edge-traefik'))
        self.assertEqual(calls[0][:3], ('compose', '-p', 'edge-traefik'))
        self.assertEqual(calls[0][-2:], ('config', '--quiet'))
        self.assertFalse(any('up' in call or 'restart' in call for call in calls))
        self.path.write_text('services: {}\n')
        with self.patches(module), mock.patch.object(module, 'docker') as docker, self.assertRaisesRegex(core.Failure, 'EDGE_COMPOSE_CHANGED'):
            module.apply(plan)
        docker.assert_not_called()

    def test_existing_attachment_is_idempotent_and_conflicting_definition_fails(self):
        module = self.module()
        with self.patches(module):
            plan = module.check(self.path)
        self.path.write_bytes(plan['after'])
        self.live['NetworkSettings']['Networks']['edge-penpot'] = {}
        with self.patches(module), mock.patch.object(module, 'docker') as docker:
            plan = module.check(self.path)
            module.apply(plan)
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(docker.call_args.args[-2:], ('config', '--quiet'))
        value = yaml.safe_load(self.path.read_bytes())
        value['networks']['edge-penpot']['external'] = False
        self.path.write_text(yaml.safe_dump(value))
        with self.patches(module), self.assertRaises(core.Failure):
            module.check(self.path)

    def test_origin_probe_rejects_wrong_ca_source_peer_ip_tls_or_root_helper(self):
        module = self.module()
        item = dict(profile(), api_host='design.tuannguyenviet.site')
        entry = {'images': {role: repository + '@sha256:' + 'a' * 64
                            for role, repository in item['registration']['manifest']['images'].items()}}
        mounts = [{'Type': 'bind', 'Source': '/opt/platform/edge/cloudflare-ca',
                   'Destination': '/etc/cloudflare-origin-ca', 'RW': False}]
        cloudflared = {'Id': 'cloudflared', 'Mounts': mounts, 'NetworkSettings': {'Networks': {
            'tunnel': {'NetworkID': 'network', 'IPAddress': '172.31.250.2'}}}}
        traefik = {'Id': 'traefik', 'Mounts': [{'Type': 'bind',
            'Source': '/opt/platform/edge/traefik.yml', 'Destination': '/etc/traefik/traefik.yml', 'RW': False}],
            'NetworkSettings': {'Networks': {'tunnel': {'NetworkID': 'network', 'IPAddress': '172.31.250.4'}}}}
        network = {'Containers': {'cloudflared': {'IPv4Address': '172.31.250.2/24'},
                                  'traefik': {'IPv4Address': '172.31.250.4/24'}}}
        static = {'entryPoints': {'web': {'address': ':8080', 'http': {'tls': {}}}}}
        image = {'Config': {'User': '1001:1001'}}
        cases = {'ca-source': 'CLOUDFLARED_ORIGIN_CA_POLICY', 'writable-ca': 'CLOUDFLARED_ORIGIN_CA_POLICY',
                 'peer-ip': 'PENPOT_ORIGIN_NETWORK_POLICY', 'network-id': 'PENPOT_ORIGIN_NETWORK_POLICY',
                 'plaintext': 'PENPOT_ORIGIN_ENTRYPOINT_POLICY', 'root-helper': 'PENPOT_ORIGIN_HELPER_USER'}
        for case in cases:
            cf, tf, policy, helper = map(copy.deepcopy, (cloudflared, traefik, static, image))
            if case == 'ca-source':
                cf['Mounts'][0]['Source'] = '/etc/cloudflare-origin-ca'
            elif case == 'writable-ca':
                cf['Mounts'][0]['RW'] = True
            elif case == 'peer-ip':
                tf['NetworkSettings']['Networks']['tunnel']['IPAddress'] = '172.31.250.5'
            elif case == 'network-id':
                tf['NetworkSettings']['Networks']['tunnel']['NetworkID'] = 'foreign'
            elif case == 'plaintext':
                policy['entryPoints']['web']['http'] = {}
            else:
                helper['Config']['User'] = '0:1001'
            self.path.write_text(yaml.safe_dump(policy))
            def trusted(path, **kwargs):
                return self.path if str(path) == '/opt/platform/edge/traefik.yml' else Path(path)
            with self.subTest(case=case), \
                 mock.patch.object(module, 'trusted_path', side_effect=trusted), \
                 mock.patch.object(module, 'container', side_effect=lambda name, **kw: cf if name == 'edge-cloudflared' else tf), \
                 mock.patch.object(module, 'inspect', side_effect=lambda kind, name: network if kind == 'network' else helper), \
                 self.assertRaisesRegex(core.Failure, cases[case]):
                module.origin_topology(item, entry)


if __name__ == '__main__':
    unittest.main()
