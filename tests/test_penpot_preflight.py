import copy
import json
import re
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml
from test_penpot_contract import deploy_request, profile
import core
import penpot

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'install'))
import preflight


class PenpotEnrollmentParity(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.cfg = Path(self.home.name)
        self.runtime = self.cfg / 'runtime.env'
        self.runtime.write_text('PENPOT_SECRET_KEY=' + 'S' * 64 + '\nPENPOT_DB_PASSWORD=' + 'a' * 64 + '\n')
        self.runtime.chmod(0o600)
        self.profile = dict(profile(), compose_project='penpot', edge_network='edge-penpot')
        self.registration = self.profile['registration']
        self.req = deploy_request()
        self.source_sha = self.req['source_sha']
        self.network_fault = None
        self.ready_response = 'OK200'
        self.image_defaults = {}
        (self.cfg / 'app.yml').write_text(yaml.safe_dump(self.registration['manifest']))
        (self.cfg / 'app.yml').chmod(0o600)
        self.values = {'PENPOT_SECRET_KEY': 'S' * 64, 'PENPOT_DB_PASSWORD': 'a' * 64}
        self.values.update({'PENPOT_' + role.upper() + '_IMAGE': ref for role, ref in self.req['images'].items()})
        raw = (ROOT / 'apps/penpot/docker-compose.prod.yml').read_text()
        self.composed = yaml.safe_load(re.sub(r'\$\{([A-Z_]+):\?[^}]+\}', lambda m: self.values[m[1]], raw))
        self.composed = {key: value for key, value in self.composed.items() if not key.startswith('x-')}
        for key, value in self.composed['networks'].items():
            value.setdefault('name', 'penpot_' + key)
        self.live = {}
        for name, service in self.composed['services'].items():
            for field in ('mem_limit', 'shm_size'):
                if field in service:
                    value = service[field]
                    service[field] = int(value[:-1]) * (1024 ** {'m': 2, 'g': 3}[value[-1]])
            service['volumes'] = [dict(type='volume', source=row.split(':')[0], target=row.split(':')[1],
                                       read_only=row.endswith(':ro')) for row in service.get('volumes', [])]
            networks = {self.composed['networks'][key]['name']: {} for key in service['networks']}
            mounts = [dict(Type='volume', Name=row['source'], Destination=row['target'], RW=not row['read_only'])
                      for row in service['volumes']]
            user = 'node' if name == 'penpot-mcp' else 'penpot:penpot' if name in penpot.APP_SERVICES else ''
            self.live[name] = {'Image': service['image'], 'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                'Config': {'User': user, 'Env': [key + '=' + str(value) for key, value in service.get('environment', {}).items()],
                    'Labels': {'vps-deploy.app': 'penpot', 'com.docker.compose.project': 'penpot',
                               'com.docker.compose.service': name}, 'Healthcheck': {'Test': service['healthcheck']['test']}},
                'HostConfig': {'SecurityOpt': ['no-new-privileges:true'], 'Memory': service['mem_limit'],
                               'ShmSize': service.get('shm_size', 67108864)},
                'NetworkSettings': {'Networks': networks, 'Ports': {}}, 'Mounts': mounts}

    def check(self):
        def image(kind, ref):
            if kind == 'network':
                members = set(self.live) if ref == 'penpot_penpot' else {'penpot-frontend', 'penpot-backend', 'penpot-exporter'} if ref == 'penpot-egress' else {'edge-traefik', 'penpot-frontend'}
                value = {'Driver': 'bridge', 'Internal': ref in ('penpot_penpot', 'edge-penpot'), 'Labels': {'vps-deploy.app': 'penpot'},
                         'Containers': {name: {'Name': name} for name in members}}
                if self.network_fault == 'internal' and ref == 'penpot_penpot':
                    value['Internal'] = False
                if self.network_fault == 'foreign' and ref == 'edge-penpot':
                    value['Containers']['foreign'] = {'Name': 'unrelated-app'}
                return value
            return {'Config': {'Env': self.image_defaults.get(ref, []),
                               'Labels': {'org.opencontainers.image.source': 'https://github.com/TheDemonTuan/penpot',
                                          'org.opencontainers.image.revision': self.source_sha}}}
        def live(name, ref=None, **kwargs):
            value = self.live[name]
            if ref is not None and value['Image'] != ref:
                raise core.Failure('IDENTITY_MISMATCH')
            return value
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kw: Path(path)))
            stack.enter_context(mock.patch.object(penpot, 'container', side_effect=live))
            stack.enter_context(mock.patch.object(penpot, 'inspect', side_effect=image))
            import penpot_preflight
            stack.enter_context(mock.patch.object(penpot_preflight, 'container_digest', side_effect=lambda value, repository: value['Image']))
            stack.enter_context(mock.patch.object(penpot, 'owned_volumes'))
            stack.enter_context(mock.patch.object(penpot, 'docker', return_value=self.ready_response))
            stack.enter_context(mock.patch.object(preflight.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(self.composed).encode())))
            return preflight.check(ROOT, 'penpot', self.registration, self.profile, self.runtime, None,
                                   source_sha=self.req['source_sha'], platform_ref=self.req['platform_ref'])

    def test_complete_six_service_parity_needs_no_primary_image(self):
        self.assertNotIn('image', self.registration['manifest'])
        before = {path.name: path.read_bytes() for path in self.cfg.iterdir()}
        self.assertEqual(set(self.check()['services']), set(self.live))
        self.assertEqual({path.name: path.read_bytes() for path in self.cfg.iterdir()}, before)

    def test_wrong_mount_mode_secret_flags_health_and_capability_fail_closed(self):
        for fault in ('mount_mode', 'secret', 'flags', 'extra_env', 'health', 'root', 'capability', 'paused', 'unlimited'):
            original = copy.deepcopy(self.live)
            value = self.live['penpot-backend']
            if fault == 'mount_mode':
                value['Mounts'][0]['RW'] = False
            elif fault in ('secret', 'flags'):
                key = 'PENPOT_SECRET_KEY' if fault == 'secret' else 'PENPOT_FLAGS'
                value['Config']['Env'] = [row for row in value['Config']['Env'] if not row.startswith(key + '=')]
            elif fault == 'extra_env':
                value['Config']['Env'].append('PENPOT_SMTP_HOST=unexpected-mailer')
            elif fault == 'health':
                value['Config']['Healthcheck']['Test'] = ['CMD', 'true']
            elif fault == 'root':
                value['Config']['User'] = '0'
            elif fault == 'capability':
                value['HostConfig']['CapAdd'] = ['SYS_ADMIN']
            elif fault == 'paused':
                value['State']['Paused'] = True
            else:
                value['HostConfig']['Memory'] = 0
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                self.check()
            self.live = original

    def test_extra_service_bind_mount_or_public_port_is_rejected(self):
        original = copy.deepcopy(self.composed)
        for fault in ('extra', 'bind', 'port'):
            if fault == 'extra':
                self.composed['services']['foreign'] = copy.deepcopy(self.composed['services']['penpot-mcp'])
            elif fault == 'bind':
                self.composed['services']['penpot-backend']['volumes'][0]['type'] = 'bind'
            else:
                self.composed['services']['penpot-mcp']['ports'] = [{'target': 4401, 'published': '4401'}]
            with self.subTest(fault=fault), self.assertRaises(core.Failure):
                self.check()
            self.composed = copy.deepcopy(original)

    def test_image_defaults_are_retained_but_compose_flags_override_them(self):
        self.image_defaults[self.req['images']['backend']] = ['LANG=C', 'PENPOT_FLAGS=upstream-defaults']
        self.live['penpot-backend']['Config']['Env'].append('LANG=C')
        self.assertEqual(set(self.check()['services']), set(self.live))

    def test_exact_source_network_isolation_and_frontend_readiness_are_required(self):
        for fault, code in [('source', 'PENPOT_IMAGE_REVISION'), ('internal', 'PENPOT_NETWORK_OWNERSHIP'),
                            ('foreign', 'PENPOT_NETWORK_OWNERSHIP'), ('ready', 'PENPOT_INTERNAL_READINESS')]:
            self.source_sha = 'f' * 40 if fault == 'source' else self.req['source_sha']
            self.network_fault = fault
            self.ready_response = 'OK302' if fault == 'ready' else 'OK200'
            with self.subTest(fault=fault), self.assertRaisesRegex(core.Failure, code):
                self.check()

    def test_manifest_or_secret_drift_is_rejected_without_printing_values(self):
        self.runtime.write_text('PENPOT_SECRET_KEY=too-short\nPENPOT_DB_PASSWORD=' + 'a' * 64 + '\n')
        with self.assertRaises(core.Failure) as caught:
            self.check()
        self.assertNotIn('too-short', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
