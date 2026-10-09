import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from test_penpot_contract import ROOT, deploy_request, profile, registration
import core
import penpot


class PenpotStorage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.backup = self.root / 'backup'
        self.backup.mkdir(mode=0o700)
        self.trust = mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kwargs: Path(path))
        self.trust.start()
        self.addCleanup(self.trust.stop)
        dump_check = mock.patch.object(penpot, 'check_dump')
        dump_check.start()
        self.addCleanup(dump_check.stop)
        self.entry = {'slot': 'single', 'images': deploy_request()['images'], 'source_sha': 'a' * 40,
                      'platform_ref': 'b' * 40, 'manifest_sha256': 'c' * 64}
        self.runtime = b'PENPOT_SECRET_KEY=' + b'A' * 86 + b'\nPENPOT_DB_PASSWORD=' + b'1' * 64 + b'\n'
        self.write_snapshot()

    def archive(self, members=None):
        with tarfile.open(self.backup / 'assets.tar', 'w') as archive:
            for name, kind, target in members or [('asset.txt', tarfile.REGTYPE, '')]:
                value = tarfile.TarInfo(name)
                value.type = kind
                value.linkname = target
                value.uid = value.gid = 1001
                data = b'known-asset' if kind == tarfile.REGTYPE else b''
                value.size = len(data)
                archive.addfile(value, io.BytesIO(data) if data else None)
        (self.backup / 'assets.tar').chmod(0o600)

    def write_snapshot(self):
        self.archive()
        data = {'database.dump': b'PGDMP\x00binary-fixture\xff', 'runtime.env': self.runtime,
                'app.yml': yaml.safe_dump(registration()['manifest']).encode(),
                'route.yml': b'normal-old-route'}
        for name, content in data.items():
            if (self.backup / name).is_symlink():
                (self.backup / name).unlink()
            (self.backup / name).write_bytes(content)
            (self.backup / name).chmod(0o600)
        self.metadata = {
            'schemaVersion': 1, 'app': 'penpot', 'createdAt': '2026-10-07T09:00:00Z',
            'sourceSha': self.entry['source_sha'], 'platformRef': self.entry['platform_ref'],
            'images': self.entry['images'],
            'volumes': {'database': 'penpot_postgres_v15', 'assets': 'penpot_assets'},
            'sha256': {name: hashlib.sha256((self.backup / name).read_bytes()).hexdigest()
                       for name in ('database.dump', 'assets.tar', 'runtime.env', 'app.yml', 'route.yml')},
        }
        self.save_metadata()

    def save_metadata(self):
        (self.backup / 'manifest.json').write_text(json.dumps(self.metadata))
        (self.backup / 'manifest.json').chmod(0o600)

    def verify(self):
        return penpot.verify_snapshot(self.backup, registration())

    def test_exact_complete_snapshot_preserves_binary_and_identity(self):
        self.assertEqual(self.verify(), self.metadata)

    def test_missing_marker_checksum_tamper_and_unknown_file_fail(self):
        original = (self.backup / 'manifest.json').read_bytes()
        (self.backup / 'manifest.json').unlink()
        with self.assertRaises(core.Failure):
            self.verify()
        (self.backup / 'manifest.json').write_bytes(original)
        (self.backup / 'manifest.json').chmod(0o600)
        (self.backup / 'database.dump').write_bytes(b'PGDMPcorrupted')
        with self.assertRaisesRegex(core.Failure, 'PENPOT_BACKUP_CHECKSUM'):
            self.verify()
        self.write_snapshot()
        (self.backup / 'unexpected').write_bytes(b'extra')
        with self.assertRaises(core.Failure):
            self.verify()

    def test_wrong_manifest_repo_schema_volume_and_timestamp_rejected(self):
        for change in ('manifest', 'repository', 'schema', 'volume', 'timestamp'):
            self.write_snapshot()
            if change == 'manifest':
                (self.backup / 'app.yml').write_text('version: 1\napp: wrong\n')
                self.metadata['sha256']['app.yml'] = hashlib.sha256((self.backup / 'app.yml').read_bytes()).hexdigest()
            elif change == 'repository':
                self.metadata['images'] = {**self.metadata['images'], 'backend': self.entry['images']['frontend']}
            elif change == 'schema':
                self.metadata['schemaVersion'] = True
            elif change == 'volume':
                self.metadata['volumes']['database'] = '9router-data'
            else:
                self.metadata['createdAt'] = '2026-99-07T09:00:00Z'
            self.save_metadata()
            with self.subTest(change=change), self.assertRaises(core.Failure):
                self.verify()

    def test_symlink_or_public_backup_is_not_accepted_even_with_matching_hash(self):
        source = self.root / 'external'
        source.write_bytes(self.runtime)
        (self.backup / 'runtime.env').unlink()
        (self.backup / 'runtime.env').symlink_to(source)
        with self.assertRaises(core.Failure):
            self.verify()
        self.write_snapshot()
        (self.backup / 'database.dump').chmod(0o644)
        with self.assertRaises(core.Failure):
            self.verify()
        self.backup.chmod(0o755)
        with self.assertRaises(core.Failure):
            self.verify()

    def test_unsafe_archive_rejected_before_any_database_restore(self):
        for name, kind, target in [('/etc/passwd', tarfile.REGTYPE, ''),
                                   ('../escape', tarfile.REGTYPE, ''),
                                   ('safe/../../escape', tarfile.REGTYPE, ''),
                                   ('link', tarfile.SYMTYPE, '../../escape'),
                                   ('hard', tarfile.LNKTYPE, '/etc/passwd'),
                                   ('pipe', tarfile.FIFOTYPE, ''),
                                   ('device', tarfile.CHRTYPE, '')]:
            self.archive([(name, kind, target)])
            self.metadata['sha256']['assets.tar'] = penpot.file_hash(self.backup / 'assets.tar')
            self.save_metadata()
            with self.subTest(name=name), self.assertRaises(core.Failure):
                self.verify()
        self.archive([('asset', tarfile.REGTYPE, ''), ('asset', tarfile.REGTYPE, '')])
        with self.assertRaises(core.Failure):
            penpot.safe_assets(self.backup / 'assets.tar')

    def test_runtime_has_exact_secrets_and_no_dotenv_expansion_or_duplicate(self):
        self.assertEqual(set(penpot.runtime_values(self.runtime, registration())), {'PENPOT_SECRET_KEY', 'PENPOT_DB_PASSWORD'})
        for data in (self.runtime + b'PENPOT_DB_PASSWORD=repeat\n', self.runtime + b'EVIL=value\n',
                     self.runtime.replace(b'A' * 86, b'${SECRET}'), self.runtime.replace(b'1' * 64, b'password')):
            with self.subTest(data_length=len(data)), self.assertRaises(core.Failure):
                penpot.runtime_values(data, registration())

    def test_streaming_failure_does_not_publish_partial_file(self):
        target = self.root / 'output'
        def fail_run(argv, **kwargs):
            kwargs['stdout'].write(b'PGDMPpartial\xff')
            return type('Process', (), {'returncode': 1})()
        with mock.patch.object(penpot.subprocess, 'run', side_effect=fail_run), self.assertRaises(core.Failure):
            penpot.stream_file(target, ['/usr/bin/docker', 'exec', 'penpot-postgres', 'pg_dump'])
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob('.stream-*')), [])

    def test_snapshot_refuses_any_running_writer_before_dump(self):
        current_profile = profile()
        current_profile['compose_project'] = 'penpot'
        def running_container(name, ref=None):
            return {'State': {'Running': True}, 'Config': {'Labels': {
                'com.docker.compose.project': 'penpot', 'com.docker.compose.service': name,
                'vps-deploy.app': 'penpot',
            }}}
        with mock.patch.object(penpot, 'container', side_effect=running_container), mock.patch.object(penpot, 'stream_file') as streamed:
            with self.assertRaisesRegex(core.Failure, 'PENPOT_WRITER_RUNNING'):
                penpot.snapshot(current_profile, self.root, self.root, 'gh-123-1-app', self.entry, b'normal-old-route')
            streamed.assert_not_called()

    def test_snapshot_streams_binary_then_publishes_marker_last(self):
        cfg = self.root / 'config'
        cfg.mkdir(mode=0o700)
        for name in ('runtime.env', 'app.yml'):
            (cfg / name).write_bytes((self.backup / name).read_bytes())
            (cfg / name).chmod(0o600)
        current_profile = profile()
        current_profile['compose_project'] = 'penpot'
        calls = []
        def stopped_container(name, ref=None, **kwargs):
            return {'State': {'Running': name == 'penpot-postgres'},
                    'Config': {'Labels': {'com.docker.compose.project': 'penpot',
                                          'com.docker.compose.service': name, 'vps-deploy.app': 'penpot'}},
                    'Mounts': [{'Type': 'volume', 'Name': 'penpot_postgres_v15',
                                'Destination': '/var/lib/postgresql/data', 'RW': True}]}
        def fake_volume(kind, name):
            return {'Name': name, 'Driver': 'local', 'Options': None, 'Labels': {'vps-deploy.app': 'penpot'}}
        def binary_command(argv, **kwargs):
            calls.append(argv)
            self.assertFalse((self.root / 'backups/gh-456-1-app/manifest.json').exists())
            data = (self.backup / ('database.dump' if 'pg_dump' in argv else 'assets.tar')).read_bytes()
            kwargs['stdout'].write(data)
            return type('Process', (), {'returncode': 0})()
        with mock.patch.object(penpot, 'container', side_effect=stopped_container), mock.patch.object(penpot, 'inspect', side_effect=fake_volume), mock.patch.object(penpot.subprocess, 'run', side_effect=binary_command):
            result = penpot.snapshot(current_profile, cfg, self.root, 'gh-456-1-app', self.entry, b'normal-old-route')
        metadata = self.verify_directory(result)
        self.assertEqual(metadata['sourceSha'], self.entry['source_sha'])
        self.assertEqual((result / 'database.dump').read_bytes(), b'PGDMP\x00binary-fixture\xff')
        self.assertEqual((result / 'route.yml').read_bytes(), b'normal-old-route')
        self.assertEqual(len(calls), 2)
        self.assertIn('none', calls[1])
        self.assertIn(self.entry['images']['backend'], calls[1])
        self.assertIn('type=volume,src=penpot_assets,dst=/opt/data/assets,readonly', calls[1])

    def verify_directory(self, directory):
        return penpot.verify_snapshot(directory, registration())

    def test_foreign_or_bind_mounted_volume_is_rejected(self):
        current_profile = profile()
        for bad in ({'Name': 'penpot_assets', 'Driver': 'local', 'Options': None, 'Labels': {}},
                    {'Name': 'penpot_assets', 'Driver': 'local', 'Options': {'device': '/opt/9router'}, 'Labels': {'vps-deploy.app': 'penpot'}},
                    {'Name': 'foreign', 'Driver': 'local', 'Options': None, 'Labels': {'vps-deploy.app': 'penpot'}}):
            with self.subTest(bad=bad), mock.patch.object(penpot, 'inspect', return_value=bad), self.assertRaisesRegex(core.Failure, 'PENPOT_VOLUME_OWNERSHIP'):
                penpot.owned_volumes(current_profile)


class PenpotComposeContract(unittest.TestCase):
    def test_no_published_ports_and_only_frontend_on_owned_edge(self):
        value = yaml.safe_load((ROOT / 'apps/penpot/docker-compose.prod.yml').read_text())
        services = value['services']
        self.assertEqual(set(services), {'penpot-' + role for role in ('frontend', 'backend', 'exporter', 'mcp', 'postgres', 'valkey')})
        for name, service in services.items():
            self.assertNotIn('ports', service)
            self.assertNotIn('privileged', service)
            self.assertFalse(any('docker.sock' in volume for volume in service.get('volumes', [])))
            self.assertEqual('edge' in service['networks'], name == 'penpot-frontend')
            self.assertEqual('egress' in service['networks'], name in ('penpot-backend', 'penpot-exporter'))
        self.assertTrue(value['networks']['penpot']['internal'])
        self.assertEqual(value['networks']['edge'], {'external': True, 'name': 'edge-penpot'})
        for volume in value['volumes'].values():
            self.assertTrue(volume['external'])
        self.assertIn('penpot_assets:/opt/data/assets:ro', services['penpot-frontend']['volumes'])
        self.assertIn('penpot_assets:/opt/data/assets', services['penpot-backend']['volumes'])
        for role in ('frontend', 'backend', 'exporter'):
            flags = services['penpot-' + role]['environment']['PENPOT_FLAGS'].split()
            self.assertEqual(set(flags), {'enable-mcp', 'enable-prepl-server', 'disable-registration'})
        for role in ('postgres', 'valkey'):
            self.assertRegex(services['penpot-' + role]['image'], r'@sha256:[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
