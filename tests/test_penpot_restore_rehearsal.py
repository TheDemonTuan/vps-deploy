import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('penpot_rehearsal', ROOT / 'scripts/rehearse-penpot-backup.py')
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)
SHA = 'a' * 40
SOURCE = 'b' * 40
FILE_ID = 'd9b4c7f6-6872-4d39-92e8-ef3de27a5e81'
IMAGES = {role: 'ghcr.io/thedemontuan/penpot-' + role + '@sha256:' + 'c' * 64
          for role in ('frontend', 'backend', 'exporter', 'mcp')}


def member(name, payload=b'payload', kind=tarfile.REGTYPE, link=''):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    info.mode = 0o777  # Archive permissions must never become output permissions.
    info.size = len(payload) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    return info, payload


def make_tar(path, members):
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as archive:
        for info, payload in members:
            archive.addfile(info, io.BytesIO(payload) if info.isreg() else None)
    os.chmod(path, 0o600)
    return path


class SnapshotExtraction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / 'backup.tar'
        self.destination = self.root / 'extracted'
        self.valid = [member(name, name.encode()) for name in sorted(rehearsal.FILES)]

    def rejected(self, members):
        make_tar(self.archive, members)
        with patch.object(rehearsal.core, 'docker') as docker:
            with self.assertRaises(rehearsal.core.Failure) as caught:
                rehearsal.extract_snapshot(self.archive, self.destination)
            self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_ARCHIVE')
            docker.assert_not_called()
        self.assertFalse(self.destination.exists(), 'Invalid headers must precede every output write')

    def test_exact_closure_preserves_bytes_and_private_permissions(self):
        make_tar(self.archive, self.valid)
        with patch.object(rehearsal.core, 'docker') as docker:
            result = rehearsal.extract_snapshot(self.archive, self.destination)
            docker.assert_not_called()
        self.assertEqual(result, self.destination)
        self.assertEqual({path.name for path in result.iterdir()}, rehearsal.FILES)
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o700)
        for info, payload in self.valid:
            output = result / info.name
            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertFalse(output.is_symlink())

    def test_missing_member(self):
        self.rejected(self.valid[:-1])

    def test_unknown_member_at_end(self):
        self.rejected(self.valid + [member('unexpected')])

    def test_duplicate_member_at_end(self):
        self.rejected(self.valid + [member('manifest.json')])

    def test_absolute_nested_traversal_and_alias_names(self):
        for name in ('/manifest.json', '../manifest.json', 'nested/manifest.json',
                     './manifest.json', 'x/../manifest.json', 'manifest.json/', 'C:/manifest.json', ''):
            with self.subTest(name=name):
                self.rejected(self.valid + [member(name)])

    def test_symlink_hardlink_special_and_directory_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                self.rejected(self.valid[:-1] + [member(self.valid[-1][0].name, kind=kind, link='/etc/shadow')])

    def test_directory_file_conflict(self):
        self.rejected(self.valid + [member('assets.tar/child')])

    def test_empty_member(self):
        self.rejected([member(name, b'' if name == 'manifest.json' else b'x')
                       for name in sorted(rehearsal.FILES)])

    def test_oversized_private_metadata(self):
        self.rejected([member(name, b'x' * 65537 if name == 'manifest.json' else b'x')
                       for name in sorted(rehearsal.FILES)])

    def test_pax_path_override_is_validated(self):
        info, payload = member('manifest.json')
        info.pax_headers = {'path': '../manifest.json'}
        self.rejected(self.valid[:-1] + [(info, payload)])

    def test_truncated_archive(self):
        make_tar(self.archive, self.valid)
        self.archive.write_bytes(self.archive.read_bytes()[:700])
        with self.assertRaises(rehearsal.core.Failure) as caught:
            rehearsal.extract_snapshot(self.archive, self.destination)
        self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_ARCHIVE')
        self.assertFalse(self.destination.exists())

    def test_existing_member_is_never_overwritten(self):
        make_tar(self.archive, self.valid)
        self.destination.mkdir()
        sentinel = self.destination / 'manifest.json'
        sentinel.write_bytes(b'untouched')
        with self.assertRaises(rehearsal.core.Failure):
            rehearsal.extract_snapshot(self.archive, self.destination)
        self.assertEqual(sentinel.read_bytes(), b'untouched')
        self.assertEqual(list(self.destination.iterdir()), [sentinel])

    def test_symlink_destination_and_input_are_rejected(self):
        make_tar(self.archive, self.valid)
        real = self.root / 'real'
        real.mkdir()
        self.destination.symlink_to(real, target_is_directory=True)
        with self.assertRaises(rehearsal.core.Failure):
            rehearsal.extract_snapshot(self.archive, self.destination)
        self.assertEqual(list(real.iterdir()), [])
        self.destination.unlink()
        symlink = self.root / 'link.tar'
        symlink.symlink_to(self.archive)
        with self.assertRaises(rehearsal.core.Failure):
            rehearsal.extract_snapshot(symlink, self.destination)
        self.assertFalse(self.destination.exists())


class RehearsalIdentityAndData(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = {'image_repositories': {role: ref.split('@')[0] for role, ref in IMAGES.items()}}
        self.metadata = {'sourceSha': SOURCE, 'platformRef': SHA, 'images': IMAGES,
                         'sha256': {'app.yml': 'd' * 64}}
        self.origin = {'app': 'penpot', 'host': 'oracle-main', 'platformRef': SHA, 'sourceSha': SOURCE,
                       'images': IMAGES, 'generation': 'e' * 32, 'healthy': True, 'origin_tls_verified': True}
        self.receipt = self.root / 'origin.json'

    def identity(self):
        self.receipt.write_text(json.dumps(self.origin))
        return rehearsal.origin_identity(self.receipt, self.metadata, SHA, self.profile)

    def test_valid_origin_snapshot_identity(self):
        self.assertEqual(self.identity(), {'slot': 'single', 'source_sha': SOURCE, 'platform_ref': SHA,
                                          'images': IMAGES, 'manifest_sha256': 'd' * 64})

    def test_origin_platform_is_independent_of_helper_checkout(self):
        self.profile['platform_ref'] = 'f' * 40
        with patch.dict(os.environ, {'PLATFORM_REF': 'f' * 40, 'GITHUB_SHA': 'f' * 40}):
            self.assertEqual(self.identity()['platform_ref'], SHA)

    def test_historical_snapshot_requires_explicit_cross_release_mode(self):
        self.origin['sourceSha'] = 'f' * 40
        self.origin['images'] = {role: ref[:-1] + 'f' for role, ref in IMAGES.items()}
        self.receipt.write_text(json.dumps(self.origin))
        with self.assertRaises(rehearsal.core.Failure):
            rehearsal.origin_identity(self.receipt, self.metadata, SHA, self.profile)
        entry = rehearsal.origin_identity(self.receipt, self.metadata, SHA, self.profile, historical=True)
        self.assertEqual(entry['source_sha'], SOURCE)
        self.assertEqual(entry['images'], IMAGES)
        self.metadata['platformRef'] = 'f' * 40
        with self.assertRaises(rehearsal.core.Failure):
            rehearsal.origin_identity(self.receipt, self.metadata, SHA, self.profile, historical=True)

    def test_origin_platform_must_be_an_explicit_immutable_sha(self):
        self.receipt.write_text(json.dumps(self.origin))
        for platform in ('', 'main', SHA.upper(), None):
            with self.subTest(platform=platform), self.assertRaises(rehearsal.core.Failure):
                rehearsal.origin_identity(self.receipt, self.metadata, platform, self.profile)

    @patch.object(rehearsal.penpot, 'trusted_path', new=lambda path, **kwargs: Path(path))
    def test_target_artifact_strict_schema_and_source_only_platform_binding(self):
        origin = self.identity()
        target = {'schemaVersion': 1, 'sourceSha': 'f' * 40, 'platformRef': SHA,
                  'platform': 'linux/arm64', 'images': {role: ref[:-1] + 'f' for role, ref in IMAGES.items()}}
        path = self.root / 'target-release.json'
        path.write_text(json.dumps(target))
        os.chmod(path, 0o600)
        entry = rehearsal.target_identity(path, origin, self.profile)
        self.assertEqual(entry['source_sha'], 'f' * 40)
        self.assertEqual(entry['manifest_sha256'], origin['manifest_sha256'])
        for key, changed in (('schemaVersion', True), ('sourceSha', SOURCE), ('sourceSha', 'main'),
                             ('platformRef', 'f' * 40), ('platform', 'linux/amd64'),
                             ('images', dict(IMAGES, backend='foreign@sha256:' + 'a' * 64)),
                             ('unexpected', 'private')):
            with self.subTest(key=key, changed=changed):
                path.write_text(json.dumps(dict(target, **{key: changed})))
                with self.assertRaises(rehearsal.core.Failure):
                    rehearsal.target_identity(path, origin, self.profile)

    def test_snapshot_source_platform_and_images_must_match_origin(self):
        for field, changed in (('sourceSha', 'f' * 40), ('platformRef', 'f' * 40),
                               ('images', dict(IMAGES, backend=IMAGES['backend'][:-1] + 'f'))):
            with self.subTest(field=field):
                original = self.metadata[field]
                self.metadata[field] = changed
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    self.identity()
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_IDENTITY')
                self.metadata[field] = original

    def test_origin_schema_and_health_are_enforced(self):
        for field, value in (('healthy', False), ('origin_tls_verified', False), ('host', 'foreign'),
                             ('generation', 'bad'), ('platformRef', 'f' * 40), ('sourceSha', 1)):
            with self.subTest(field=field):
                original = self.origin[field]
                self.origin[field] = value
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    self.identity()
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_IDENTITY')
                self.origin[field] = original
        self.origin['secret'] = 'must not appear'
        with self.assertRaises(rehearsal.core.Failure):
            self.identity()

    def test_asset_catalog_matches_full_paths_hashes_sizes_ignoring_tar_order(self):
        expected = make_tar(self.root / 'expected.tar', [member('./a', b'one'), member('./dir/b', b'two')])
        restored = make_tar(self.root / 'restored.tar', [member('dir/b', b'two'), member('a', b'one')])
        rehearsal.assets_match(expected, restored)
        self.assertEqual(rehearsal.asset_catalog(expected), {
            'a': (hashlib.sha256(b'one').hexdigest(), 3),
            'dir/b': (hashlib.sha256(b'two').hexdigest(), 3)})

    def test_asset_content_names_missing_and_extra_mismatch(self):
        expected = make_tar(self.root / 'expected.tar', [member('./a', b'one')])
        for members in ([member('a', b'two')], [member('a', b'longer')], [member('b', b'one')],
                        [], [member('a', b'one'), member('extra', b'x')]):
            with self.subTest(members=members):
                restored = make_tar(self.root / 'restored.tar', members)
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    rehearsal.assets_match(expected, restored)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_ASSETS')

    def test_inner_asset_links_are_rejected(self):
        archive = make_tar(self.root / 'assets.tar', [member('escape', kind=tarfile.SYMTYPE, link='/etc/shadow')])
        with self.assertRaises(rehearsal.core.Failure) as caught:
            rehearsal.asset_catalog(archive)
        self.assertEqual(caught.exception.code, 'PENPOT_UNSAFE_ASSETS')

    def test_database_fingerprint_uses_exact_query_stdout_without_final_newline(self):
        raw = json.dumps({'file': {'id': FILE_ID, 'data': 'synthetic'}, 'file_data': []}).encode()
        process = subprocess.CompletedProcess([], 0, raw + b'\n', b'')
        with patch.object(rehearsal.subprocess, 'run', return_value=process) as run:
            rehearsal.database_matches(FILE_ID, hashlib.sha256(raw).hexdigest())
        arguments, keywords = run.call_args
        self.assertEqual(arguments[0], ['/usr/bin/docker', 'exec', '-i', 'penpot-postgres', 'psql', '-X', '-At',
                                        '-U', 'penpot', '-d', 'penpot', '--set=ON_ERROR_STOP=1'])
        self.assertIn(("f.id = '" + FILE_ID + "'::uuid").encode(), keywords['input'])
        self.assertIn(b'jsonb_agg(to_jsonb(d) ORDER BY d.id)', keywords['input'])
        self.assertIn(("d.file_id = '" + FILE_ID + "'::uuid").encode(), keywords['input'])

    def test_database_rejects_missing_file_multiple_rows_and_mismatched_fingerprint(self):
        rows = (b'{"file":null,"file_data":[]}\n', b'{}\n{}\n', b'invalid\n',
                json.dumps({'file': {'id': FILE_ID}, 'file_data': []}).encode() + b'\n')
        for raw in rows:
            with self.subTest(raw=raw), patch.object(rehearsal.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, raw, b'private error')):
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    rehearsal.database_matches(FILE_ID, '0' * 64)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_DATABASE')


class UpgradeBoundaries(unittest.TestCase):
    # These exercise fail-closed boundaries, not substitutes for the hosted run.
    def setUp(self):
        self.before = {'legacyTable': True, 'registry': [
            {'module': 'main', 'step': '0153-del-orphan-profile-rels-after-team-leave',
             'created_at': '2026-10-01T00:00:00'}]}
        self.migration = {'module': 'main', 'step': rehearsal.MIGRATION,
                          'created_at': '2026-10-14T00:00:00'}
        self.after = {'legacyTable': False, 'registry': self.before['registry'] + [self.migration]}
        self.checks = dict.fromkeys(('empty', 'ordinary', 'dependencies', 'triggers',
                                    'policies', 'inheritance'), True)

    def test_legacy_rows_dependencies_and_catalog_drift_fail_closed(self):
        for key in self.checks:
            with self.subTest(key=key), patch.object(rehearsal, 'database_json',
                    return_value=dict(self.checks, **{key: False})), self.assertRaises(rehearsal.core.Failure):
                rehearsal.legacy_preconditions(self.before)
        for state in ({'legacyTable': False, 'registry': []},
                      {'legacyTable': True, 'registry': [self.migration]}):
            with self.subTest(state=state), patch.object(rehearsal, 'database_json') as query:
                with self.assertRaises(rehearsal.core.Failure):
                    rehearsal.legacy_preconditions(state)
                query.assert_not_called()

    def test_migration_requires_exact_new_registry_step_and_preserves_old_rows(self):
        rehearsal.migration_applied(self.before, self.after)
        bad = ({'legacyTable': True, 'registry': self.after['registry']},
               {'legacyTable': False, 'registry': self.before['registry']},
               {'legacyTable': False, 'registry': [self.migration]},
               {'legacyTable': False, 'registry': self.before['registry'] +
                    [dict(self.migration, module='other')]},
               {'legacyTable': False, 'registry': self.after['registry'] +
                    [{'module': 'main', 'step': 'unexpected'}]})
        for state in bad:
            with self.subTest(state=state), self.assertRaises(rehearsal.core.Failure):
                rehearsal.migration_applied(self.before, state)

    def test_sql_errors_never_return_or_print_private_output(self):
        process = subprocess.CompletedProcess([], 1, b'private row', b'private database error')
        with patch.object(rehearsal.subprocess, 'run', return_value=process), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(rehearsal.core.Failure) as caught:
                rehearsal.database_json('SELECT private;')
        self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_MIGRATION')
        self.assertEqual(output.getvalue(), '')

    def test_failed_legacy_precondition_never_prepares_or_starts_target(self):
        with patch.object(rehearsal.penpot, 'stop_applications'), \
                patch.object(rehearsal, 'migration_state', return_value={'legacyTable': False, 'registry': []}), \
                patch.object(rehearsal.penpot, 'prepare_images') as prepare, \
                patch.object(rehearsal.penpot, 'start_applications') as start:
            with self.assertRaises(rehearsal.core.Failure):
                rehearsal.upgrade_and_restore(None, None, None, None, {}, {}, None, FILE_ID, '0' * 64)
        prepare.assert_not_called()
        start.assert_not_called()


class HostAndOutputPolicy(unittest.TestCase):
    ENVIRONMENT = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'PENPOT_DISPOSABLE_VM': '1', 'GITHUB_REPOSITORY': 'TheDemonTuan/vps-deploy',
                   'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': SHA, 'PLATFORM_REF': SHA}

    def simulated_host(self, *, environment=None, uid=0, machine='aarch64',
                       server='aarch64', endpoint='unix:///var/run/docker.sock', occupied='', path=None):
        def command(*arguments, **kwargs):
            if arguments[0] == '/usr/bin/git':
                return SHA + '\n'
            if arguments[1] == 'context':
                return endpoint + '\n'
            return json.dumps({'Architecture': server, 'OSType': 'linux'})
        with patch.dict(os.environ, environment or self.ENVIRONMENT, clear=True), \
                patch.object(rehearsal.os, 'geteuid', return_value=uid), \
                patch.object(rehearsal.os, 'uname', return_value=types.SimpleNamespace(machine=machine)), \
                patch.object(Path, 'exists', lambda candidate: candidate == path), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(rehearsal.core, 'command', side_effect=command), \
                patch.object(rehearsal.core, 'docker', return_value=occupied):
            return rehearsal.host_policy()

    def test_valid_host_admission_uses_native_local_arm64_docker(self):
        self.assertEqual(self.simulated_host(), SHA)

    def test_root_architecture_native_server_and_local_endpoint_are_required(self):
        for arguments in ({'uid': 1000}, {'machine': 'x86_64'}, {'server': 'x86_64'},
                          {'endpoint': 'ssh://production'}, {'occupied': 'penpot-backend\n'},
                          {'path': Path('/opt/penpot')}, {'path': Path('/etc/vps-deploy/apps')},
                          {'path': Path('/opt/platform/edge')}):
            with self.subTest(arguments=arguments):
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    self.simulated_host(**arguments)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_HOST_POLICY')

    def test_each_disposable_ci_identity_flag_and_platform_binding_is_required(self):
        for key in self.ENVIRONMENT:
            with self.subTest(key=key):
                environment = dict(self.ENVIRONMENT)
                environment[key] = 'wrong'
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    self.simulated_host(environment=environment)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_HOST_POLICY')
        environment = dict(self.ENVIRONMENT, DOCKER_HOST='ssh://production')
        with self.assertRaises(rehearsal.core.Failure):
            self.simulated_host(environment=environment)

    def test_invalid_uuid_and_fingerprint_fail_before_host_or_docker(self):
        for file_id, fingerprint in (("'; DROP TABLE file;--", '0' * 64), (FILE_ID, 'BAD')):
            args = types.SimpleNamespace(file_id=file_id, file_sha256=fingerprint)
            with patch.object(rehearsal, 'host_policy') as host:
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    rehearsal.rehearse(args)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_DATABASE')
                host.assert_not_called()

    def test_workstation_refused_before_docker(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(rehearsal.core, 'docker') as docker:
            with self.assertRaises(rehearsal.core.Failure) as caught:
                rehearsal.host_policy()
            self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_HOST_POLICY')
            docker.assert_not_called()

    def test_safe_cli_error_is_one_json_without_exception_details(self):
        arguments = ['rehearse', '--archive', 'private.tar', '--origin-receipt', 'private.json',
                     '--file-id', FILE_ID, '--file-sha256', '0' * 64]
        for error, code in ((OSError('secret material'), 'PENPOT_REHEARSAL_FAILED'),
                            (rehearsal.core.Failure('PENPOT_BACKUP_CHECKSUM'), 'PENPOT_BACKUP_CHECKSUM')):
            with self.subTest(code=code), patch.object(sys, 'argv', arguments), \
                    patch.object(rehearsal, 'rehearse', side_effect=error), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(rehearsal.main(), 1)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'failed', 'error_code': code})
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertNotIn('secret', output.getvalue())

    def test_missing_cli_arguments_fail_without_usage_or_paths(self):
        with patch.object(sys, 'argv', ['rehearse']), contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(rehearsal.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {'status': 'failed', 'error_code': 'PENPOT_REHEARSAL_FAILED'})
        self.assertEqual(errors.getvalue(), '')

    def test_tar_helper_ownership_is_bound_to_new_volume_exact_image_and_baseline(self):
        with patch.object(rehearsal.core, 'docker', return_value='old-id\n'):
            resources = rehearsal.Resources()
        resources.backend = IMAGES['backend']
        container = {'Id': 'new-id', 'Config': {'Image': IMAGES['backend']},
                     'HostConfig': {'NetworkMode': 'none', 'AutoRemove': True},
                     'Mounts': [{'Type': 'volume', 'Name': 'penpot_assets', 'Destination': '/opt/data/assets'}]}
        self.assertTrue(resources.helper_owned(container))
        container['Id'] = 'old-id'
        self.assertFalse(resources.helper_owned(container))
        container['Id'] = 'new-id'
        container['Config']['Image'] = 'foreign'
        self.assertFalse(resources.helper_owned(container))
        container['Config']['Image'] = IMAGES['backend']
        container['Mounts'][0]['Name'] = 'foreign-volume'
        self.assertFalse(resources.helper_owned(container))

    def test_teardown_refuses_foreign_resource_and_continues_owned_resources(self):
        with patch.object(rehearsal.core, 'docker', return_value=''):
            resources = rehearsal.Resources()
        resources.created = [('volume', 'foreign', 'foreign'), ('volume', 'owned', 'owned')]
        values = {'foreign': {'Labels': {'vps-deploy.app': 'foreign'}},
                  'owned': {'Labels': {'vps-deploy.app': 'penpot', 'penpot-rehearsal': resources.token}}}
        calls = []
        def docker(*arguments):
            calls.append(arguments)
            return 'foreign\nowned\n' if arguments[:2] == ('volume', 'ls') else ''
        with patch.object(rehearsal.core, 'docker', side_effect=docker), \
                patch.object(rehearsal.core, 'inspect', side_effect=lambda kind, name: values[name]):
            with self.assertRaises(rehearsal.core.Failure):
                resources.teardown()
        self.assertIn(('volume', 'rm', 'owned'), calls)
        self.assertNotIn(('volume', 'rm', 'foreign'), calls)

    def test_bad_real_archive_tears_down_and_never_stages_or_prepares_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = make_tar(root / 'bad.tar', [member(name) for name in rehearsal.FILES] +
                               [member('../escape')])
            base = root / 'private'
            args = types.SimpleNamespace(archive=str(archive), origin_receipt='unused',
                                         file_id=FILE_ID, file_sha256='0' * 64)
            with patch.object(rehearsal, 'BASE', base), \
                    patch.object(rehearsal, 'host_policy', return_value=SHA), \
                    patch.object(rehearsal.core, 'trusted_path', side_effect=lambda path, **kwargs: path), \
                    patch.object(rehearsal, 'Resources') as resources, \
                    patch.object(rehearsal, 'stage_engine') as stage, \
                    patch.object(rehearsal.penpot, 'prepare_images') as images:
                # A teardown error must not hide the original bounded archive error.
                resources.return_value.teardown.side_effect = OSError('private details')
                with self.assertRaises(rehearsal.core.Failure) as caught:
                    rehearsal.rehearse(args)
                self.assertEqual(caught.exception.code, 'PENPOT_REHEARSAL_ARCHIVE')
                resources.return_value.teardown.assert_called_once_with()
                stage.assert_not_called()
                images.assert_not_called()
            self.assertFalse(base.exists())
            self.assertFalse((root / 'escape').exists())

    def test_capture_failure_still_attempts_tracked_owned_teardown(self):
        with patch.object(rehearsal.core, 'docker', return_value=''):
            resources = rehearsal.Resources()
        resources.created = [('volume', 'owned', 'owned')]
        labels = {'vps-deploy.app': 'penpot', 'penpot-rehearsal': resources.token}
        with patch.object(resources, 'capture_compose', side_effect=rehearsal.core.Failure('COMMAND_FAILED')), \
                patch.object(rehearsal.core, 'docker', return_value='owned\n') as docker, \
                patch.object(rehearsal.core, 'inspect', return_value={'Labels': labels}):
            with self.assertRaises(rehearsal.core.Failure):
                resources.teardown()
        docker.assert_any_call('volume', 'rm', 'owned')


if __name__ == '__main__':
    unittest.main()
