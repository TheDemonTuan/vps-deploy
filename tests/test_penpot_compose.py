from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from test_penpot_contract import deploy_request, profile
import core
import penpot


class PenpotCompose(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cfg = self.root / 'cfg'
        self.cfg.mkdir()
        self.runtime = self.cfg / 'runtime.env'
        self.runtime.write_text('PENPOT_SECRET_KEY=' + 's' * 32 + '\nPENPOT_DB_PASSWORD=' + 'a' * 64 + '\n')
        self.runtime.chmod(0o600)
        self.release = self.root / 'release'
        self.compose = self.release / 'apps/penpot/docker-compose.prod.yml'
        self.compose.parent.mkdir(parents=True)
        self.compose.write_text('services: {}\n')
        self.profile = dict(profile(), compose_project='penpot')
        self.entry = penpot.release_entry(deploy_request(), self.profile)

    def test_update_only_recreates_four_applications_and_never_datastores(self):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        with mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kwargs: path), mock.patch.object(core.subprocess, 'run', side_effect=run), mock.patch.object(penpot, 'stack_health'):
            penpot.start_applications(self.release, self.profile, self.cfg, self.entry)
        argv, options = calls[0]
        self.assertEqual(argv, ('/usr/bin/docker', 'compose', '--env-file', str(self.runtime), '-p', 'penpot', '-f', str(self.compose), '--ansi=never', '--progress=plain', 'up', '-d', '--no-deps', '--pull', 'never', '--wait', '--wait-timeout', '180', *penpot.APP_SERVICES))
        self.assertEqual(options['timeout'], 210)
        self.assertNotIn('penpot-postgres', argv)
        self.assertNotIn('penpot-valkey', argv)
        for role, ref in self.entry['images'].items():
            self.assertEqual(options['env']['PENPOT_' + role.upper() + '_IMAGE'], ref)
        self.assertNotIn('IMAGE_REF', options['env'])
        self.assertNotIn('PENPOT_SECRET_KEY=' + 's' * 32, argv)
        self.assertEqual(options['env']['PATH'], '/usr/bin:/bin')

    def test_stop_only_stops_application_writers_and_verifies_they_are_stopped(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
        with mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kwargs: path), mock.patch.object(core.subprocess, 'run', side_effect=run), mock.patch.object(penpot, 'writers_stopped') as stopped, mock.patch.object(penpot, 'writers_owned') as owned:
            penpot.stop_applications(self.release, self.profile, self.cfg, self.entry)
        self.assertEqual(calls[0][-7:], ('stop', '--timeout', '60', *penpot.APP_SERVICES))
        owned.assert_called_once_with(self.profile, self.entry['images'])
        stopped.assert_called_once_with(self.profile, self.entry['images'])

    def test_foreign_container_is_rejected_before_any_writer_stop(self):
        foreign = {'State': {'Running': True}, 'Config': {'Labels': {
            'com.docker.compose.project': 'other', 'com.docker.compose.service': 'penpot-frontend',
            'vps-deploy.app': 'other',
        }}}
        with mock.patch.object(penpot, 'container', return_value=foreign), mock.patch.object(penpot, 'command') as run, self.assertRaisesRegex(core.Failure, 'PENPOT_CONTAINER_OWNERSHIP'):
            penpot.stop_applications(self.release, self.profile, self.cfg, self.entry)
        run.assert_not_called()

    def test_malformed_secret_or_wrong_project_is_rejected_before_any_docker_command(self):
        for wrong in ('secret', 'project'):
            selected = dict(self.profile)
            if wrong == 'secret':
                self.runtime.write_text('PENPOT_SECRET_KEY=$EXPANSION\nPENPOT_DB_PASSWORD=' + 'a' * 64 + '\n')
            else:
                selected['compose_project'] = 'other'
            with self.subTest(wrong=wrong), mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kwargs: path), mock.patch.object(core.subprocess, 'run') as run, self.assertRaises(core.Failure):
                penpot.start_applications(self.release, selected, self.cfg, self.entry)
            run.assert_not_called()

    def test_compose_failure_does_not_report_the_stack_as_healthy(self):
        with mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kwargs: path), mock.patch.object(core.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr=b'migration failed')), mock.patch.object(penpot, 'stack_health') as health, self.assertRaisesRegex(core.Failure, 'COMMAND_FAILED'):
            penpot.start_applications(self.release, self.profile, self.cfg, self.entry)
        health.assert_not_called()


if __name__ == '__main__':
    unittest.main()
