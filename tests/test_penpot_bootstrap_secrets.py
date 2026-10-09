import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from test_penpot_contract import profile
import core
import penpot

ROOT = Path(__file__).resolve().parents[1]


class PenpotBootstrapSecrets(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('penpot_secrets', ROOT / 'install/penpot_secrets.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name) / 'work'
        self.cfg = Path(self.tmp.name) / 'cfg'
        self.work.mkdir(mode=0o700)
        self.cfg.mkdir(mode=0o700)
        self.registration = profile()['registration']
        for patch in (mock.patch.object(self.module.os, 'geteuid', return_value=0),
                      mock.patch.object(self.module, 'trusted_path', side_effect=lambda path, **kw: Path(path)),
                      mock.patch.object(penpot, 'trusted_path', side_effect=lambda path, **kw: Path(path))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_initialization_and_retry_keep_exact_secret_bytes_and_modes(self):
        self.module.runtime(self.work, self.cfg, self.registration)
        source = self.work / '.env'
        installed = self.cfg / 'runtime.env'
        raw = source.read_bytes()
        self.assertEqual(raw, installed.read_bytes())
        values = penpot.runtime_values(raw, self.registration)
        self.assertEqual(len(values['PENPOT_DB_PASSWORD']), 64)
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
        with mock.patch.object(self.module.secrets, 'token_urlsafe', side_effect=AssertionError('must not rotate')):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.assertEqual(raw, installed.read_bytes())

    def test_resume_after_one_copy_does_not_generate_new_values(self):
        self.module.runtime(self.work, self.cfg, self.registration)
        raw = (self.work / '.env').read_bytes()
        (self.cfg / 'runtime.env').unlink()
        with mock.patch.object(self.module.secrets, 'token_hex', side_effect=AssertionError('must not rotate')):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.assertEqual(raw, (self.cfg / 'runtime.env').read_bytes())

    def test_mismatched_existing_secrets_fail_without_overwrite(self):
        self.module.runtime(self.work, self.cfg, self.registration)
        installed = self.cfg / 'runtime.env'
        raw = installed.read_bytes().replace(b'PENPOT_SECRET_KEY=', b'PENPOT_SECRET_KEY=different')
        installed.write_bytes(raw)
        with self.assertRaisesRegex(core.Failure, 'PENPOT_RUNTIME_MISMATCH'):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.assertEqual(raw, installed.read_bytes())

    def test_nonroot_public_directory_and_symlink_are_rejected(self):
        with mock.patch.object(self.module.os, 'geteuid', return_value=1000), self.assertRaisesRegex(core.Failure, 'ROOT_REQUIRED'):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.work.chmod(0o755)
        with self.assertRaisesRegex(core.Failure, 'PENPOT_RUNTIME_DIRECTORY'):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.work.chmod(0o700)
        (self.work / '.env').symlink_to(self.work / 'absent')
        with self.assertRaises(core.Failure):
            self.module.runtime(self.work, self.cfg, self.registration)
        self.assertFalse((self.cfg / 'runtime.env').exists())


if __name__ == '__main__':
    unittest.main()
