import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import core

ROOT = Path(__file__).resolve().parents[1]


class PenpotBackupInstallation(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('penpot_backup', ROOT / 'install/penpot_backup.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


    def test_running_backup_blocks_activation_and_restores_active_timer(self):
        module = self.module()
        run = mock.Mock(return_value=SimpleNamespace(returncode=0))
        with self.assertRaisesRegex(core.Failure, 'INSTALL_BUSY'):
            module.pause(run)
        self.assertEqual(run.call_args.args, ('/usr/bin/systemctl', 'start', module.TIMER))
        self.assertFalse(any('enable' in call.args for call in run.call_args_list))



if __name__ == '__main__':
    unittest.main()
