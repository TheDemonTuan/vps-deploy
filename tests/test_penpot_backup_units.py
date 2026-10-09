import configparser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PenpotBackupUnits(unittest.TestCase):
    def unit(self, name):
        result = configparser.ConfigParser(interpolation=None)
        result.optionxform = str
        result.read(ROOT / 'install' / name)
        return result

    def test_timer_runs_at_0315_vietnam_and_catches_missed_runs(self):
        timer = self.unit('vps-deploy-penpot-backup.timer')
        self.assertEqual(timer['Timer']['OnCalendar'], '*-*-* 20:15:00 UTC')
        self.assertEqual(timer['Timer']['Persistent'], 'true')
        self.assertEqual(timer['Timer']['Unit'], 'vps-deploy-penpot-backup.service')
        self.assertEqual(timer['Install']['WantedBy'], 'timers.target')

    def test_service_uses_only_fixed_root_wrapper_and_bounded_runtime(self):
        service = self.unit('vps-deploy-penpot-backup.service')
        settings = service['Service']
        self.assertEqual(settings['Type'], 'oneshot')
        self.assertEqual(settings['User'], 'root')
        self.assertEqual(settings['Group'], 'root')
        self.assertEqual(settings['UMask'], '0077')
        self.assertEqual(settings['TimeoutStartSec'], '1800')
        self.assertEqual(settings['ExecStart'], '/usr/local/libexec/vps-deploy-penpot-backup')
        self.assertNotIn('Environment', settings)
        self.assertNotIn('EnvironmentFile', settings)
        self.assertNotIn('ExecStartPre', settings)
        wrapper = (ROOT / 'install' / 'vps-deploy-app').read_text()
        self.assertIn('"$#" -eq 0', wrapper)
        self.assertIn('/opt/vps-deploy/releases/@RELEASE@/bin/deployctl @ACTION@ --app @APP@', wrapper)


if __name__ == '__main__':
    unittest.main()
