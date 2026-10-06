import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import core


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('waf_controller', ROOT / 'scripts/tune-opendesign-waf.py')
remote = load('waf_remote', ROOT / 'install/tune-reviewed-opendesign-waf.py')
smoke = load('waf_smoke', ROOT / 'install/smoke-opendesign-appsec.py')
P, A = 'a' * 40, 'b' * 40


def acquisition():
    return ('# untouched comment\nsource: appsec\nlisten_addr: 172.31.254.1:7422\nappsec_configs:\n' +
            ''.join('  - ' + name + '\n' for name in remote.ORDER) +
            'labels:\n  type: appsec\nname: traefikAppSec\nroutines: 1\nauth_cache_duration: 1m\n'
            'auth_timeout: 200ms\nbody_read_timeout: 1s\n').encode()


def receipt():
    return dict(app='opendesign', host='oracle-main', platform_ref=P, app_ref=A,
                rule_id=911100, policy_name=remote.CONFIG_NAME,
                **{key: True for key in controller.FIELDS -
                   {'app', 'host', 'platform_ref', 'app_ref', 'rule_id', 'policy_name'}})


class ControllerBoundaries(unittest.TestCase):
    def test_invalid_input_cannot_open_transport(self):
        for bad in ('', 'A' * 40, P + ';id', P + '\n', 'a' * 39):
            with self.subTest(bad=bad), mock.patch.object(controller.reviewed, 'github') as api, \
                    mock.patch.object(controller.reviewed, 'run') as commands, \
                    mock.patch.object(controller.reviewed, 'reviewed_admin') as ssh, \
                    mock.patch('sys.stderr', new=io.StringIO()):
                self.assertEqual(controller.main(['--platform-ref', bad, '--app-ref', A,
                    '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
                api.assert_not_called()
                commands.assert_not_called()
                ssh.assert_not_called()

    def test_validation_only_never_uses_transport(self):
        with mock.patch.object(controller.reviewed, 'check_inputs', return_value={}) as validation, \
                mock.patch.object(controller.reviewed, 'reviewed_admin') as ssh, \
                mock.patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A, '--check-inputs']), 0)
            validation.assert_called_once_with(P, A)
            ssh.assert_not_called()

    def test_review_failures_cannot_open_transport(self):
        for code in ('COMMIT_NOT_ON_MAIN', 'CI_MISSING', 'CI_NOT_SUCCESSFUL', 'INVALID_MANIFEST', 'CHECKOUT_NOT_REVIEWED'):
            with mock.patch.object(controller.reviewed, 'check_inputs', side_effect=core.Failure(code)), \
                    mock.patch.object(controller.reviewed, 'reviewed_admin') as ssh, \
                    mock.patch('sys.stderr', new=io.StringIO()):
                self.assertEqual(controller.main(['--platform-ref', P, '--app-ref', A,
                    '--admin-key-file', '/key', '--public-key-file', '/pub']), 1)
                ssh.assert_not_called()

    def test_fixed_reviewed_entry_and_receipt_contract(self):
        value = receipt()
        self.assertEqual(controller.validate_receipt(value, P, A), value)
        for changes in ({'rule_id': 942100}, {'host': 'other'}, {'app_ref': P}, {'healthy': 1},
                        {'security_retained': False}, {'private_key': 'forbidden'}):
            with self.assertRaisesRegex(core.Failure, 'INVALID_RECEIPT'):
                controller.validate_receipt({**value, **changes}, P, A)


class PolicyAdmission(unittest.TestCase):
    def test_append_preserves_every_setting_and_existing_bytes(self):
        raw = acquisition()
        result = remote.acquisition_candidate(raw)
        self.assertEqual(result.replace(b'  - local/opendesign-crs-scope\n', b''), raw)
        before, after = remote.load_yaml(raw), remote.load_yaml(result)
        self.assertEqual(after.pop('appsec_configs'), before.pop('appsec_configs') + [remote.CONFIG_NAME])
        self.assertEqual(before, after)
        self.assertEqual(remote.acquisition_candidate(result), result)

    def test_unexpected_order_extra_hooks_duplicate_key_or_changed_listen_rejected(self):
        raw = acquisition()
        bad = [raw.replace(b'172.31.254.1:7422', b'0.0.0.0:7422'),
               raw.replace(b'  - local/body-scope\n', b'  - local/unknown-hook\n'),
               raw.replace(b'  - crowdsecurity/crs\n', b'  - crowdsecurity/crs\n  - crowdsecurity/crs\n'),
               raw + b'source: appsec\n',
               raw.replace(b'  - local/bot-scope\n', b'  - local/bot-scope\n  - local/unknown\n')]
        for value in bad:
            with self.assertRaises(remote.Failure):
                remote.acquisition_candidate(value)

    def test_loaded_policy_drift_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            etc = Path(directory)
            configs = etc / 'appsec-configs'
            configs.mkdir()
            raw = b'name: crowdsecurity/crs\noutofband_rules: [crowdsecurity/crs]\n'
            (configs / 'crs.yaml').write_bytes(raw)
            expected = {'crowdsecurity/crs': remote.hashlib.sha256(raw).hexdigest()}
            with mock.patch.object(remote, 'ETC', etc), \
                    mock.patch.object(remote, 'trusted_asset', side_effect=lambda path: path), \
                    mock.patch.object(remote.json, 'loads', return_value=expected), \
                    mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=lambda path: raw if path.name == 'crs.yaml' else b'{}'):
                remote.policy_baseline(ROOT, b'name: local/opendesign-crs-scope\n')
                expected['crowdsecurity/crs'] = '0' * 64
                with self.assertRaisesRegex(remote.Failure, 'LOADED_POLICY_CHANGED'):
                    remote.policy_baseline(ROOT, b'name: local/opendesign-crs-scope\n')

    def test_root_and_input_rejections_precede_fetch_or_apply(self):
        with mock.patch.object(remote.os, 'geteuid', return_value=1000), \
                mock.patch.object(remote, 'checkout') as fetch, \
                mock.patch.object(remote, 'apply_transaction') as apply:
            with self.assertRaisesRegex(remote.Failure, 'ROOT_REQUIRED'):
                remote.tune(P, A, b'')
            fetch.assert_not_called()
            apply.assert_not_called()
        with mock.patch.object(remote.os, 'geteuid', return_value=0), \
                mock.patch.object(remote, 'checkout') as fetch:
            with self.assertRaisesRegex(remote.Failure, 'INVALID_SHA'):
                remote.tune(P + ';id', A, b'')
            fetch.assert_not_called()


class TargetedTransaction(unittest.TestCase):
    def test_apply_atomic_files_rolls_back_only_targets_on_restart_failure(self):
        for failure in ('restart', 'validate', 'postcheck'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                acquis, policy, unrelated = root / 'appsec.yaml', root / 'scope.yaml', root / 'other.yaml'
                acquis.write_bytes(b'old-acquisition')
                unrelated.write_bytes(b'unrelated-policy')
                originals = {acquis: (b'old-acquisition', 0o600, os.getuid(), os.getgid()), policy: None}
                candidates = {acquis: (b'new-acquisition', 0o600, os.getuid(), os.getgid()),
                              policy: (b'new-scope', 0o600, os.getuid(), os.getgid())}
                failed = remote.Failure('EXPECTED_FAILURE')
                with mock.patch.object(remote, 'secure_path', side_effect=lambda path, **kw: path), \
                        mock.patch.object(remote, 'crowdsec_validate', side_effect=[failed, None] if failure == 'validate' else None), \
                        mock.patch.object(remote, 'restart', side_effect=[failed, None] if failure == 'restart' else None), \
                        mock.patch.object(remote, 'readiness'):
                    postcheck = mock.Mock(side_effect=failed if failure == 'postcheck' else None)
                    with self.assertRaisesRegex(remote.Failure, 'EXPECTED_FAILURE'):
                        remote.apply_transaction(originals, candidates, postcheck)
                self.assertEqual(acquis.read_bytes(), b'old-acquisition')
                self.assertFalse(policy.exists())
                self.assertEqual(unrelated.read_bytes(), b'unrelated-policy')

    def test_idempotent_replay_does_not_write_or_restart(self):
        value = {Path('/fixed/a'): (b'installed', 0o600, 0, 0), Path('/fixed/b'): (b'scope', 0o600, 0, 0)}
        with mock.patch.object(remote, 'atomic_file') as write, \
                mock.patch.object(remote, 'crowdsec_validate'), mock.patch.object(remote, 'restart') as restart, \
                mock.patch.object(remote, 'readiness') as ready:
            postcheck = mock.Mock()
            remote.apply_transaction(value, value, postcheck)
            write.assert_not_called()
            restart.assert_not_called()
            ready.assert_called_once()
            postcheck.assert_called_once()

    def test_failed_rollback_never_reports_success(self):
        value = {Path('/fixed/a'): (b'old', 0o600, 0, 0)}
        candidates = {Path('/fixed/a'): (b'new', 0o600, 0, 0)}
        with mock.patch.object(remote, 'atomic_file', side_effect=[None, OSError()]), \
                mock.patch.object(remote, 'crowdsec_validate', side_effect=remote.Failure('BAD_CONFIG')):
            with self.assertRaisesRegex(remote.Failure, 'WAF_ROLLBACK_FAILED'):
                remote.apply_transaction(value, candidates, mock.Mock())


class NativeSmokeBoundaries(unittest.TestCase):
    def test_production_namespace_cannot_start_native_process(self):
        with mock.patch.object(smoke.os, 'geteuid', return_value=0), \
                mock.patch.object(smoke.os, 'readlink', return_value='net:[production]'), \
                mock.patch.object(smoke.subprocess, 'run') as commands, \
                mock.patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(smoke.main([str(ROOT), '/private']), 1)
            commands.assert_not_called()

    def test_native_rule_metrics_delta_not_http_status_drives_proof(self):
        before = smoke.counters('cs_appsec_rule_hits{rule_name="911100",type="outofband"} 3\n')
        after = smoke.counters('cs_appsec_rule_hits{rule_name="911100",type="outofband"} 4\n'
                               'cs_appsec_rule_hits{rule_name="941100",type="outofband"} 1\n')
        self.assertEqual(smoke.rule_delta(before, after), {911100, 941100})
        self.assertEqual(smoke.rule_delta(after, after), set())
        custom = smoke.counters('cs_appsec_rule_hits{rule_name="custom-block",type="inband"} 1\n')
        self.assertEqual(smoke.rule_delta({}, custom), {-1})

    def test_fake_lapi_contains_no_real_identity_or_ban_store(self):
        self.assertFalse(hasattr(smoke.FakeLapi, 'decisions'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc, data, sandbox = root / 'etc-source', root / 'data-source', root / 'private'
            etc.mkdir(); data.mkdir(); sandbox.mkdir()
            (etc / 'hub').mkdir()
            (etc / 'hub/.index.json').write_text('{}')
            (etc / 'config.yaml').write_text('crowdsec_service: {}\napi:\n  client:\n    credentials_path: /real/secret\n')
            (etc / 'notifications').mkdir()
            (etc / 'notifications/secret.yaml').write_text('secret: never-copy')
            (data / 'crowdsec.db').write_text('real-decision-data')
            with mock.patch.object(smoke, 'ETC', etc), mock.patch.object(smoke, 'DATA', data):
                cloned = smoke.clone(sandbox, 11111, 22222, 33333, remote.load_yaml(acquisition()))
            config = remote.load_yaml((cloned / 'config.yaml').read_bytes())
            self.assertNotIn('server', config['api'])
            self.assertEqual(list((sandbox / 'notifications').iterdir()), [])
            self.assertFalse((sandbox / 'data/crowdsec.db').exists())
            self.assertNotIn(b'/real/secret', (cloned / 'config.yaml').read_bytes())
            self.assertEqual(remote.load_yaml((cloned / 'acquis.yaml').read_bytes())['listen_addr'], '127.0.0.1:33333')

    def test_clone_retains_referenced_crs_conf_and_plugin_assets_without_identity_stores(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc, data, sandbox = root / 'etc-source', root / 'data-source', root / 'private'
            etc.mkdir(); data.mkdir(); sandbox.mkdir()
            (etc / 'appsec-rules').mkdir()
            references = ['crs-setup.conf', 'REQUEST-911-METHOD-ENFORCEMENT.conf',
                          'crs-plugins/*/*-config.conf', 'crs-plugins/*/*-before.conf',
                          'crs-plugins/*/*-after.conf']
            import yaml
            (etc / 'appsec-rules/crs.yaml').write_text(yaml.safe_dump(
                {'name': 'crowdsecurity/crs', 'seclang_files_rules': references}))
            assets = {'crs-setup.conf': b'SecAction "id:900000,phase:1,pass,nolog"\n',
                      'REQUEST-911-METHOD-ENFORCEMENT.conf': b'SecRule REQUEST_METHOD "!@rx ^GET$" "id:911100,phase:1,deny"\n',
                      'crs-plugins/example/example-config.conf': b'# plugin configuration\n',
                      'crs-plugins/example/example-before.conf': b'# before rules\n',
                      'crs-plugins/example/example-after.conf': b'# after rules\n',
                      'crs-plugins/example/example.data': b'rule-only data\n'}
            excluded = ['crowdsec.db', 'crowdsec.db-wal', 'machine_credentials.yaml',
                        'identity.json', 'tokens.json', 'secret.txt',
                        'crs-plugins/example/credentials.conf', 'crs-plugins/example/identity.json',
                        'other-subtree/arbitrary.conf']
            for name, raw in {**assets, **{name: b'never-copy' for name in excluded}}.items():
                target = data / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            with mock.patch.object(smoke, 'ETC', etc), mock.patch.object(smoke, 'DATA', data):
                cloned = smoke.clone(sandbox, 11111, 22222, 33333, remote.load_yaml(acquisition()))
            config = remote.load_yaml((cloned / 'config.yaml').read_bytes())
            config_data = Path(config['config_paths']['data_dir'])
            rules = remote.load_yaml((cloned / 'appsec-rules/crs.yaml').read_bytes())
            for pattern in rules['seclang_files_rules']:
                resolved = list(config_data.glob(pattern))
                self.assertTrue(resolved, pattern)
                for path in resolved:
                    self.assertEqual(path.read_bytes(), assets[str(path.relative_to(config_data))])
            for name, raw in assets.items():
                self.assertEqual((config_data / name).read_bytes(), raw)
            for name in excluded:
                self.assertFalse((config_data / name).exists(), name)
            self.assertEqual(list((sandbox / 'notifications').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
