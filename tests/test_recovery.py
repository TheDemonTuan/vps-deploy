import contextlib
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
from core import APP_IMAGE, Failure, atomic, json_bytes, load, save
import operations
loader = importlib.machinery.SourceFileLoader('deployctl_fixture', str(ROOT/'bin/deployctl'))
spec = importlib.util.spec_from_loader(loader.name, loader)
ctl = importlib.util.module_from_spec(spec)
loader.exec_module(ctl)

DIGEST = APP_IMAGE + '@sha256:' + 'd'*64
REQUEST = {'version':1, 'op':'deploy', 'app':'9router', 'component':'app', 'request_id':'test-receipt', 'platform_ref':'a'*40, 'manifest_sha256':'b'*64, 'source_sha':'c'*40, 'image':DIGEST}


class ReceiptRecovery(unittest.TestCase):
    def test_same_request_only_dispatches_once_and_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            state = home/'state'; state.mkdir(); (state/'requests').mkdir()
            locks = home/'locks'; locks.mkdir()
            fake_run = mock.Mock(return_value=mock.Mock(returncode=0))
            with mock.patch.object(ctl, 'host', return_value={'platform_ref':'a'*40}), mock.patch.object(ctl, 'verify_request', return_value=home), mock.patch.object(ctl, 'lock', side_effect=lambda *_: contextlib.nullcontext()), mock.patch.object(ctl.subprocess, 'run', fake_run), mock.patch.object(ctl, 'unit_active', return_value=True):
                first = ctl.submit(REQUEST, home, state, locks)
                second = ctl.submit(REQUEST, home, state, locks)
                self.assertEqual(first['request_id'], second['request_id'])
                self.assertEqual(fake_run.call_count, 1)
                with self.assertRaisesRegex(Failure, 'REQUEST_CONFLICT'):
                    ctl.submit(dict(REQUEST, image=APP_IMAGE+'@sha256:'+'e'*64), home, state, locks)

    def test_prestart_retries_but_started_without_unit_never_replays(self):
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            state = home/'state'; state.mkdir(); (state/'requests').mkdir()
            locks = home/'locks'; locks.mkdir()
            fake_run = mock.Mock(return_value=mock.Mock(returncode=0))
            with mock.patch.object(ctl, 'host', return_value={'platform_ref':'a'*40}), mock.patch.object(ctl, 'verify_request', return_value=home), mock.patch.object(ctl, 'lock', side_effect=lambda *_: contextlib.nullcontext()), mock.patch.object(ctl.subprocess, 'run', fake_run), mock.patch.object(ctl, 'unit_active', return_value=False):
                ctl.submit(REQUEST, home, state, locks)
                ctl.submit(REQUEST, home, state, locks)
                self.assertEqual(fake_run.call_count, 2)
                atomic(state/'requests'/REQUEST['request_id']/'started', b'1')
                self.assertEqual(ctl.submit(REQUEST, home, state, locks)['status'], 'recovery_required')
                self.assertEqual(fake_run.call_count, 2)

    def test_rtk_kill_after_up_commits_only_if_digest_healthy(self):
        with tempfile.TemporaryDirectory() as home:
            home=Path(home)
            cfg=home/'cfg'; cfg.mkdir(); lock=home/'lock'; lock.mkdir()
            old='ghcr.io/thedemontuan/rtk-sidecar@sha256:'+'a'*64
            new='ghcr.io/thedemontuan/rtk-sidecar@sha256:'+'b'*64
            state={'version':1,'revision':3,'rtk':{'current':old,'previous':None},'operation':{'request_id':'crashed','component':'rtk','phase':'rtk_started','previous':old,'previous_id':'sha256:'+'c'*64,'image':new}}
            save(home/'state.json', state)
            req={'component':'rtk'}
            with mock.patch.object(operations, 'rtk_wait') as healthy:
                operations.reconcile(req, state, home, cfg, home, {}, lock)
                self.assertEqual(state['rtk'], {'current':new,'previous':old})
                self.assertIsNone(load(home/'state.json')['operation'])
                healthy.assert_called_once_with('9router-rtk-rtk-1',new)

    def test_rtk_uncertain_previous_keeps_intent(self):
        with tempfile.TemporaryDirectory() as home:
            home=Path(home)
            old='ghcr.io/thedemontuan/rtk-sidecar@sha256:'+'a'*64
            new='ghcr.io/thedemontuan/rtk-sidecar@sha256:'+'b'*64
            state={'version':1,'revision':1,'rtk':{'current':old,'previous':None},'operation':{'request_id':'crashed','component':'rtk','phase':'rtk_started','previous':None,'previous_id':None,'image':new}}
            save(home/'state.json', state)
            with mock.patch.object(operations,'rtk_wait',side_effect=Failure('RTK_UNHEALTHY')):
                with self.assertRaisesRegex(Failure,'RECOVERY_REQUIRED'):
                    operations.reconcile({'component':'rtk'},state,home,home,home,{},home)
            self.assertEqual(load(home/'state.json')['operation']['phase'],'rtk_started')

    def test_route_ack_crash_commits_recorded_target(self):
        with tempfile.TemporaryDirectory() as home:
            home=Path(home); (home/'requests').mkdir()
            old_ref=DIGEST; new_ref=APP_IMAGE+'@sha256:'+'e'*64
            old={'slot':'blue','image':old_ref,'platform_ref':'a'*40,'manifest_sha256':'b'*64}
            new=dict(old,slot='green',image=new_ref)
            original=b'old route bytes'; candidate=b'new route bytes'
            snapshot=home/'requests'/'snapshot'; atomic(snapshot,original)
            intent={'request_id':'crashed','component':'app','phase':'publishing','old_hash':__import__('core').digest(original),'old_generation':'1'*32,'snapshot':str(snapshot),'target':'green','image':new_ref,'new_hash':__import__('core').digest(candidate),'new_generation':'2'*32,'target_entry':new}
            state={'version':1,'revision':4,'active':old,'previous':None,'rtk':{'current':None,'previous':None},'operation':intent,'generation':'1'*32,'draining':None}
            save(home/'state.json',state)
            with mock.patch.object(operations,'lock',side_effect=lambda *_: contextlib.nullcontext()), mock.patch.object(operations.route,'dynamic',return_value=home), mock.patch.object(operations.route,'preflight',return_value=(home/'route.yml',candidate,{})), mock.patch.object(operations.route,'route_state',return_value=('green','2'*32)), mock.patch.object(operations,'wait_health') as direct, mock.patch.object(operations.route,'ack') as ack:
                operations.reconcile({'component':'app'},state,home,home,home,{},home)
                direct.assert_called_once_with('green',new_ref,6)
                ack.assert_called_once_with({},('green','2'*32))
            observed=load(home/'state.json')
            self.assertEqual(observed['active'],new)
            self.assertEqual(observed['previous'],old)
            self.assertEqual(observed['draining'],'blue')
            self.assertIsNone(observed['operation'])

    def test_unproven_candidate_preserves_old_and_requires_recovery(self):
        with tempfile.TemporaryDirectory() as home:
            home=Path(home); original=b'old'; candidate=b'new'
            atomic(home/'snapshot',original)
            old={'slot':'blue','image':DIGEST,'platform_ref':'a'*40,'manifest_sha256':'b'*64}
            new=dict(old,slot='green')
            state={'version':1,'revision':2,'active':old,'previous':None,'rtk':{'current':None,'previous':None},'operation':{'request_id':'crashed','component':'app','phase':'publishing','old_hash':__import__('core').digest(original),'old_generation':'1'*32,'snapshot':str(home/'snapshot'),'target':'green','image':DIGEST,'new_hash':__import__('core').digest(candidate),'new_generation':'2'*32,'target_entry':new},'generation':'1'*32,'draining':None}
            save(home/'state.json',state)
            with mock.patch.object(operations,'lock',side_effect=lambda *_: contextlib.nullcontext()), mock.patch.object(operations.route,'dynamic',return_value=home), mock.patch.object(operations.route,'preflight',return_value=(home/'route.yml',candidate,{})), mock.patch.object(operations.route,'route_state',return_value=('green','2'*32)), mock.patch.object(operations,'wait_health',side_effect=Failure('CANDIDATE_UNHEALTHY')), mock.patch.object(operations.route,'ack') as ack:
                with self.assertRaisesRegex(Failure,'RECOVERY_REQUIRED'):
                    operations.reconcile({'component':'app'},state,home,home,home,{},home)
                ack.assert_not_called()
            observed=load(home/'state.json')
            self.assertEqual(observed['active'],old)
            self.assertEqual(observed['operation']['phase'],'recovery_required')



if __name__ == '__main__':
    unittest.main()
