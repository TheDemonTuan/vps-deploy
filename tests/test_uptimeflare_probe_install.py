import base64
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location('uptimeflare_probe_install', ROOT / 'install/install-uptimeflare-probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(path, members, mode='w:gz'):
    with tarfile.open(path, mode) as tar:
        for name, raw, kind in members:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.type = kind
            member.size = len(raw) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = '/etc/shadow'
            tar.addfile(member, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)


class UptimeflareProbeInstall(unittest.TestCase):
    def fixture(self, home, stack):
        module = load_module()
        base = Path(home)
        # Positive fixtures bypass host ownership only; trust rejection tests below
        # exercise the real lstat/ancestor policy independently of runner UID.
        stack.enter_context(mock.patch.object(module, 'trusted', side_effect=lambda path, **kw: Path(path)))
        stack.enter_context(mock.patch.object(module, 'trusted_executable', side_effect=lambda path: Path(path)))
        stack.enter_context(mock.patch.object(module.os, 'geteuid', return_value=0))
        stack.enter_context(mock.patch.object(module.os, 'uname', return_value=SimpleNamespace(machine='aarch64')))
        stack.enter_context(mock.patch.object(module.os, 'access', return_value=True))
        stack.enter_context(mock.patch.object(module, 'account_state', return_value=False))
        for name, value in {
            'BASE': base / 'opt/probe', 'HOME': base / 'home/probe',
            'ENTRY': base / 'libexec/probe-entry', 'WRAPPER': base / 'libexec/probe',
            'SUDOERS': base / 'sudoers.d/probe', 'INSTALL_LOCK': base / 'run/install.lock',
            'RESTORECON': base / 'restorecon',
        }.items():
            stack.enter_context(mock.patch.object(module, name, value))
        for name in ('opt', 'home', 'sudoers.d', 'run'):
            (base / name).mkdir()
        source = base / 'source'
        (source / 'cloudflare').mkdir(parents=True)
        (source / 'install').mkdir()
        release = 'a' * 40
        (source / '.probe-source-sha').write_text(release + '\n')
        (source / 'cloudflare/uptimeflare-http.mjs').write_text('export const probe = true;\n')
        (source / 'install/install-uptimeflare-probe.py').write_bytes((ROOT / 'install/install-uptimeflare-probe.py').read_bytes())
        records = {}
        for name in ('playwright', 'playwright-core'):
            path = base / (name + '.tgz')
            archive(path, [('package/package.json', json.dumps({'name': name, 'version': '1.63.0'}).encode(), tarfile.REGTYPE),
                           ('package/index.mjs', b'export {};\n', tarfile.REGTYPE)])
            records['node_modules/' + name] = {'version': '1.63.0',
                'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()}
        records['node_modules/playwright']['dependencies'] = {'playwright-core': '1.63.0'}
        (source / 'cloudflare/package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': records}))
        node = base / 'node.tar.xz'
        archive(node, [('node-v24.21.0-linux-arm64/bin/node', b'node fixture', tarfile.REGTYPE)], 'w:xz')
        stack.enter_context(mock.patch.dict(module.NODE_DIGESTS, {'arm64': hashlib.sha256(node.read_bytes()).hexdigest()}))
        key = base / 'probe.pub'
        blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'k' * 32
        key.write_bytes(b'ssh-ed25519 ' + base64.b64encode(blob) + b' operator comment\n')
        args = SimpleNamespace(source=str(source), release=release, public_key=str(key), node_archive=str(node),
                               playwright_archive=str(base / 'playwright.tgz'),
                               playwright_core_archive=str(base / 'playwright-core.tgz'))
        return module, args

    def test_check_has_no_mutations_or_processes_and_reports_digest_manifest(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            before = {str(path): (path.stat().st_mode, path.read_bytes() if path.is_file() else None)
                      for path in Path(home).rglob('*')}
            with mock.patch.object(module.subprocess, 'run') as run:
                plan = module.check(args)
            after = {str(path): (path.stat().st_mode, path.read_bytes() if path.is_file() else None)
                     for path in Path(home).rglob('*')}
            self.assertEqual(before, after)
            run.assert_not_called()
            self.assertFalse(plan['reused'])
            self.assertEqual(plan['manifest']['release'], args.release)
            self.assertEqual(set(plan['manifest']['package_integrity']), {'playwright', 'playwright-core'})
            self.assertIn('cloudflare/uptimeflare-http.mjs', plan['manifest']['source_sha256'])
            self.assertIn('node/bin/node', plan['manifest']['files'])

    def test_main_check_does_not_open_install_lock_or_apply(self):
        module = load_module()
        manifest = {'version': 1}
        with mock.patch.object(module, 'check', return_value={'manifest': manifest, 'reused': False}), \
                mock.patch.object(module, 'apply') as apply, mock.patch.object(module.os, 'open') as opened, \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            result = module.main(['--source', '/source', '--release', 'a' * 40, '--public-key', '/key',
                                  '--node-archive', '/node', '--playwright-archive', '/pw',
                                  '--playwright-core-archive', '/core', '--check'])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'checked')
        apply.assert_not_called()
        opened.assert_not_called()

    def test_root_only_and_full_release_sha(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            with mock.patch.object(module.os, 'geteuid', return_value=1000):
                with self.assertRaisesRegex(module.Failure, 'ROOT_REQUIRED'):
                    module.check(args)
            args.release = 'a' * 12
            with self.assertRaisesRegex(module.Failure, 'INVALID_RELEASE_SHA'):
                module.check(args)

    def test_staged_source_identity_and_installer_must_match(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            marker = Path(args.source) / '.probe-source-sha'
            marker.write_text('b' * 40 + '\n')
            with self.assertRaisesRegex(module.Failure, 'SOURCE_SHA_MISMATCH'):
                module.check(args)
            marker.write_text(args.release + '\n')
            (Path(args.source) / 'install/install-uptimeflare-probe.py').write_text('# tampered\n')
            with self.assertRaisesRegex(module.Failure, 'INSTALLER_SOURCE_MISMATCH'):
                module.check(args)

    def test_archive_tampering_rejected_before_use(self):
        for name, code in (('node_archive', 'NODE_DIGEST_MISMATCH'),
                           ('playwright_archive', 'PACKAGE_DIGEST_MISMATCH'),
                           ('playwright_core_archive', 'PACKAGE_DIGEST_MISMATCH')):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as home, ExitStack() as stack:
                module, args = self.fixture(home, stack)
                with Path(getattr(args, name)).open('ab') as stream:
                    stream.write(b'tamper')
                with self.assertRaisesRegex(module.Failure, code):
                    module.check(args)
                self.assertFalse(module.BASE.exists())

    def test_package_rejects_links_traversal_duplicates_and_special_files(self):
        for name, kind in (('package/link', tarfile.SYMTYPE), ('package/../../escape', tarfile.REGTYPE),
                           ('/package/absolute', tarfile.REGTYPE), ('package/fifo', tarfile.FIFOTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as home, ExitStack() as stack:
                module, args = self.fixture(home, stack)
                path = Path(args.playwright_archive)
                archive(path, [(name, b'x', kind)])
                record = {'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()}
                with self.assertRaisesRegex(module.Failure, 'UNSAFE_PACKAGE_ARCHIVE'):
                    module.package(path, 'playwright', record)
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            path = Path(args.playwright_archive)
            archive(path, [('package/same', b'a', tarfile.REGTYPE), ('package/same', b'b', tarfile.REGTYPE)])
            record = {'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()}
            with self.assertRaisesRegex(module.Failure, 'UNSAFE_PACKAGE_ARCHIVE'):
                module.package(path, 'playwright', record)

    def test_idempotence_reuses_exact_bytes_and_rejects_release_tampering(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            with mock.patch.object(module.subprocess, 'run') as run:
                plan = module.check(args)
                previous_mask = os.umask(0o077)
                try:
                    module.apply(plan)
                finally:
                    os.umask(previous_mask)
                self.assertEqual(run.call_count, 2)  # useradd and visudo, never npm/network.
                useradd = run.call_args_list[0].args[0]
                self.assertIn('--no-log-init', useradd)
                self.assertNotIn('--key', useradd)
                self.assertEqual(useradd[useradd.index('--password') + 1], '*')
                module.account_state.return_value = True
                second = module.check(args)
                self.assertTrue(second['reused'])
                before = {str(path): (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
                          for path in Path(home).rglob('*') if path.is_file()}
                run.reset_mock()
                module.apply(second)
                after = {str(path): (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
                         for path in Path(home).rglob('*') if path.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], ['/usr/sbin/visudo', '-cf', '-'])
                (second['release_path'] / 'cloudflare/uptimeflare-http.mjs').write_bytes(b'tamper')
                with self.assertRaisesRegex(module.Failure, 'IMMUTABLE_RELEASE_CONFLICT'):
                    module.check(args)

    def test_existing_forced_command_or_key_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            module.ENTRY.parent.mkdir()
            module.ENTRY.parent.chmod(0o755)
            module.ENTRY.write_text('# conflicting entry\n')
            module.ENTRY.chmod(0o755)
            with self.assertRaisesRegex(module.Failure, 'IMMUTABLE_RESOURCE_CONFLICT'):
                module.check(args)
            self.assertEqual(module.ENTRY.read_text(), '# conflicting entry\n')

    def test_real_trust_rejects_unowned_writable_and_symlink_ancestors(self):
        module = load_module()
        path = Path('/root/stage/probe.pub')
        for target, uid, mode in ((path, 1000, stat.S_IFREG | 0o644),
                                  (path, 0, stat.S_IFREG | 0o666),
                                  (path.parent, 0, stat.S_IFDIR | 0o775),
                                  (path.parent, 0, stat.S_IFLNK | 0o777),
                                  (path, 0, stat.S_IFLNK | 0o777)):
            with self.subTest(target=str(target), uid=uid, mode=mode):
                def lstat(item):
                    if item == target:
                        return SimpleNamespace(st_uid=uid, st_mode=mode)
                    return SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o644) if item == path else (stat.S_IFDIR | 0o755))
                with mock.patch.object(Path, 'lstat', lstat):
                    with self.assertRaisesRegex(module.Failure, 'UNTRUSTED_PATH'):
                        module.trusted(path)

    def test_os_executable_links_require_trusted_links_targets_and_ancestors(self):
        module = load_module()
        link = Path('/usr/bin/chromium-browser')
        target = Path('/usr/lib64/chromium-browser/chromium-browser.sh')
        for bad_path, uid, mode in ((None, 0, 0),
                                   (link, 1000, stat.S_IFLNK | 0o777),
                                   (link.parent, 0, stat.S_IFDIR | 0o775),
                                   (target, 1000, stat.S_IFREG | 0o755),
                                   (target, 0, stat.S_IFREG | 0o777),
                                   (target.parent, 0, stat.S_IFDIR | 0o777)):
            with self.subTest(bad_path=str(bad_path), uid=uid, mode=mode):
                def lstat(item):
                    if item == bad_path:
                        return SimpleNamespace(st_uid=uid, st_mode=mode)
                    kind = stat.S_IFLNK if item == link else stat.S_IFREG if item == target else stat.S_IFDIR
                    return SimpleNamespace(st_uid=0, st_mode=kind | (0o777 if item == link else 0o755))
                with mock.patch.object(Path, 'lstat', lstat), \
                        mock.patch.object(module.os, 'readlink', return_value='../../usr/lib64/chromium-browser/chromium-browser.sh'), \
                        mock.patch.object(module.os, 'access', return_value=True):
                    if bad_path is None:
                        self.assertEqual(module.trusted_executable(link), target)
                        with self.assertRaisesRegex(module.Failure, 'UNTRUSTED_PATH'):
                            module.trusted(link)  # Staged inputs/resources still forbid links.
                    else:
                        with self.assertRaises(module.Failure):
                            module.trusted_executable(link)

    def test_selinux_relabel_is_confined_to_dedicated_home(self):
        with tempfile.TemporaryDirectory() as home, ExitStack() as stack:
            module, args = self.fixture(home, stack)
            module.RESTORECON.write_text('fixture executable\n')
            module.RESTORECON.chmod(0o755)
            plan = module.check(args)
            self.assertTrue(plan['restorecon'])
            with mock.patch.object(module.subprocess, 'run') as run:
                module.apply(plan)
            self.assertEqual(run.call_args.args[0], [str(module.RESTORECON), '-RF', str(module.HOME)])
            self.assertEqual(run.call_count, 3)

    def test_wrappers_have_only_fixed_forced_command_and_transient_sandbox(self):
        module = load_module()
        entry, wrapper, sudoers = module.scripts('a' * 40)
        self.assertIn(b'"${SSH_ORIGINAL_COMMAND-}" = probe', entry)
        self.assertIn(b'"$#" -eq 0', entry)
        self.assertIn(b'"$#" -eq 0', wrapper)
        for token in (b'--pipe --wait --collect', b'PrivateTmp=yes', b'ProtectSystem=strict', b'ProtectHome=yes',
                      b'NoNewPrivileges=yes', b'CapabilityBoundingSet=', b'AmbientCapabilities=', b'RuntimeMaxSec=90',
                      b'MemoryMax=768M', b'CPUQuota=100%', b'TasksMax=256', b'/usr/bin/env -i',
                      b'PrivateDevices=yes', b'ReadOnlyPaths=', b'InaccessiblePaths=-/etc/vps-deploy',
                      b'-/var/lib/vps-deploy', b'-/opt/platform', b'-/opt/9router', b'-/opt/penpot',
                      b'-/opt/tuan-portfolio', b'-/run/docker.sock', b'HOME=/tmp'):
            self.assertIn(token, wrapper)
        self.assertIn(b'NOPASSWD: /usr/local/libexec/vps-deploy-uptimeflare-probe ""\n', sudoers)
        self.assertNotIn(b'--no-sandbox', wrapper)
        self.assertNotIn(b'node_modules/.bin', wrapper)
        self.assertNotIn(b'--unit=', wrapper)
        self.assertNotIn(b'2>/dev/null', wrapper)


if __name__ == '__main__':
    unittest.main()
