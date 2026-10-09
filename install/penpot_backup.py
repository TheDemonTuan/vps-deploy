"""Render dedicated backup files and pause the timer during Penpot enrollment."""
from pathlib import Path
from core import SHA, require, trusted_path

SERVICE = 'vps-deploy-penpot-backup.service'
TIMER = 'vps-deploy-penpot-backup.timer'
WRAPPER = 'vps-deploy-penpot-backup'


def files(release, libexec, systemd):
    release = trusted_path(Path(release), directory=True)
    require(SHA.fullmatch(release.name), 'INVALID_RELEASE_SHA')
    source = trusted_path(release / 'install/vps-deploy-app').read_text()
    wrapper = source.replace('@APP@', 'penpot').replace('@RELEASE@', release.name).replace('@ACTION@', 'backup')
    require('@APP@' not in wrapper and '@RELEASE@' not in wrapper and '@ACTION@' not in wrapper,
            'BACKUP_WRAPPER_POLICY')
    return {
        Path(libexec) / WRAPPER: (wrapper.encode(), 0o755),
        Path(systemd) / SERVICE: (trusted_path(release / 'install' / SERVICE).read_bytes(), 0o644),
        Path(systemd) / TIMER: (trusted_path(release / 'install' / TIMER).read_bytes(), 0o644),
    }


def pause(run):
    """Do not update the wrapper while a backup or another app operation runs."""
    enabled = run('/usr/bin/systemctl', 'is-enabled', '--quiet', TIMER, check=False).returncode == 0
    active = run('/usr/bin/systemctl', 'is-active', '--quiet', TIMER, check=False).returncode == 0
    run('/usr/bin/systemctl', 'stop', TIMER)
    if run('/usr/bin/systemctl', 'is-active', '--quiet', SERVICE, check=False).returncode == 0:
        if active:
            run('/usr/bin/systemctl', 'start', TIMER, check=False)
        from core import Failure
        raise Failure('INSTALL_BUSY')
    return TIMER, enabled, active

