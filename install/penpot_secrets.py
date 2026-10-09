"""Create bootstrap runtime secrets once; never rotate an existing master key."""
import os
import secrets
from pathlib import Path

from core import atomic, require, trusted_path
from penpot import bounded_file, runtime_values


def runtime(work, cfg, registration):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    work = trusted_path(Path(work), directory=True)
    cfg = trusted_path(Path(cfg), directory=True)
    require(work.stat().st_mode & 0o777 == 0o700 and cfg.stat().st_mode & 0o777 == 0o700,
            'PENPOT_RUNTIME_DIRECTORY')
    source, installed = work / '.env', cfg / 'runtime.env'
    # lexists includes broken symlinks, which bounded_file will reject.
    existing = [path for path in (source, installed) if os.path.lexists(path)]
    if existing:
        raw = bounded_file(existing[0])
        values = runtime_values(raw, registration)
        for path in existing[1:]:
            require(runtime_values(bounded_file(path), registration) == values, 'PENPOT_RUNTIME_MISMATCH')
    else:
        raw = ('PENPOT_SECRET_KEY=' + secrets.token_urlsafe(48) + '\nPENPOT_DB_PASSWORD=' +
               secrets.token_hex(32) + '\n').encode('ascii')
        runtime_values(raw, registration)
    for path in (source, installed):
        if not os.path.lexists(path):
            atomic(path, raw, 0o600)
    # Caller holds the app/install locks. Verify both copies before any startup.
    require(runtime_values(bounded_file(source), registration) ==
            runtime_values(bounded_file(installed), registration), 'PENPOT_RUNTIME_MISMATCH')
