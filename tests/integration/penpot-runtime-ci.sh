#!/usr/bin/env bash
# Fail-closed native lifecycle proof; the Python driver writes failure evidence.
set -euo pipefail
umask 077
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
exec /usr/bin/python3 "$root/tests/integration/penpot-runtime-driver.py"
