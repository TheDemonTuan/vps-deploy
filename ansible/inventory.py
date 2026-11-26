#!/usr/bin/env python3
"""Ansible inventory from hosts/*.yml (validated by lib/core.py): every host with an `edge` block is
in group `edge`. SSH is pinned: the hosts' `ssh.host_key` go to ansible/.known_hosts (regenerated
on every run, gitignored) and nothing else is trusted."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from core import host_registration  # noqa: E402


def main():
    if '--host' in sys.argv:
        print('{}')
        return
    known, hostvars, edge = [], {}, []
    for path in sorted((ROOT / 'hosts').glob('*.yml')):
        record = host_registration(ROOT, path.stem)
        ssh = record['ssh']
        if 'edge' not in record:
            continue
        if 'host_key' not in ssh:
            raise SystemExit(f'{path.stem}: ssh.host_key is required for ansible (pin the key, not only its fingerprint)')
        address = ssh['address']
        known.append(f"[{address}]:{ssh['port']} {ssh['host_key']}" if ssh['port'] != 22 else f"{address} {ssh['host_key']}")
        edge.append(path.stem)
        hostvars[path.stem] = {
            'ansible_host': address,
            'ansible_port': ssh['port'],
            'edge_id': record['edge']['id'],
            'edge_tunnel': record['edge'].get('tunnel'),
            'edge_ip': address,
            'ssh_host_key': ssh['host_key'],
            'host_apps': sorted(record['apps']),
        }
    known_hosts = ROOT / 'ansible' / '.known_hosts'
    known_hosts.write_text('\n'.join(known) + '\n')
    for values in hostvars.values():
        values['ansible_ssh_common_args'] = f'-o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes'
    print(json.dumps({'_meta': {'hostvars': hostvars}, 'all': {'children': ['edge']}, 'edge': {'hosts': edge}}, indent=2))


if __name__ == '__main__':
    main()
