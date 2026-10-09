"""Root-only offline restore checkpoints. Never called by the app transport."""
import os
import re
import subprocess
import uuid
from pathlib import Path

import penpot
import route
from core import Failure, HASH, atomic, digest, fault, fsync_dir, json_bytes, lock, parse_json, require, save

PHASES = {'prepared', 'maintenance', 'stopped', 'backed_up', 'restoring', 'checking', 'exposing', 'complete'}


def selected_backup(directory, state_dir, profile):
    directory = Path(directory)
    require(directory.is_absolute() and directory.parent == Path(state_dir) / 'backups' and
            penpot.REQUEST_ID.fullmatch(directory.name), 'PENPOT_RESTORE_DIRECTORY')
    penpot.private_directory(directory.parent)
    metadata = penpot.verify_snapshot(directory, profile['registration'])
    return metadata


def snapshot_entry(metadata):
    return {'slot': 'single', 'images': metadata['images'], 'source_sha': metadata['sourceSha'],
            'platform_ref': metadata['platformRef'], 'manifest_sha256': metadata['sha256']['app.yml']}


def check(directory, state_dir, cfg, profile):
    require(os.geteuid() == 0 and profile['app'] == 'penpot', 'ROOT_REQUIRED')
    metadata = selected_backup(directory, state_dir, profile)
    penpot.runtime_values(penpot.bounded_file(Path(cfg) / 'runtime.env'), profile['registration'])
    require(penpot.bounded_file(Path(cfg) / 'app.yml') == penpot.bounded_file(Path(directory) / 'app.yml'),
            'PENPOT_RESTORE_MANIFEST_MISMATCH')
    penpot.owned_volumes(profile)
    return {'status': 'checked', 'source_sha': metadata['sourceSha'], 'data_timestamp': metadata['createdAt'],
            'backup': str(directory)}


def checkpoint(state, state_dir, profile, release):
    penpot.validate_state(state, profile)
    operation = state['operation']
    require(type(operation) is dict and set(operation) == {
        'kind', 'phase', 'request_id', 'committed', 'checkpoint',
    } and operation['kind'] == 'restore' and type(operation['committed']) is bool and
            operation['phase'] in PHASES, 'PENPOT_OPERATOR_RESTORE_REQUIRED')
    base = penpot.private_directory(Path(state_dir) / 'restores')
    directory = penpot.private_directory(base / operation['request_id'])
    require(operation['checkpoint'] == str(directory / 'checkpoint.json') and
            {p.name for p in directory.iterdir()} == {'checkpoint.json', *penpot.ROUTE_RECORDS.values()},
            'PENPOT_RESTORE_CHECKPOINT')
    value = parse_json(penpot.bounded_file(directory / 'checkpoint.json'))
    require(type(value) is dict and set(value) == {
        'request_id', 'selected', 'selected_manifest', 'data_timestamp', 'old', 'target', 'generation',
        'old_generation', 'route_path', 'shared_routes', 'route_hashes', 'safety_backup',
    } and value['request_id'] == operation['request_id'], 'PENPOT_RESTORE_CHECKPOINT')
    penpot.validate_entry(value['old'], profile)
    penpot.validate_entry(value['target'], profile)
    require(value['target']['platform_ref'] == profile['platform_ref'] and
            all(type(value[name]) is str and re.fullmatch('[0-9a-f]{32}', value[name])
                for name in ('generation', 'old_generation')) and value['generation'] != value['old_generation'],
            'PENPOT_RESTORE_CHECKPOINT')
    require(state['active'] == (value['target'] if operation['committed'] else value['old']) and
            state['generation'] == (value['generation'] if operation['committed'] else value['old_generation']) and
            (not operation['committed'] or state['previous'] == value['old']) and
            (operation['phase'] in {'exposing', 'complete'}) == operation['committed'], 'PENPOT_RESTORE_CHECKPOINT')
    dynamic = route.dynamic(profile)
    require(value['route_path'] == str(dynamic / profile['route_name']) and
            value['safety_backup'] == str(Path(state_dir) / 'backups' / operation['request_id']) and
            type(value['shared_routes']) is dict and all(Path(name).is_absolute() and Path(name).parent == dynamic and
            name != value['route_path'] and type(h) is str and HASH.fullmatch(h)
            for name, h in value['shared_routes'].items()), 'PENPOT_RESTORE_CHECKPOINT')
    metadata = selected_backup(value['selected'], state_dir, profile)
    require(digest(penpot.bounded_file(Path(value['selected']) / 'manifest.json')) == value['selected_manifest'] and
            metadata['createdAt'] == value['data_timestamp'] and
            dict(snapshot_entry(metadata), platform_ref=profile['platform_ref']) == value['target'],
            'PENPOT_RESTORE_CHECKPOINT')
    forms = {name: penpot.bounded_file(directory / filename) for name, filename in penpot.ROUTE_RECORDS.items()}
    require(type(value['route_hashes']) is dict and set(value['route_hashes']) == set(forms) and
            all(digest(raw) == value['route_hashes'][name] for name, raw in forms.items()) and
            route.route_state(forms['old'], profile) == ('single', value['old_generation']) and
            forms['target'] == route.render(profile, 'single', value['generation'], release_root=release) and
            forms['maintenance'] == penpot.maintenance_route(forms['target'], profile), 'PENPOT_RESTORE_CHECKPOINT')
    require(penpot.parse_yaml(forms['old']) == penpot.parse_yaml(
        route.render(profile, 'single', value['old_generation'], release_root=release)), 'PENPOT_RESTORE_CHECKPOINT')
    return value, forms, metadata


def phase(state, state_dir, name, value):
    require(parse_json(penpot.bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    candidate = parse_json(json_bytes(state))
    candidate['operation']['phase'] = name
    if name in {'exposing', 'complete'}:
        candidate['operation']['committed'] = True
        candidate.update(active=value['target'], previous=value['old'], generation=value['generation'])
    candidate['revision'] += 1
    save(Path(state_dir) / 'state.json', candidate)
    state.clear()
    state.update(candidate)


def publish(value, forms, profile, locks, desired=None, allowed=None):
    with lock(Path(locks) / 'traefik.lock', 60):
        dynamic = route.dynamic(profile)
        route.unchanged(value['shared_routes'], dynamic, profile['route_name'])
        path = Path(value['route_path'])
        current = route.checked_file(path, managed=True)
        require(allowed is None or penpot.recorded_route(current, forms) in allowed, 'PENPOT_ROUTE_DRIFT')
        if desired is not None and current != forms[desired]:
            route.publish(path, forms[desired], digest(current))
        route.unchanged(value['shared_routes'], dynamic, profile['route_name'])


def begin(directory, state, state_dir, cfg, release, profile, locks):
    require(state['operation'] is None and state['active'] is not None, 'RECOVERY_REQUIRED')
    check(directory, state_dir, cfg, profile)
    metadata = selected_backup(directory, state_dir, profile)
    target = dict(snapshot_entry(metadata), platform_ref=profile['platform_ref'])
    req = {'version': 1, 'op': 'deploy', 'component': 'app', 'app': 'penpot', 'request_id': 'restore-' + uuid.uuid4().hex,
           'platform_ref': target['platform_ref'], 'source_sha': target['source_sha'],
           'manifest_sha256': target['manifest_sha256'], 'images': target['images']}
    penpot.prepare_images(req, profile)
    penpot.matching(state, profile)
    penpot.public_ack(profile, state['generation'])
    with lock(Path(locks) / 'traefik.lock', 60):
        dynamic = route.dynamic(profile)
        path, normal, shared = route.preflight(dynamic, profile, release_root=release)
        require(route.route_state(normal, profile) == ('single', state['generation']), 'ROUTE_STATE_MISMATCH')
        generation = uuid.uuid4().hex
        target_route = route.render(profile, 'single', generation, release_root=release)
        forms = {'old': normal, 'target': target_route, 'maintenance': penpot.maintenance_route(target_route, profile)}
        base = Path(state_dir) / 'restores'
        if not base.exists():
            base.mkdir(mode=0o700)
            fsync_dir(base.parent)
        penpot.private_directory(base)
        destination = base / req['request_id']
        destination.mkdir(mode=0o700)
        fsync_dir(base)
        for name, filename in penpot.ROUTE_RECORDS.items():
            atomic(destination / filename, forms[name])
        value = {'request_id': req['request_id'], 'selected': str(directory),
                 'selected_manifest': digest(penpot.bounded_file(Path(directory) / 'manifest.json')),
                 'data_timestamp': metadata['createdAt'], 'old': state['active'], 'target': target,
                 'generation': generation, 'old_generation': state['generation'], 'route_path': str(path),
                 'shared_routes': shared, 'route_hashes': {name: digest(raw) for name, raw in forms.items()},
                 'safety_backup': str(Path(state_dir) / 'backups' / req['request_id'])}
        save(destination / 'checkpoint.json', value)
        require(parse_json(penpot.bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
        candidate = dict(state, revision=state['revision'] + 1, operation={
            'kind': 'restore', 'phase': 'prepared', 'committed': False, 'request_id': req['request_id'],
            'checkpoint': str(destination / 'checkpoint.json')})
        checkpoint(candidate, state_dir, profile, release)
        route.unchanged(shared, dynamic, profile['route_name'])
        require(route.checked_file(path, managed=True) == normal, 'PENPOT_ROUTE_DRIFT')
        save(Path(state_dir) / 'state.json', candidate)
        state.clear()
        state.update(candidate)
    fault(profile, 'penpot_restore_prepared')


def change_password(directory, profile):
    values = penpot.runtime_values(penpot.bounded_file(Path(directory) / 'runtime.env'), profile['registration'])
    # Password is validated hexadecimal and goes only through stdin, never argv.
    sql = ("ALTER ROLE penpot WITH PASSWORD '" + values['PENPOT_DB_PASSWORD'] + "';\n").encode('ascii')
    # Send logging settings as a separate command before transmitting the password.
    settings = "SET log_statement='none'; SET log_min_duration_statement=-1; SET log_min_error_statement='panic'; SET log_duration=off;"
    process = subprocess.run(['/usr/bin/docker', 'exec', '-i', 'penpot-postgres', 'psql', '-X', '-U', 'penpot',
                              '-d', 'postgres', '--set=ON_ERROR_STOP=1', '-c', settings, '-f', '-'], input=sql, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}, timeout=60)
    require(process.returncode == 0, 'PENPOT_RESTORE_ROLE_PASSWORD')


def apply(directory, state_dir, cfg, release, profile, locks):
    require(os.geteuid() == 0 and profile['app'] == 'penpot', 'ROOT_REQUIRED')
    with lock(Path(locks) / 'penpot@operation.lock'):
        state = parse_json(penpot.bounded_file(Path(state_dir) / 'state.json'))
        penpot.validate_state(state, profile)
        if state['operation'] is None:
            begin(directory, state, state_dir, cfg, release, profile, locks)
        value, forms, metadata = checkpoint(state, state_dir, profile, release)
        require(value['selected'] == str(directory), 'PENPOT_RESTORE_CHECKPOINT')
        try:
            operation = state['operation']
            current_phase = operation['phase']
            allowed = {'old', 'maintenance'} if current_phase in {'prepared', 'maintenance'} else {'maintenance', 'target'} if operation['committed'] else {'maintenance'}
            publish(value, forms, profile, locks, allowed=allowed)
            if current_phase == 'prepared':
                phase(state, state_dir, 'maintenance', value)
            publish(value, forms, profile, locks, 'maintenance', allowed)
            penpot.public_ack(profile, maintenance=True)
            if current_phase in {'prepared', 'maintenance'}:
                phase(state, state_dir, 'stopped', value)
            if state['operation']['phase'] == 'stopped':
                penpot.transaction_writers(profile, value)
                penpot.application_command(release, profile, cfg, value['old'], 'stop')
                penpot.writers_stopped(profile)
                safety = Path(value['safety_backup'])
                if safety.exists():
                    saved = penpot.verify_snapshot(safety, profile['registration'])
                    require(snapshot_entry(saved) == value['old'] and saved['sha256']['route.yml'] == digest(forms['old']),
                            'PENPOT_RESTORE_SAFETY_BACKUP')
                else:
                    penpot.snapshot(profile, cfg, state_dir, value['request_id'], value['old'], forms['old'])
                phase(state, state_dir, 'backed_up', value)
                fault(profile, 'penpot_restore_backed_up')
            if state['operation']['phase'] == 'backed_up':
                phase(state, state_dir, 'restoring', value)
            if state['operation']['phase'] == 'restoring':
                penpot.transaction_writers(profile, value)
                penpot.application_command(release, profile, cfg, value['target'], 'stop')
                penpot.writers_stopped(profile)
                # Revalidate both archives before touching config, database, or assets.
                metadata = selected_backup(directory, state_dir, profile)
                safety_metadata = penpot.verify_snapshot(Path(value['safety_backup']), profile['registration'])
                require(snapshot_entry(safety_metadata) == value['old'] and
                        safety_metadata['sha256']['route.yml'] == digest(forms['old']), 'PENPOT_RESTORE_SAFETY_BACKUP')
                penpot.owned_volumes(profile)
                penpot.postgres_owned(profile)
                for ref in metadata['images'].values():
                    penpot.image_id(ref)
                atomic(Path(cfg) / 'runtime.env', penpot.bounded_file(Path(directory) / 'runtime.env'))
                change_password(directory, profile)
                penpot.restore_data(profile, cfg, directory, snapshot_entry(metadata))
                fault(profile, 'penpot_restore_data')
                phase(state, state_dir, 'checking', value)
            penpot.transaction_writers(profile, value)
            penpot.start_applications(release, profile, cfg, value['target'])
            route.ack(profile, ('single', value['generation']), timeout=30)
            if not state['operation']['committed']:
                phase(state, state_dir, 'exposing', value)
            fault(profile, 'penpot_restore_exposing')
            publish(value, forms, profile, locks, 'target', {'maintenance'})
            route.ack(profile, ('single', value['generation']), timeout=30)
            penpot.public_ack(profile, value['generation'])
            publish(value, forms, profile, locks, allowed={'target'})
            phase(state, state_dir, 'complete', value)
            fault(profile, 'penpot_restore_complete')
            penpot.finish_operation(state, state_dir)
            return {'status': 'complete', 'request_id': value['request_id'], 'checkpoint': str(Path(state_dir) / 'restores' / value['request_id']),
                    'source_sha': value['target']['source_sha'], 'data_timestamp': value['data_timestamp'],
                    'safety_backup': value['safety_backup']}
        except (Failure, OSError, subprocess.TimeoutExpired):
            publish(value, forms, profile, locks, 'maintenance', {'old', 'maintenance', 'target'})
            raise
