"""Penpot release identities, readiness, routes, and binary snapshot boundaries."""
import datetime
import hashlib
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
from contextlib import nullcontext

import yaml
from pathlib import Path, PurePosixPath

from core import (Failure, HASH, PENPOT_ROLES, REQUEST_ID, SHA, command, container, digest, docker,
                  fault, fsync_dir, image_id, image_map, inspect, json_bytes, load, lock, manifest,
                  parse_json, parse_yaml, request as parse_request, require, save, trusted_path, atomic,
                  verify_request)

from operations import anonymous_image

APP_SERVICES = tuple('penpot-' + role for role in PENPOT_ROLES)
SNAPSHOT_FILES = ('database.dump', 'assets.tar', 'runtime.env', 'app.yml', 'route.yml')
VOLUMES = {'database': 'penpot_postgres_v15', 'assets': 'penpot_assets'}
DATASTORE_IMAGES = {
    'penpot-postgres': 'postgres:15@sha256:7e2070cf6ad06fb3cbbd141b1bafbb7fd5bb63e2b6001e6daf34448eb555e4b3',
    'penpot-valkey': 'valkey/valkey:8.1@sha256:640c5e62cea04b6d6f2084232651d0cc70362d31f4f805e7be94dbed6855e8f2',
}


def validate_entry(value, profile):
    require(type(value) is dict and set(value) == {'slot', 'images', 'source_sha', 'platform_ref', 'manifest_sha256'} and
            value['slot'] == 'single', 'PENPOT_RELEASE_ENTRY')
    image_map(value['images'], profile['image_repositories'])
    require(type(value['source_sha']) is str and SHA.fullmatch(value['source_sha']) and
            type(value['platform_ref']) is str and SHA.fullmatch(value['platform_ref']) and
            type(value['manifest_sha256']) is str and HASH.fullmatch(value['manifest_sha256']), 'PENPOT_RELEASE_ENTRY')
    return value


def adopt_state(profile, manifest_hash, generation):
    """Adopt only one coherent source release already running on the owned stack."""
    from core import container_digest
    images = {}
    sources = set()
    for role in PENPOT_ROLES:
        live = container('penpot-' + role, running=True)
        ref = container_digest(live, profile['image_repositories'][role])
        labels = inspect('image', ref).get('Config', {}).get('Labels') or {}
        require(labels.get('org.opencontainers.image.source') == 'https://github.com/TheDemonTuan/penpot',
                'PENPOT_IMAGE_REVISION')
        source = labels.get('org.opencontainers.image.revision')
        require(type(source) is str and SHA.fullmatch(source), 'PENPOT_IMAGE_REVISION')
        sources.add(source)
        images[role] = ref
    require(len(sources) == 1, 'PENPOT_IMAGE_REVISION')
    entry = validate_entry({'slot': 'single', 'images': images, 'source_sha': sources.pop(),
                            'platform_ref': profile['platform_ref'], 'manifest_sha256': manifest_hash}, profile)
    prepare_images(entry, profile)
    stack_health(profile, entry)
    return validate_state({'version': 1, 'revision': 1, 'active': entry, 'previous': None,
                           'generation': generation, 'operation': None, 'draining': None, 'rtk': None}, profile)


def release_entry(request, profile):
    return validate_entry({'slot': 'single', 'images': dict(request['images']),
                           'source_sha': request['source_sha'], 'platform_ref': request['platform_ref'],
                           'manifest_sha256': request['manifest_sha256']}, profile)


def validate_state(state, profile):
    require(type(state) is dict and set(state) == {
        'version', 'revision', 'active', 'previous', 'generation', 'operation', 'draining', 'rtk',
    }, 'INVALID_STATE')
    require(type(state['version']) is int and state['version'] == 1 and
            type(state['revision']) is int and state['revision'] > 0 and
            type(state['generation']) is str and re.fullmatch('[0-9a-f]{32}', state['generation']) and
            state['draining'] is None and state['rtk'] is None, 'INVALID_STATE')
    for key in ('active', 'previous'):
        if state[key] is not None:
            validate_entry(state[key], profile)
    operation = state['operation']
    require(operation is None or type(operation) is dict and
            type(operation.get('phase')) is str and operation['phase'] in {
                'prepared', 'maintenance', 'stopped', 'backed_up', 'applying',
                'checking', 'exposing', 'complete', 'restoring', 'resuming', 'recovery_required',
            } and type(operation.get('request_id')) is str and
            REQUEST_ID.fullmatch(operation['request_id']), 'INVALID_STATE')
    return state


def stack_health(profile, entry):
    validate_entry(entry, profile)
    refs = {'penpot-' + role: ref for role, ref in entry['images'].items()}
    refs.update(DATASTORE_IMAGES)
    private_network = profile['compose_project'] + '_penpot'
    for name, ref in refs.items():
        value = container(name, ref, running=True)
        require(value.get('State', {}).get('Health', {}).get('Status') == 'healthy', 'PENPOT_STACK_UNHEALTHY')
        labels = value.get('Config', {}).get('Labels') or {}
        require(labels.get('vps-deploy.app') == 'penpot' and
                labels.get('com.docker.compose.project') == profile['compose_project'] and
                labels.get('com.docker.compose.service') == name, 'PENPOT_CONTAINER_OWNERSHIP')
        host_config = value.get('HostConfig') or {}
        settings = value.get('NetworkSettings') or {}
        require(not host_config.get('Privileged') and not host_config.get('PublishAllPorts') and
                not host_config.get('PortBindings') and
                not any(settings.get('Ports', {}).values()), 'PENPOT_CONTAINER_SECURITY')
        networks = {private_network}
        if name == 'penpot-frontend':
            networks.add(profile['edge_network'])
        elif name in ('penpot-backend', 'penpot-exporter'):
            networks.add('penpot-egress')
        require(set(settings.get('Networks', {})) == networks, 'PENPOT_CONTAINER_NETWORKS')


def matching(state, profile):
    import route
    validate_state(state, profile)
    require(state['active'] is not None, 'NOT_ADOPTED')
    require(state['operation'] is None, 'RECOVERY_REQUIRED')
    target, raw, _ = route.preflight(route.dynamic(profile), profile)
    expected = ('single', state['generation'])
    require(route.route_state(raw, profile) == expected, 'ROUTE_STATE_MISMATCH')
    require(route.probe(profile) == expected, 'ROUTE_OBSERVED_MISMATCH')
    stack_health(profile, state['active'])
    return target, raw


ROUTE_RECORDS = {'old': 'normal-old.yml', 'maintenance': 'maintenance-target.yml', 'target': 'normal-target.yml'}


def private_directory(path):
    path = trusted_path(Path(path), directory=True)
    require(stat.S_IMODE(path.lstat().st_mode) == 0o700, 'PENPOT_INTENT_PERMISSIONS')
    return path


def intent_routes(state, state_dir, profile, release):
    import route
    validate_state(state, profile)
    operation = state['operation']
    fields = {'kind', 'phase', 'request_id', 'committed', 'old', 'target', 'old_generation', 'generation',
              'directory', 'route_path', 'shared_routes', 'route_hashes', 'snapshot'}
    require(type(operation) is dict and set(operation) in (fields, fields | {'recovery_from', 'error_code'}) and
            operation['kind'] in {'deploy', 'backup'} and type(operation['committed']) is bool, 'PENPOT_INTENT')
    if 'recovery_from' in operation:
        require(operation['phase'] == 'recovery_required' and operation['recovery_from'] in {
            'prepared', 'maintenance', 'stopped', 'backed_up', 'applying', 'checking', 'restoring', 'resuming', 'exposing', 'complete',
        } and type(operation['error_code']) is str and re.fullmatch('[A-Z0-9_]{1,128}', operation['error_code']), 'PENPOT_INTENT')
    for name in ('old', 'target'):
        validate_entry(operation[name], profile)
    require(operation['target']['platform_ref'] == profile['platform_ref'] and
            all(type(operation[key]) is str and re.fullmatch('[0-9a-f]{32}', operation[key])
                for key in ('old_generation', 'generation')) and
            (operation['old_generation'] != operation['generation'] if operation['kind'] == 'deploy' else
             operation['old_generation'] == operation['generation'] and operation['old'] == operation['target'] and
             not operation['committed']), 'PENPOT_INTENT')
    active = operation['target'] if operation['committed'] else operation['old']
    generation = operation['generation'] if operation['committed'] else operation['old_generation']
    require(state['active'] == active and state['generation'] == generation, 'PENPOT_INTENT_STATE')
    if operation['committed']:
        require(state['previous'] == operation['old'] and
                operation['phase'] in ('exposing', 'complete', 'recovery_required'), 'PENPOT_INTENT_STATE')
    else:
        require(operation['phase'] not in ('exposing', 'complete'), 'PENPOT_INTENT_STATE')
    private_directory(state_dir)
    base = private_directory(Path(state_dir) / 'operations')
    directory = base / operation['request_id']
    require(operation['directory'] == str(directory), 'PENPOT_INTENT_DIRECTORY')
    private_directory(directory)
    require({path.name for path in directory.iterdir()} == set(ROUTE_RECORDS.values()), 'PENPOT_INTENT_FILES')
    dynamic = route.dynamic(profile)
    require(operation['route_path'] == str(dynamic / profile['route_name']), 'PENPOT_INTENT_ROUTE')
    shared = operation['shared_routes']
    require(type(shared) is dict and all(type(name) is str and Path(name).is_absolute() and
            Path(name).parent == dynamic and name != operation['route_path'] and
            type(value) is str and HASH.fullmatch(value) for name, value in shared.items()), 'PENPOT_INTENT_ROUTE')
    hashes = operation['route_hashes']
    require(type(hashes) is dict and set(hashes) == set(ROUTE_RECORDS) and
            all(type(value) is str and HASH.fullmatch(value) for value in hashes.values()), 'PENPOT_INTENT_ROUTE')
    forms = {name: bounded_file(directory / filename) for name, filename in ROUTE_RECORDS.items()}
    require(all(raw and digest(raw) == hashes[name] for name, raw in forms.items()), 'PENPOT_INTENT_ROUTE')
    require(route.route_state(forms['old'], profile) == ('single', operation['old_generation']) and
            route.route_state(forms['target'], profile) == ('single', operation['generation']) and
            (forms['target'] == route.render(profile, 'single', operation['generation'], release_root=release)
             if operation['kind'] == 'deploy' else forms['target'] == forms['old']) and
            forms['maintenance'] == maintenance_route(forms['target'], profile), 'PENPOT_INTENT_ROUTE')
    old_expected = route.render(profile, 'single', operation['old_generation'], release_root=release)
    require(parse_yaml(forms['old']) == parse_yaml(old_expected), 'PENPOT_INTENT_ROUTE')
    require(operation['snapshot'] is None or operation['snapshot'] ==
            str(Path(state_dir) / 'backups' / operation['request_id']), 'PENPOT_INTENT_SNAPSHOT')
    return forms


def prepare_transaction(req, state, state_dir, cfg, release, profile, locks, *, backup=False, _locked=False):
    """Save intent under the app lock; no routing, writer, or data mutation here."""
    import route
    require(profile['app'] == 'penpot', 'PENPOT_INTENT')
    private_directory(state_dir)
    trusted_path(Path(locks), directory=True)
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        validate_state(state, profile)
        require(state['operation'] is None, 'RECOVERY_REQUIRED')
        require(state['active'] is not None, 'NOT_ADOPTED')
        require(load(private_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
        req = parse_request(json_bytes(req), profile)
        require(req['op'] == 'deploy' and req['component'] == 'app', 'INVALID_REQUEST')
        require(Path(release) == verify_request(req, cfg, profile), 'PLATFORM_MISMATCH')
        target_entry = prepare_images(req, profile)
        stack_health(profile, state['active'])
        with lock(Path(locks) / 'traefik.lock', 60):
            dynamic = route.dynamic(profile)
            route_path, normal_old, hashes = route.preflight(dynamic, profile, release_root=release)
            require(route_path == dynamic / profile['route_name'] and
                    route.route_state(normal_old, profile) == ('single', state['generation']) and
                    route.probe(profile) == ('single', state['generation']), 'ROUTE_STATE_MISMATCH')
            require(not backup or target_entry == state['active'], 'PENPOT_BACKUP_ARGUMENT')
            generation = state['generation'] if backup else uuid.uuid4().hex
            require(backup or generation != state['generation'], 'PENPOT_INTENT_GENERATION')
            normal_target = normal_old if backup else route.render(profile, 'single', generation, release_root=release)
            forms = {'old': normal_old, 'target': normal_target,
                     'maintenance': maintenance_route(normal_target, profile)}
            require(all(type(raw) is bytes and 0 < len(raw) <= 65536 for raw in forms.values()), 'PENPOT_INTENT_ROUTE')
            base = Path(state_dir) / 'operations'
            if not base.exists():
                base.mkdir(mode=0o700)
                fsync_dir(base.parent)
            private_directory(base)
            directory = base / req['request_id']
            require(not directory.exists() and not directory.is_symlink(), 'PENPOT_INTENT_EXISTS')
            directory.mkdir(mode=0o700)
            fsync_dir(base)
            for name, filename in ROUTE_RECORDS.items():
                atomic(directory / filename, forms[name])
            operation = {
                'kind': 'backup' if backup else 'deploy', 'phase': 'prepared', 'request_id': req['request_id'], 'committed': False,
                'old': state['active'], 'target': target_entry, 'old_generation': state['generation'],
                'generation': generation, 'directory': str(directory), 'route_path': str(route_path),
                'shared_routes': hashes, 'route_hashes': {name: digest(raw) for name, raw in forms.items()},
                'snapshot': None,
            }
            candidate = parse_json(json_bytes(dict(state, operation=operation, revision=state['revision'] + 1)))
            intent_routes(candidate, state_dir, profile, release)
            route.unchanged(hashes, dynamic, profile['route_name'])
            require(route.checked_file(route_path, managed=True) == normal_old and
                    load(private_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
            require(len(json_bytes(candidate)) <= 65536, 'PENPOT_INTENT_SIZE')
            save(Path(state_dir) / 'state.json', candidate)
            state.clear()
            state.update(candidate)
        fault(profile, 'penpot_prepared')
        return state['operation']


def persist_stop_phase(state, state_dir, phase):
    require((state['operation']['phase'], phase) in {('prepared', 'maintenance'), ('maintenance', 'stopped')}, 'PENPOT_PHASE')
    require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    candidate = parse_json(json_bytes(state))
    candidate['operation']['phase'] = phase
    candidate['revision'] += 1
    require(len(json_bytes(candidate)) <= 65536, 'PENPOT_INTENT_SIZE')
    save(Path(state_dir) / 'state.json', candidate)
    state.clear()
    state.update(candidate)


def abort_maintenance(state, state_dir, profile, forms, dynamic):
    """Abort before writer stop; retain intent if the old route cannot be proved."""
    import route
    operation = state['operation']
    require(operation['phase'] == 'maintenance' and not operation['committed'], 'PENPOT_PHASE')
    route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
    target = Path(operation['route_path'])
    current = route.checked_file(target, managed=True)
    require(recorded_route(current, forms) in ('old', 'maintenance'), 'PENPOT_ROUTE_DRIFT')
    stack_health(profile, operation['old'])
    if current != forms['old']:
        route.publish(target, forms['old'], digest(current))
    try:
        route.ack(profile, ('single', operation['old_generation']), timeout=30)
        route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
        require(route.checked_file(target, managed=True) == forms['old'], 'PENPOT_ROUTE_DRIFT')
    except Failure:
        route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
        current = route.checked_file(target, managed=True)
        require(current == forms['old'], 'PENPOT_ROUTE_DRIFT')
        route.publish(target, forms['maintenance'], digest(current))
        raise
    require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    candidate = dict(state, operation=None, revision=state['revision'] + 1)
    save(Path(state_dir) / 'state.json', candidate)
    state.clear()
    state.update(candidate)


def close_and_stop(state, state_dir, cfg, release, profile, locks, *, _locked=False):
    """Prove maintenance before stopping; abort safely if acknowledgement fails."""
    import route
    private_directory(state_dir)
    trusted_path(Path(locks), directory=True)
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
        forms = intent_routes(state, state_dir, profile, release)
        operation = state['operation']
        require(not operation['committed'] and operation['phase'] in ('prepared', 'maintenance', 'stopped'), 'PENPOT_PHASE')
        with lock(Path(locks) / 'traefik.lock', 60):
            dynamic = route.dynamic(profile)
            target = Path(operation['route_path'])
            route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
            current = route.checked_file(target, managed=True)
            form = recorded_route(current, forms)
            allowed = {'old'} if operation['phase'] == 'prepared' else {'maintenance'} if operation['phase'] == 'stopped' else {'old', 'maintenance'}
            require(form in allowed, 'PENPOT_ROUTE_DRIFT')
            if operation['phase'] == 'prepared':
                persist_stop_phase(state, state_dir, 'maintenance')
                fault(profile, 'penpot_maintenance_intent')
            if form == 'old':
                route.publish(target, forms['maintenance'], digest(current))
                fault(profile, 'penpot_maintenance_published')
            try:
                if state['operation']['phase'] != 'stopped':
                    route.ack(profile, ('single', operation['generation']), timeout=30)
                public_ack(profile, maintenance=True)
            except Failure:
                if state['operation']['phase'] == 'maintenance':
                    abort_maintenance(state, state_dir, profile, forms, dynamic)
                raise
            route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
            require(route.checked_file(target, managed=True) == forms['maintenance'], 'PENPOT_ROUTE_DRIFT')
            if state['operation']['phase'] == 'maintenance':
                persist_stop_phase(state, state_dir, 'stopped')
                fault(profile, 'penpot_stopped_intent')
        stop_applications(release, profile, cfg, state['operation']['old'])
        fault(profile, 'penpot_stopped')
        return state['operation']


def persist_operation(state, state_dir, profile, release, phase, **updates):
    require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    candidate = parse_json(json_bytes(state))
    operation = candidate['operation']
    operation.pop('recovery_from', None)
    operation.pop('error_code', None)
    operation['phase'] = phase
    operation.update(updates)
    if operation['committed']:
        candidate.update(active=operation['target'], previous=operation['old'], generation=operation['generation'])
    candidate['revision'] += 1
    intent_routes(candidate, state_dir, profile, release)
    require(len(json_bytes(candidate)) <= 65536, 'PENPOT_INTENT_SIZE')
    save(Path(state_dir) / 'state.json', candidate)
    state.clear()
    state.update(candidate)


def finish_operation(state, state_dir):
    require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    candidate = dict(state, operation=None, revision=state['revision'] + 1)
    save(Path(state_dir) / 'state.json', candidate)
    state.clear()
    state.update(candidate)


def transaction_route(state, state_dir, profile, release, locks, desired=None, allowed=None):
    import route
    require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
    forms = intent_routes(state, state_dir, profile, release)
    operation = state['operation']
    with lock(Path(locks) / 'traefik.lock', 60):
        dynamic = route.dynamic(profile)
        route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
        path = Path(operation['route_path'])
        current = route.checked_file(path, managed=True)
        name = recorded_route(current, forms)
        require(allowed is None or name in allowed, 'PENPOT_ROUTE_DRIFT')
        if desired is not None and current != forms[desired]:
            route.publish(path, forms[desired], digest(current))
        route.unchanged(operation['shared_routes'], dynamic, profile['route_name'])
    return forms


def transaction_writers(profile, operation):
    values = writers_owned(profile)
    for role, value in zip(PENPOT_ROLES, values):
        require(value.get('Config', {}).get('Image') in {
            operation['old']['images'][role], operation['target']['images'][role],
        }, 'PENPOT_FOREIGN_WRITER')


def operation_snapshot(state, profile, forms):
    operation = state['operation']
    require(operation['snapshot'] is not None, 'PENPOT_BACKUP_INCOMPLETE')
    metadata = verify_snapshot(Path(operation['snapshot']), profile['registration'])
    old = operation['old']
    require(metadata['images'] == old['images'] and metadata['sourceSha'] == old['source_sha'] and
            metadata['platformRef'] == old['platform_ref'] and metadata['sha256']['app.yml'] == old['manifest_sha256'] and
            metadata['sha256']['route.yml'] == digest(forms['old']), 'PENPOT_RESTORE_IDENTITY')
    return metadata


def recovery_required(state, state_dir, profile, release, error):
    operation = state['operation']
    phase = operation.get('recovery_from', operation['phase'])
    code = error.code if isinstance(error, Failure) else 'PENPOT_RECOVERY_FAILED'
    persist_operation(state, state_dir, profile, release, 'recovery_required', recovery_from=phase, error_code=code)


def _recover_pre_boundary(state, state_dir, cfg, release, profile, locks):
    import route
    operation = state['operation']
    require(not operation['committed'], 'PENPOT_COMMITTED')
    phase = operation.get('recovery_from', operation['phase'])
    require(phase in {'prepared', 'maintenance', 'stopped', 'backed_up', 'applying', 'checking', 'restoring', 'resuming'}, 'PENPOT_PHASE')
    forms = transaction_route(state, state_dir, profile, release, locks, 'maintenance', {'old', 'maintenance'})
    public_ack(profile, maintenance=True)
    transaction_writers(profile, operation)
    application_command(release, profile, cfg, operation['old'], 'stop')
    writers_stopped(profile)
    if operation['kind'] == 'deploy' and phase in {'applying', 'checking', 'restoring'}:
        persist_operation(state, state_dir, profile, release, 'restoring')
        operation = state['operation']
        operation_snapshot(state, profile, forms)
        fault(profile, 'penpot_restoring')
        restore_data(profile, cfg, Path(operation['snapshot']), operation['old'])
        fault(profile, 'penpot_restored')
    start_applications(release, profile, cfg, state['operation']['old'])
    # A crash after reopening old must never replay the restore over new writes.
    persist_operation(state, state_dir, profile, release, 'resuming')
    operation = state['operation']
    transaction_route(state, state_dir, profile, release, locks, 'old', {'maintenance'})
    fault(profile, 'penpot_old_exposed')
    try:
        route.ack(profile, ('single', operation['old_generation']), timeout=30)
        public_ack(profile, operation['old_generation'])
        transaction_route(state, state_dir, profile, release, locks, allowed={'old'})
    except (Failure, OSError, subprocess.TimeoutExpired):
        transaction_route(state, state_dir, profile, release, locks, 'maintenance', {'old', 'maintenance'})
        raise
    finish_operation(state, state_dir)


def recover_pre_boundary(state, state_dir, cfg, release, profile, locks, *, _locked=False):
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        intent_routes(state, state_dir, profile, release)
        require(not state['operation']['committed'], 'PENPOT_COMMITTED')
        try:
            _recover_pre_boundary(state, state_dir, cfg, release, profile, locks)
        except (Failure, OSError, subprocess.TimeoutExpired) as error:
            recovery_required(state, state_dir, profile, release, error)
            raise


def apply_candidate(state, state_dir, cfg, release, profile, locks, *, _locked=False):
    import route
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        operation = state['operation']
        require(operation['kind'] == 'deploy' and not operation['committed'] and operation['phase'] == 'stopped', 'PENPOT_PHASE')
        forms = transaction_route(state, state_dir, profile, release, locks, allowed={'maintenance'})
        public_ack(profile, maintenance=True)
        try:
            writers_stopped(profile, operation['old']['images'])
            directory = Path(state_dir) / 'backups' / operation['request_id']
            persist_operation(state, state_dir, profile, release, 'stopped', snapshot=str(directory))
            snapshot(profile, cfg, state_dir, operation['request_id'], operation['old'], forms['old'])
            operation_snapshot(state, profile, forms)
            persist_operation(state, state_dir, profile, release, 'backed_up')
            fault(profile, 'penpot_backed_up')
            transaction_route(state, state_dir, profile, release, locks, allowed={'maintenance'})
            persist_operation(state, state_dir, profile, release, 'applying')
            fault(profile, 'penpot_applying')
            start_applications(release, profile, cfg, state['operation']['target'])
            fault(profile, 'penpot_applied')
            persist_operation(state, state_dir, profile, release, 'checking')
            route.ack(profile, ('single', state['operation']['generation']), timeout=30)
            public_ack(profile, maintenance=True)
            transaction_route(state, state_dir, profile, release, locks, allowed={'maintenance'})
        except (Failure, OSError, subprocess.TimeoutExpired):
            try:
                _recover_pre_boundary(state, state_dir, cfg, release, profile, locks)
            except (Failure, OSError, subprocess.TimeoutExpired) as recovery_error:
                recovery_required(state, state_dir, profile, release, recovery_error)
                raise
            raise


def expose_candidate(state, state_dir, cfg, release, profile, locks, *, _locked=False):
    import route
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        intent_routes(state, state_dir, profile, release)
        operation = state['operation']
        require(operation['kind'] == 'deploy' and (operation['phase'] == 'checking' or operation['committed'] and
                operation['phase'] in {'exposing', 'complete', 'recovery_required'}), 'PENPOT_PHASE')
        try:
            transaction_route(state, state_dir, profile, release, locks,
                              allowed={'maintenance', 'target'} if operation['committed'] else {'maintenance'})
            if operation['committed']:
                transaction_route(state, state_dir, profile, release, locks, 'maintenance', {'maintenance', 'target'})
                public_ack(profile, maintenance=True)
                transaction_writers(profile, operation)
                start_applications(release, profile, cfg, operation['target'])
            stack_health(profile, operation['target'])
            route.ack(profile, ('single', operation['generation']), timeout=30)
            if not operation['committed']:
                # From this durable boundary onward, no pre-update dump can be restored.
                persist_operation(state, state_dir, profile, release, 'exposing', committed=True)
                fault(profile, 'penpot_exposing')
            elif operation['phase'] == 'recovery_required':
                persist_operation(state, state_dir, profile, release, 'exposing')
            transaction_route(state, state_dir, profile, release, locks, 'target', {'maintenance', 'target'})
            fault(profile, 'penpot_exposed')
            route.ack(profile, ('single', state['operation']['generation']), timeout=30)
            public_ack(profile, state['operation']['generation'])
            transaction_route(state, state_dir, profile, release, locks, allowed={'target'})
            persist_operation(state, state_dir, profile, release, 'complete')
            fault(profile, 'penpot_complete')
            finish_operation(state, state_dir)
        except (Failure, OSError, subprocess.TimeoutExpired) as error:
            try:
                transaction_route(state, state_dir, profile, release, locks, 'maintenance', {'maintenance', 'target'})
            finally:
                recovery_required(state, state_dir, profile, release, error)
            raise


def reconcile_transaction(state, state_dir, cfg, release, profile, locks, *, _locked=False):
    validate_state(state, profile)
    if state['operation'] is None:
        with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
            require(parse_json(bounded_file(Path(state_dir) / 'state.json')) == state, 'PENPOT_STATE_DRIFT')
            matching(state, profile)
            public_ack(profile, state['generation'])
        return
    intent_routes(state, state_dir, profile, release)
    if state['operation']['committed']:
        expose_candidate(state, state_dir, cfg, release, profile, locks, _locked=_locked)
    else:
        recover_pre_boundary(state, state_dir, cfg, release, profile, locks, _locked=_locked)


def transaction(req, state, state_dir, cfg, release, profile, locks, *, _locked=False):
    """Hold one app lock across the entire release, including recovery."""
    with nullcontext() if _locked else lock(Path(locks) / 'penpot@operation.lock'):
        prepare_transaction(req, state, state_dir, cfg, release, profile, locks, _locked=True)
        try:
            close_and_stop(state, state_dir, cfg, release, profile, locks, _locked=True)
            apply_candidate(state, state_dir, cfg, release, profile, locks, _locked=True)
            expose_candidate(state, state_dir, cfg, release, profile, locks, _locked=True)
        except (Failure, OSError, subprocess.TimeoutExpired):
            operation = state['operation']
            if operation is not None and not operation['committed'] and operation['phase'] != 'recovery_required':
                recover_pre_boundary(state, state_dir, cfg, release, profile, locks, _locked=True)
            raise
        prune_snapshots(state_dir, state, profile)


def backup(req, state, state_dir, cfg, release, profile, locks):
    """Root operator entry point; not available to the app SSH request protocol."""
    with lock(Path(locks) / 'penpot@operation.lock'):
        prepare_transaction(req, state, state_dir, cfg, release, profile, locks, backup=True, _locked=True)
        try:
            close_and_stop(state, state_dir, cfg, release, profile, locks, _locked=True)
            operation = state['operation']
            forms = transaction_route(state, state_dir, profile, release, locks, allowed={'maintenance'})
            path = Path(state_dir) / 'backups' / operation['request_id']
            persist_operation(state, state_dir, profile, release, 'stopped', snapshot=str(path))
            snapshot(profile, cfg, state_dir, operation['request_id'], operation['old'], forms['old'])
            operation_snapshot(state, profile, forms)
            persist_operation(state, state_dir, profile, release, 'backed_up')
            fault(profile, 'penpot_backed_up')
            _recover_pre_boundary(state, state_dir, cfg, release, profile, locks)
        except (Failure, OSError, subprocess.TimeoutExpired):
            if state['operation'] is not None:
                try:
                    _recover_pre_boundary(state, state_dir, cfg, release, profile, locks)
                except (Failure, OSError, subprocess.TimeoutExpired) as recovery_error:
                    recovery_required(state, state_dir, profile, release, recovery_error)
                    raise
            raise
        prune_snapshots(state_dir, state, profile)
        return path


def operator_backup(profile, cfg, state_dir, locks):
    require(os.geteuid() == 0 and profile['app'] == 'penpot', 'ROOT_REQUIRED')
    state = parse_json(bounded_file(Path(state_dir) / 'state.json'))
    validate_state(state, profile)
    require(state['active'] is not None, 'NOT_ADOPTED')
    require(state['operation'] is None, 'RECOVERY_REQUIRED')
    entry = state['active']
    require(entry['platform_ref'] == profile['platform_ref'], 'PLATFORM_MISMATCH')
    request_id = 'backup-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex
    req = {'version': 1, 'op': 'deploy', 'component': 'app', 'app': 'penpot', 'request_id': request_id,
           'source_sha': entry['source_sha'], 'platform_ref': entry['platform_ref'],
           'manifest_sha256': entry['manifest_sha256'], 'images': entry['images']}
    release = verify_request(req, cfg, profile)
    directory = backup(req, state, state_dir, cfg, release, profile, locks)
    return {'status': 'complete', 'request_id': request_id, 'backup': str(directory),
            'source_sha': entry['source_sha'], 'generation': state['generation']}


def application_command(release, profile, cfg, entry, action):
    require(profile['app'] == 'penpot' and profile['compose_project'] == 'penpot' and
            action in ('start', 'stop'), 'PENPOT_COMPOSE_ARGUMENT')
    validate_entry(entry, profile)
    release = trusted_path(Path(release), directory=True)
    cfg = trusted_path(Path(cfg), directory=True)
    runtime = cfg / 'runtime.env'
    values = runtime_values(bounded_file(runtime), profile['registration'])
    values.update({'PENPOT_' + role.upper() + '_IMAGE': ref for role, ref in entry['images'].items()})
    environment = dict(PATH='/usr/bin:/bin', HOME='/root', LANG='C', **values)
    compose_file = trusted_path(release / 'apps/penpot/docker-compose.prod.yml')
    arguments = ('up', '-d', '--no-deps', '--pull', 'never', '--wait', '--wait-timeout', '180') if action == 'start' else ('stop', '--timeout', '60')
    return command('/usr/bin/docker', 'compose', '--env-file', str(runtime), '-p', 'penpot',
                   '-f', str(compose_file), '--ansi=never', '--progress=plain',
                   *arguments, *APP_SERVICES, env=environment, timeout=210 if action == 'start' else 90)


def start_applications(release, profile, cfg, entry):
    application_command(release, profile, cfg, entry, 'start')
    stack_health(profile, entry)


def stop_applications(release, profile, cfg, entry):
    validate_entry(entry, profile)
    writers_owned(profile, entry['images'])
    application_command(release, profile, cfg, entry, 'stop')
    writers_stopped(profile, entry['images'])


def prepare_images(request, profile):
    entry = release_entry(request, profile)
    for ref in entry['images'].values():
        try:
            identity = image_id(ref)
        except Failure as error:
            if error.code != 'COMMAND_FAILED':
                raise
            anonymous_image(ref)
            docker('pull', ref, timeout=650)
            identity = image_id(ref)
        value = inspect('image', ref)
        labels = value.get('Config', {}).get('Labels') or {}
        require(value.get('Id') == identity and
                labels.get('org.opencontainers.image.source') == 'https://github.com/TheDemonTuan/penpot' and
                labels.get('org.opencontainers.image.revision') == entry['source_sha'], 'PENPOT_IMAGE_REVISION')
    return entry


def maintenance_route(normal, profile):
    import route
    route.route_state(normal, profile)
    document = parse_yaml(normal)
    routers = document['http'].get('routers', {})
    require(set(routers) == {'penpot-public-router', 'penpot-internal-health'}, 'PENPOT_ROUTE_SHAPE')
    require(routers['penpot-public-router'].get('service') == 'penpot-service' and
            routers['penpot-public-router'].get('rule') == 'Host(`' + profile['api_host'] + '`)' and
            routers['penpot-public-router'].get('entryPoints') == ['web'], 'PENPOT_ROUTE_SHAPE')
    del routers['penpot-public-router']
    return yaml.safe_dump(document, sort_keys=False).encode('utf-8')


def recorded_route(raw, forms):
    require(type(forms) is dict and set(forms) == {'old', 'maintenance', 'target'} and
            all(type(value) is bytes and value for value in forms.values()), 'PENPOT_ROUTE_DRIFT')
    matches = [name for name, value in forms.items() if value == raw]
    require(forms['maintenance'] not in (forms['old'], forms['target']) and matches, 'PENPOT_ROUTE_DRIFT')
    return 'old' if 'old' in matches else matches[0]


def health_response(profile, status, headers, body, generation=None, maintenance=False):
    """Validate readiness bytes independently of the public or origin transport."""
    require(maintenance or type(generation) is str and re.fullmatch('[0-9a-f]{32}', generation), 'PENPOT_PUBLIC_HEALTH')
    expected = b'404' if maintenance else b'200'
    require(status == expected and len(headers) <= 65536 and len(body) <= (65536 if maintenance else 64), 'PENPOT_PUBLIC_HEALTH')
    lines = headers.decode('latin-1').splitlines()
    statuses = [line for line in lines if line.startswith('HTTP/')]
    require(len(statuses) == 1 and re.fullmatch(r'HTTP/(?:1\.[01]|2(?:\.0)?|3) ' + expected.decode() + r'(?: .*)?', statuses[0]), 'PENPOT_PUBLIC_HEALTH')
    generations, ages = [], []
    header = profile['registration']['route']['generation_header'].lower()
    for line in lines:
        key, separator, value = line.partition(':')
        if separator and key.strip().lower() == header:
            generations.append(value.strip())
        elif separator and key.strip().lower() == 'age':
            ages.append(value.strip())
        elif separator and key.strip().lower() == 'location':
            raise Failure('PENPOT_PUBLIC_HEALTH')
    require(len(ages) <= 1 and all(value == '0' for value in ages), 'PENPOT_PUBLIC_HEALTH')
    if maintenance:
        require(not generations, 'PENPOT_PUBLIC_HEALTH')
    else:
        require(generations == [generation] and body.strip() == b'OK', 'PENPOT_PUBLIC_HEALTH')


def public_health(profile, generation=None, maintenance=False):
    require(maintenance or type(generation) is str and re.fullmatch('[0-9a-f]{32}', generation), 'PENPOT_PUBLIC_HEALTH')
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
    if profile.get('fixture_ci'):
        environment['CURL_CA_BUNDLE'] = profile['ca_bundle']
    url = 'https://' + profile['api_host'] + '/readyz?deploy_probe=' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='penpot-probe-') as temporary:
        headers, body = Path(temporary) / 'headers', Path(temporary) / 'body'
        process = subprocess.run(['/usr/bin/curl', '--silent', '--show-error', '--proto', '=https',
                                  '--max-time', '8', '--max-redirs', '0', '--dump-header', str(headers),
                                  '--output', str(body), '--write-out', '%{http_code}', url],
                                 env=environment, capture_output=True, timeout=10)
        require(process.returncode == 0, 'PENPOT_PUBLIC_HEALTH')
        require(headers.is_file() and body.is_file() and headers.stat().st_size <= 65536 and
                body.stat().st_size <= (65536 if maintenance else 64), 'PENPOT_PUBLIC_HEALTH')
        health_response(profile, process.stdout, headers.read_bytes(), body.read_bytes(), generation, maintenance)


def public_ack(profile, generation=None, maintenance=False, timeout=30):
    deadline, consecutive = time.monotonic() + timeout, 0
    while time.monotonic() < deadline:
        try:
            public_health(profile, generation, maintenance)
            consecutive += 1
            if consecutive == 2:
                return
        except Failure:
            consecutive = 0
        time.sleep(1)
    raise Failure('PENPOT_PUBLIC_ROUTE_ACK')


def runtime_values(raw, registration):
    require(len(raw) <= 65536, 'INVALID_RUNTIME_ENV')
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        raise Failure('INVALID_RUNTIME_ENV') from None
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and key not in values and key in registration['runtime']['allowed_env'], 'INVALID_RUNTIME_ENV')
        values[key] = value
    require(set(values) == set(registration['runtime']['required_env']), 'INVALID_RUNTIME_ENV')
    require(re.fullmatch(r'[A-Za-z0-9_-]{32,256}', values['PENPOT_SECRET_KEY']) and
            re.fullmatch(r'[0-9a-f]{64}', values['PENPOT_DB_PASSWORD']), 'INVALID_RUNTIME_ENV')
    return values


def file_hash(path):
    result = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def private_file(path):
    path = trusted_path(Path(path))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, 'PENPOT_BACKUP_PERMISSIONS')
    return path


def safe_assets(path):
    """Reject links and special files, including links that need chain resolution."""
    names, regular_files, directories = set(), set(), set()
    try:
        with tarfile.open(path, mode='r|') as archive:
            for member in archive:
                parts = PurePosixPath(member.name)
                require(member.name and '\x00' not in member.name and not parts.is_absolute() and
                        '..' not in parts.parts and (member.isdir() or member.isreg()), 'PENPOT_UNSAFE_ASSETS')
                name = parts.as_posix()
                require(name not in names and (name != '.' or member.isdir()), 'PENPOT_UNSAFE_ASSETS')
                names.add(name)
                require(len(names) <= 1000000, 'PENPOT_UNSAFE_ASSETS')
                parent = parts.parent
                while parent.as_posix() != '.':
                    require(parent.as_posix() not in regular_files, 'PENPOT_UNSAFE_ASSETS')
                    directories.add(parent.as_posix())
                    parent = parent.parent
                if member.isreg():
                    require(name not in directories, 'PENPOT_UNSAFE_ASSETS')
                    regular_files.add(name)
                else:
                    directories.add(name)
    except (tarfile.TarError, OSError, ValueError):
        raise Failure('PENPOT_UNSAFE_ASSETS') from None


def check_dump(path):
    with open(path, 'rb') as source:
        require(source.read(5) == b'PGDMP', 'PENPOT_INVALID_DUMP')
        source.seek(0)
        process = subprocess.run(['/usr/bin/docker', 'exec', '-i', 'penpot-postgres',
                                  'pg_restore', '--list'], stdin=source,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    require(process.returncode == 0, 'PENPOT_INVALID_DUMP')


def bounded_file(path):
    path = private_file(path)
    require(path.stat().st_size <= 65536, 'PENPOT_BACKUP_MANIFEST')
    return path.read_bytes()


def owned_volumes(profile):
    require(profile['app'] == 'penpot', 'PENPOT_BACKUP_ARGUMENT')
    for name in VOLUMES.values():
        value = inspect('volume', name)
        require(value.get('Name') == name and value.get('Driver') == 'local' and
                not value.get('Options') and (value.get('Labels') or {}).get('vps-deploy.app') == 'penpot', 'PENPOT_VOLUME_OWNERSHIP')


def verify_snapshot(directory, registration):
    directory = trusted_path(Path(directory), directory=True)
    require(stat.S_IMODE(directory.lstat().st_mode) == 0o700, 'PENPOT_BACKUP_PERMISSIONS')
    require({entry.name for entry in directory.iterdir()} == set(SNAPSHOT_FILES) | {'manifest.json'}, 'PENPOT_BACKUP_INCOMPLETE')
    metadata = parse_json(bounded_file(directory / 'manifest.json'))
    require(set(metadata) == {'schemaVersion', 'app', 'createdAt', 'sourceSha', 'platformRef', 'images', 'volumes', 'sha256'} and
            type(metadata['schemaVersion']) is int and metadata['schemaVersion'] == 1 and
            metadata['app'] == 'penpot' and metadata['volumes'] == VOLUMES, 'PENPOT_BACKUP_MANIFEST')
    require(type(metadata['sourceSha']) is str and SHA.fullmatch(metadata['sourceSha']) and
            type(metadata['platformRef']) is str and SHA.fullmatch(metadata['platformRef']), 'PENPOT_BACKUP_MANIFEST')
    require(type(metadata['createdAt']) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', metadata['createdAt']), 'PENPOT_BACKUP_MANIFEST')
    try:
        datetime.datetime.strptime(metadata['createdAt'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise Failure('PENPOT_BACKUP_MANIFEST') from None
    image_map(metadata['images'], registration['manifest']['images'])
    checksums = metadata['sha256']
    require(type(checksums) is dict and set(checksums) == set(SNAPSHOT_FILES), 'PENPOT_BACKUP_MANIFEST')
    for name in SNAPSHOT_FILES:
        path = private_file(directory / name)
        require(type(checksums[name]) is str and HASH.fullmatch(checksums[name]) and
                path.stat().st_size > 0 and file_hash(path) == checksums[name], 'PENPOT_BACKUP_CHECKSUM')
    try:
        manifest(bounded_file(directory / 'app.yml'), registration)
    except Failure:
        raise Failure('PENPOT_RESTORE_MANIFEST_MISMATCH') from None
    runtime_values(bounded_file(directory / 'runtime.env'), registration)
    safe_assets(directory / 'assets.tar')
    check_dump(directory / 'database.dump')
    return metadata


def prune_snapshots(state_dir, state, profile):
    """Called under the operation lock; keep incomplete and recovery-referenced data."""
    base = private_directory(Path(state_dir) / 'backups')
    referenced = (state.get('operation') or {}).get('snapshot')
    previous_source = (state.get('previous') or {}).get('source_sha')
    complete = []
    # Validate the entire set before any deletion. A bad complete backup is evidence,
    # not permission to discard it or another backup.
    for directory in sorted(base.iterdir()):
        require(REQUEST_ID.fullmatch(directory.name), 'PENPOT_BACKUP_ARGUMENT')
        private_directory(directory)
        marker = directory / 'manifest.json'
        if not marker.exists() and not marker.is_symlink():
            continue
        metadata = verify_snapshot(directory, profile['registration'])
        complete.append((metadata['createdAt'], directory, metadata))
    complete.sort(key=lambda value: (value[0], value[1].name), reverse=True)
    retained = {directory for _, directory, _ in complete[:7]}
    retained.update(directory for _, directory, metadata in complete
                    if str(directory) == referenced or metadata['sourceSha'] == previous_source)
    removed = []
    for _, directory, metadata in reversed(complete):
        if directory in retained:
            continue
        private_directory(directory)
        require(verify_snapshot(directory, profile['registration']) == metadata, 'PENPOT_BACKUP_CHANGED')
        # Removing the complete marker first makes an interrupted prune incomplete.
        (directory / 'manifest.json').unlink()
        fsync_dir(directory)
        for filename in SNAPSHOT_FILES:
            private_file(directory / filename).unlink()
        directory.rmdir()
        fsync_dir(base)
        removed.append(directory.name)
    return removed


def postgres_owned(profile):
    require(profile['app'] == 'penpot' and profile['compose_project'] == 'penpot', 'PENPOT_RESTORE_ARGUMENT')
    postgres = container('penpot-postgres', DATASTORE_IMAGES['penpot-postgres'], running=True)
    labels = (postgres.get('Config') or {}).get('Labels') or {}
    mounts = postgres.get('Mounts') or []
    require(labels.get('vps-deploy.app') == 'penpot' and
            labels.get('com.docker.compose.project') == 'penpot' and
            labels.get('com.docker.compose.service') == 'penpot-postgres' and len(mounts) == 1 and
            mounts[0].get('Type') == 'volume' and mounts[0].get('Name') == VOLUMES['database'] and
            mounts[0].get('Destination') == '/var/lib/postgresql/data' and mounts[0].get('RW') is True,
            'PENPOT_CONTAINER_OWNERSHIP')
    return postgres


def restore_data(profile, cfg, directory, entry):
    """Restore pre-boundary data only; caller must hold the app lock and keep maintenance."""
    require(profile['app'] == 'penpot' and profile['compose_project'] == 'penpot', 'PENPOT_RESTORE_ARGUMENT')
    validate_entry(entry, profile)
    metadata = verify_snapshot(directory, profile['registration'])
    require(metadata['images'] == entry['images'] and metadata['sourceSha'] == entry['source_sha'] and
            metadata['platformRef'] == entry['platform_ref'] and
            metadata['sha256']['app.yml'] == entry['manifest_sha256'], 'PENPOT_RESTORE_IDENTITY')
    require(bounded_file(Path(cfg) / 'runtime.env') == bounded_file(Path(directory) / 'runtime.env') and
            bounded_file(Path(cfg) / 'app.yml') == bounded_file(Path(directory) / 'app.yml'), 'PENPOT_RESTORE_CONFIG_CHANGED')
    writers_stopped(profile)
    owned_volumes(profile)
    postgres_owned(profile)
    for ref in entry['images'].values():
        image_id(ref)
    # Recreate this database, not the PostgreSQL container or its volume.
    sql = (b"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='penpot' AND pid <> pg_backend_pid();\n"
           b'DROP DATABASE IF EXISTS penpot;\nCREATE DATABASE penpot OWNER penpot TEMPLATE template0;\n')
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}
    process = subprocess.run(['/usr/bin/docker', 'exec', '-i', 'penpot-postgres', 'psql', '-X',
                              '-U', 'penpot', '-d', 'postgres', '--set=ON_ERROR_STOP=1'], input=sql,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment, timeout=60)
    require(process.returncode == 0, 'PENPOT_RESTORE_DATABASE_RESET')
    stream_input(Path(directory) / 'database.dump', ['/usr/bin/docker', 'exec', '-i', 'penpot-postgres',
                 'pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '-U', 'penpot', '-d', 'penpot'])
    writers_stopped(profile)
    owned_volumes(profile)
    stream_input(Path(directory) / 'assets.tar', ['/usr/bin/docker', 'run', '--rm', '-i', '--pull=never',
                 '--network', 'none', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
                 '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER', '--security-opt', 'no-new-privileges:true',
                 '--mount', 'type=volume,src=penpot_assets,dst=/opt/data/assets', '--entrypoint', '/bin/sh',
                 entry['images']['backend'], '-eu', '-c',
                 'find /opt/data/assets -mindepth 1 -delete; exec /bin/tar --numeric-owner --same-owner --same-permissions -xf - -C /opt/data/assets'])
    return metadata


def stream_input(path, argv, timeout=600):
    with private_file(path).open('rb') as source:
        process = subprocess.run(argv, stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C'}, timeout=timeout)
    require(process.returncode == 0, 'PENPOT_RESTORE_COMMAND_FAILED')


def stream_file(target, argv, timeout=600):
    """Stream stdout to a private file, and publish it only on successful exit."""
    target = Path(target)
    require(not target.exists() and not target.is_symlink(), 'PENPOT_BACKUP_EXISTS')
    fd, temporary = tempfile.mkstemp(prefix='.stream-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            process = subprocess.run(argv, stdout=output, stderr=subprocess.DEVNULL, timeout=timeout)
            require(process.returncode == 0, 'PENPOT_BACKUP_COMMAND_FAILED')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        fsync_dir(target.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def writers_owned(profile, images=None):
    values = []
    for role, name in zip(PENPOT_ROLES, APP_SERVICES):
        value = container(name, (images or {}).get(role))
        labels = (value.get('Config') or {}).get('Labels') or {}
        require(type(value.get('State', {}).get('Running')) is bool and
                labels.get('com.docker.compose.project') == profile['compose_project'] and
                labels.get('com.docker.compose.service') == name and labels.get('vps-deploy.app') == 'penpot', 'PENPOT_CONTAINER_OWNERSHIP')
        values.append(value)
    return values


def writers_stopped(profile, images=None):
    require(all(not value['State']['Running'] for value in writers_owned(profile, images)), 'PENPOT_WRITER_RUNNING')


def snapshot(profile, cfg, state_dir, request_id, entry, normal_old):
    require(profile['app'] == 'penpot' and type(request_id) is str and REQUEST_ID.fullmatch(request_id), 'PENPOT_BACKUP_ARGUMENT')
    image_map(entry['images'], profile['image_repositories'])
    require(entry['slot'] == 'single' and type(entry['source_sha']) is str and SHA.fullmatch(entry['source_sha']) and
            type(entry['platform_ref']) is str and SHA.fullmatch(entry['platform_ref']), 'PENPOT_BACKUP_ARGUMENT')
    require(type(normal_old) is bytes and 0 < len(normal_old) <= 65536, 'PENPOT_BACKUP_ARGUMENT')
    writers_stopped(profile, entry['images'])
    owned_volumes(profile)
    postgres = container('penpot-postgres', running=True)
    labels = postgres['Config'].get('Labels') or {}
    require(labels.get('com.docker.compose.project') == profile['compose_project'] and
            labels.get('com.docker.compose.service') == 'penpot-postgres' and labels.get('vps-deploy.app') == 'penpot', 'PENPOT_CONTAINER_OWNERSHIP')
    require(any(mount.get('Type') == 'volume' and mount.get('Name') == VOLUMES['database'] and
                mount.get('Destination') == '/var/lib/postgresql/data' and mount.get('RW') is True
                for mount in postgres.get('Mounts', [])), 'PENPOT_VOLUME_OWNERSHIP')
    backups = Path(state_dir) / 'backups'
    if not backups.exists():
        backups.mkdir(mode=0o700)
        fsync_dir(backups.parent)
    trusted_path(backups, directory=True)
    require(stat.S_IMODE(backups.lstat().st_mode) == 0o700, 'PENPOT_BACKUP_PERMISSIONS')
    directory = backups / request_id
    require(not directory.exists() and not directory.is_symlink(), 'PENPOT_BACKUP_EXISTS')
    directory.mkdir(mode=0o700)
    fsync_dir(backups)
    stream_file(directory / 'database.dump', ['/usr/bin/docker', 'exec', 'penpot-postgres',
                                              'pg_dump', '-U', 'penpot', '-d', 'penpot', '-Fc'])
    stream_file(directory / 'assets.tar', ['/usr/bin/docker', 'run', '--rm', '--network', 'none',
                                           '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                                           '--mount', 'type=volume,src=penpot_assets,dst=/opt/data/assets,readonly',
                                           '--entrypoint', '/bin/tar', entry['images']['backend'],
                                           '--numeric-owner', '-cf', '-', '-C', '/opt/data/assets', '.'])
    atomic(directory / 'runtime.env', bounded_file(Path(cfg) / 'runtime.env'))
    atomic(directory / 'app.yml', bounded_file(Path(cfg) / 'app.yml'))
    atomic(directory / 'route.yml', normal_old)
    metadata = {
        'schemaVersion': 1, 'app': 'penpot',
        'createdAt': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'sourceSha': entry['source_sha'], 'platformRef': entry['platform_ref'], 'images': entry['images'],
        'volumes': dict(VOLUMES), 'sha256': {name: file_hash(directory / name) for name in SNAPSHOT_FILES},
    }
    # Validate all contents before publishing the complete marker.
    safe_assets(directory / 'assets.tar')
    check_dump(directory / 'database.dump')
    manifest(bounded_file(directory / 'app.yml'), profile['registration'])
    runtime_values(bounded_file(directory / 'runtime.env'), profile['registration'])
    writers_stopped(profile, entry['images'])
    save(directory / 'manifest.json', metadata)
    verify_snapshot(directory, profile['registration'])
    return directory
