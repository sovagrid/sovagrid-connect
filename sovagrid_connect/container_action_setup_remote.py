# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded root SSH helper for an exact, default-off Docker action allowlist.

This source is sent as an argument to isolated Python. It imports the broker
only after comparing every imported Agent module with the approved bundle.
Raw Docker inspect data never crosses the SSH connection.
"""

SCRIPT = r'''
import base64, fcntl, grp, hashlib, http.client, json, os, pathlib, re, stat, subprocess, sys, tempfile, time

OPT = pathlib.Path('/opt')
ROOT = OPT / 'sovagrid-src'
CONFIGS = {'default': pathlib.Path('/etc/sovagrid-container-actions'),
           'local': pathlib.Path('/etc/sovagrid-container-actions-local')}
INSTALLS = {'default': OPT / 'sovagrid-agent',
            'local': OPT / 'sovagrid-agent-local'}
INVENTORIES = {
    'default': ('sovagrid-container-inventory.timer',
                pathlib.Path('/var/lib/sovagrid-containers/snapshot.json'), 'sovagrid'),
    'local': ('sovagrid-container-inventory-local.timer',
              pathlib.Path('/var/lib/sovagrid-containers-local/snapshot.json'), 'sovagrid-local'),
}
FILES = ('__init__.py', 'agent.py', 'service_broker.py',
         'container_action_broker.py', 'container_actions.py',
         'container_collector.py', 'containers.py', 'service_control.py')
SHA = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9a-f]{32}\Z')
LOCK = pathlib.Path('/run/sovagrid-container-action-setup.lock')

def need(value, reason='INVALID_STATE'):
    if not value:
        raise Refusal(reason)

class Refusal(Exception):
    pass

def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'INVALID_INPUT')
        value[key] = item
    return value

def directory(path, exact=False):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
         (stat.S_IMODE(info.st_mode) == 0o700 if exact else not info.st_mode & 0o022),
         'UNSAFE_PATH')

def regular(path, modes, maximum):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes and
         0 < info.st_size <= maximum, 'UNSAFE_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        need((current.st_dev, current.st_ino, current.st_size) ==
             (info.st_dev, info.st_ino, info.st_size), 'STATE_CHANGED')
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size, 'STATE_CHANGED')
        return raw
    finally:
        os.close(fd)

def check_root():
    return os.geteuid() == 0

def source(expected, profile):
    need(check_root() and SHA.fullmatch(expected) is not None and
         profile in CONFIGS, 'SOURCE_UNVERIFIED')
    for parent in (OPT, ROOT, ROOT / 'sovagrid-agent',
                   ROOT / 'sovagrid-agent/sovagrid_agent'):
        directory(parent)
    raw = regular(ROOT / 'sovagrid-bundle.json', {0o644}, 524288)
    need(hashlib.sha256(raw).hexdigest() == expected, 'SOURCE_UNVERIFIED')
    manifest = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'} and
         type(manifest['format']) is int and manifest['format'] == 1 and
         isinstance(manifest['sha256'], dict), 'SOURCE_UNVERIFIED')
    target = INSTALLS[profile]
    directory(target)
    directory(target / 'sovagrid_agent')
    verified = {}
    for name in FILES:
        relative = 'sovagrid-agent/sovagrid_agent/' + name
        digest = manifest['sha256'].get(relative)
        need(isinstance(digest, str) and SHA.fullmatch(digest) is not None,
             'SOURCE_UNVERIFIED')
        src = regular(ROOT / relative, {0o644}, 1048576)
        need(hashlib.sha256(src).hexdigest() == digest and
             regular(target / 'sovagrid_agent' / name, {0o644}, 1048576) == src,
             'SOURCE_UNVERIFIED')
        verified[name] = src
    # Never import bytecode from an unverified __pycache__.
    sys.path.insert(0, str(target))
    import types
    package = types.ModuleType('sovagrid_agent')
    package.__path__ = [str(target / 'sovagrid_agent')]
    sys.modules['sovagrid_agent'] = package
    for name in ('containers', 'service_control', 'container_actions',
                 'container_collector', 'container_action_broker'):
        location = target / 'sovagrid_agent' / (name + '.py')
        module_name = 'sovagrid_agent.' + name
        module = types.ModuleType(module_name)
        module.__package__ = 'sovagrid_agent'
        module.__file__ = str(location)
        sys.modules[module_name] = module
        exec(compile(verified[name + '.py'], str(location), 'exec'), module.__dict__)
    broker = sys.modules['sovagrid_agent.container_action_broker']
    need(broker.CONFIG == CONFIGS['default'] and
         broker.LOCAL_CONFIG == CONFIGS['local'] and
         broker.MAX_POLICY_BYTES == 8192 and broker.MAX_CONTAINERS == 16,
         'SOURCE_UNVERIFIED')
    return broker

def private(path, maximum):
    if not path.exists() and not path.is_symlink():
        return None
    return regular(path, {0o600}, maximum)

def config_state(config, broker, profile):
    if config.exists() or config.is_symlink():
        directory(config, exact=True)
    policy = private(config / 'policy.json', broker.MAX_POLICY_BYTES)
    marker = private(config / 'enabled', 8)
    transaction = private(config / 'setup-transaction', 16384)
    if policy is not None:
        parsed = broker.parse_policy(policy)
        entries = [{'id': ident, 'name': entry['name'],
                    'image_id': entry['image_id'], 'actions': sorted(entry['actions'])}
                   for ident, entry in sorted(parsed.items())]
    else:
        entries = None
    need(marker in (None, b'enabled\n') and (marker is None or policy is not None),
         'INVALID_STATE')
    parts = [profile, 'dir' if config.exists() else 'absent',
             hashlib.sha256(policy).hexdigest() if policy is not None else '-',
             hashlib.sha256(marker).hexdigest() if marker is not None else '-',
             hashlib.sha256(transaction).hexdigest() if transaction is not None else '-']
    revision = hashlib.sha256('\n'.join(parts).encode('ascii')).hexdigest()
    return {'ok': True, 'profile': profile, 'state_revision': revision,
            'armed': marker is not None, 'policy': entries,
            'policy_raw': base64.b64encode(policy).decode('ascii') if policy is not None else None,
            'transaction_pending': transaction is not None}

def inventory(profile):
    timer, path, group = INVENTORIES[profile]
    try:
        for verb in ('is-enabled', 'is-active'):
            result = subprocess.run(('/usr/bin/systemctl', verb, '--quiet', timer),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=8, check=False)
            need(result.returncode == 0, 'INVENTORY_UNAVAILABLE')
        group_gid = grp.getgrnam(group).gr_gid
    except (OSError, subprocess.TimeoutExpired, KeyError) as exc:
        raise Refusal('INVENTORY_UNAVAILABLE') from exc
    container_module = sys.modules['sovagrid_agent.containers']
    now = int(time.time())
    snapshot = container_module.read_snapshot(path, owner_uid=0, group_gid=group_gid, now=now)
    need(isinstance(snapshot, dict) and 0 <= now - snapshot['collected_at'] <= 120,
         'INVENTORY_UNAVAILABLE')
    docker = snapshot['engines'][0]
    need(docker['engine'] == 'docker' and docker['source_status'] == 'ok' and
         docker['reason'] is None and docker['truncated'] is False,
         'INVENTORY_UNAVAILABLE')
    return {item['id']: (item['name'], item['image']) for item in docker['containers']}

def catalog(broker, profile):
    snapshot = inventory(profile)
    path = broker.SOCKETS['docker']
    broker._socket(path)
    listing = broker._get(path, '/containers/json?all=1', limit=262144, timeout=5)
    need(isinstance(listing, list) and len(listing) <= 64, 'CATALOG_TOO_LARGE')
    available = []
    excluded = 0
    listed = {}
    for summary in listing:
        if not isinstance(summary, dict):
            raise Refusal('INVENTORY_UNAVAILABLE')
        ident = summary.get('Id')
        if not isinstance(ident, str) or broker.CONTAINER_ID.fullmatch(ident) is None:
            raise Refusal('INVENTORY_UNAVAILABLE')
        names = summary.get('Names')
        name = names[0].lstrip('/') if isinstance(names, list) and names and isinstance(names[0], str) else None
        image_ref = summary.get('Image')
        need(isinstance(name, str) and isinstance(image_ref, str) and
             ident not in listed, 'INVENTORY_UNAVAILABLE')
        listed[ident] = (name, image_ref)
    need(listed == snapshot, 'INVENTORY_UNAVAILABLE')
    for ident in listed:
        try:
            detail = broker._get(path, '/containers/' + ident + '/json',
                                 limit=65536, timeout=3)
            name = detail.get('Name') if isinstance(detail, dict) else None
            image_id = detail.get('Image') if isinstance(detail, dict) else None
            if not isinstance(name, str) or not name.startswith('/'):
                raise PermissionError
            name = name[1:]
            if (broker.NAME.fullmatch(name) is None or
                    not isinstance(image_id, str) or
                    broker.IMAGE_ID.fullmatch(image_id) is None):
                raise PermissionError
            entry = {'name': name, 'image_id': image_id, 'actions': frozenset(('status',))}
            state = broker._identity(detail, ident, entry)
            image = detail['Config']['Image']
            if (not 1 <= len(image) <= 160 or not image.isprintable() or
                    (name, image) != listed[ident]):
                raise PermissionError
            available.append({'id': ident, 'name': name, 'image_id': image_id,
                              'image': image, 'state': state})
        except (OSError, ValueError, PermissionError, TypeError, KeyError):
            excluded += 1
    return sorted(available, key=lambda item: (item['name'], item['id'])), excluded

def selected(raw, broker, candidates):
    need(isinstance(raw, bytes) and 0 < len(raw) <= broker.MAX_POLICY_BYTES,
         'INVALID_POLICY')
    parsed = broker.parse_policy(raw)
    ids = {entry['id']: entry for entry in candidates}
    for ident, entry in parsed.items():
        candidate = ids.get(ident)
        need(candidate is not None and candidate['name'] == entry['name'] and
             candidate['image_id'] == entry['image_id'], 'IDENTITY_CHANGED')
    return parsed

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def atomic(path, raw):
    fd, name = tempfile.mkstemp(prefix='.sovagrid-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        fd = -1
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(name):
            os.unlink(name)

def remove(path):
    if path.exists() or path.is_symlink():
        path.unlink()
        fsync_dir(path.parent)

def create_config(config):
    config.mkdir(mode=0o700)
    os.chown(config, 0, 0)
    os.chmod(config, 0o700)
    fsync_dir(config.parent)

def lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
         info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
         'UNSAFE_PATH')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refusal('SETUP_BUSY')
    return fd

def read_transaction(config, token):
    raw = private(config / 'setup-transaction', 16384)
    need(raw is not None, 'TRANSACTION_MISSING')
    value = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(value, dict) and set(value) ==
         {'version', 'token', 'previous', 'previous_dir', 'target_sha'} and
         type(value['version']) is int and value['version'] == 1 and
         value['token'] == token and type(value['previous_dir']) is bool and
         isinstance(value['target_sha'], str) and SHA.fullmatch(value['target_sha']) and
         (value['previous'] is None or isinstance(value['previous'], str)),
         'TRANSACTION_CHANGED')
    previous = base64.b64decode(value['previous'], validate=True) if value['previous'] is not None else None
    need(previous is None or len(previous) <= 8192, 'TRANSACTION_CHANGED')
    return value, previous

def pending_token(config):
    raw = private(config / 'setup-transaction', 16384)
    need(raw is not None, 'TRANSACTION_MISSING')
    value = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(value, dict) and isinstance(value.get('token'), str) and
         TOKEN.fullmatch(value['token']) is not None, 'TRANSACTION_CHANGED')
    return value['token']

def recover(config, broker, profile, token):
    transaction, previous = read_transaction(config, token)
    current = config_state(config, broker, profile)
    actual = base64.b64decode(current['policy_raw']) if current['policy_raw'] is not None else None
    need(actual == previous or
         actual is not None and hashlib.sha256(actual).hexdigest() == transaction['target_sha'],
         'TRANSACTION_CHANGED')
    remove(config / 'enabled')
    if previous is None:
        remove(config / 'policy.json')
    else:
        atomic(config / 'policy.json', previous)
    remove(config / 'setup-transaction')
    if not transaction['previous_dir']:
        config.rmdir()
        fsync_dir(config.parent)
    result = config_state(config, broker, profile)
    need(not result['armed'] and not result['transaction_pending'] and
         result['policy_raw'] == (base64.b64encode(previous).decode('ascii')
                                  if previous is not None else None),
         'ROLLBACK_INCOMPLETE')
    return result

def run(action, profile, expected_manifest, expected_revision, token, raw):
    broker = source(expected_manifest, profile)
    config = CONFIGS[profile]
    if action == 'status':
        return config_state(config, broker, profile)
    if action == 'inspect':
        result = config_state(config, broker, profile)
        try:
            result['catalog'], result['excluded'] = catalog(broker, profile)
            result['catalog_status'] = 'ok'
        except (OSError, ValueError, PermissionError, http.client.HTTPException,
                subprocess.TimeoutExpired, KeyError, TypeError, Refusal):
            result['catalog'], result['excluded'] = [], 0
            result['catalog_status'] = 'unavailable'
        return result
    if action == 'preview':
        result = config_state(config, broker, profile)
        need(not result['armed'] and not result['transaction_pending'], 'DISARM_FIRST')
        result['catalog'], result['excluded'] = catalog(broker, profile)
        result['catalog_status'] = 'ok'
        selected(raw, broker, result['catalog'])
        result['plan'] = {'config_path': str(config),
                          'containers': json.loads(raw)['containers'],
                          'write_policy': result['policy_raw'] != base64.b64encode(raw).decode('ascii'),
                          'enable': True}
        return result
    fd = lock()
    try:
        if action == 'arm':
            need(SHA.fullmatch(expected_revision) is not None and
                 TOKEN.fullmatch(token) is not None, 'INVALID_INPUT')
            before = config_state(config, broker, profile)
            need(before['state_revision'] == expected_revision, 'STATE_CHANGED')
            need(not before['armed'] and not before['transaction_pending'], 'DISARM_FIRST')
            candidates, _excluded = catalog(broker, profile)
            selected(raw, broker, candidates)
            existed = config.exists()
            try:
                if not existed:
                    create_config(config)
                directory(config, exact=True)
                previous = base64.b64decode(before['policy_raw']) if before['policy_raw'] is not None else None
                transaction = {'version': 1, 'token': token, 'previous_dir': existed,
                               'previous': base64.b64encode(previous).decode('ascii') if previous is not None else None,
                               'target_sha': hashlib.sha256(raw).hexdigest()}
                atomic(config / 'setup-transaction',
                       json.dumps(transaction, sort_keys=True, separators=(',', ':')).encode('ascii'))
            except Exception:
                if not existed and config.exists():
                    try:
                        config.rmdir()
                        fsync_dir(config.parent)
                    except Exception as exc:
                        raise Refusal('ROLLBACK_INCOMPLETE') from exc
                raise
            try:
                atomic(config / 'policy.json', raw)
                atomic(config / 'enabled', b'enabled\n')
                need(broker.read_policy(config / 'policy.json', config / 'enabled') ==
                     broker.parse_policy(raw), 'INVALID_STATE')
                return config_state(config, broker, profile)
            except Exception:
                try:
                    recover(config, broker, profile, token)
                except Exception as exc:
                    raise Refusal('ROLLBACK_INCOMPLETE') from exc
                raise
        if action == 'rollback':
            need(TOKEN.fullmatch(token) is not None, 'INVALID_INPUT')
            if not (config / 'setup-transaction').exists():
                result = config_state(config, broker, profile)
                need(result['state_revision'] == expected_revision, 'TRANSACTION_MISSING')
                return result
            return recover(config, broker, profile, token)
        if action == 'finalize':
            need(TOKEN.fullmatch(token) is not None, 'INVALID_INPUT')
            transaction, _previous = read_transaction(config, token)
            result = config_state(config, broker, profile)
            actual = base64.b64decode(result['policy_raw']) if result['policy_raw'] is not None else None
            need(result['armed'] and actual is not None and
                 hashlib.sha256(actual).hexdigest() == transaction['target_sha'],
                 'TRANSACTION_CHANGED')
            remove(config / 'setup-transaction')
            return config_state(config, broker, profile)
        if action == 'disarm':
            need(SHA.fullmatch(expected_revision) is not None, 'INVALID_INPUT')
            before = config_state(config, broker, profile)
            need(before['state_revision'] == expected_revision, 'STATE_CHANGED')
            need(not before['transaction_pending'], 'TRANSACTION_PENDING')
            if before['armed']:
                remove(config / 'enabled')
            result = config_state(config, broker, profile)
            need(not result['armed'], 'INVALID_STATE')
            return result
        if action == 'clear':
            need(SHA.fullmatch(expected_revision) is not None, 'INVALID_INPUT')
            before = config_state(config, broker, profile)
            need(before['state_revision'] == expected_revision, 'STATE_CHANGED')
            need(not before['armed'] and not before['transaction_pending'], 'DISARM_FIRST')
            need(before['policy_raw'] is not None, 'INVALID_STATE')
            remove(config / 'policy.json')
            # Keep unrelated files untouched. An empty directory can be
            # removed so a test allowlist leaves no persistent configuration.
            try:
                config.rmdir()
                fsync_dir(config.parent)
            except OSError:
                pass
            result = config_state(config, broker, profile)
            need(not result['armed'] and not result['transaction_pending'] and
                 result['policy_raw'] is None, 'INVALID_STATE')
            return result
        if action == 'abort':
            need(SHA.fullmatch(expected_revision) is not None, 'INVALID_INPUT')
            before = config_state(config, broker, profile)
            need(before['state_revision'] == expected_revision, 'STATE_CHANGED')
            return recover(config, broker, profile, pending_token(config))
        raise Refusal('INVALID_INPUT')
    finally:
        os.close(fd)

if __name__ == '__main__':
    try:
        need(len(sys.argv) == 6, 'INVALID_INPUT')
        action, profile, manifest, revision, token = sys.argv[1:]
        need(action in ('status', 'inspect', 'preview', 'arm', 'rollback', 'finalize',
                        'disarm', 'clear', 'abort') and
             profile in CONFIGS, 'INVALID_INPUT')
        raw = sys.stdin.buffer.read(8193) if action in ('preview', 'arm') else b''
        result = run(action, profile, manifest, revision, token, raw)
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    except Refusal as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, separators=(',', ':')))
        raise SystemExit(40)
    except Exception:
        print(json.dumps({'ok': False, 'error': 'UNCONFIRMED'}, separators=(',', ':')))
        raise SystemExit(41)
'''
