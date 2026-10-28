# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed root program for reviewed local-Agent command opt-in on server 0.5.1."""

from .local_operations import _SOURCE_PROBE


_TEMPLATE = r'''
import fcntl, hashlib, json, os, pathlib, re, select, signal, sqlite3, stat, subprocess, sys, time, uuid

PROBE = __SOURCE_PROBE__
ROOT = pathlib.Path('/opt/sovagrid-src')
HELPER = ROOT / 'sovagrid-blueprint/deploy/promote_agent_only.py'
LOG_DIR = pathlib.Path('/var/lib/sovagrid-promotion')
LOCK = pathlib.Path('/run/sovagrid-promotion.lock')
SHA = re.compile(r'[0-9a-f]{64}\Z')

class Refused(Exception):
    pass

def need(value, reason):
    if not value:
        raise Refused(reason)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'STATE')
        result[key] = value
    return result

def json_object(raw):
    need(len(raw) <= 4096, 'STATE')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    need(isinstance(value, dict) and type(value.get('protocol')) is int and
         value['protocol'] == 1, 'STATE')
    return value

def checked_run(argv, *, timeout=90):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False, timeout=timeout,
                            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    need(result.returncode == 0 and len(result.stdout) <= 4096, 'INSPECT')
    return json_object(result.stdout)

def readiness(expected, *, metric_since=None):
    need(os.geteuid() == 0 and SHA.fullmatch(expected) is not None, 'ROOT_OR_DIGEST')
    source = checked_run(['/usr/bin/python3', '-I', '-c', PROBE, expected])
    need(set(source) == {'protocol', 'manifest_sha256', 'local_server_id', 'commands'} and
         source['manifest_sha256'] == expected and
         type(source['commands']) is bool and
         isinstance(source['local_server_id'], str) and
         str(uuid.UUID(source['local_server_id'])) == source['local_server_id'], 'SOURCE')
    state = checked_run(['/usr/bin/python3', '-I', str(HELPER), 'inspect'])
    need(set(state) == {'protocol', 'phase', 'external_agent_preserved',
                        'baseline_sha256', 'pinned_manifest_sha256',
                        'source_manifest_sha256', 'local_server_id', 'reason_code'} and
         state['phase'] == 'activated' and state['external_agent_preserved'] is True and
         state['pinned_manifest_sha256'] == expected and
         state['source_manifest_sha256'] == expected and
         state['local_server_id'] == source['local_server_id'] and
         state['reason_code'] is None and
         isinstance(state['baseline_sha256'], str) and
         SHA.fullmatch(state['baseline_sha256']) is not None, 'PROMOTION_STATE')
    with sqlite3.connect('file:/var/lib/sovagrid/hub/hub.sqlite?mode=ro',
                         uri=True, timeout=2) as db:
        db.execute('PRAGMA query_only=ON')
        row = db.execute('SELECT remote_commands_enabled FROM servers WHERE id=?',
                         (source['local_server_id'],)).fetchone()
        metric = db.execute('SELECT received_at FROM metrics WHERE server_id=? '
                            'ORDER BY id DESC LIMIT 1', (source['local_server_id'],)).fetchone()
    need(row is not None and len(row) == 1 and type(row[0]) is int and
         row[0] in (0, 1) and bool(row[0]) == source['commands'], 'COMMANDS_INCONSISTENT')
    now = int(time.time())
    need(metric is not None and len(metric) == 1 and type(metric[0]) is int and
         abs(now - metric[0]) < 180 and
         (metric_since is None or metric[0] >= metric_since), 'METRIC_STALE')
    journal = LOG_DIR / 'local-agent.json'
    info = journal.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 32768, 'JOURNAL')
    journal_sha = hashlib.sha256(journal.read_bytes()).hexdigest()
    revision = hashlib.sha256(json.dumps({
        'protocol': 1, 'manifest': expected, 'server_id': source['local_server_id'],
        'baseline': state['baseline_sha256'], 'journal_sha256': journal_sha,
        'commands': source['commands'],
    }, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()
    return {'protocol': 1, 'phase': 'ready', 'manifest_sha256': expected,
            'local_server_id': source['local_server_id'],
            'commands_enabled': source['commands'],
            'external_agent_preserved': True, 'state_revision': revision}

def lock_root():
    need(not LOCK.is_symlink(), 'LOCK')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600, 'LOCK')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refused('BUSY')
    return fd

def private_log():
    info = LOG_DIR.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, 'LOG')
    path = LOG_DIR / 'local-commands-enable.log'
    if os.path.lexists(path):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600, 'LOG')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600, 'LOG')
    return fd

def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)

def enable(expected, revision):
    need(SHA.fullmatch(revision) is not None, 'EXPECTED_STATE')
    fd = lock_root()
    try:
        before = readiness(expected)
        need(before['state_revision'] == revision and not before['commands_enabled'],
             'STATE_CHANGED')
        started = int(time.time())
        log_fd = private_log()
        with os.fdopen(log_fd, 'wb') as output:
            process = subprocess.Popen(['/usr/bin/python3', '-I', str(HELPER),
                                        'activate', '--enable-commands'],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            remaining = 2 * 1024 * 1024
            truncated = False
            deadline = time.monotonic() + 540
            with process.stdout:
                while True:
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0 or not select.select(
                            [process.stdout], [], [], remaining_time)[0]:
                        stop_group(process)
                        raise Refused('ENABLE_TIMEOUT')
                    block = os.read(process.stdout.fileno(), 64 * 1024)
                    if not block:
                        break
                    kept = block[:remaining]
                    if kept:
                        output.write(kept)
                        remaining -= len(kept)
                    if len(block) > len(kept):
                        truncated = True
            if truncated:
                output.write(b'\n[output truncated after 2 MiB]\n')
            output.flush()
            os.fsync(output.fileno())
            try:
                result = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                stop_group(process)
                raise Refused('ENABLE_TIMEOUT')
        need(result == 0, 'ENABLE_UNCONFIRMED')
        after = readiness(expected, metric_since=started)
        need(after['commands_enabled'] and
             after['local_server_id'] == before['local_server_id'], 'POSTCHECK')
        return after
    finally:
        os.close(fd)

try:
    os.umask(0o077)
    need(len(sys.argv) in (3, 4), 'ARGS')
    action, expected = sys.argv[1:3]
    need(action in ('preview', 'enable') and SHA.fullmatch(expected) is not None, 'ARGS')
    if action == 'preview':
        need(len(sys.argv) == 3, 'ARGS')
        result = readiness(expected)
    else:
        need(len(sys.argv) == 4, 'ARGS')
        result = enable(expected, sys.argv[3])
    print(json.dumps(result, separators=(',', ':')), flush=True)
except Exception as exc:
    code = str(exc) if isinstance(exc, Refused) else type(exc).__name__.upper()
    print('SG_LOCAL_COMMANDS_REFUSE:' + code, flush=True)
    raise SystemExit(40)
'''


SCRIPT = _TEMPLATE.replace("__SOURCE_PROBE__", repr(_SOURCE_PROBE))
