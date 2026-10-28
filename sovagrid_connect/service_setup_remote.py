# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only proof of the exact installed service setup code before root use."""

SCRIPT = r'''
import hashlib, json, os, pathlib, re, stat, sys

ROOT = pathlib.Path('/opt/sovagrid-src')
SHA = re.compile(r'[0-9a-f]{64}\Z')
FILES = ('__init__.py', 'service_setup.py', 'service_broker.py', 'service_control.py')

def need(condition):
    if not condition:
        raise ValueError('SOURCE_UNVERIFIED')

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result

def directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)

def regular(path, modes, maximum):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) in modes and 0 < info.st_size <= maximum)
    return path.read_bytes()

def check(expected, profile):
    need(os.geteuid() == 0 and SHA.fullmatch(expected) is not None and
         profile in ('default', 'local'))
    for parent in (pathlib.Path('/opt'), ROOT, ROOT / 'sovagrid-agent',
                   ROOT / 'sovagrid-agent/sovagrid_agent'):
        directory(parent)
    raw = regular(ROOT / 'sovagrid-bundle.json', {0o644}, 524288)
    need(hashlib.sha256(raw).hexdigest() == expected)
    manifest = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'} and
         type(manifest['format']) is int and manifest['format'] == 1 and
         isinstance(manifest['sha256'], dict))
    # A target may have an independently managed external Agent whose older code must
    # remain untouched. The selected local profile verifies only its own
    # installed copy against the approved server bundle.
    installed = [pathlib.Path('/opt/sovagrid-agent-local' if profile == 'local'
                              else '/opt/sovagrid-agent')]
    for target in installed:
        directory(target)
        directory(target / 'sovagrid_agent')
    for filename in FILES:
        relative = 'sovagrid-agent/sovagrid_agent/' + filename
        digest = manifest['sha256'].get(relative)
        need(isinstance(digest, str) and SHA.fullmatch(digest) is not None)
        source = regular(ROOT / relative, {0o644}, 1048576)
        need(hashlib.sha256(source).hexdigest() == digest)
        for target in installed:
            module = regular(target / 'sovagrid_agent' / filename, {0o644}, 1048576)
            need(module == source)
    return {'protocol': 1, 'manifest_sha256': expected, 'profile': profile}

try:
    need(len(sys.argv) == 3)
    print(json.dumps(check(sys.argv[1], sys.argv[2]), separators=(',', ':')))
except (OSError, ValueError, TypeError, UnicodeError):
    print('SG_SERVICE_SOURCE_REFUSE:UNVERIFIED')
    raise SystemExit(40)
'''
