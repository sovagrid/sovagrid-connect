# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned root-only VPN source probe. It never opens a Docker or VPN socket."""

SCRIPT = r'''
import hashlib, json, os, pathlib, re, stat, sys

ROOT = pathlib.Path('/opt/sovagrid-src')
SOURCE = ROOT / 'sovagrid-vpn'
PACKAGE = pathlib.Path('/opt/sovagrid-vpn')
SHA = re.compile(r'[0-9a-f]{64}\Z')
DEPLOY = ('sovagrid-amnezia-ctl', 'sovagrid-amnezia-broker',
          'sovagrid-amnezia-control.service', 'sovagrid-amnezia-control.socket')

def need(condition):
    if not condition:
        raise ValueError('SOURCE_UNVERIFIED')

def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value

def directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)

def regular(path, modes, limit):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) in modes and 0 < info.st_size <= limit)
    return path.read_bytes()

def check(expected, feature):
    need(os.geteuid() == 0 and SHA.fullmatch(expected) is not None and
         feature in ('routing', 'amnezia'))
    for path in (pathlib.Path('/opt'), ROOT, SOURCE, SOURCE / 'sovagrid_vpn',
                 PACKAGE, PACKAGE / 'sovagrid_vpn'):
        directory(path)
    raw = regular(ROOT / 'sovagrid-bundle.json', {0o644}, 524288)
    need(hashlib.sha256(raw).hexdigest() == expected)
    manifest = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'} and
         type(manifest['format']) is int and manifest['format'] == 1 and
         isinstance(manifest['sha256'], dict))
    files = sorted(SOURCE.joinpath('sovagrid_vpn').glob('*.py'))
    need(4 <= len(files) <= 64)
    for path in files:
        relative = 'sovagrid-vpn/sovagrid_vpn/' + path.name
        digest = manifest['sha256'].get(relative)
        need(isinstance(digest, str) and SHA.fullmatch(digest) is not None)
        source = regular(path, {0o644}, 1048576)
        installed = regular(PACKAGE / 'sovagrid_vpn' / path.name, {0o644}, 1048576)
        need(hashlib.sha256(source).hexdigest() == digest and installed == source)
    for required in ('__init__.py', 'managed.py', 'proposal.py',
                     'routing.py', 'amnezia_install.py', 'amnezia_admin.py',
                     'amnezia_control.py'):
        need(required in {path.name for path in files})
    if feature == 'amnezia':
        directory(SOURCE / 'deploy')
        for name in DEPLOY:
            relative = 'sovagrid-vpn/deploy/' + name
            digest = manifest['sha256'].get(relative)
            need(isinstance(digest, str) and SHA.fullmatch(digest) is not None)
            source = regular(SOURCE / 'deploy' / name, {0o644, 0o755}, 262144)
            need(hashlib.sha256(source).hexdigest() == digest)
    return {'protocol': 1, 'manifest_sha256': expected, 'feature': feature}

try:
    need(len(sys.argv) == 3)
    print(json.dumps(check(sys.argv[1], sys.argv[2]), separators=(',', ':')))
except (OSError, ValueError, TypeError, UnicodeError):
    print('SG_VPN_SOURCE_REFUSE:UNVERIFIED')
    raise SystemExit(40)
'''
