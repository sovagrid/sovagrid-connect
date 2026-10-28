# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed Ubuntu apt dependency helper; never invokes nft or systemctl mutations."""

SCRIPT = r'''
import hashlib, json, os, pathlib, re, stat, subprocess, sys

SHA = re.compile(r'[0-9a-f]{64}\Z')
VERSIONS = {'22.04', '24.04', '26.04'}
APT = '/usr/bin/apt-get'
DPKG = '/usr/bin/dpkg-query'
SYSTEMCTL = '/usr/bin/systemctl'
NFT = '/usr/sbin/nft'
ENV = {'DEBIAN_FRONTEND': 'noninteractive', 'APT_LISTCHANGES_FRONTEND': 'none',
       'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}

class Refused(Exception):
    pass

def need(condition, code):
    if not condition:
        raise Refused(code)

def run(argv, timeout):
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                              env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused('TOOL_UNAVAILABLE')

def executable(path):
    info = pathlib.Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         not info.st_mode & 0o022 and info.st_mode & 0o111, 'UNSAFE_TOOL')

def service_state(action):
    result = run([SYSTEMCTL, action, 'nftables.service'], 8)
    text = result.stdout.decode('ascii', errors='replace').strip()
    need(len(text) <= 32, 'SYSTEMD_UNKNOWN')
    if action == 'is-enabled':
        need(text in ('disabled', 'not-found', 'masked', 'enabled', 'static'), 'SYSTEMD_UNKNOWN')
    else:
        need(text in ('inactive', 'not-found', 'unknown', 'active', 'failed'), 'SYSTEMD_UNKNOWN')
    return text

def release():
    raw = pathlib.Path('/etc/os-release').read_text(encoding='utf-8')
    need(len(raw) <= 8192, 'UNSUPPORTED_OS')
    values = dict(line.split('=', 1) for line in raw.splitlines()
                  if '=' in line and not line.startswith('#'))
    os_id = values.get('ID', '').strip('"\'')
    version = values.get('VERSION_ID', '').strip('"\'')
    need(os_id == 'ubuntu' and version in VERSIONS, 'UNSUPPORTED_OS')
    return version

def status():
    need(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_REQUIRED')
    version = release()
    for tool in (APT, DPKG, SYSTEMCTL):
        executable(tool)
    package = run([DPKG, '-W', '-f=${db:Status-Status}', 'nftables'], 10)
    if package.returncode == 1 and not package.stdout:
        package_state = 'absent'
    else:
        need(package.returncode == 0, 'PACKAGE_UNKNOWN')
        package_state = package.stdout.decode('ascii', errors='replace').strip()
        need(package_state in ('installed', 'not-installed'), 'PACKAGE_UNKNOWN')
    nft_version = None
    if pathlib.Path(NFT).exists():
        executable(NFT)
        version_result = run([NFT, '--version'], 8)
        need(version_result.returncode == 0 and len(version_result.stdout) <= 128,
             'NFT_UNAVAILABLE')
        nft_version = version_result.stdout.decode('ascii', errors='replace').strip()
        need(re.fullmatch(r'nftables v[0-9][ -~]{1,120}', nft_version) is not None,
             'NFT_UNAVAILABLE')
    enabled = service_state('is-enabled')
    active = service_state('is-active')
    snapshot = {'ubuntu_version': version, 'package': package_state,
                'nft_version': nft_version, 'service_enabled': enabled,
                'service_active': active}
    revision = hashlib.sha256(json.dumps(snapshot, sort_keys=True,
                                         separators=(',', ':')).encode('ascii')).hexdigest()
    return {'protocol': 1, 'state_revision': revision, **snapshot}

def install(expected):
    before = status()
    need(SHA.fullmatch(expected) is not None and
         before['state_revision'] == expected, 'STATE_CHANGED')
    if before['nft_version'] is not None:
        return before
    need(before['package'] in ('absent', 'not-installed') and
         before['service_enabled'] == 'not-found' and
         before['service_active'] in ('inactive', 'not-found', 'unknown'),
         'PACKAGE_STATE_UNSAFE')
    # Ubuntu ships nftables.service disabled by default. We never call
    # systemctl enable/start, nor execute nft with a ruleset.
    for argv, timeout in (([APT, '-o', 'DPkg::Lock::Timeout=30', 'update'], 240),
                          ([APT, '-o', 'DPkg::Lock::Timeout=30', 'install', '-y',
                            '--no-install-recommends', '--no-remove',
                            '--no-upgrade', 'nftables'], 300)):
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False, env=ENV)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused('APT_UNCERTAIN')
        need(result.returncode == 0, 'APT_FAILED')
    after = status()
    need(after['package'] == 'installed' and after['nft_version'] is not None,
         'POSTCHECK_FAILED')
    need(after['service_enabled'] == 'disabled' and
         after['service_active'] == 'inactive', 'SERVICE_CHANGED')
    return after

try:
    need(len(sys.argv) in (2, 3), 'ARGS')
    action = sys.argv[1]
    need(action in ('preview', 'install'), 'ARGS')
    if action == 'preview':
        need(len(sys.argv) == 2, 'ARGS')
        result = status()
    else:
        need(len(sys.argv) == 3, 'ARGS')
        result = install(sys.argv[2])
    print(json.dumps({'ok': True, **result}, sort_keys=True, separators=(',', ':')))
except (Refused, OSError, UnicodeError, ValueError, TypeError) as exc:
    code = str(exc) if isinstance(exc, Refused) else 'UNVERIFIED'
    print(json.dumps({'ok': False, 'error': code}, separators=(',', ':')))
    raise SystemExit(40)
'''
