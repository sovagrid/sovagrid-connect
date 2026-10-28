# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read-only proof of the exact installed host backup helper and server package."""

from .release_feed_remote import SOURCE_PROOF


SCRIPT = SOURCE_PROOF + r'''
try:
    need(len(sys.argv) == 2, 'ARGS')
    expected = sys.argv[1]
    hashes = source(expected)
    need({'sovagrid-blueprint/deploy/host_backup.py',
          'sovagrid-blueprint/deploy/host_backup_orchestrator.py'} <= set(hashes),
         'SOURCE_MANIFEST')
    print(json.dumps({'protocol': 1, 'manifest_sha256': expected,
                      'host_backup_verified': True},
                     sort_keys=True, separators=(',', ':')))
except (Refused, OSError, ValueError, TypeError, UnicodeError) as exc:
    code = str(exc) if isinstance(exc, Refused) else 'UNVERIFIED'
    print('SG_HOST_BACKUP_SOURCE_REFUSE:' + code)
    raise SystemExit(40)
'''
