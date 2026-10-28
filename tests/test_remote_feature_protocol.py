# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import unittest
import uuid

from sovagrid_connect.agent_rpc import AgentRPC, RPCError
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.enrollment_protocol import validate_request, validate_reply, ProtocolError

SID, EID, RID = (str(uuid.UUID(int=n)) for n in (1, 2, 3))


class RemoteFeatureProtocolTests(unittest.TestCase):
    def fixture(self):
        flags = {'commands': True, 'terminal': True, 'files': True}
        cas = {k: 'a'*64 for k in ('source_manifest_sha256','features_sha256','policy_sha256','state_sha256')}
        return {'protocol': 1, 'ok': True, 'identity': {'request_id': RID, 'enrollment_id': EID,
            'server_id': SID, 'agent_token_sha256': 'b'*64}, 'current': flags, 'expected': cas,
            'source_manifest_sha256': 'a'*64, 'recovery_required': False, 'pending_features': None,
            'services': {'agent': True, 'tunnel': True, 'terminal': True}, 'desired': dict(flags), 'changed': True, 'applied': True}

    def test_apply_binds_identity_source_and_truthful_service_result(self):
        reply = self.fixture()
        request = {'protocol': 1, 'server_id': SID, 'enrollment_id': EID, 'agent_token_sha256': 'b'*64,
                   'features': reply['desired'], 'expected': reply['expected']}
        validate_request('target-features-apply', request)
        validate_reply('target-features-apply', reply, request=request)
        for change in ({'identity': {**reply['identity'],'server_id':str(uuid.uuid4())}},
                       {'source_manifest_sha256':'c'*64}, {'pending_features':reply['desired']},
                       {'services':{**reply['services'],'agent':False}}, {'token':'must-not-exist'}):
            with self.subTest(change=change), self.assertRaises(ProtocolError):
                validate_reply('target-features-apply', {**reply,**change}, request=request)

    def test_terminal_or_files_cannot_silently_grant_command_permission(self):
        for flags in ({'commands':False,'terminal':True,'files':False},
                      {'commands':False,'terminal':False,'files':True},
                      {'commands':1,'terminal':False,'files':False}):
            with self.assertRaises(ProtocolError):
                validate_request('target-features-preview', {'protocol':1,'server_id':SID,'features':flags})

    def test_features_require_verified_stage_before_any_ssh_spawn(self):
        def never(*_a, **_k): raise AssertionError('SSH must not start')
        rpc = AgentRPC(ConnectionOptions('target.example', user='root'), role='target', popen=never)
        with self.assertRaises(RPCError) as caught:
            rpc.call('target-features-status', {'protocol':1,'server_id':SID})
        self.assertEqual(caught.exception.code, 'INVALID_REQUEST')


if __name__ == '__main__': unittest.main()
