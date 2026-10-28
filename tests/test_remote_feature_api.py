# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import io
import json
import types
import unittest
from unittest.mock import Mock
import uuid

from sovagrid_connect.enrollment_api import EnrollmentAPI, EnrollmentAPIError
from sovagrid_connect.remote_feature_api import RemoteFeatureAPI

SID, EID = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))


class Response(io.BytesIO):
    def read1(self, count): return self.read(count)
    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


class RemoteFeatureAPITests(unittest.TestCase):
    def client(self, payload, cls=RemoteFeatureAPI):
        tunnel = types.SimpleNamespace(url='http://127.0.0.1:12345', alive=True)
        raw = json.dumps(payload).encode()
        return cls(tunnel, opener=lambda *_a, **_k: Response(raw))

    def policy(self):
        return {'server_id': SID, 'enrollment_id': EID, 'agent_token_sha256': 'a'*64, 'enabled': False, 'revision': 0}

    def test_only_fixed_picker_route_can_read_more_than_default_four_kib(self):
        payload = {'servers':[{'id':str(uuid.UUID(int=i+1)), 'name':'Я'*80} for i in range(20)], 'truncated':False}
        self.assertGreater(len(json.dumps(payload).encode()), 4096)
        client = self.client(payload)
        reply = client._request('GET', '/api/v1/agent-management')
        self.assertEqual(len(reply['servers']), 20)
        with self.assertRaises(EnrollmentAPIError):
            client._request('GET', '/api/v1/users')
        with self.assertRaises(EnrollmentAPIError):
            self.client(payload, EnrollmentAPI)._request('GET', '/api/v1/agent-management')
        with self.assertRaises(EnrollmentAPIError):
            self.client({'padding':'x'*(256*1024)})._request('GET', '/api/v1/agent-management')

    def test_picker_rejects_duplicates_tokens_and_truncated_results(self):
        client = self.client({})
        row = {'id':SID, 'name':'home'}
        for value in ({'servers':[row,row], 'truncated':False},
                      {'servers':[{**row,'token':'must-not-exist'}], 'truncated':False},
                      {'servers':[row], 'truncated':True}):
            client._operation = Mock(return_value=value)
            with self.assertRaises(EnrollmentAPIError): client.list_servers()

    def test_cas_request_contains_only_identity_revision_and_explicit_permission(self):
        client = self.client({})
        expected = self.policy()
        client._operation = Mock(return_value={**expected,'enabled':True,'revision':1,'changed':True})
        result = client.set_management(expected, True)
        self.assertEqual(result['revision'], 1)
        client._operation.assert_called_once_with('POST', '/api/v1/servers/'+SID+'/agent-management',
            {'enrollment_id':EID,'agent_token_sha256':'a'*64,'expected_revision':0,'enabled':True})
        self.assertEqual(expected, self.policy())

    def test_wrong_identity_revision_or_boolean_is_not_accepted_as_success(self):
        client = self.client({}); expected = self.policy()
        for change in ({'agent_token_sha256':'b'*64}, {'revision':0}, {'changed':False}, {'enabled':False}):
            client._operation = Mock(return_value={**expected,'enabled':True,'revision':1,'changed':True,**change})
            with self.assertRaises(EnrollmentAPIError): client.set_management(expected, True)
        client._operation = Mock()
        with self.assertRaises(EnrollmentAPIError):
            client.set_management({**expected,'revision':True}, True)
        client._operation.assert_not_called()


if __name__ == '__main__': unittest.main()
