# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Public helper contracts reject credential leakage and wrong identities."""
import base64
import copy
import json
import unittest
import uuid

from sovagrid_connect.enrollment_protocol import (CAS_FIELDS, HelperError, ProtocolError,
    decode_reply, hub_username, public_key_fingerprint, validate_cas, validate_hub_trust,
    validate_registration, validate_reply, validate_request, validate_stage_descriptor, validate_target)

# Disposable self-signed public CA only. Its private key was deleted; this is
# syntax/trust-store test data, never a production trust anchor or credential.
CA_PEM = '''-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIUb9IXM08GIcY8+IAoVgCrtssTZwwwDQYJKoZIhvcNAQEL
BQAwKjEoMCYGA1UEAwwfU292YUdyaWQgcHVibGljIHRlc3QgZml4dHVyZSBDQTAe
Fw0yNjEwMjUxMjA4NTNaFw0zNjEwMjIxMjA4NTNaMCoxKDAmBgNVBAMMH1NvdmFH
cmlkIHB1YmxpYyB0ZXN0IGZpeHR1cmUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCuFaZrHJ2oJVu2C69CcYR1AJ+u5vTE0XBxo8sCZb93LaBpqTda
uKBhBsmr3Mxj1xi9MmEHpzc7nLRrLTOfN8LNa+kRBn9JL9Ou9xcRzRhlyAEKHKPl
UG/Ljv0YUvpwY/UmLhmNTtWhMY1m4DrWmdkFoQynSUh4udrWBYk0+KZWyJQrzC59
x5orlDU2JNqdJiHxdir7uqzlo6u/R7GQH3jTvGex5wO0BM+uuybEc6TpIzuqkusp
YZsUnyn/9kg/i0fGbI76pnej34KG4xhECyiBrqBcj+RZ/fqeeMDaYNLNNFwXwc8W
qjgD+5U66Pi7Sv2JtCXKETsJp3xZparGV8+ZAgMBAAGjMjAwMB0GA1UdDgQWBBSc
fk1wAfhLUvVLJ4cUi9EPsZoaXTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQBzf0tYk4E6q9ijLuPBC+tQ5T7ELg0I8pT8qrohZMrnEcMi42qBexlP
+gUEn+0pqlqfB+Ii6qwBo/lsfw8T9dH5wx33x0qprF3wQCSl2Qg7nmy6TufqOX8c
cPlgb2+gD03AJj46RdB7LzRYQ7GCuEsJ9PFrQDdhEakXAaZu+jOCV+GEIUtX59i4
SIcuINgsSxFfD7V1hNlHLDcje5gxpR4sHIYVGlXHEe72EQnJkMa7KvMEgAwWV8Zp
rpcV+XdKzqlp2xQtgNOehbqCambDvO9PZpN/9lIaKFeGh4FbjAT/m18jhNMg4AcE
9DqQT0zDD/eq+6r6w8oIRRkMqPw4AXdI
-----END CERTIFICATE-----
'''
PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPRTpJuN2rxjZZK9kkZoJM2cJk3IbxYhOaUdhiC9fGK2'
FINGERPRINT = 'SHA256:SrbhBlTOh2a/c4K39n6CIdF7RBBWV0Ajag8rJD7OXY0'
RID, EID, SID = (str(uuid.uuid4()) for _ in range(3))
CAS = {key: 'a' * 64 for key in CAS_FIELDS}


def target(**changes):
    return dict(request_id=RID, enrollment_id=EID, server_id=SID, phase='prepared',
        agent_token_sha256='b' * 64, ssh_public_key=PUBLIC_KEY, ssh_key_fingerprint=FINGERPRINT, local_port=None) | changes


def registration(**changes):
    return dict(id=EID, server_id=SID, name='Target', state='pending', revision=1, created_at=100, last_seen=None) | changes


class ProtocolTests(unittest.TestCase):
    def test_public_openssh_blob_matches_actual_ssh_keygen_fingerprint(self):
        self.assertEqual(public_key_fingerprint(PUBLIC_KEY), FINGERPRINT)
        for value in (PUBLIC_KEY+' comment', PUBLIC_KEY+'\n', 'restrict '+PUBLIC_KEY,
                      'ssh-rsa '+PUBLIC_KEY.split()[1], 'ssh-ed25519 '+base64.b64encode(b'x'*51).decode(),
                      PUBLIC_KEY[:-1], 'ssh-ed25519 !', None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ProtocolError):
                public_key_fingerprint(value)
        with self.assertRaises(ProtocolError): validate_target(target(ssh_key_fingerprint='SHA256:'+'a'*43))

    def test_public_ca_only_strict_certificate_validation_and_size(self):
        trust={'hub_host_key':PUBLIC_KEY,'hub_ca_pem':CA_PEM}
        self.assertEqual(validate_hub_trust(trust),trust)
        for value in ('not a certificate',CA_PEM+'-----BEGIN PRIVATE KEY-----\ncanary\n-----END PRIVATE KEY-----',
                      CA_PEM+'private response canary',CA_PEM*16,'\ud800'):
            with self.assertRaises(ProtocolError) as caught:
                validate_hub_trust(dict(trust,hub_ca_pem=value))
            self.assertNotIn('canary',str(caught.exception))

    def test_partial_credentials_are_only_prepared_preview_or_status(self):
        partial=target(agent_token_sha256='b'*64,ssh_public_key=None,ssh_key_fingerprint=None)
        for action in ('target-preview','target-status'):
            value={'protocol':1,'ok':True,'cas':CAS,'target':partial}
            if action=='target-preview':value['platform']={'ubuntu_version':'26.04','python_version':'3.14.0','systemd_version':'257'}
            else:value['services']={'tunnel':False,'agent':False}
            self.assertEqual(validate_reply(action,value)['target'],partial)
        with self.assertRaises(ProtocolError):validate_reply('target-prepare',{'protocol':1,'ok':True,'cas':CAS,'target':partial})
        with self.assertRaises(ProtocolError):validate_target(partial)
        with self.assertRaises(ProtocolError):validate_target(dict(partial,phase='registered',local_port=18767),allow_partial=True)
        with self.assertRaises(ProtocolError):validate_target(target(ssh_key_fingerprint=None),allow_partial=True)
        self.assertEqual(validate_target(target(local_port=18767)),target(local_port=18767))

    def test_all_success_shapes_and_identity_binding(self):
        identity={'protocol':1,'request_id':RID,'enrollment_id':EID,'server_id':SID}
        advanced=target(phase='active',local_port=18767)
        for action in ('target-transport','target-registered','target-activate'):
            reply={'protocol':1,'ok':True,'cas':CAS,'target':advanced,'services':{'tunnel':True,'agent':True}}
            if action=='target-transport':reply['tls_ready']=True
            self.assertEqual(validate_reply(action,reply,request=identity),reply)
            with self.assertRaises(ProtocolError):validate_reply(action,reply,request=dict(identity,server_id=str(uuid.uuid4())))
        preview={'protocol':1,'ok':True,'cas':CAS,'helper_v1':True,'hub_host_key':PUBLIC_KEY,'hub_ca_pem':CA_PEM}
        self.assertEqual(validate_reply('hub-preview',preview),preview)
        hub={'protocol':1,'ok':True,'cas':CAS,'enrollment_id':EID,'server_id':SID,'username':hub_username(SID),
             'ssh_key_fingerprint':FINGERPRINT,'authorized':True}
        self.assertEqual(validate_reply('hub-authorize',hub,request=identity),hub)
        unknown=dict(hub,ssh_key_fingerprint=None,authorized=False)
        self.assertEqual(validate_reply('hub-status',unknown,request=identity),unknown)
        with self.assertRaises(ProtocolError):validate_reply('hub-authorize',unknown,request=identity)
        with self.assertRaises(ProtocolError):validate_reply('hub-status',dict(hub,username='root'))
        for action,flag in (('target-remove','removed'),('hub-revoke','revoked')):
            value={'protocol':1,'ok':True,flag:True,'cleanup_required':False}
            self.assertEqual(validate_reply(action,value),value)
            with self.assertRaises(ProtocolError):validate_reply(action,dict(value,cleanup_required=True))

    def test_cas_service_types_extra_fields_and_raw_limits_fail_closed(self):
        for value in (dict(CAS,extra='secret'),dict(CAS,state_sha256=True),dict(CAS,state_sha256='A'*64)):
            with self.assertRaises(ProtocolError):validate_cas(value)
        good={'protocol':1,'ok':True,'cas':CAS,'target':None,'services':{'tunnel':False,'agent':False}}
        self.assertEqual(decode_reply('target-status',json.dumps(good).encode()),good)
        for value in (dict(good,secret='private-output-canary'),dict(good,protocol=True),
                      dict(good,services={'tunnel':0,'agent':False}),dict(good,services={'tunnel':True,'agent':False})):
            with self.assertRaises(ProtocolError):validate_reply('target-status',value)
        for raw in (b'x'*32769,b'{"protocol":1,"protocol":1}',b'private-output-canary',b'{} {}',b'['*1500+b']'*1500):
            with self.assertRaises(ProtocolError) as caught:decode_reply('target-status',raw)
            self.assertNotIn('private-output-canary',str(caught.exception))
        with self.assertRaises(HelperError) as caught:
            decode_reply('target-status',b'{"protocol":1,"ok":false,"error":"STALE_PREVIEW"}')
        self.assertEqual(caught.exception.code,'STALE_PREVIEW')
        with self.assertRaises(ProtocolError):decode_reply('target-status',b'{"protocol":1,"ok":false,"error":"private-output-canary"}')

    def test_request_unions_pin_target_registration_and_literal_reachable_hub(self):
        identity={'protocol':1,'request_id':RID,'enrollment_id':EID,'server_id':SID,'expected':CAS}
        transport=identity|{'hub_host':'8.8.8.8','hub_port':22,'local_port':18767,
                            'hub_host_key':PUBLIC_KEY,'hub_ca_pem':CA_PEM}
        self.assertEqual(validate_request('target-transport',transport),transport)
        for host in ('127.0.0.1','::ffff:127.0.0.1','0.0.0.0','::','224.0.0.1','ff02::1','home','fe80::1%eth0','x;id'):
            with self.subTest(host=host),self.assertRaises(ProtocolError):validate_request('target-transport',transport|{'hub_host':host})
        for change in ({'hub_port':True},{'local_port':1023},{'local_port':65536},{'command':'private-canary'}):
            with self.assertRaises(ProtocolError):validate_request('target-transport',transport|change)
        active=registration(state='active',last_seen=101)
        validate_request('target-registered',identity|{'registration':registration()})
        validate_request('target-activate',identity|{'registration':active})
        with self.assertRaises(ProtocolError):validate_request('target-activate',identity|{'registration':registration()})
        with self.assertRaises(ProtocolError):validate_request('target-registered',identity|{'registration':active|{'server_id':str(uuid.uuid4())}})
        for action in ('bad-action',None,[]):
            with self.assertRaises(ProtocolError):validate_request(action,identity)

    def test_stage_descriptor_has_no_arbitrary_path_or_implicit_execution_authority(self):
        identifier=uuid.uuid4().hex
        stage={'stage_id':identifier,'remote_dir':'/var/tmp/sovagrid-agent-enroll.'+identifier,'sha256':'a'*64,
               'source_manifest_sha256':'b'*64,'helper_sha256':'c'*64}
        self.assertEqual(validate_stage_descriptor(stage),stage)
        for change in ({'remote_dir':'/etc'},{'stage_id':'../escape'},{'remote_dir':stage['remote_dir']+'/source'},
                       {'helper_sha256':None},{'stage_id':str(uuid.uuid4())},{'owner':'root'}):
            with self.assertRaises(ProtocolError):validate_stage_descriptor(stage|change)

    def test_registration_state_revision_and_returned_data_are_independent(self):
        self.assertEqual(validate_registration(registration()),registration())
        for change in ({'revision':True},{'state':'cancelled'},{'state':'active'},
                       {'name':'\ud800'},{'last_seen':False},{'agent_token_sha256':'a'*64}):
            with self.assertRaises(ProtocolError):validate_registration(registration()|change)
        value={'protocol':1,'ok':True,'cas':dict(CAS),'target':target()}
        clean=validate_reply('target-prepare',value)
        value['cas']['state_sha256']='f'*64;value['target']['server_id']=str(uuid.uuid4())
        self.assertNotEqual(clean['cas']['state_sha256'],value['cas']['state_sha256'])
        self.assertEqual(clean['target']['server_id'],SID)


if __name__=='__main__':unittest.main()
