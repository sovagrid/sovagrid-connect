# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Interrupted SSH effects are reconciled, never represented as rollback."""
import copy
from dataclasses import dataclass
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from sovagrid_connect.agent_enrollment import AgentEnrollment, EnrollmentError, EnrollmentCancelled
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.enrollment_api import EnrollmentAPIError
from sovagrid_connect.enrollment_journal import EnrollmentJournal
from test_enrollment_journal import PUBLIC_CA, PUBLIC_KEY, FINGERPRINT


class Failure(RuntimeError):
    code = 'SSH_FAILED'


@dataclass
class Stage:
    data: dict
    def descriptor(self):
        return dict(self.data)


class World:
    def __init__(self):
        self.target = None; self.authorized = False; self.registration = None
        self.log = []; self.keys_created = 0; self.stage = None
        self.auto_active = True; self.fail_after = None; self.fail_before = None
        self.cancel_registration = None; self.cleanup_fail = False
        self.service_running = False; self.tunnel_running = False
        self.hub_fingerprint = None; self.hub_uid_present = False
        self.fail_after_registered_phase = False; self.fail_after_hub_entry = False
        self.require_service_when_polling = False
        self.verify_count = 0; self.revoke_at_verify = None
        self.versions = {'hub': 1, 'target': 1}
        self.trust = {'hub_host_key': PUBLIC_KEY, 'hub_ca_pem': PUBLIC_CA}

    def cas(self, role):
        return dict(source_manifest_sha256='1' * 64, features_sha256='2' * 64,
                    policy_sha256='3' * 64, state_sha256=f'{self.versions[role]:064x}')

    def api(self, tunnel):
        world = self
        class API:
            def login(self, user, password):
                world.log.append(('login', user))
            def adopt_bearer(self, token):
                world.log.append(('borrow-browser-session', len(token)))
            def verify(self):
                world.verify_count += 1
                if world.verify_count == world.revoke_at_verify:
                    raise EnrollmentAPIError('Session revoked', 401)
                world.log.append(('verify-admin',))
            def get(self, identifier):
                row = world.registration
                if row is None or row['id'] != identifier: return None
                if (world.require_service_when_polling and row['state']=='pending' and world.target
                        and world.target['phase']=='registered' and not world.service_running):
                    raise AssertionError('A journal phase is not proof that the Agent service started')
                if world.auto_active and row['state'] == 'pending' and world.target and world.service_running:
                    row.update(state='active', last_seen=101)
                return copy.deepcopy(row)
            def register(self, eid, sid, name, digest):
                world.log.append(('register', eid))
                if world.registration is None:
                    world.registration = dict(id=eid, server_id=sid, name=name, state='pending', revision=1, created_at=100, last_seen=None)
                if world.cancel_registration:
                    world.cancel_registration()
                return copy.deepcopy(world.registration)
            def cancel(self, eid, revision):
                world.log.append(('cancel', eid))
                if world.registration['state'] == 'active': raise EnrollmentAPIError('active', 409)
                world.registration.update(state='cancelled', revision=2)
                return copy.deepcopy(world.registration)
            def logout(self):
                world.log.append(('logout',))
        return API()

    def rpc(self, options, *, role, progress):
        world = self
        class RPC:
            def preflight(self):
                return dict(protocol=1, ok=True, euid=0, ubuntu_version='26.04', python_version='3.14', systemd_version='259')
            def stage_target(self, bundle, sha256, *, checkpoint):
                identifier = uuid.uuid4().hex
                stage = Stage(dict(remote_dir='/var/tmp/sovagrid-agent-enroll.' + identifier, stage_id=identifier,
                    sha256=sha256, source_manifest_sha256='1' * 64, helper_sha256='4' * 64))
                checkpoint(stage.descriptor())
                world.log.append(('stage-after-checkpoint',))
                world.stage = stage
                return stage
            def recover_stage(self, descriptor, *, for_cleanup=False):
                if world.stage is None:
                    error = Failure(); error.code = 'STAGE_NOT_FOUND'; raise error
                return Stage(descriptor)
            def cleanup_stage(self, stage):
                if world.cleanup_fail: raise Failure()
                world.log.append(('stage-removed',)); world.stage = None
            def cancel(self):
                pass
            def call(self, action, value, *, stage=None):
                world.log.append((action,))
                if world.fail_before == action:
                    world.fail_before = None; raise Failure()
                if action == 'hub-preview':
                    return dict(protocol=1, ok=True, helper_v1=True, cas=world.cas(role), **world.trust)
                if action == 'hub-status':
                    return dict(protocol=1, ok=True, cas=world.cas(role), authorized=world.authorized,
                                ssh_key_fingerprint=world.hub_fingerprint)
                if action == 'hub-authorize':
                    world.hub_fingerprint = value['ssh_key_fingerprint']; world.hub_uid_present = True
                    if world.fail_after_hub_entry:
                        world.fail_after_hub_entry = False; world.versions[role] += 1; raise Failure()
                    world.authorized = True
                elif action == 'hub-revoke':
                    world.authorized = False; world.hub_uid_present = False
                elif action == 'target-prepare' and world.target is None:
                    world.target = dict(request_id=value['request_id'], enrollment_id=str(uuid.uuid4()), server_id=str(uuid.uuid4()),
                        phase='prepared', agent_token_sha256='b' * 64, ssh_public_key=PUBLIC_KEY,
                        ssh_key_fingerprint=FINGERPRINT, local_port=None)
                    world.keys_created += 1
                elif action == 'target-transport':
                    world.target.update(phase='transport_ready', local_port=value['local_port']); world.tunnel_running = True
                elif action == 'target-registered':
                    if world.target['phase'] != 'active': world.target['phase'] = 'registered'
                    if world.fail_after_registered_phase:
                        world.fail_after_registered_phase = False; world.versions[role] += 1; raise Failure()
                    world.service_running = True
                elif action == 'target-activate':
                    if not world.service_running: raise Failure()
                    world.target['phase'] = 'active'
                elif action == 'target-remove':
                    world.target = None; world.service_running = False; world.tunnel_running = False
                if action not in ('target-preview', 'target-status', 'hub-status'):
                    world.versions[role] += 1
                if world.fail_after == action:
                    world.fail_after = None; raise Failure()
                if role == 'hub':
                    return dict(protocol=1, ok=True, cas=world.cas(role), authorized=world.authorized)
                return dict(protocol=1, ok=True, cas=world.cas(role), target=copy.deepcopy(world.target),
                            services={'tunnel': world.tunnel_running, 'agent': world.service_running})
        return RPC()


class EnrollmentControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.journal = EnrollmentJournal(self.root / 'records')
        self.world = World()
        self.tunnel = SimpleNamespace(alive=True, options=ConnectionOptions(host='hub.example', user='root'))
        self.source = {'path': str(self.root / 'bundle.tar.gz'), 'sha256': 'a' * 64}
        self.patch = patch('sovagrid_connect.agent_enrollment.source_bundle', return_value=(self.source, SimpleNamespace(commits={})))
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.controller = self.new_controller()

    def tearDown(self):
        self.directory.cleanup()

    def new_controller(self):
        return AgentEnrollment(self.tunnel, journal=self.journal, rpc_factory=self.world.rpc, api_factory=self.world.api)

    def prepare(self):
        return self.controller.prepare(target_options=ConnectionOptions(host='target.example', user='operator'),
            name='Target', bundle=self.source['path'], hub_host='192.0.2.1', hub_port=22, local_port=18767,
            username='owner', password='private-fixture-password')

    def test_prepare_is_review_only_and_records_no_password_or_plaintext_token(self):
        result = self.prepare()
        self.assertEqual(result['record']['phase'], 'prepared')
        self.assertIsNone(result['record']['target']); self.assertEqual(self.world.keys_created, 0)
        self.assertFalse(self.world.authorized); self.assertIsNone(self.world.registration)
        text = next((self.root / 'records').glob('*.json')).read_text()
        self.assertNotIn('private-fixture-password', text)
        self.assertNotIn('agent_token"', text); self.assertNotIn('PRIVATE KEY', text)
        self.assertIsNotNone(self.journal.load(result['record']['request_id'])['stage'])

    def test_prepare_borrows_browser_session_without_persisting_or_requiring_password(self):
        bearer = 'b' * 43
        result = self.controller.prepare(target_options=ConnectionOptions(host='target.example', user='operator'),
            name='Target', bundle=self.source['path'], hub_host='192.0.2.1', hub_port=22, local_port=18767,
            session_token=bearer)
        self.assertEqual(result['record']['phase'], 'prepared')
        self.assertIn(('borrow-browser-session', 43), self.world.log)
        self.assertNotIn(bearer, next((self.root / 'records').glob('*.json')).read_text())
        with self.assertRaises(EnrollmentError):
            self.new_controller().prepare(target_options=ConnectionOptions(host='target.example', user='operator'),
                name='Target', bundle=self.source['path'], hub_host='192.0.2.1', hub_port=22,
                local_port=18767, username='owner', password='fixture', session_token=bearer)

    def test_revocation_before_apply_does_not_prepare_remote_agent(self):
        self.prepare()
        self.world.revoke_at_verify = self.world.verify_count + 1
        with self.assertRaises(EnrollmentAPIError): self.controller.apply()
        self.assertIsNone(self.world.target)
        self.assertFalse(any(action in ('target-prepare', 'hub-authorize') for action, *_ in self.world.log))
        self.assertTrue(self.controller.record['cleanup_required'])

    def test_successful_order_activates_only_after_observed_metric_and_removes_temporary_package(self):
        self.prepare(); record = self.controller.apply()
        self.assertEqual(record['phase'], 'active'); self.assertFalse(record['cleanup_required'])
        self.assertEqual(record['registration']['state'], 'active'); self.assertIsNone(record['stage'])
        self.assertEqual(self.world.keys_created, 1)
        steps = [row[0] for row in self.world.log]
        self.assertLess(steps.index('target-transport'), steps.index('register'))
        self.assertLess(steps.index('register'), steps.index('target-registered'))
        self.assertLess(steps.index('target-registered'), steps.index('target-activate'))
        self.controller.close(); self.assertEqual(self.world.log[-1], ('logout',))

    def test_lost_registered_reply_resumes_without_new_key_or_server(self):
        request_id = self.prepare()['record']['request_id']; self.world.fail_after = 'target-registered'
        with self.assertRaises(Failure): self.controller.apply()
        old_target = copy.deepcopy(self.world.target)
        restarted = self.new_controller(); preview = restarted.resume(request_id, username='owner', password='fixture')
        self.assertFalse(preview['record']['cleanup_required'])
        result = restarted.apply()
        self.assertEqual(result['phase'], 'active'); self.assertEqual(self.world.keys_created, 1)
        for key in ('server_id', 'enrollment_id', 'agent_token_sha256', 'ssh_public_key'):
            self.assertEqual(result['target'][key], old_target[key])

    def test_resume_restarts_service_after_crash_between_registered_journal_and_start(self):
        request_id = self.prepare()['record']['request_id']
        self.world.fail_after_registered_phase = True
        with self.assertRaises(Failure): self.controller.apply()
        self.assertEqual(self.world.target['phase'], 'registered')
        self.assertFalse(self.world.service_running)
        self.assertEqual(self.world.registration['state'], 'pending')
        restarted = self.new_controller()
        preview = restarted.resume(request_id, username='owner', password='fixture')
        self.assertEqual(preview['record']['phase'], 'registered')
        before = len([step for step in self.world.log if step == ('target-registered',)])
        self.world.require_service_when_polling = True
        result = restarted.apply()
        self.assertEqual(result['phase'], 'active')
        self.assertTrue(self.world.service_running)
        self.assertEqual(self.world.keys_created, 1)
        self.assertEqual(len([step for step in self.world.log if step == ('target-registered',)]), before + 1)

    def test_cleanup_revokes_partial_hub_account_even_before_key_became_authorized(self):
        self.prepare(); self.world.fail_after_hub_entry = True
        with self.assertRaises(Failure): self.controller.apply()
        self.assertTrue(self.world.hub_uid_present)
        self.assertEqual(self.world.hub_fingerprint, FINGERPRINT)
        self.assertFalse(self.world.authorized)
        self.assertIsNone(self.world.registration)
        result = self.controller.cleanup()
        self.assertTrue(result['removed'])
        self.assertFalse(self.world.hub_uid_present)
        self.assertFalse(self.world.authorized)
        self.assertIsNone(self.world.target)
        self.assertIn(('hub-revoke',), self.world.log)
        self.assertEqual(self.journal.list(), [])

    def test_cancel_after_registration_cancels_mapping_before_removing_target_and_hub_key(self):
        self.prepare(); self.world.cancel_registration = self.controller.cancel
        with self.assertRaises(EnrollmentCancelled): self.controller.apply()
        result = self.controller.cleanup()
        self.assertTrue(result['removed']); self.assertIsNone(self.world.target); self.assertFalse(self.world.authorized)
        self.assertEqual(self.world.registration['state'], 'cancelled'); self.assertEqual(self.journal.list(), [])
        steps = [row[0] for row in self.world.log]
        self.assertLess(steps.index('cancel'), steps.index('target-remove'))
        self.assertLess(steps.index('target-remove'), steps.index('hub-revoke'))

    def test_cancel_after_first_metric_preserves_working_installation(self):
        self.prepare(); self.world.fail_after = 'target-registered'
        with self.assertRaises(Failure): self.controller.apply()
        result = self.controller.cleanup()
        self.assertTrue(result['active']); self.assertFalse(result['removed'])
        self.assertEqual(self.world.target['phase'], 'active'); self.assertTrue(self.world.authorized)
        self.assertNotIn(('target-remove',), self.world.log); self.assertNotIn(('hub-revoke',), self.world.log)

    def test_lost_target_remove_reply_can_finish_hub_cleanup_on_restart(self):
        request_id = self.prepare()['record']['request_id']; self.world.fail_before = 'target-registered'
        self.world.auto_active = False
        with self.assertRaises(Failure): self.controller.apply()
        self.world.fail_after = 'target-remove'
        with self.assertRaises(Failure): self.controller.cleanup()
        self.assertIsNone(self.world.target); self.assertTrue(self.world.authorized)
        restarted = self.new_controller(); result = restarted.resume(request_id, username='owner', password='fixture')
        self.assertTrue(result['record']['cleanup_required'])
        self.assertTrue(restarted.cleanup()['removed']); self.assertFalse(self.world.authorized)
        self.assertEqual(self.journal.list(), [])

    def test_changed_hub_pin_never_reauthorizes_or_restarts_target(self):
        request_id = self.prepare()['record']['request_id']
        self.world.trust['hub_ca_pem'] = PUBLIC_CA + '\n'
        restarted = self.new_controller()
        with self.assertRaisesRegex(EnrollmentError, 'изменился'):
            restarted.resume(request_id, username='owner', password='fixture')
        self.assertEqual(self.world.keys_created, 0); self.assertFalse(self.world.authorized)

    def test_resume_to_another_hub_is_refused_before_sending_the_password(self):
        request_id = self.prepare()['record']['request_id']
        self.tunnel.options = ConnectionOptions(host='another.example', user='root')
        before = len([item for item in self.world.log if item[0] == 'login'])
        restarted = self.new_controller()
        with self.assertRaisesRegex(EnrollmentError, 'тому же Hub'):
            restarted.resume(request_id, username='owner', password='private-fixture-password')
        self.assertEqual(len([item for item in self.world.log if item[0] == 'login']), before)
        self.assertEqual(self.world.keys_created, 0)

    def test_active_agent_is_reported_even_if_only_temporary_package_cleanup_failed(self):
        self.prepare(); self.world.cleanup_fail = True
        result = self.controller.apply()
        self.assertEqual(result['phase'], 'active'); self.assertTrue(result['cleanup_required'])
        self.assertTrue(self.world.authorized); self.assertIsNotNone(self.world.target)


if __name__ == '__main__':
    unittest.main()
