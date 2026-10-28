# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Tk event-loop checks; CI opts in under Xvfb, without a browser."""
import copy
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sovagrid_connect.agent_enrollment import AgentEnrollment
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.enrollment_journal import EnrollmentJournal
from test_agent_enrollment import World

GUI_TESTS = os.environ.get("SOVAGRID_GUI_TESTS") == "1"
if GUI_TESTS:
    import tkinter as tk
    from sovagrid_connect.enrollment_dialog import EnrollmentDialog


class Theme:
    def style_window(self, window):
        pass
    def style_text(self, widget):
        pass


@unittest.skipUnless(GUI_TESTS, "Tk display test; run with SOVAGRID_GUI_TESTS=1 under Xvfb")
class EnrollmentDialogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.journal = EnrollmentJournal(self.base / 'records')
        self.world = World()
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.root.destroy)
        self.callbacks = []
        self.root.report_callback_exception = lambda *args: self.callbacks.append(args)
        self.closed = []
        self.controllers = []
        self.credential_references = []
        self.gate = None
        self.entered = threading.Event()
        self.tunnel = SimpleNamespace(alive=True, options=ConnectionOptions(host='hub.example', user='root'))
        source = {'path': str(self.base / 'bundle.tar.gz'), 'sha256': 'a' * 64}
        mock = patch('sovagrid_connect.agent_enrollment.source_bundle', return_value=(source, SimpleNamespace(commits={})))
        mock.start()
        self.addCleanup(mock.stop)
        owner = self
        class Controller(AgentEnrollment):
            def prepare(self, **kwargs):
                owner.credential_references.append(kwargs['credentials'])
                owner.entered.set()
                if owner.gate is not None:
                    owner.gate.wait(3)
                return super().prepare(**kwargs)
        def factory(tunnel, *, journal, progress):
            controller = Controller(tunnel, journal=journal, progress=progress,
                                    rpc_factory=self.world.rpc, api_factory=self.world.api)
            self.controllers.append(controller)
            return controller
        self.dialog = EnrollmentDialog(self.root, Theme(), self.tunnel, lambda: self.closed.append(True),
                                       journal=self.journal, controller_factory=factory)
        for name, value in {'name': 'Target', 'host': 'target.example', 'bundle': source['path'],
                            'hub_host': '192.0.2.1', 'username': 'owner', 'password': 'fixture-ui-private'}.items():
            self.dialog.fields[name].set(value)

    def until(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.01)
        self.root.update()
        self.assertTrue(predicate(), 'Tk worker did not finish')
        self.assertEqual(self.callbacks, [])

    def check(self):
        self.dialog.check_button.invoke()
        self.until(lambda: not self.dialog.busy)
        self.assertTrue(self.dialog.reviewed, self.dialog.status.get())

    def test_real_check_clears_password_and_freezes_saved_endpoints_before_explicit_apply(self):
        self.check()
        self.assertEqual(self.dialog.fields['password'].get(), '')
        self.assertEqual(self.credential_references, [{}])
        self.assertEqual(str(self.dialog.entries['host'].cget('state')), 'disabled')
        self.assertEqual(str(self.dialog.entries['identity'].cget('state')), 'normal')
        self.assertIsNone(self.world.target)
        self.assertNotIn('fixture-ui-private', self.dialog.preview.get('1.0', 'end'))
        self.assertIn('192.0.2.1:22', self.dialog.preview.get('1.0', 'end'))
        self.dialog.apply_button.invoke()
        self.until(lambda: not self.dialog.busy)
        self.assertEqual(self.dialog.controller.record['phase'], 'active')
        self.assertIn('прислал измерение', self.dialog.status.get())
        self.dialog.close()
        self.until(lambda: self.dialog.closed)
        self.assertEqual(self.world.log[-1], ('logout',))
        self.assertEqual(self.closed, [True])

    def test_switching_selection_never_cleans_the_previous_visible_server(self):
        self.check()
        old_record = copy.deepcopy(self.dialog.controller.record)
        self.dialog.selection.set('Новая установка')
        self.dialog._select_record()
        self.assertEqual(str(self.dialog.cleanup_button.cget('state')), 'disabled')
        with patch('sovagrid_connect.enrollment_dialog.messagebox.askyesno') as confirm:
            self.dialog.request_cleanup()
            confirm.assert_not_called()
        self.assertIsNotNone(self.journal.load(old_record['request_id']))
        self.assertNotIn(('target-remove',), self.world.log)
        self.dialog.close()
        self.until(lambda: self.dialog.closed)

    def test_close_waits_for_cancelled_worker_and_logs_out_without_running_cleanup_concurrently(self):
        self.gate = threading.Event()
        self.dialog.check_button.invoke()
        self.assertTrue(self.entered.wait(1))
        self.dialog.close()
        self.assertTrue(self.dialog.busy)
        self.assertFalse(self.dialog.closed)
        self.assertEqual(self.closed, [])
        self.gate.set()
        self.until(lambda: self.dialog.closed)
        self.assertEqual(self.world.log[-1], ('logout',))
        self.assertNotIn(('target-remove',), self.world.log)
        self.assertEqual(self.closed, [True])


if __name__ == '__main__':
    unittest.main()
