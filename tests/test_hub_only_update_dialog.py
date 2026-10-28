# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real Tk review gates for the promoted local Hub updater."""

import os
from pathlib import Path
import time
import types
import unittest
from unittest.mock import Mock, patch

try:
    import tkinter as tk
except ImportError:
    tk = None


@unittest.skipUnless(tk is not None and os.environ.get('SOVAGRID_GUI_TESTS') == '1',
                     'actual Tk test; run under Xvfb with SOVAGRID_GUI_TESTS=1')
class HubOnlyUpdateDialogTests(unittest.TestCase):
    def test_preview_stage_and_close_leave_apply_and_timer_mutations_unrun(self):
        from sovagrid_connect.core import ConnectionOptions
        from sovagrid_connect.hub_only_update import (HubOnlyInstalled, HubOnlyPrepared, HubOnlyPreview)
        from sovagrid_connect.installer import BundleSummary, COMPONENTS
        from sovagrid_connect.promotion_protocol import PromotionState
        from sovagrid_connect import hub_only_update_dialog as module

        root = tk.Tk()
        self.addCleanup(root.destroy)
        root.geometry('500x350')
        root.update()
        options = ConnectionOptions(host='target.example.org', user='exampleuser',
                                    jump_host='relay.example.org', jump_user='relay').validated()
        state = PromotionState('activated', True, 'd' * 64, 'b' * 64, 'b' * 64,
                               'c432d4dc-3cf2-4929-947c-8869fb85bff9', None)
        installed = HubOnlyInstalled('b' * 64, state, {name: 'b' * 40 for name in COMPONENTS}, False)
        preview = HubOnlyPreview(options, BundleSummary(Path('/tmp/fixture.tar.gz'), 123, 260,
                                                         {name: 'a' * 40 for name in COMPONENTS}),
                                 'a' * 64, 'c' * 64, installed)
        prepared = HubOnlyPrepared(preview)
        controller = Mock()
        controller.preview.return_value = preview
        controller.stage.return_value = prepared
        controller.timer_status.return_value = None
        theme = types.SimpleNamespace(style_window=lambda _window: None, style_text=lambda _text: None)
        errors = []
        with patch.object(module, 'nearby_server_bundle', return_value=None), \
             patch.object(module, 'HubOnlyUpdateController', return_value=controller), \
             patch.object(module.messagebox, 'showerror', side_effect=lambda *args, **_kwargs: errors.append(args)):
            dialog = module.HubOnlyUpdateDialog(root, theme, options, lambda: None,
                                                approved_sha256='a' * 64)
            dialog.source.set('/tmp/fixture.tar.gz')
            dialog.window.geometry('660x460')
            root.update()
            self.assertIn('relay.example.org', str(dialog.route_label.cget('text')))
            self.assertEqual(str(dialog.stage_button.cget('state')), 'disabled')
            self.assertEqual(str(dialog.apply_button.cget('state')), 'disabled')
            dialog.check_button.invoke()
            deadline = time.monotonic() + 5
            while dialog.preview_result is None and time.monotonic() < deadline:
                root.update()
                dialog._pump()
                time.sleep(.01)
            self.assertIs(dialog.preview_result, preview)
            self.assertIn('a' * 64, dialog.details.get('1.0', 'end'))
            self.assertEqual(str(dialog.stage_button.cget('state')), 'normal')
            self.assertEqual(str(dialog.apply_button.cget('state')), 'disabled')
            dialog.stage_button.invoke()
            while dialog.prepared is None and time.monotonic() < deadline:
                root.update()
                dialog._pump()
                time.sleep(.01)
            self.assertIs(dialog.prepared, prepared)
            self.assertEqual(str(dialog.apply_button.cget('state')), 'normal')
            self.assertEqual(str(dialog.arm_button.cget('state')), 'disabled')
            self.assertEqual(errors, [])
            controller.stage.assert_called_once_with(Path('/tmp/fixture.tar.gz'), preview)
            controller.apply.assert_not_called()
            controller.arm.assert_not_called()
            dialog.close()


if __name__ == '__main__':
    unittest.main()
