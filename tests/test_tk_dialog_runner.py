# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise fixture lifetime ordering without importing Tk or opening windows."""
import gc
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import run_tk_dialogs as runner


class TkDialogRunnerTests(unittest.TestCase):
    def test_previous_case_cycle_is_finalized_on_main_thread_before_next_worker(self):
        events = []
        main_id = threading.get_ident()

        class WidgetCycle:
            def __init__(self):
                self.cycle = self

            def __del__(self):
                events.append(("finalized", threading.get_ident()))

        class PreviousCase(unittest.TestCase):
            def runTest(self):
                self.widget = WidgetCycle()
                self.case_cycle = self

        class NextCase(unittest.TestCase):
            def runTest(self):
                events.append(("before_worker", threading.get_ident()))

                def collect_in_worker():
                    gc.collect()
                    events.append(("worker_collected", threading.get_ident()))

                worker = threading.Thread(target=collect_in_worker)
                worker.start()
                worker.join(2)
                self.assertFalse(worker.is_alive())

        result = runner.run_suite(
            unittest.TestSuite([PreviousCase(), NextCase()]), stream=io.StringIO(),
        )
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 2)
        self.assertEqual(events[:2], [("finalized", main_id), ("before_worker", main_id)])
        self.assertEqual(events[2][0], "worker_collected")
        self.assertNotEqual(events[2][1], main_id)
        self.assertEqual(len(events), 3)

    def test_last_case_cycle_is_collected_after_suite_releases_it(self):
        finalized = []

        class LastCase(unittest.TestCase):
            def runTest(self):
                self.cycle = self

            def __del__(self):
                finalized.append(threading.get_ident())

        result = runner.run_suite(unittest.TestSuite([LastCase()]), stream=io.StringIO())
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(finalized, [threading.get_ident()])

    def test_result_preserves_test_failures_and_errors(self):
        def fail():
            raise AssertionError("fixture failure")

        def error():
            raise ValueError("fixture error")

        result = runner.run_suite(unittest.TestSuite([
            unittest.FunctionTestCase(fail), unittest.FunctionTestCase(error),
        ]), stream=io.StringIO())
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.testsRun, 2)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(len(result.errors), 1)

    def test_main_requires_explicit_gui_opt_in(self):
        with patch.dict(os.environ, {"SOVAGRID_GUI_TESTS": "0"}), \
                patch.object(runner, "run_suite") as run, patch("sys.stderr", io.StringIO()):
            self.assertEqual(runner.main(), 2)
        run.assert_not_called()

    def test_main_preserves_failure_exit_code_and_discovery_pattern(self):
        loader = Mock()
        result = Mock()
        result.wasSuccessful.return_value = False
        with patch.dict(os.environ, {"SOVAGRID_GUI_TESTS": "1"}), \
                patch.object(runner.unittest, "TestLoader", return_value=loader), \
                patch.object(runner, "run_suite", return_value=result) as run:
            self.assertEqual(runner.main(), 1)
        loader.discover.assert_called_once_with(str(runner.TEST_ROOT), pattern="test_*_dialog.py")
        run.assert_called_once_with(loader.discover.return_value)

    def test_main_discovers_real_matching_tests_and_returns_success(self):
        module_name = "test_sovagrid_runner_fixture_dialog"
        old_path = sys.path[:]
        try:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / (module_name + ".py")).write_text(
                    "import unittest\nclass Fixture(unittest.TestCase):\n"
                    "    def test_included(self): self.assertTrue(True)\n",
                    encoding="utf-8",
                )
                (directory / "test_sovagrid_runner_fixture_other.py").write_text(
                    "raise AssertionError('non-dialog fixture must not be imported')\n",
                    encoding="utf-8",
                )
                output = io.StringIO()
                with patch.dict(os.environ, {"SOVAGRID_GUI_TESTS": "1"}), \
                        patch.object(runner, "TEST_ROOT", directory), \
                        patch("sys.stderr", output):
                    self.assertEqual(runner.main(), 0)
                self.assertIn("Ran 1 test", output.getvalue())
        finally:
            sys.modules.pop(module_name, None)
            sys.path[:] = old_path

    def test_worker_cannot_run_the_tk_suite(self):
        errors = []

        def run_in_worker():
            try:
                runner.run_suite(unittest.TestSuite(), stream=io.StringIO())
            except RuntimeError as error:
                errors.append(str(error))

        worker = threading.Thread(target=run_in_worker)
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ["Tk dialog tests must run on the main thread"])


if __name__ == "__main__":
    unittest.main()
