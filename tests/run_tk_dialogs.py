# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Run opted-in Tk tests with old fixture cycles collected on the main thread."""
import gc
import os
from pathlib import Path
import sys
import threading
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_ROOT = PROJECT_ROOT / "tests"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _require_main_thread():
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Tk dialog tests must run on the main thread")


class MainThreadGCResult(unittest.TextTestResult):
    def startTest(self, test):
        _require_main_thread()
        # TestSuite has now released the preceding case. Its destroyed Tk root
        # may still be held in cycles; collect those before a new worker starts.
        gc.collect()
        super().startTest(test)


def run_suite(suite, *, stream=None):
    _require_main_thread()
    try:
        return unittest.TextTestRunner(
            stream=stream, verbosity=2, resultclass=MainThreadGCResult,
        ).run(suite)
    finally:
        gc.collect()


def main():
    if os.environ.get("SOVAGRID_GUI_TESTS") != "1":
        print("Set SOVAGRID_GUI_TESTS=1 to run real Tk dialog tests.", file=sys.stderr)
        return 2
    _require_main_thread()
    suite = unittest.TestLoader().discover(str(TEST_ROOT), pattern="test_*_dialog.py")
    return 0 if run_suite(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
