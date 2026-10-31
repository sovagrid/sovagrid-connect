# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Execute the remote command wrapper without granting local test privileges."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from sovagrid_connect.installer import _privileged_command


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "requires a POSIX shell")
class PrivilegedCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sovagrid sudo wrapper ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.probe = self.root / "id probe"
        self.sudo = self.root / "sudo helper"
        self.arguments = self.root / "sudo-args.json"

    def run_command(self, command, payload=b"", *, root=False, denied=False):
        self.probe.write_text("#!/bin/sh\nprintf '%s\\n' " + ("0" if root else "1000") + "\n")
        self.probe.chmod(0o700)
        self.sudo.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            f"open({str(self.arguments)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
            "assert sys.argv[1:3] == ['-n', '--']\n"
            + ("raise SystemExit(77)\n" if denied else "os.execv(sys.argv[3], sys.argv[3:])\n"))
        self.sudo.chmod(0o700)
        wrapped = _privileged_command(command, uid_probe=(str(self.probe),),
                                       sudo_executable=str(self.sudo))
        return subprocess.run(["/bin/sh", "-c", wrapped], input=payload,
                              capture_output=True, check=False, timeout=10)

    def test_binary_input_is_unchanged_and_sudo_cannot_prompt(self):
        payload = bytes(range(256)) * 1000
        command = shlex.join([sys.executable, "-I", "-c",
                              "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"])
        result = self.run_command(command, payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(json.loads(self.arguments.read_text())[:4], ["-n", "--", "/bin/sh", "-c"])

    def test_actual_root_branch_avoids_sudo(self):
        result = self.run_command("printf 'already-root'", root=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"already-root")
        self.assertFalse(self.arguments.exists())

    def test_denied_sudo_never_executes_the_payload(self):
        marker = self.root / "must-not-exist"
        command = shlex.join([sys.executable, "-I", "-c",
                              f"open({str(marker)!r}, 'wb').write(b'executed')"])
        result = self.run_command(command, b"not a sudo password\n", denied=True)
        self.assertEqual(result.returncode, 77)
        self.assertFalse(marker.exists())
        self.assertEqual(result.stdout, b"")

    def test_fixed_shell_argument_preserves_quotes_and_metacharacters(self):
        literal = "quotes ' and \" and $HOME and $(touch forbidden) and a newline\nend"
        command = shlex.join([sys.executable, "-I", "-c", "import sys; print(sys.argv[1], end='')", literal])
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode(), literal)


if __name__ == "__main__":
    unittest.main()
