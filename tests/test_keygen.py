# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise actual OpenSSH output, cancellation and no-overwrite publication."""

from __future__ import annotations

import csv
import io
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from sovagrid_connect.keygen import (COMMENT, KeyGenerationError, KeyGenerator,
                                     _inspect_pair, _windows_tool, default_key_path)


TEST_PHRASE = "test-only-key-generation-phrase"


def decode_acl(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-16-le" if b"\0" in data[:256] else "utf-8-sig")


def acl_trustees(text: str, current_sid: str) -> set[str]:
    trustees = set(re.findall(r";;;([^)]*)\)", text))
    # SDDL serializes the built-in Administrator *account* (RID 500) as
    # LA. This is distinct from BA, the entire Administrators group.
    # https://learn.microsoft.com/windows/win32/secauthz/sid-strings
    if "LA" in trustees and re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-500", current_sid):
        trustees.remove("LA")
        trustees.add(current_sid)
    return trustees


def fixture_askpass(root: Path, *, empty=False) -> Path:
    if os.name != "nt":
        helper = root / "fixture-askpass"
        helper.write_text('#!/bin/sh\nprintf "%s\\n" "' + ("" if empty else TEST_PHRASE) + '"\n')
        helper.chmod(0o700)
        return helper
    # Use an actual executable: Windows OpenSSH cannot rely on POSIX shell
    # scripts for SSH_ASKPASS. The phrase is synthetic test data only.
    compiler = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        raise unittest.SkipTest("Windows C# fixture compiler is unavailable")
    source, helper = root / "Askpass.cs", root / "Askpass.exe"
    value = "" if empty else TEST_PHRASE
    source.write_text('using System; class Askpass { static void Main() { Console.WriteLine("' + value + '"); } }')
    subprocess.run([str(compiler), "/nologo", "/out:" + str(helper), str(source)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    return helper


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is required")
class KeyGenerationTests(unittest.TestCase):
    def test_unencrypted_pair_has_valid_public_key_fingerprint_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary), Path(temporary) / "new key"
            try:
                result = KeyGenerator().generate(output, encrypted=False)
            except KeyGenerationError as error:
                cause = error.__context__
                self.fail("Key generation OS diagnostic: errno=" + str(getattr(cause, "errno", None)) +
                          ", winerror=" + str(getattr(cause, "winerror", None)))
            self.assertEqual(result.private_path, output)
            self.assertEqual(result.public_path, root / "new key.pub")
            self.assertFalse(result.encrypted)
            derived = subprocess.check_output(["ssh-keygen", "-y", "-f", str(output)], stdin=subprocess.DEVNULL, timeout=10).decode().strip()
            self.assertEqual(derived.split()[:2], result.public_key.split()[:2])
            fingerprint = subprocess.check_output(["ssh-keygen", "-l", "-E", "sha256", "-f", str(result.public_path)], timeout=10).decode()
            self.assertIn(result.fingerprint, fingerprint)
            self.assertTrue(result.public_key.endswith(COMMENT))
            self.assertEqual(list(root.glob(".sovagrid-keygen-*")), [])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(result.public_path.stat().st_mode), 0o644)
            else:
                acl = root / "acl.txt"
                subprocess.run([_windows_tool("icacls.exe"), str(output), "/save", str(acl)],
                               check=True, stdout=subprocess.DEVNULL, timeout=10)
                entries = decode_acl(acl.read_bytes())
                who = subprocess.check_output([_windows_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"]).decode(errors="replace")
                sid = next(csv.reader(io.StringIO(who)))[1]
                self.assertNotIn(";;;WD)", entries)  # Everyone
                self.assertNotIn(";;;BU)", entries)  # Builtin Users
                self.assertNotIn(";;;AU)", entries)  # Authenticated Users
                self.assertEqual(acl_trustees(entries, sid), {sid})

    def test_encryption_uses_askpass_and_never_exposes_the_phrase_in_argv_or_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = fixture_askpass(root)
            captured = {}

            def launch(argv, **options):
                captured.update(argv=argv, options=options)
                return subprocess.Popen(argv, **options)

            result = KeyGenerator(popen=launch, askpass=lambda _directory: str(helper)).generate(root / "protected")
            self.assertTrue(result.encrypted)
            self.assertNotIn(TEST_PHRASE, str(captured))
            self.assertNotIn("-N", captured["argv"])
            self.assertEqual(captured["options"]["stdin"], subprocess.DEVNULL)
            self.assertEqual(captured["options"]["stdout"], subprocess.DEVNULL)
            self.assertEqual(captured["options"]["stderr"], subprocess.DEVNULL)
            self.assertEqual(captured["options"]["env"]["SSH_ASKPASS_REQUIRE"], "force")
            env = os.environ.copy()
            env.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force")
            derived = subprocess.check_output(["ssh-keygen", "-y", "-f", str(result.private_path)],
                stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=20)
            self.assertEqual(derived.decode().split()[:2], result.public_key.split()[:2])

    def test_empty_or_cancelled_askpass_cannot_silently_publish_an_unencrypted_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = fixture_askpass(root, empty=True)
            with self.assertRaisesRegex(KeyGenerationError, "не задана|отменён"):
                KeyGenerator(askpass=lambda _directory: str(helper)).generate(root / "protected")
            self.assertFalse((root / "protected").exists())
            self.assertFalse((root / "protected.pub").exists())
            self.assertEqual(list(root.glob(".sovagrid-keygen-*")), [])

    def test_existing_private_or_public_file_is_never_changed_or_sent_to_keygen(self):
        for existing in ("key", "key.pub"):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / existing).write_bytes(b"retain-existing-bytes")
                launch = mock.Mock()
                with self.assertRaisesRegex(KeyGenerationError, "уже существует"):
                    KeyGenerator(popen=launch).generate(root / "key", encrypted=False)
                launch.assert_not_called()
                self.assertEqual((root / existing).read_bytes(), b"retain-existing-bytes")

    @unittest.skipIf(os.name == "nt", "symlink creation needs optional Windows privileges")
    def test_dangling_symlink_is_an_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "key").symlink_to(root / "missing")
            with self.assertRaisesRegex(KeyGenerationError, "уже существует"):
                KeyGenerator().generate(root / "key", encrypted=False)
            self.assertTrue((root / "key").is_symlink())
            self.assertFalse((root / "missing").exists())

    def test_racing_private_destination_keeps_other_file_and_rolls_back_only_own_public_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = os.link

            def publish(source, target):
                if Path(target) == root / "key":
                    (root / "key").write_bytes(b"other-writer")
                return original(source, target)

            with mock.patch("sovagrid_connect.keygen.os.link", side_effect=publish):
                with self.assertRaisesRegex(KeyGenerationError, "Имя ключа занято"):
                    KeyGenerator().generate(root / "key", encrypted=False)
            self.assertEqual((root / "key").read_bytes(), b"other-writer")
            self.assertFalse((root / "key.pub").exists())
            self.assertEqual(list(root.glob(".sovagrid-keygen-*")), [])

    def test_partial_publish_failure_leaves_neither_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = os.link

            def publish(source, target):
                if Path(target) == root / "key":
                    raise OSError("filesystem does not support publication")
                return original(source, target)

            with mock.patch("sovagrid_connect.keygen.os.link", side_effect=publish):
                with self.assertRaises(KeyGenerationError):
                    KeyGenerator().generate(root / "key", encrypted=False)
            self.assertFalse((root / "key").exists())
            self.assertFalse((root / "key.pub").exists())

    def test_staged_public_key_must_match_the_private_containers_public_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            one = KeyGenerator().generate(root / "one", encrypted=False)
            two = KeyGenerator().generate(root / "two", encrypted=False)
            with self.assertRaisesRegex(KeyGenerationError, "корректную пару"):
                _inspect_pair(one.private_path, two.public_path, False)

    def test_worker_timeout_and_cancel_terminate_the_process_and_remove_staging(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                started, processes = threading.Event(), []

                def launch(_argv, **options):
                    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], **options)
                    processes.append(process)
                    started.set()
                    return process

                generator = KeyGenerator(popen=launch)
                errors = []

                def work():
                    try:
                        generator.generate(root / "key", encrypted=False, timeout=0.15 if not cancelled else 10)
                    except KeyGenerationError as error:
                        errors.append(str(error))

                worker = threading.Thread(target=work)
                worker.start()
                self.assertTrue(started.wait(3))
                if cancelled:
                    generator.cancel()
                worker.join(15)
                self.assertFalse(worker.is_alive())
                self.assertTrue(errors)
                self.assertIsNotNone(processes[0].poll())
                self.assertFalse((root / "key").exists())
                self.assertEqual(list(root.glob(".sovagrid-keygen-*")), [])

    def test_target_and_jump_suggestions_are_separate_and_pub_is_not_a_private_path(self):
        self.assertNotEqual(default_key_path("identity"), default_key_path("jump_identity"))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(KeyGenerationError, "окончания .pub"):
                KeyGenerator().generate(Path(temporary) / "key.pub", encrypted=False)

    def test_acl_inventory_accepts_windows_unicode_with_or_without_bom_and_utf8(self):
        text = "key\r\nD:P(A;;FA;;;S-1-5-21-123)\r\n"
        for encoding in ("utf-16", "utf-16-le", "utf-8", "utf-8-sig"):
            self.assertEqual(decode_acl(text.encode(encoding)), text)

    def test_acl_alias_only_represents_the_matching_administrator_account(self):
        sid = "S-1-5-21-123-456-789-500"
        self.assertEqual(acl_trustees("D:PAI(A;;FA;;;LA)", sid), {sid})
        self.assertEqual(acl_trustees("D:PAI(A;;FA;;;LA)", "S-1-5-21-123-456-789-1000"), {"LA"})
        self.assertEqual(acl_trustees("D:PAI(A;;FA;;;BA)", sid), {"BA"})


if __name__ == "__main__":
    unittest.main()
