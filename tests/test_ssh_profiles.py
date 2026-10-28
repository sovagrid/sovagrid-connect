# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sovagrid_connect.core import _ssh_config
from sovagrid_connect.ssh_profiles import OpenSSHProfiles, ProfileImportError, _config_words


class OpenSSHProfileTests(unittest.TestCase):
    def test_config_tokenizer_preserves_windows_paths_and_embedded_hash(self) -> None:
        cases = (
            (r'IdentityFile C:\Users\operator\key', r'C:\Users\operator\key'),
            (r'IdentityFile "C:\Users\operator\target key"', r'C:\Users\operator\target key'),
            (r'IdentityFile /tmp/key#label # comment', '/tmp/key#label'),
            (r'IdentityFile /tmp/target\ key', '/tmp/target key'),
            (r'IdentityFile "/tmp/target\ key"', r'/tmp/target\ key'),
        )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config'
            for line, expected in cases:
                with self.subTest(line=line):
                    self.assertEqual(_config_words(line), ['IdentityFile', expected])
                    if shutil.which('ssh'):
                        config.write_text('Host fixture\n HostName example.org\n User operator\n ' + line + '\n')
                        actual = subprocess.run(['ssh', '-G', '-F', str(config), 'fixture'],
                                                capture_output=True, text=True, timeout=5, check=True)
                        self.assertIn('identityfile ' + expected, actual.stdout.splitlines())
        with self.assertRaises(ValueError):
            _config_words('IdentityFile "unclosed')

    def test_optional_equals_spacing_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config'
            config.write_text('Host fixture\n HostName =example.org\n User=operator\n Port = 2222\n')
            profile = OpenSSHProfiles(config).profile('fixture')
            self.assertEqual(profile.errors, ())
            self.assertEqual((profile.connection.host, profile.connection.user, profile.connection.port),
                             ('example.org', 'operator', 2222))

    def test_imports_target_and_jump_alias_with_separate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_key = root / "target key"
            jump_key = root / "jump key"
            target_key.write_text("fixture")
            jump_key.write_text("fixture")
            (root / "config").write_text(
                f'Host home\n  HostName 127.0.0.1\n  User homeuser\n  Port 2223\n'
                f'  IdentityFile "{target_key}"\n  IdentitiesOnly yes\n'
                f'  HostKeyAlias home-via-vps\n  ProxyJump relay\n'
                f'Host relay\n  HostName relay.example.org\n  User operator\n  Port 2202\n'
                f'  IdentityFile "{jump_key}"\n  IdentitiesOnly yes\n'
                f'  HostKeyAlias relay-key\n', encoding="utf-8"
            )
            catalog = OpenSSHProfiles(root / "config")
            self.assertEqual(catalog.aliases, ("home", "relay"))
            profile = catalog.profile("home")
            self.assertEqual(profile.errors, ())
            self.assertEqual(profile.warnings, ())
            options = profile.connection
            self.assertIsNotNone(options)
            self.assertEqual((options.host, options.user, options.port), ("127.0.0.1", "homeuser", 2223))
            self.assertEqual((options.jump_host, options.jump_user, options.jump_port),
                             ("relay.example.org", "operator", 2202))
            self.assertEqual(options.identity, target_key.resolve().as_posix())
            self.assertEqual(options.jump_identity, jump_key.resolve().as_posix())
            config = _ssh_config(options, confirm_host_keys=True)
            self.assertIn("StrictHostKeyChecking ask", config)
            self.assertIn("ProxyJump sovagrid-jump", config)
            self.assertIn("HostKeyAlias home-via-vps", config)
            self.assertIn("HostKeyAlias relay-key", config)
            if shutil.which("ssh"):
                generated = root / "generated"
                generated.write_text(config, encoding="utf-8")
                for host, expected_alias in (("sovagrid-target", "home-via-vps"),
                                             ("sovagrid-jump", "relay-key")):
                    resolved = subprocess.run(["ssh", "-G", "-F", str(generated), host],
                                              capture_output=True, text=True, timeout=5, check=True)
                    self.assertIn(f"hostkeyalias {expected_alias}", resolved.stdout)
                    self.assertIn("stricthostkeychecking ask", resolved.stdout)

    def test_include_order_wildcards_negation_and_ignored_directives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "extra.conf").write_text(
                "Host app.example.org skip.example.org\n  User first\n"
                "Host *.example.org !skip.example.org\n  Port 2222\n",
                encoding="utf-8",
            )
            (root / "config").write_text(
                "Include extra.conf\nHost *\n  User second\n  ForwardAgent yes\n",
                encoding="utf-8",
            )
            catalog = OpenSSHProfiles(root / "config")
            self.assertEqual(catalog.aliases, ("app.example.org", "skip.example.org"))
            app = catalog.profile("app.example.org")
            skipped = catalog.profile("skip.example.org")
            self.assertEqual((app.connection.user, app.connection.port), ("first", 2222))
            self.assertEqual((skipped.connection.user, skipped.connection.port), ("first", 22))
            self.assertTrue(any("forwardagent" in message for message in app.warnings))
            self.assertTrue(any("forwardagent" in message for message in skipped.warnings))

    def test_include_inside_host_does_not_expose_unrelated_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").write_text(
                "Host foo\n  Include scoped.conf\n  User operator\n"
                "Host public\n  HostName public.example.org\n  User operator\n",
                encoding="utf-8",
            )
            (root / "scoped.conf").write_text(
                "HostName foo.example.org\nHost private\n  HostName private.example.org\n",
                encoding="utf-8",
            )
            catalog = OpenSSHProfiles(root / "config")
            self.assertEqual(catalog.aliases, ("foo", "public"))
            self.assertEqual(catalog.profile("foo").connection.host, "foo.example.org")
            self.assertEqual(catalog.profile("public").connection.host, "public.example.org")
            with self.assertRaises(ProfileImportError):
                catalog.profile("private")

    def test_proxycommand_and_match_exec_are_never_run_and_block_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "executed"
            (root / "config").write_text(
                f"Host target\n  HostName example.org\n  ProxyCommand touch {marker}\n"
                f"Match exec touch {marker}\n  User attacker\n",
                encoding="utf-8",
            )
            with patch.object(subprocess, "run", side_effect=AssertionError("SSH should not execute")):
                profile = OpenSSHProfiles(root / "config").profile("target")
            self.assertIsNone(profile.connection)
            self.assertTrue(any("proxycommand" in message for message in profile.errors))
            self.assertTrue(any("Match" in message for message in profile.errors))
            self.assertFalse(marker.exists())
            self.assertFalse(any(str(marker) in message for message in profile.errors))

    def test_inline_proxyjump_and_unsupported_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").write_text(
                "Host direct\n  HostName example.org\n  User target\n"
                "  ProxyJump jumpuser@relay.example.org:2022\n"
                "Host chain\n  HostName example.org\n  User target\n"
                "  ProxyJump first.example.org,second.example.org\n",
                encoding="utf-8",
            )
            catalog = OpenSSHProfiles(root / "config")
            direct = catalog.profile("direct")
            self.assertEqual((direct.connection.jump_host, direct.connection.jump_user,
                              direct.connection.jump_port), ("relay.example.org", "jumpuser", 2022))
            chain = catalog.profile("chain")
            self.assertIsNone(chain.connection)
            self.assertTrue(any("нескольких" in message for message in chain.errors))

    def test_multiple_identity_and_missing_key_cannot_be_silently_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "id_ed25519"
            key.write_text("fixture")
            (root / "config").write_text(
                f"Host many\n  HostName example.org\n  User me\n"
                f"  IdentityFile {key}\n  IdentityFile {key}\n"
                f"Host missing\n  HostName example.org\n  User me\n"
                f"  IdentityFile {root / 'missing'}\n", encoding="utf-8"
            )
            catalog = OpenSSHProfiles(root / "config")
            self.assertIsNone(catalog.profile("many").connection)
            self.assertTrue(any("Несколько IdentityFile" in item for item in catalog.profile("many").errors))
            missing = catalog.profile("missing")
            self.assertIsNone(missing.connection)
            self.assertTrue(any("file does not exist" in item for item in missing.errors))

    def test_identity_agent_difference_is_visible_and_proxyjump_none_is_direct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "key"
            key.write_text("fixture")
            (root / "config").write_text(
                f"Host direct\n  HostName example.org\n  User me\n"
                f"  IdentityFile {key}\n  ProxyJump none\n",
                encoding="utf-8",
            )
            profile = OpenSSHProfiles(root / "config").profile("direct")
            self.assertEqual(profile.errors, ())
            self.assertIsNone(profile.connection.jump_host)
            self.assertTrue(any("другие ключи агента" in item for item in profile.warnings))

    def test_include_cycle_and_unsupported_token_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_text("Include b\n", encoding="utf-8")
            (root / "b").write_text("Include a\n", encoding="utf-8")
            with self.assertRaisesRegex(ProfileImportError, "Циклический Include"):
                OpenSSHProfiles(root / "a")
            (root / "config").write_text("Host test\n  HostName %C.example.org\n", encoding="utf-8")
            profile = OpenSSHProfiles(root / "config").profile("test")
            self.assertIsNone(profile.connection)
            self.assertTrue(any("%-токен" in item for item in profile.errors))


if __name__ == "__main__":
    unittest.main()
