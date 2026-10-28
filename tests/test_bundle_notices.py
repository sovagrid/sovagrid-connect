# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Packaging checks that prevent mismatched or silently omitted native notices."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "bundle" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_script("collect_linux_native_notices")
packager = load_script("package_notices")
windows = load_script("normalize_windows_runtime")


class NativeNoticeTests(unittest.TestCase):
    def test_debian_copyright_sentence_punctuation_is_not_part_of_filename(self):
        self.assertEqual(collector.referenced_common_licenses(
            "See /usr/share/common-licenses/GPL-2.\n"
            "And `/usr/share/common-licenses/LGPL-2.1`, or /usr/share/common-licenses/Apache-2.0."
        ), {"GPL-2", "LGPL-2.1", "Apache-2.0"})

    def test_library_inventory_keeps_blt_and_openssl_and_rejects_differing_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("libBLT.2.5.so.8.6", "libcrypto.so.3", "libtcl8.6.so"):
                (root / name).write_bytes(b"native")
            (root / "not-a-library.txt").write_text("ignored")
            self.assertEqual(set(collector.bundled_libraries(root)),
                             {"libBLT.2.5.so.8.6", "libcrypto.so.3", "libtcl8.6.so"})
            other = root / "second"
            other.mkdir()
            (other / "libcrypto.so.3").write_bytes(b"different")
            with self.assertRaisesRegex(RuntimeError, "different hashes"):
                collector.resolve_library("libcrypto.so.3", [root / "libcrypto.so.3", other / "libcrypto.so.3"], {})

    def test_modified_rpath_uses_elf_build_id_and_unknown_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, host = root / "bundle.so", root / "host.so"
            bundle.write_bytes(b"rewritten rpath")
            host.write_bytes(b"original rpath")
            with patch.object(collector, "elf_build_id", return_value="abcdef"):
                self.assertEqual(collector.resolve_library("libx.so", [bundle], {"libx.so": [host]}),
                                 (host.resolve(), "elf_build_id"))
            with patch.object(collector, "elf_build_id", return_value=None), \
                    patch.object(Path, "rglob", return_value=iter(())):
                with self.assertRaisesRegex(RuntimeError, "no matching installed library"):
                    collector.resolve_library("libx.so", [bundle], {"libx.so": [host]})

    def test_collector_refuses_output_inside_distribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(sys, "argv", ["collect", "--dist", str(root), "--output", str(root / "notices")]), \
                    patch.object(sys, "platform", "linux"), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    collector.main()
            self.assertEqual(error.exception.code, 2)
            self.assertFalse((root / "notices").exists())

    def test_runtime_drift_is_refused_before_notices_are_copied(self):
        fake_tk = types.SimpleNamespace(Tcl=lambda: types.SimpleNamespace(call=lambda *args: "8.6.18"))
        fake_installer = types.SimpleNamespace(__version__="6.22.3")
        with patch.dict(sys.modules, {"tkinter": fake_tk, "PyInstaller": fake_installer}), \
                patch.object(packager.platform, "system", return_value="Darwin"), \
                patch.object(packager.platform, "python_version", return_value="3.13.16"), \
                patch.object(packager.ssl, "OPENSSL_VERSION", "OpenSSL 3.5.9 9 Jun 2026"):
            record = packager.runtime_inventory()
            self.assertEqual(record["python"], "3.13.16")
            self.assertIn("CPython-3.13.16-LICENSE", record["static_notices_sha256"])
            with patch.object(packager.platform, "python_version", return_value="3.13.17"):
                with self.assertRaisesRegex(RuntimeError, "need a notice audit"):
                    packager.runtime_inventory()

    def test_windows_uses_unmodified_redist_copy_and_removes_only_system_dlls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            source = root / "VC" / "Redist" / "MSVC" / "14.44.1" / "x64" / "Microsoft.VC143.CRT" / "VCRUNTIME140.dll"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"canonical official redistributable")
            for name in ("CLI", "GUI", "Askpass"):
                runtime = dist / name / "_internal"
                runtime.mkdir(parents=True)
                (runtime / "VCRUNTIME140.dll").write_bytes(b"older")
                (runtime / "api-ms-win-crt-runtime-l1-1-0.dll").write_bytes(b"system")
                (runtime / "ucrtbase.dll").write_bytes(b"system")
                (runtime / "libcrypto-3.dll").write_bytes(b"keep")
            manifest = root / "build" / "windows-runtime.json"
            with patch.object(windows, "DIST", dist), patch.object(windows, "MANIFEST", manifest), \
                    patch.object(windows.platform, "system", return_value="Windows"), \
                    patch.object(windows, "redist_vcruntime", return_value=source), \
                    contextlib.redirect_stdout(io.StringIO()):
                windows.main()
            record = json.loads(manifest.read_text())
            self.assertEqual(len(record["vc_runtime"]["destinations"]), 3)
            self.assertEqual(len(record["system_ucrt"]["removed_app_local_dlls"]), 6)
            for runtime in dist.rglob("_internal"):
                self.assertEqual((runtime / "VCRUNTIME140.dll").read_bytes(), source.read_bytes())
                self.assertEqual((runtime / "libcrypto-3.dll").read_bytes(), b"keep")
                self.assertFalse((runtime / "ucrtbase.dll").exists())


if __name__ == "__main__":
    unittest.main()
