# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The first-install download must be bounded and checked before SSH."""

from __future__ import annotations

import hashlib
import io
import os
import unittest
from unittest.mock import patch
from urllib.request import Request

from sovagrid_connect.installer import InstallError
from sovagrid_connect.server_bundle_download import (
    PUBLISHED_SERVER_SOURCE_URL, _ReleaseRedirectHandler, downloaded_server_bundle,
)


ASSET_URL = "https://release-assets.githubusercontent.com/github-production-release-asset/123/uuid?token=signed"


class Response(io.BytesIO):
    def __init__(self, data: bytes, url: str = ASSET_URL, **headers: str) -> None:
        super().__init__(data)
        self._url = url
        self.headers = headers

    def geturl(self) -> str:
        return self._url


class Opener:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class ServerBundleDownloadTests(unittest.TestCase):
    def test_download_checks_digest_layout_and_private_file_before_yield(self) -> None:
        payload = b"published fixture"
        opener = Opener(Response(payload, **{"Content-Length": str(len(payload))}))
        progress = []
        with patch("sovagrid_connect.server_bundle_download.PUBLISHED_SERVER_SOURCE_SHA256",
                   hashlib.sha256(payload).hexdigest()), \
             patch("sovagrid_connect.server_bundle_download.verify_bundle") as verify:
            with downloaded_server_bundle(opener=opener, progress=progress.append) as path:
                self.assertEqual(path.read_bytes(), payload)
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                verify.assert_called_once_with(path)
                saved = path
        self.assertFalse(saved.exists())
        self.assertEqual(opener.request.full_url, PUBLISHED_SERVER_SOURCE_URL)
        self.assertEqual(opener.request.get_header("Accept-encoding"), "identity")
        self.assertEqual(opener.timeout, 20)
        self.assertTrue(any("SHA-256" in item for item in progress))

    def test_wrong_digest_never_validates_or_yields(self) -> None:
        opener = Opener(Response(b"tampered"))
        with patch("sovagrid_connect.server_bundle_download.verify_bundle") as verify:
            with self.assertRaisesRegex(InstallError, "SHA-256"):
                with downloaded_server_bundle(opener=opener):
                    self.fail("unverified package was yielded")
        verify.assert_not_called()

    def test_rejects_unapproved_final_url_without_echoing_signed_query(self) -> None:
        opener = Opener(Response(b"data", "https://attacker.example/archive?token=secret"))
        with self.assertRaises(InstallError) as result:
            with downloaded_server_bundle(opener=opener):
                self.fail("unapproved URL was yielded")
        self.assertNotIn("secret", str(result.exception))

    def test_rejects_content_length_and_streaming_overflow(self) -> None:
        with self.assertRaisesRegex(InstallError, "64 МиБ"):
            with downloaded_server_bundle(opener=Opener(Response(b"x", **{"Content-Length": str(64 * 1024 * 1024 + 1)}))):
                self.fail("oversized package was yielded")
        with patch("sovagrid_connect.server_bundle_download.MAX_ARCHIVE_BYTES", 5):
            with self.assertRaisesRegex(InstallError, "64 МиБ"):
                with downloaded_server_bundle(opener=Opener(Response(b"123456"))):
                    self.fail("oversized package was yielded")

    def test_layout_failure_never_yields(self) -> None:
        payload = b"matching digest but invalid layout"
        with patch("sovagrid_connect.server_bundle_download.PUBLISHED_SERVER_SOURCE_SHA256",
                   hashlib.sha256(payload).hexdigest()), \
             patch("sovagrid_connect.server_bundle_download.verify_bundle",
                   side_effect=InstallError("invalid layout")):
            with self.assertRaisesRegex(InstallError, "invalid layout"):
                with downloaded_server_bundle(opener=Opener(Response(payload))):
                    self.fail("invalid package was yielded")

    def test_redirect_accepts_only_real_release_asset_host_and_path(self) -> None:
        handler = _ReleaseRedirectHandler()
        initial = Request(PUBLISHED_SERVER_SOURCE_URL)
        accepted = handler.redirect_request(initial, None, 302, "Found", {}, ASSET_URL)
        self.assertEqual(accepted.full_url, ASSET_URL)
        for url in (
            "http://release-assets.githubusercontent.com/github-production-release-asset/123/uuid",
            "https://attacker.example/github-production-release-asset/123/uuid",
            "https://release-assets.githubusercontent.com/other-path/123",
            "https://user@release-assets.githubusercontent.com/github-production-release-asset/123/uuid",
        ):
            with self.subTest(url=url), self.assertRaises(InstallError):
                _ReleaseRedirectHandler().redirect_request(initial, None, 302, "Found", {}, url)


if __name__ == "__main__":
    unittest.main()
