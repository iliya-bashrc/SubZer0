"""Policy tests for verify_pages.py — adapted for the Next.js SubZer0 repo.

Kept from the legacy suite: origin pinning, path-escape rejection, and
cross-origin redirect rejection (pure logic, no network). Tests that checked
legacy static-site assets (app.js-era SITE_ASSETS, rebuild.css palette,
README telegram badges) were removed: those files do not exist in this repo.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_pages as pages  # noqa: E402


class PagesVerifierPolicyTests(unittest.TestCase):
    def test_only_the_configured_https_pages_origin_is_accepted(self):
        base, origin, path = pages._validate_base_url(pages.DEFAULT_BASE_URL)
        self.assertEqual(base, pages.DEFAULT_BASE_URL)
        self.assertEqual(origin, ("https", "iliya-bashrc.github.io", None))
        self.assertEqual(path, "/SubZer0/")
        for value in (
            "http://iliya-bashrc.github.io/SubZer0/",
            "https://attacker.example/SubZer0/",
            "https://iliya-bashrc.github.io/Other/",
            "https://user:pass@iliya-bashrc.github.io/SubZer0/",
            "https://iliya-bashrc.github.io/SubZer0/?next=https://attacker.example/",
        ):
            with self.subTest(value=value), self.assertRaises(pages.PagesVerificationError):
                pages._validate_base_url(value)

    def test_resource_paths_cannot_escape_the_site_root(self):
        for path in ("../manifest.json", "data/../../secret", "/outside.json", "data\\escape.json"):
            with self.subTest(path=path), self.assertRaises(pages.PagesVerificationError):
                pages._fetch(None, pages.DEFAULT_BASE_URL, path, 1024)

    def test_cross_origin_redirects_are_rejected(self):
        _, origin, path = pages._validate_base_url(pages.DEFAULT_BASE_URL)
        handler = pages._SameOriginRedirect(origin, path)
        request = pages.urllib.request.Request(pages.DEFAULT_BASE_URL + "snapshot/manifest.json")
        with self.assertRaises(pages.PagesVerificationError):
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://attacker.example/exfiltrate"
            )


if __name__ == "__main__":
    unittest.main()
