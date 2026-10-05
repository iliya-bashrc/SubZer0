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

    def test_deployment_verification_covers_every_application_asset(self):
        snapshot_root = Path(__file__).resolve().parents[1] / "snapshot"
        manifest_bytes = (snapshot_root / "manifest.json").read_bytes()
        manifest = pages.verifier._loads(manifest_bytes, "manifest.json")
        paths = {resource[0] for resource in pages._resources(snapshot_root, manifest)}
        self.assertTrue(set(pages.SITE_ASSETS).issubset(paths))
        self.assertIn("sw.js", pages.SITE_ASSETS)
        self.assertIn("assets/telegram-mark.svg", pages.SITE_ASSETS)
        self.assertIn("assets/telegram-bugcod3.svg", pages.SITE_ASSETS)
        self.assertIn("assets/telegram-rootaccessclub.svg", pages.SITE_ASSETS)
        self.assertIn("snapshot/data/overview.json", paths)
        self.assertIn("snapshot/data/epss.json", paths)

    def test_telegram_mark_uses_the_existing_steel_palette(self):
        root = Path(__file__).resolve().parents[1]
        styles = (root / "styles.css").read_text(encoding="utf-8")
        mark = (root / "assets/telegram-mark.svg").read_text(encoding="utf-8")
        self.assertIn("--steel-bright: #64747b;", styles)
        self.assertIn("--steel-edge: #3b4a51;", styles)
        self.assertIn('stop-color="#64747b"', mark)
        self.assertIn('stop-color="#3b4a51"', mark)

    def test_readme_telegram_images_resolve_to_their_channel_destinations(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        expected = (
            ("[![Join @RootAccessClub on Telegram](assets/telegram-rootaccessclub.svg)](https://t.me/RootAccessClub)", "assets/telegram-rootaccessclub.svg"),
            ("[![Join @BugCod3 on Telegram](assets/telegram-bugcod3.svg)](https://t.me/BugCod3)", "assets/telegram-bugcod3.svg"),
        )
        root = Path(__file__).resolve().parents[1]
        for markdown, asset in expected:
            with self.subTest(asset=asset):
                self.assertIn(markdown, readme)
                self.assertTrue((root / asset).is_file())
        self.assertIn("not affiliated with Telegram", readme)

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
