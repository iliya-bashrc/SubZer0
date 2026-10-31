import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import digest_cards as cards  # noqa: E402
import notify_telegram as nt  # noqa: E402


def row(product=""):
    return ["CVE-2026-1", "t", "critical", 9.8, 1, 0.5, "2026-10-24", "", product]


class WidgetTests(unittest.TestCase):
    def test_widget_is_self_contained_and_strict(self):
        html = (ROOT / "site/widget.html").read_text()
        csp = re.search(r'Content-Security-Policy" content="([^"]+)"', html).group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotRegex(html, r"<script>(?!</script>)")  # no inline script
        self.assertIn("https://t.me/RootAccessClub", html)
        self.assertIn('name="robots" content="noindex"', html)
        js = (ROOT / "site/widget.js").read_text()
        self.assertNotIn("innerHTML", js)  # titles come from feeds: text only
        self.assertIn("api/latest.json", js)

    def test_embed_script_sandboxes_the_iframe(self):
        js = (ROOT / "site/embed.js").read_text()
        self.assertIn("widget.html?", js)
        self.assertIn("sandbox", js)
        self.assertIn("e.source===f.contentWindow", js)  # only our iframe may resize it

    def test_about_page_offers_the_snippet(self):
        js = (ROOT / "site/app.js").read_text()
        self.assertIn('id="embed"', js)
        self.assertIn("embed.js", js)


class ChannelTests(unittest.TestCase):
    def test_alert_offers_version_check_for_named_products(self):
        b = nt.alert_buttons([row("Google Chrome")])["inline_keyboard"]
        urls = [x["url"] for r in b for x in r]
        self.assertIn("https://iliya-bashrc.github.io/SubZer0/?check=Google%20Chrome", urls)
        b = nt.alert_buttons([row("")])["inline_keyboard"]
        self.assertFalse(any("check=" in x["url"] for r in b for x in r))

    def test_cards_carry_the_channel_handle(self):
        d = {"count": 1, "items": [{"id": "CVE-2026-1", "name": "Acme", "score": 9.8, "why": "", "epss": .5, "kev": True, "weap": False}],
             "stamp": "now", "kev": 1, "weap": 0}
        self.assertIn("t.me/RootAccessClub", cards.alert(d))
        self.assertIn("t.me/RootAccessClub", cards._chrome({"week": 44, "span": "Oct 26 – Nov 1"}))


if __name__ == "__main__":
    unittest.main()
