import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import digest  # noqa: E402

NOW = datetime(2026, 10, 24, 20, 0, tzinfo=timezone.utc)


def row(cid, sev="medium", score=5.0, kev=0, epss=0.0, date="2026-10-24", title="A vulnerability in Foo Bar allows x"):
    return [cid, title, sev, score, kev, epss, date, date, ""]


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.ctx = {"poc": {"CVE-2026-0003"}, "intel": {"CVE-2026-0004": {"m": [["x"]]}}}
        self.rows = [
            row("CVE-2026-0001", "critical", 9.4, kev=1, title="VeloCloud Orchestrator issue"),
            row("CVE-2026-0002", "critical", 9.8),
            row("CVE-2026-0003", "high", 8.1, epss=0.4),
            row("CVE-2026-0004", "high", 7.5),
            row("CVE-2026-0005", "low", 2.0),
            row("CVE-2026-0099", "critical", 9.9, kev=1, date="2026-10-01"),  # outside every period
        ]

    def test_daily_lists_kev_and_priority_one_only_inside_the_period(self):
        d = digest.build_digest(self.rows, self.ctx, "daily", NOW)
        self.assertEqual([r[0] for r in d["kev"]], ["CVE-2026-0001"])
        self.assertEqual({r[0] for r in d["p1"]}, {"CVE-2026-0003", "CVE-2026-0004"})
        self.assertEqual(d["total"], 5)
        text = digest.daily_text(d, {**self.ctx, "names": {"CVE-2026-0001": "Arista VeloCloud Orchestrator"}})
        self.assertIn("SubZer0 Daily", text)
        self.assertIn("cve/CVE-2026-0001", text)
        self.assertIn("Arista VeloCloud Orchestrator", text)
        self.assertNotIn("CVE-2026-0099", text)

    def test_quiet_day_posts_nothing(self):
        quiet = [row("CVE-2026-0007", "medium", 5.0), row("CVE-2026-0008", "high", 7.2)]
        d = digest.build_digest(quiet, {"poc": set(), "intel": {}}, "daily", NOW)
        self.assertIsNone(digest.daily_text(d, {}))

    def test_weekly_caption_fits_telegram_limit(self):
        many = [row(f"CVE-2026-{i:05d}", "critical", 9.8, kev=i % 2, title="X" * 300) for i in range(1, 60)]
        d = digest.build_digest(many, {"poc": set(), "intel": {}}, "weekly", NOW)
        cap = digest.weekly_caption(d, {}, ["PHP2Shell", "Plex2Shell"])
        self.assertLessEqual(digest.visible_len(cap), digest.CAPTION_MAX)
        self.assertIn("SubZer0 Weekly", cap)
        self.assertIn("@SubZer0Robot", cap)

    def test_card_markup_escapes_titles(self):
        d = digest.build_digest([row("CVE-2026-0001", "critical", 9.8, kev=1, title="<script>x</script>")],
                                {"poc": set(), "intel": {}}, "weekly", NOW)
        markup = digest.card_html(d, {"poc": set(), "intel": {}}, ["<b>"])
        self.assertNotIn("<script>x", markup)
        self.assertIn("&lt;script&gt;", markup)

    def test_short_title_extracts_product_names(self):
        cases = {
            "Incorrect Privilege Assignment vulnerability in Brainstorm Force OttoKit suretriggers allows": "Brainstorm Force OttoKit",
            "Deserialization of Untrusted Data vulnerability in Apache Camel. This": "Apache Camel",
            "A flaw was found in Keycloak. An attacker": "Keycloak",
            "A vulnerability in Cisco IOS XE Software could allow": "Cisco IOS XE Software",
        }
        for title, want in cases.items():
            self.assertEqual(digest.short_title(title), want)
        self.assertIsNone(digest.short_title("In the Linux kernel, the following vulnerability has been resolved"))

    def test_workflow_is_read_only_and_pinned(self):
        wf = (ROOT / ".github/workflows/digest.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", wf)
        self.assertNotIn("write", wf)
        self.assertRegex(wf, r"uses: actions/checkout@[0-9a-f]{40}")
        self.assertIn("persist-credentials: false", wf)


if __name__ == "__main__":
    unittest.main()
