import sys
import unittest
from unittest import mock
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
        many = [row(f"CVE-2026-{i:05d}", "critical", 9.8, kev=i % 2, date="2026-10-23", title="X" * 300) for i in range(1, 60)]
        d = digest.build_digest(many, {"poc": set(), "intel": {}}, "weekly", NOW)
        cap = digest.weekly_caption(d, {}, ["PHP2Shell", "Plex2Shell"])
        self.assertLessEqual(digest.visible_len(cap), digest.CAPTION_MAX)
        self.assertIn("SubZer0 Weekly", cap)
        self.assertIn("@SubZer0Robot", cap)

    def card(self, **over):
        data = {"week": 43, "span": "Oct 18 \u2013 Oct 24", "total": 4703, "critical": 351, "high": 1501, "kev": 8,
                "pocs": 413, "p1": 2, "top": [{"id": "CVE-2026-0001", "score": 9.8, "name": "<script>x</script>"}],
                "kev_list": [{"id": "CVE-2026-0001", "score": 9.8, "name": "<script>x</script>"}],
                "days": [{"date": "2026-10-18", "label": "SUN", "count": 500, "critical": 12}] * 7,
                "spotlight": None, "spotlight_cves": []}
        data.update(over)
        return data

    def test_every_theme_renders_and_escapes(self):
        import digest_cards as cards
        for theme in cards.THEMES:
            markup = cards.render(theme, self.card(spotlight="<b>Wave</b>"))
            self.assertIn("WEEK 43", markup)
            self.assertNotIn("<script>x", markup)
            self.assertNotIn("<b>Wave</b>", markup)

    def test_theme_rotation_never_repeats_back_to_back_and_spotlight_wins(self):
        import digest_cards as cards
        picks = [cards.pick_theme(w, None) for w in range(1, 54)]
        self.assertTrue(all(a != b for a, b in zip(picks, picks[1:])))
        self.assertEqual(set(picks), set(cards.ROTATION))
        self.assertEqual(cards.pick_theme(43, "PHP2Shell"), "spotlight")
        self.assertEqual(cards.split_name("PHP2Shell"), ("PHP2", "Shell"))
        self.assertEqual(cards.split_name("CitrixBleed"), ("Citrix", "Bleed"))

    def test_same_week_renders_identically_and_weeks_differ(self):
        import digest_cards as cards
        self.assertEqual(cards.render("frost", self.card()), cards.render("frost", self.card()))
        self.assertNotEqual(cards.render("frost", self.card()), cards.render("frost", self.card(week=48)))

    def test_weekly_period_is_seven_full_days_before_the_snapshot_day(self):
        self.assertEqual(digest.period_dates("weekly", NOW), [f"2026-10-{d}" for d in range(23, 16, -1)])

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


class AlertBannerTests(unittest.TestCase):
    def setUp(self):
        import digest_cards
        self.cards = digest_cards

    def item(self, **kw):
        base = {"id": "CVE-2026-0001", "name": "Acme <Gate>", "score": 9.8, "why": "weaponized (Metasploit)",
                "epss": 0.5, "kev": True, "weap": True}
        base.update(kw)
        return base

    def test_single_and_multi_render_escaped(self):
        one = self.cards.alert({"count": 1, "stamp": "1 Jan", "items": [self.item()]})
        self.assertIn("&lt;Gate&gt;", one)
        self.assertIn("9.8", one)
        many = self.cards.alert({"count": 7, "stamp": "1 Jan", "kev": 4, "weap": 2,
                                 "items": [self.item(id=f"CVE-2026-000{i}") for i in range(3)]})
        self.assertIn("7 <em>to patch</em>", many)
        self.assertIn("4 CISA KEV", many)
        self.assertIn("+ 4 more", many)

    def test_unscored_single_has_no_gauge(self):
        out = self.cards.alert({"count": 1, "stamp": "x", "items": [self.item(score=0, kev=False)]})
        self.assertNotIn("<svg viewBox=\"0 0 380 380\"", out)
        self.assertIn("weaponized (Metasploit)", out)


class AlertCaptionTests(unittest.TestCase):
    def test_caption_fits_telegram_limit(self):
        import notify_telegram as nt
        rows = [[f"CVE-2026-{i:05d}", "X" * 200, None, 9.0, True, 0.9] for i in range(12)]
        with mock.patch.object(nt, "priority_reason", return_value=(1, "on CISA KEV")):
            text = nt.caption(rows, {})
        self.assertLessEqual(nt.digest.visible_len(text), 1024)
        self.assertIn("more:", text)
