import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import early_warning as ew  # noqa: E402

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def art(src, title, body="", hours=2, w=1):
    return {"src": src, "w": w, "url": f"https://{src.lower().replace(' ', '')}.example/x", "title": title,
            "text": f"{title} {body}", "at": NOW - timedelta(hours=hours)}


class DeltaLogTests(unittest.TestCase):
    def test_reads_newest_entries_and_tolerates_a_truncated_range(self):
        log = [
            {"fetchTime": "2026-10-21T11:00:00Z", "new": [{"cveId": "CVE-2026-1111"}], "updated": [{"cveId": "CVE-2026-2222"}]},
            {"fetchTime": "2026-10-21T09:00:00Z", "new": [{"cveId": "CVE-2026-3333"}], "updated": []},
            {"fetchTime": "2026-10-20T01:00:00Z", "new": [{"cveId": "CVE-2026-9999"}], "updated": []},
        ]
        raw = json.dumps(log, indent=2).encode()
        since = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
        self.assertEqual(ew.parse_delta_log(raw, since), ["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"])
        cut = raw[: raw.index(b"CVE-2026-3333") + 4]  # mid-object, like a ranged download
        self.assertEqual(ew.parse_delta_log(cut, since), ["CVE-2026-1111", "CVE-2026-2222"])


class RecordTests(unittest.TestCase):
    def test_cve5_record_becomes_an_index_row(self):
        doc = {"cveMetadata": {"cveId": "CVE-2026-1234", "state": "PUBLISHED", "datePublished": "2026-10-21T10:00:00Z"},
               "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Remote code execution in Foo."}],
                                       "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                                       "affected": [{"vendor": "Acme", "product": "Foo"}]}}}
        row = ew.cve_record_row(doc)
        self.assertEqual(row[:4], ["CVE-2026-1234", "Remote code execution in Foo.", "critical", 9.8])
        self.assertEqual(row[7], "2026-10-21")
        self.assertEqual(row[9], "cve.org")
        self.assertIsNone(ew.cve_record_row({"cveMetadata": {"cveId": "CVE-2026-1", "state": "REJECTED"}}))

    def test_feed_parser_handles_rss_and_atom_and_refuses_entities(self):
        rss = b"<rss><channel><item><title>A &amp; B</title><link>https://x.example/a</link><pubDate>Tue, 21 Oct 2026 10:00:00 GMT</pubDate><description>&lt;p&gt;hi&lt;/p&gt;</description></item></channel></rss>"
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>T</title><link href="https://y.example/b"/><updated>2026-10-21T10:00:00Z</updated></entry></feed>'
        self.assertEqual(ew.parse_feed(rss)[0]["title"], "A & B")
        self.assertEqual(ew.parse_feed(atom)[0]["link"], "https://y.example/b")
        with self.assertRaises(ValueError):
            ew.parse_feed(b'<!DOCTYPE x [<!ENTITY a "b">]><rss/>')


class EmergingTests(unittest.TestCase):
    def test_leaked_pre_nvd_vulnerability_becomes_p0(self):
        arts = [
            art("The Hacker News", "PHP2Shell: Two Unpatched Critical PHP RCE Flaws", "CVE-2026-109618 and CVE-2026-109619"),
            art("SecurityWeek", "PHP2Shell: Mass Exploitation Looms for Leaked Critical PHP Flaws", "CVE-2026-109618, exploitation reported"),
            art("SANS ISC", "Critical PHP Vulnerability (CVE-2026-109618, CVE-2026-109619)", "remote code execution", w=1),
            art("Some Blog", "Weekly roundup", " ".join(f"CVE-2026-{i:05d}" for i in range(10000, 10020))),
        ]
        out = ew.build_emerging(arts, {}, {}, [], NOW, lambda c: "unpublished")
        self.assertEqual(len(out), 1)
        e = out[0]
        self.assertEqual(e["name"].lower(), "php2shell")
        self.assertEqual(e["level"], "p0")
        self.assertEqual(e["cves"], ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(set(e["status"].values()), {"unpublished"})
        self.assertIn("rce", e["signals"])
        self.assertEqual(len(e["sources"]), 3)

    def test_single_source_or_old_known_kev_news_is_not_an_early_warning(self):
        one = [art("BleepingComputer", "Critical RCE in Foo", "CVE-2026-5555")]
        self.assertEqual(ew.build_emerging(one, {}, {}, [], NOW, lambda c: "unpublished"), [])
        idx = {"CVE-2025-1111": ["CVE-2025-1111", "", "high", 8.0, 1]}
        old = [art("A", "Hackers exploit CVE-2025-1111 RCE"), art("B", "CVE-2025-1111 RCE exploited in the wild")]
        self.assertEqual(ew.build_emerging(old, idx, {}, [], NOW), [])

    def test_cert_source_counts_double_and_state_is_kept(self):
        arts = [art("CISA", "Emergency directive: exploited zero-day in Bar", "CVE-2026-7777", w=2)]
        prev = [{"key": "cve:CVE-2026-7777", "first_seen": "2026-10-20T00:00:00Z"}]
        out = ew.build_emerging(arts, {}, {}, prev, NOW, lambda c: "reserved")
        self.assertEqual(out[0]["first_seen"], "2026-10-20T00:00:00Z")
        self.assertEqual(out[0]["status"]["CVE-2026-7777"], "reserved")

    def test_names_ignore_everyday_words(self):
        self.assertEqual(ew._named("PowerShell webshell in a nutshell"), [])
        self.assertEqual(ew._named("React2Shell and Log4Shell and CitrixBleed"), ["react2shell", "log4shell", "citrixbleed"])


class WorkflowTests(unittest.TestCase):
    def test_live_layer_runs_on_a_schedule_and_never_blocks_the_deploy(self):
        deploy = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "4,19,34,49 * * * *"', deploy)
        self.assertIn("scripts/early_warning.py --site _site", deploy)
        self.assertIn('|| echo "live layer skipped"', deploy)
        self.assertLess(deploy.index("early_warning.py"), deploy.index("sign_manifest.py"))
        watchdog = deploy.split("  watchdog:\n", 1)[1]
        self.assertIn("if: github.event_name == 'schedule'", watchdog)
        self.assertIn("permissions:\n      actions: write\n      contents: read", watchdog)
        self.assertIn("gh workflow run update-snapshot.yml", watchdog)


if __name__ == "__main__":
    unittest.main()
