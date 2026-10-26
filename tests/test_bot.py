import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_site  # noqa: E402
import notify_telegram as nt  # noqa: E402


def row(cid, title, product=""):
    return [cid, title, "critical", 9.8, 1, 0.5, "2026-10-24", "", product]


class WatchlistTests(unittest.TestCase):
    def test_norm_matches_worker_rules(self):
        self.assertEqual(nt._norm("  Fortinet  FortiOS!! "), "fortinet fortios")
        self.assertEqual(nt._norm("Node.js/C++"), "node.js c++")

    def test_watch_matches_on_whole_words_only(self):
        new = [row("CVE-2026-1111", "Fortinet FortiOS heap overflow", "Fortinet FortiOS"),
               row("CVE-2026-2222", "Apache Tomcat request smuggling")]
        watches = {"1": ["fortinet"], "2": ["tom"], "3": ["apache tomcat", "cve-2026-1111"]}
        hits = nt.watch_matches(new, watches, {})
        self.assertEqual([r[0] for r, _ in hits["1"]], ["CVE-2026-1111"])
        self.assertNotIn("2", hits)
        self.assertEqual(sorted(r[0] for r, _ in hits["3"]), ["CVE-2026-1111", "CVE-2026-2222"])

    def test_watch_dms_skip_without_cloudflare(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "", "CLOUDFLARE_ACCOUNT_ID": ""}):
            with mock.patch.object(nt, "load_watches", side_effect=AssertionError("must not call")):
                nt.send_watch_dms([row("CVE-2026-1", "x")], {}, "tok", dry=True)


class CveApiTests(unittest.TestCase):
    def test_cve_api_shape(self):
        rec = {"id": "CVE-2026-1111", "title": "Heap overflow", "desc": "d" * 900, "sev": "unknown",
               "kev": {"vendor": "Fortinet", "product": "FortiOS"}, "published": "2026-10-20T00:00:00Z"}
        out = build_site.cve_api(rec, None, (1, "KEV"), {"c": 9.1, "poc": 1}, "2026-10-01T00:00:00Z")
        self.assertEqual(out["severity"], "critical")
        self.assertEqual(out["products"], "Fortinet FortiOS")
        self.assertEqual(len(out["desc"]), 600)
        self.assertTrue(out["public_exploit"])
        self.assertFalse(out["weaponized"])
        self.assertEqual(out["priority"], 1)
        self.assertEqual(out["archived"], "2026-10-01")
        self.assertTrue(out["url"].endswith("cve/CVE-2026-1111"))


class WorkerTests(unittest.TestCase):
    def test_worker_checks_webhook_secret_and_limits_watchlists(self):
        js = (ROOT / "worker/bot.js").read_text(encoding="utf-8")
        self.assertIn("X-Telegram-Bot-Api-Secret-Token", js)
        self.assertIn("WEBHOOK_SECRET", js)
        self.assertIn("export default", js)
        for cmd in ("start", "cve", "top", "week", "watch", "unwatch", "list", "help"):
            self.assertIn(f"cmd === '{cmd}'", js)
        self.assertIn("MAX_WATCH = 10", js)


class DeployTests(unittest.TestCase):
    def test_deploy_metadata_and_secret(self):
        import deploy_bot
        secret = deploy_bot.webhook_secret("123:abc")
        self.assertRegex(secret, r"^[0-9a-f]{48}$")
        self.assertNotIn("123:abc", secret)
        meta = deploy_bot.metadata("kvid", "123:abc")
        names = {b["name"]: b["type"] for b in meta["bindings"]}
        self.assertEqual(names, {"KV": "kv_namespace", "BOT_TOKEN": "secret_text",
                                 "WEBHOOK_SECRET": "secret_text", "SITE": "plain_text"})
        self.assertEqual(meta["main_module"], "bot.js")
        cmds = [c for c, _d in deploy_bot.COMMANDS]
        self.assertIn("week", cmds)
        js = (ROOT / "worker/bot.js").read_text(encoding="utf-8")
        for c in cmds:  # every advertised command is handled
            self.assertIn(f"cmd === '{c}'", js)

    def test_bot_workflow_is_pinned_and_read_only(self):
        import re
        wf = (ROOT / ".github/workflows/bot.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", wf)
        self.assertIn("persist-credentials: false", wf)
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s]+)", wf)
        self.assertTrue(uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses)


if __name__ == "__main__":
    unittest.main()
