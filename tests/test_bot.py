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


class GroupAlertTests(unittest.TestCase):
    def test_group_alerts_use_links_not_mini_app_buttons(self):
        import notify_telegram as nt
        row = ["CVE-2026-1", "Bug"] + [None] * 12
        dm = nt.watch_buttons([(row, "nginx")])
        grp = nt.watch_buttons([(row, "nginx")], group=True)
        self.assertIn("web_app", dm["inline_keyboard"][0][0])
        first = grp["inline_keyboard"][0][0]
        self.assertNotIn("web_app", first)
        self.assertTrue(first["url"].endswith("cve/CVE-2026-1"))
        self.assertIn("Group", grp["inline_keyboard"][1][0]["text"])


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
        admin = {b["name"]: b["text"] for b in deploy_bot.metadata("kvid", "123:abc", "4242")["bindings"] if b["type"] == "plain_text"}
        self.assertEqual(admin["ADMIN_ID"], "4242")
        self.assertNotIn("ADMIN_ID", {b["name"] for b in deploy_bot.metadata("kvid", "123:abc", "not-an-id")["bindings"]})
        cmds = [c for c, _d in deploy_bot.COMMANDS]
        self.assertIn("week", cmds)
        js = (ROOT / "worker/bot.js").read_text(encoding="utf-8")
        for c in cmds:  # every advertised command is handled
            self.assertIn(f"cmd === '{c}'", js)

    def test_webhook_receives_buttons_and_inline_queries(self):
        src = (ROOT / "scripts/deploy_bot.py").read_text(encoding="utf-8")
        self.assertIn('"allowed_updates": ["message", "callback_query", "inline_query", "my_chat_member"]', src)

    def test_bot_workflow_is_pinned_and_read_only(self):
        import re
        wf = (ROOT / ".github/workflows/bot.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", wf)
        self.assertIn("persist-credentials: false", wf)
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s]+)", wf)
        self.assertTrue(uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses)


class WorkerBehaviourTests(unittest.TestCase):
    def test_worker_end_to_end_with_fake_telegram(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        r = subprocess.run([node, str(ROOT / "tests/bot_harness.mjs")], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertIn("bot harness ok", r.stdout)


class ChannelButtonTests(unittest.TestCase):
    def test_buttons_are_json_in_multipart_photo_posts(self):
        import io
        import json
        import tempfile
        from unittest import mock
        import digest
        seen = {}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake(req, timeout=0):
            seen["body"] = req.data
            return Resp(b'{"ok": true}')
        with tempfile.NamedTemporaryFile(suffix=".png") as f, mock.patch("urllib.request.urlopen", fake):
            f.write(b"png")
            f.flush()
            self.assertTrue(digest.tg_call("sendPhoto", "t", {"chat_id": "1", "reply_markup": digest.week_buttons()}, photo=Path(f.name)))
        part = seen["body"].split(b'name="reply_markup"\r\n\r\n')[1].split(b"\r\n")[0]
        kb = json.loads(part)["inline_keyboard"]
        self.assertEqual(kb[0][0]["style"], "primary")
        self.assertIn("?start=watch", kb[1][0]["url"])
        alert = nt.alert_buttons([row("CVE-2026-1111", "x")])["inline_keyboard"]
        self.assertEqual(alert[0][0]["style"], "danger")

    def test_blocked_users_are_dropped_from_watchlists(self):
        import os
        from unittest import mock
        env = {"CLOUDFLARE_API_TOKEN": "t", "CLOUDFLARE_ACCOUNT_ID": "a" * 32}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(nt, "load_watches", return_value={"7": ["fortinet"], "8": ["fortinet"]}), \
                mock.patch.object(nt, "send_dm", side_effect=[(False, 403), (True, 200)]), \
                mock.patch.object(nt, "kv_namespace", return_value="ns"), \
                mock.patch.object(nt, "drop_watch", return_value=True) as drop, mock.patch.object(nt.time, "sleep"):
            nt.send_watch_dms([row("CVE-2026-1111", "Fortinet FortiOS bug", "Fortinet FortiOS")], {}, "tok", dry=False)
        drop.assert_called_once_with("t", "a" * 32, "ns", "7")


class WatchPreferenceTests(unittest.TestCase):
    def _run(self, prefs, hour, kv=None, new=None, crit=None):
        import os
        from datetime import datetime, timezone
        from unittest import mock
        kv = {} if kv is None else kv
        sent = []

        def load(token, account, p=None):
            p.update(prefs)
            return {c: ["fortinet"] for c in prefs}
        env = {"CLOUDFLARE_API_TOKEN": "t", "CLOUDFLARE_ACCOUNT_ID": "a" * 32}
        rows = [row("CVE-2026-1111", "Fortinet FortiOS bug", "Fortinet FortiOS"), ["CVE-2026-2222", "Fortinet FortiWeb critical bug", "critical", 9.1, 0, 0.001, "2026-10-26", "", "Fortinet FortiWeb"]]
        with mock.patch.dict(os.environ, env), mock.patch.object(nt, "load_watches", side_effect=load), \
                mock.patch.object(nt, "send_dm", side_effect=lambda tok, chat, text, mk: (sent.append((chat, text)) or (True, 200))), \
                mock.patch.object(nt, "kv_namespace", return_value="ns"), \
                mock.patch.object(nt, "kv_get", side_effect=lambda t, a, n, k: kv.get(k)), \
                mock.patch.object(nt, "kv_put", side_effect=lambda t, a, n, k, v: kv.__setitem__(k, v) or True), \
                mock.patch.object(nt, "kv_delete", side_effect=lambda t, a, n, k: kv.pop(k, None) is not None), mock.patch.object(nt.time, "sleep"):
            nt.send_watch_dms(rows[:1] if new is None else new, {}, "tok", dry=False, crit=rows[1:] if crit is None else crit, rows=rows,
                              now=datetime(2026, 10, 27, hour, 17, tzinfo=timezone.utc))
        return sent, kv

    def test_critical_only_for_users_who_asked(self):
        sent, _ = self._run({"1": {"s": "p1", "m": "now"}, "2": {"s": "crit", "m": "now"}}, 12)
        by = dict(sent)
        self.assertNotIn("CVE-2026-2222", by["1"])
        self.assertIn("CVE-2026-2222", by["2"])
        self.assertIn("new critical", by["2"])

    def test_daily_users_are_queued_then_get_one_summary(self):
        import json
        sent, kv = self._run({"3": {"s": "crit", "m": "daily"}}, 0)
        self.assertEqual(sent, [])
        self.assertEqual([i for i, _ in json.loads(kv["q:3"])], ["CVE-2026-1111", "CVE-2026-2222"])
        sent, kv = self._run({"3": {"s": "crit", "m": "daily"}}, 6, kv=kv, new=[], crit=[])
        self.assertEqual(len(sent), 1)
        self.assertIn("daily watchlist summary", sent[0][1])
        self.assertNotIn("q:3", kv)
        self.assertEqual(kv["d:last"], "2026-10-27")
        sent, kv = self._run({"3": {"s": "crit", "m": "daily"}}, 12, kv=kv)  # already sent today: queue again
        self.assertEqual(sent, [])
        self.assertIn("q:3", kv)


if __name__ == "__main__":
    unittest.main()
