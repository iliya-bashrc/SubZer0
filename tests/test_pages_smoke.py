import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_pages import verify_once  # noqa: E402


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


class PagesSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = partial(QuietHandler, directory=str(ROOT))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.expected = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_local_static_site_matches_complete_committed_snapshot(self):
        result = verify_once(self.base_url, self.expected)
        self.assertEqual(result["generated_at"], self.expected["generated_at"])
        self.assertEqual(result["latest_date"], self.expected["days"][-1]["date"])
        self.assertGreater(result["latest_count"], 0)

    def test_stale_manifest_is_rejected(self):
        wrong = dict(self.expected)
        wrong["generated_at"] = "1900-01-01T00:00:00Z"
        with self.assertRaisesRegex(RuntimeError, "public snapshot is"):
            verify_once(self.base_url, wrong)


if __name__ == "__main__":
    unittest.main()
