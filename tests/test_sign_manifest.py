import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sign_manifest as sm  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class SignManifestTests(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(sm.public_key(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(sm.sign(seed, b"").hex(),
                         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_skips_without_key_and_signs_with_key(self):
        with tempfile.TemporaryDirectory() as d:
            snap = Path(d) / "snapshot"
            snap.mkdir()
            (snap / "manifest.json").write_text('{"x":1}')
            old = os.environ.pop("SUBZER0_SIGNING_KEY", None)
            try:
                self.assertEqual(sm.main(["--site", d]), 0)
                self.assertFalse((snap / "manifest.sig").exists())
                seed = bytes(range(32))
                os.environ["SUBZER0_SIGNING_KEY"] = seed.hex()
                self.assertEqual(sm.main(["--site", d]), 0)
                sig = base64.b64decode((snap / "manifest.sig").read_text())
                self.assertEqual(sig, sm.sign(seed, b'{"x":1}'))
            finally:
                os.environ.pop("SUBZER0_SIGNING_KEY", None)
                if old is not None:
                    os.environ["SUBZER0_SIGNING_KEY"] = old

    def test_app_embeds_a_32_byte_public_key(self):
        import re
        m = re.search(r"SIGN_PK='([A-Za-z0-9+/=]+)'", (ROOT / "site" / "app.js").read_text())
        self.assertIsNotNone(m)
        self.assertEqual(len(base64.b64decode(m.group(1))), 32)
