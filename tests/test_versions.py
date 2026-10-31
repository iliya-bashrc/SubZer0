import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import versions as v  # noqa: E402

CMP = [("1.0", "1.0.0", 0), ("1.0rc1", "1.0", -1), ("1.0.1", "1.0rc1", 1), ("1.24.0", "1.25.3", -1),
       ("10.0.19045.5000", "10.0.19045.7807", -1), ("11.0.0-preview.1", "11.0.0-rc.1", -1), ("11.0.0-rc.2", "11.0.0", -1),
       ("2.11.0", "2.9", 1), ("1.2.3p1", "1.2.3", 1), ("v1.2", "1.2", 0), ("2023", "2025", -1), ("1.0-beta", "1.0-alpha", 1)]
BLOCK = re.compile(r"/\* vcheck:start.*?/\* vcheck:end \*/", re.S)


class VersionEngineTests(unittest.TestCase):
    def test_compare(self):
        for a, b, want in CMP:
            self.assertEqual(v.cmp(a, b), want, (a, b))
            self.assertEqual(v.cmp(b, a), -want, (b, a))

    def test_parse_and_hit(self):
        self.assertEqual(v.parse("< 1.25.3"), ("", 1, "1.25.3", 0, "1.25.3"))
        self.assertEqual(v.parse(">= 2.1.0, <= 2.11.0"), ("2.1.0", 1, "2.11.0", 1, ""))
        self.assertEqual(v.parse(">= 11.0.0-preview.1, <= 11.0.0-rc.1; first patched: 11.0.0-rc.2"),
                         ("11.0.0-preview.1", 1, "11.0.0-rc.1", 1, "11.0.0-rc.2"))
        self.assertEqual(v.parse("4.0.0"), ("4.0.0", 1, "4.0.0", 1, ""))
        self.assertIsNone(v.parse("Version details not specified in source"))
        self.assertIsNone(v.parse("all versions"))
        r = v.parse(">= 2.1.0, < 2.5")
        self.assertTrue(v.hit("2.1.0", r) and v.hit("2.4.9", r))
        self.assertFalse(v.hit("2.5", r) or v.hit("2.0.9", r))

    def test_builder_shards(self):
        b = v.Builder()
        b.add({"id": "CVE-2026-1", "title": "t", "affected": [{"vendor": "f5", "product": "nginx", "versions": "< 1.25.3"},
                                                             {"vendor": "f5", "product": "nginx", "versions": "Version details not specified in source"}]},
              ["CVE-2026-1", "t", "high", 7.5, 0, 0.1], (2, "this week"), {"c": 7.5})
        b.add({"id": "CVE-2026-2", "title": "u", "affected": [{"vendor": "acme", "product": "9lives", "versions": "= 3.0"}]}, None, None, None)
        with tempfile.TemporaryDirectory() as d:
            b.write(Path(d))
            n = json.loads((Path(d) / "api/versions/n.json").read_text())
            self.assertEqual(n["c"][0][:3], ["CVE-2026-1", "high", 2])
            self.assertEqual(n["p"]["f5|nginx"], [[0, "", 1, "1.25.3", 0, ""], [0, "", 1, "", -1, ""]])
            self.assertTrue((Path(d) / "api/versions/0.json").exists())
            ix = json.loads((Path(d) / "api/versions/index.json").read_text())
            self.assertEqual(ix["shards"], ["0", "n"])

    def test_js_copies_are_identical_and_agree(self):
        shared = (ROOT / "shared/vcheck.js").read_text()
        want = BLOCK.search(shared).group(0)
        for f in ("site/app.js", "worker/bot.js"):
            m = BLOCK.search((ROOT / f).read_text())
            self.assertIsNotNone(m, f)
            self.assertEqual(m.group(0), want, f"{f} has a stale copy of shared/vcheck.js")
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        js = want + "\nconst C=" + json.dumps(CMP) + ";for(const [a,b,w] of C){if(vcmp(a,b)!==w||vcmp(b,a)!==-w)throw new Error(a+' vs '+b)}" + """
const S={n:{c:[['CVE-1','high',2,0,7.5,'t'],['CVE-2','critical',1,1,9.8,'u']],p:{'f5|nginx':[[0,'',1,'1.25.3',0,''],[1,'1.20.0',1,'1.22.1',1,''],[1,'',1,'',-1,'']],'nginx|nginx ui':[[0,'',1,'2.0',0,'']]}}};
let r=vcheck('nginx 1.21.0',S);if(r.products[0].key!=='f5|nginx'||r.products[0].affected.length!==2||r.products[0].fix!=='1.25.3'||r.products[0].unknown!==1)throw new Error(JSON.stringify(r));
r=vcheck('nginx 1.26',S);if(r.products[0].affected.length!==0)throw new Error('1.26');
r=vcheck('nginx ui 1.0',S);if(r.products[0].key!=='nginx|nginx ui'||r.version!=='1.0')throw new Error('ui');
if(vparse('coldfusion 2023').version!=='2023'||vparse('chrome').version!==''||vparse('nginx@v1.2').version!=='1.2')throw new Error('parse');
console.log('ok')"""
        r = subprocess.run([node, "-e", js], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-1500:])


if __name__ == "__main__":
    unittest.main()
