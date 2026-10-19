"""Offline tests for the exploit-intel enrichment and its strict validator."""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_site  # noqa: E402
import enrich_intel  # noqa: E402
import verify_data_snapshot as verifier  # noqa: E402

SNAPSHOT = ROOT / "public" / "snapshot"


def _ids() -> list[str]:
    manifest = json.loads((SNAPSHOT / "manifest.json").read_text(encoding="utf-8"))
    rows = json.loads((SNAPSHOT / manifest["search_index"]["path"]).read_text(encoding="utf-8"))
    return [r[0] for r in rows]


def _intel(cve: str) -> dict:
    return {
        "schema_version": 1, "generated_at": "2026-10-18T00:00:00Z", "built_at": "2026-10-18T00:05:00Z",
        "sources": [{"name": "PoC-in-GitHub", "ok": True, "count": 1, "seconds": 1.0}],
        "cves": {cve: {
            "g": [["someone/poc-repo", 3, 1, "2026-10-01", "PoC for the bug", ["fresh"]]],
            "m": [["exploit/linux/http/example_rce", "exploit", 600, "2026-10-01", "2026-10-02", "Example RCE", True]],
            "n": [["http/cves/2026/CVE-2026-0001.yaml", "critical", "Example - RCE"]],
            "s": ["active", "yes", "total", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            "b": [40, 2, 1, 0, 1, 1, [["hn", "https://news.ycombinator.com/item?id=1", "2026-10-02"]]],
            "f": 1,
            "t": {"poc": "2026-10-01", "msf": "2026-10-02"},
        }},
    }


class IntelValidatorTests(unittest.TestCase):
    def setUp(self):
        self.ids = set(_ids())
        self.cve = sorted(self.ids)[0]

    def test_well_formed_intel_passes(self):
        verifier._validate_intel(_intel(self.cve), self.ids)

    def test_rejects_unknown_cve_bad_hosts_and_bad_shapes(self):
        bad = []
        x = _intel(self.cve); x["cves"]["CVE-1999-0000000"] = x["cves"].pop(self.cve); bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["b"][6][0][1] = "https://evil.example/item?id=1"; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["b"][6][0][1] = "javascript:alert(1)"; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["g"][0][0] = "../../etc/passwd"; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["g"][0][5] = ["<script>"]; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["s"][0] = "maybe"; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["s"][3] = 11; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["t"]["poc"] = "yesterday"; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["zz"] = 1; bad.append(x)
        x = _intel(self.cve); x["cves"][self.cve]["b"][0] = 101; bad.append(x)
        for item in bad:
            with self.assertRaises(verifier.SnapshotValidationError):
                verifier._validate_intel(item, self.ids)

    def test_snapshot_with_intel_validates_and_tampering_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "snapshot"
            shutil.copytree(SNAPSHOT, snap)
            enrich_intel.write(snap, _intel(self.cve))
            verifier.validate_snapshot(snap)
            raw = (snap / "data" / "intel.json").read_bytes().replace(b"news.ycombinator.com", b"news.ycombinator.co")
            (snap / "data" / "intel.json").write_bytes(raw)
            with self.assertRaises(verifier.SnapshotValidationError):
                verifier.validate_snapshot(snap)


class EnrichmentTests(unittest.TestCase):
    def test_ssvc_row_reads_only_cisa_adp(self):
        doc = {"containers": {"adp": [
            {"providerMetadata": {"shortName": "other"}, "metrics": [{"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}]}}}]},
            {"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
                {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "PoC"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]}}},
                {"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
            ]},
        ]}}
        self.assertEqual(enrich_intel._ssvc_row(doc), ["poc", "yes", "total", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
        self.assertIsNone(enrich_intel._ssvc_row({"containers": {"adp": []}}))

    def test_buzz_score_is_bounded(self):
        self.assertEqual(enrich_intel.buzz_score({"bsky": 0, "masto": 0, "reddit": 0, "hn": 0}), 0)
        self.assertEqual(enrich_intel.buzz_score({"bsky": 10**6, "masto": 10**6, "reddit": 10**6, "hn": 10**6}), 100)

    def test_failed_sources_carry_forward_previous_values(self):
        ids = _ids()
        cve = ids[0]
        with tempfile.TemporaryDirectory() as tmp:
            prev = Path(tmp) / "prev"
            snap = Path(tmp) / "snap"
            shutil.copytree(SNAPSHOT, prev)
            shutil.copytree(SNAPSHOT, snap)
            old = _intel(cve)
            enrich_intel.write(prev, old)
            boom = mock.Mock(side_effect=RuntimeError("offline"))
            with mock.patch.multiple(enrich_intel, github_pocs=boom, metasploit=boom, nuclei=boom, vulnrichment=boom,
                                     bluesky=boom, mastodon=boom, reddit=boom, hackernews=boom):
                intel = enrich_intel.build(snap, prev, budget_s=5)
            entry = intel["cves"][cve]
            for key in ("g", "m", "n", "s", "b"):
                self.assertEqual(entry[key], old["cves"][cve][key], key)
            self.assertEqual(entry["t"]["msf"], "2026-10-02")
            self.assertTrue(all(not s["ok"] for s in intel["sources"]))
            enrich_intel.write(snap, intel)
            verifier.validate_snapshot(snap)


class IntelPriorityTests(unittest.TestCase):
    def test_intel_signals_raise_priority(self):
        def row(cve, score, kev, epss):
            return [cve, "t", "high", score, kev, epss, "2026-10-01", "2026-10-01", ""]
        intel = {
            "CVE-2026-0001": {"s": ["active", None, None, None, None]},
            "CVE-2026-0002": {"m": [["exploit/x/y", "exploit", 600, None, None, "x", False]]},
            "CVE-2026-0003": {"n": [["http/cves/2026/x.yaml", "high", "x"]]},
            "CVE-2026-0004": {"s": ["none", "yes", "total", None, None]},
            "CVE-2026-0005": {"s": [None, None, None, 9.4, None]},
            "CVE-2026-0006": {"g": [["a/b", 0, 0, None, "", ["bait"]]]},
            "CVE-2026-0007": {"g": [["a/b", 0, 0, None, "", []]]},
        }
        ctx = {"poc": set(), "intel": intel}
        self.assertEqual(build_site.priority(row("CVE-2026-0001", 0, 0, None), ctx), 1)
        self.assertEqual(build_site.priority(row("CVE-2026-0002", 7.5, 0, 0.0), ctx), 1)
        self.assertEqual(build_site.priority(row("CVE-2026-0003", 5.0, 0, 0.0), ctx), 2)
        self.assertEqual(build_site.priority(row("CVE-2026-0004", 5.0, 0, 0.0), ctx), 2)
        self.assertEqual(build_site.priority(row("CVE-2026-0005", 0, 0, None), ctx), 2)  # CISA ADP fallback score
        self.assertEqual(build_site.priority(row("CVE-2026-0006", 5.0, 0, 0.3), ctx), 4)  # bait repo is ignored
        self.assertEqual(build_site.priority(row("CVE-2026-0007", 5.0, 0, 0.3), ctx), 1)


if __name__ == "__main__":
    unittest.main()
