from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import update_data as feed  # noqa: E402
from migrate_legacy_snapshot import migrate_snapshot  # noqa: E402
from verify_data_snapshot import SnapshotValidationError, validate_snapshot  # noqa: E402


class SnapshotIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "snapshot"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self._create_fixture()

    def tearDown(self):
        self.temporary.cleanup()

    def _create_fixture(self):
        activity = feed.iso_z(self.now - timedelta(hours=1))
        cve = {
            "id": "CVE-2026-8001", "published": activity, "lastModified": activity,
            "descriptions": [{"lang": "en", "value": "A fixture vulnerability in Widget."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "references": [{"url": "https://vendor.example/security/8001"}],
        }
        advisory = {
            "ghsa_id": "GHSA-fixture-8001", "cve_id": "CVE-2026-8001",
            "summary": "Fixture advisory", "published_at": activity,
            "html_url": "https://github.com/advisories/GHSA-fixture-8001",
        }
        kev = {
            "cveID": "CVE-2026-8001", "dateAdded": self.now.date().isoformat(),
            "vendorProject": "Fixture", "product": "Widget", "dueDate": "",
            "requiredAction": "Apply the vendor update.", "knownRansomwareCampaignUse": "Unknown",
        }
        start = self.now - timedelta(days=30)
        records = feed.build_records([{"cve": cve}], [advisory], [kev], start, self.now)
        statuses = [
            {"name": "NVD CVE API 2.0", "ok": True, "records": 1, "pages": 1, "checked_at": feed.iso_z(self.now)},
            {"name": "GitHub Security Advisory Database", "ok": True, "advisories": 1, "pages": 1, "checked_at": feed.iso_z(self.now)},
            {"name": "CISA KEV", "ok": True, "catalog_records": 1, "checked_at": feed.iso_z(self.now)},
        ]
        manifest, shards = feed.build_manifest(records, start, self.now, self.now, statuses, 1, 1, 1)
        epss = {
            "schema_version": 1, "updated_at": feed.iso_z(self.now), "checked_at": feed.iso_z(self.now),
            "score_date": self.now.date().isoformat(), "source_updated_at": feed.iso_z(self.now), "error": "",
            "scores": {"CVE-2026-8001": {"score": 0.2, "percentile": 0.95}},
        }
        epss_status = {
            "name": "FIRST EPSS", "ok": True, "scores": 1, "records": 1,
            "score_date": self.now.date().isoformat(), "source_updated_at": feed.iso_z(self.now),
            "checked_at": feed.iso_z(self.now), "note": "",
        }
        feed.add_epss_metadata(manifest, epss, epss_status)
        feed.write_snapshot(self.root, manifest, shards, epss)

    def _manifest(self):
        return json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))

    def _save_manifest(self, manifest):
        feed._write_json(self.root / "manifest.json", manifest)

    def _update_day(self, day: str, records: list[dict], raw: bytes | None = None):
        manifest = self._manifest()
        raw = raw if raw is not None else feed._json_bytes(records)
        summary = next(item for item in manifest["days"] if item["date"] == day)
        (self.root / summary["path"]).write_bytes(raw)
        summary["count"] = len(records)
        summary["bytes"] = len(raw)
        summary["sha256"] = hashlib.sha256(raw).hexdigest()
        for severity in feed.SEVERITY_ORDER:
            summary[severity] = sum(item.get("sev") == severity for item in records)
        summary["exploited"] = sum(bool(item.get("kev")) for item in records)
        self._save_manifest(manifest)
        return manifest

    def test_new_snapshot_and_report_validate(self):
        report = validate_snapshot(self.root, write_report=True)
        self.assertEqual(report["records"], 1)
        self.assertEqual(report["shards"], 31)
        self.assertEqual(report["epss_status"], "current")
        self.assertTrue((self.root / "VALIDATION.json").is_file())

    def test_extended_cvss4_vector_validates_without_truncation(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:P/MVC:H/MVI:H/MVA:H/MSC:H/MSI:H/MSA:H/S:P/AU:N/R:A/V:D/RE:M/U:Green"
        self.assertGreater(len(vector), 128)
        day = next(item["date"] for item in self._manifest()["days"] if item["count"])
        manifest = self._manifest()
        shard = next(item for item in manifest["days"] if item["date"] == day)
        records = json.loads((self.root / shard["path"]).read_text(encoding="utf-8"))
        records[0]["cvss_version"] = "4.0"
        records[0]["cvss_vector"] = vector
        records[0]["cvss_source"] = "NVD"
        self._update_day(day, records)
        self.assertEqual(validate_snapshot(self.root)["records"], 1)

    def test_official_unprefixed_cvss2_vector_validates(self):
        day = next(item["date"] for item in self._manifest()["days"] if item["count"])
        manifest = self._manifest()
        shard = next(item for item in manifest["days"] if item["date"] == day)
        records = json.loads((self.root / shard["path"]).read_text(encoding="utf-8"))
        records[0]["cvss_version"] = "2.0"
        records[0]["cvss_vector"] = "AV:N/AC:M/Au:N/C:P/I:P/A:P"
        records[0]["cvss_source"] = "NVD"
        self._update_day(day, records)
        self.assertEqual(validate_snapshot(self.root)["records"], 1)

    def test_overview_change_preview_must_match_a_retained_history_event(self):
        manifest = self._manifest()
        overview_path = self.root / manifest["overview"]["path"]
        overview = json.loads(overview_path.read_text(encoding="utf-8"))
        record = overview["records"][0]
        overview["recent_changes"] = [{
            "id": record["id"], "title": record["title"], "type": "CVSS_CHANGED",
            "observed_at": manifest["generated_at"], "source_time": record["activity_at"], "source": "NVD",
        }]
        overview_raw = feed._json_bytes(overview)
        overview_path.write_bytes(overview_raw)
        manifest["overview"]["bytes"] = len(overview_raw)
        manifest["overview"]["sha256"] = hashlib.sha256(overview_raw).hexdigest()
        manifest["overview"]["recent_change_count"] = 1
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "newest source-verified retained events"):
            validate_snapshot(self.root)

    def test_gzip_index_raw_digest_is_verified_after_decompression(self):
        manifest = self._manifest()
        packed_path = self.root / manifest["search_index"]["path"]
        raw = gzip.decompress(packed_path.read_bytes())
        changed = raw.replace(b"CVE-2026-8001", b"CVE-2026-8002", 1)
        packed = gzip.compress(changed, compresslevel=9, mtime=0)
        packed_path.write_bytes(packed)
        manifest["search_index"]["bytes"] = len(packed)
        manifest["search_index"]["sha256"] = hashlib.sha256(packed).hexdigest()
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "(?i)uncompressed.*SHA-256 mismatch"):
            validate_snapshot(self.root)

    def test_legacy_metadata_migration_preserves_source_bytes_and_timestamp(self):
        day = next(item["date"] for item in self._manifest()["days"] if item["count"])
        source_path = self.root / "data" / f"{day}.json"
        source_records = json.loads(source_path.read_text(encoding="utf-8"))
        naive_utc = source_records[0]["activity_at"].removesuffix("Z")
        source_records[0]["published"] = naive_utc
        source_records[0]["modified"] = source_records[0]["published"]
        source_records[0]["activity_at"] = naive_utc
        self._update_day(day, source_records)
        legacy_root = Path(self.temporary.name) / "legacy"
        shutil.copytree(self.root, legacy_root)
        original_manifest = json.loads((legacy_root / "manifest.json").read_text(encoding="utf-8"))
        original_generated_at = original_manifest["generated_at"]
        original_bytes = {
            path.relative_to(legacy_root).as_posix(): path.read_bytes()
            for path in (legacy_root / "data").glob("*.json")
            if path.name not in {"overview.json", "search-index.json"}
        }
        (legacy_root / "data" / "overview.json").unlink()
        original_manifest.pop("overview", None)
        original_manifest["facets"] = {"path": "data/facets.json"}
        original_manifest["history"] = {"path": "data/history.json", "retention_days": 30}
        for summary in original_manifest["days"]:
            summary.pop("bytes", None)
        original_manifest["epss"].pop("bytes", None)
        original_manifest["epss"].pop("sha256", None)
        for status in original_manifest["source_status"]:
            if status["name"] != "FIRST EPSS":
                status.pop("checked_at", None)
        feed._write_json(legacy_root / "manifest.json", original_manifest)

        report = migrate_snapshot(legacy_root)
        migrated_manifest = json.loads((legacy_root / "manifest.json").read_text(encoding="utf-8"))
        after_bytes = {
            path.relative_to(legacy_root).as_posix(): path.read_bytes()
            for path in (legacy_root / "data").glob("*.json")
            if path.name not in {"overview.json", "search-index.json"}
        }
        self.assertEqual(after_bytes, original_bytes)
        self.assertEqual(migrated_manifest["generated_at"], original_generated_at)
        self.assertNotIn("facets", migrated_manifest)
        self.assertIn("history", migrated_manifest)
        self.assertIn("search_index", migrated_manifest)
        self.assertTrue((legacy_root / "data" / "overview.json").is_file())
        self.assertEqual(report["records"], 1)
        self.assertEqual(validate_snapshot(legacy_root)["records"], 1)

    def test_overview_v1_migrates_to_v3_without_refreshing_records_or_epss(self):
        legacy_root = Path(self.temporary.name) / "overview-v1"
        shutil.copytree(self.root, legacy_root)
        manifest_path = legacy_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        original_generated_at = manifest["generated_at"]
        original_epss = (legacy_root / "data" / "epss.json").read_bytes()
        original_shards = {
            item["path"]: (legacy_root / item["path"]).read_bytes()
            for item in manifest["days"]
        }

        overview_path = legacy_root / "data" / "overview.json"
        overview = json.loads(overview_path.read_text(encoding="utf-8"))
        old_fields = {"id", "title", "sev", "score", "window_date", "activity_at", "date_basis", "sources"}
        overview["schema_version"] = 1
        overview["records"] = [{key: value for key, value in record.items() if key in old_fields} for record in overview["records"]]
        old_bytes = feed._json_bytes(overview)
        overview_path.write_bytes(old_bytes)
        manifest["overview"].pop("schema_version", None)
        manifest["overview"]["bytes"] = len(old_bytes)
        manifest["overview"]["sha256"] = hashlib.sha256(old_bytes).hexdigest()
        manifest_path.write_bytes(feed._json_bytes(manifest))

        report = migrate_snapshot(legacy_root)
        migrated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        migrated_overview = json.loads(overview_path.read_text(encoding="utf-8"))
        self.assertEqual(migrated_manifest["generated_at"], original_generated_at)
        self.assertEqual(migrated_manifest["overview"]["schema_version"], 3)
        self.assertEqual(migrated_overview["schema_version"], 3)
        self.assertEqual(migrated_overview["records"][0]["epss"], {"score": 0.2, "percentile": 0.95})
        self.assertEqual(migrated_manifest["search_index"]["path"], "data/search-index.json.gz")
        packed = (legacy_root / "data" / "search-index.json.gz").read_bytes()
        raw_index = gzip.decompress(packed)
        self.assertEqual(len(packed), migrated_manifest["search_index"]["bytes"])
        self.assertEqual(hashlib.sha256(packed).hexdigest(), migrated_manifest["search_index"]["sha256"])
        self.assertEqual(len(raw_index), migrated_manifest["search_index"]["uncompressed_bytes"])
        self.assertEqual(hashlib.sha256(raw_index).hexdigest(), migrated_manifest["search_index"]["uncompressed_sha256"])
        self.assertEqual((legacy_root / "data" / "epss.json").read_bytes(), original_epss)
        self.assertEqual({path: (legacy_root / path).read_bytes() for path in original_shards}, original_shards)
        self.assertEqual(report["records"], 1)
        self.assertEqual(validate_snapshot(legacy_root)["records"], 1)

    def test_checked_in_capture_exposes_cvss_vector_evidence(self):
        day = next(item["date"] for item in self._manifest()["days"] if item["count"])
        record = json.loads((self.root / "data" / f"{day}.json").read_text(encoding="utf-8"))[0]
        self.assertEqual(record["cvss_version"], "3.1")
        self.assertTrue(record["cvss_vector"].startswith("CVSS:3.1/"))
        self.assertEqual(record["cvss_source"], "NVD")

    def test_real_checked_in_full_snapshot_validates(self):
        snapshot_root = ROOT / "snapshot"
        manifest = json.loads((snapshot_root / "manifest.json").read_text(encoding="utf-8"))
        report = validate_snapshot(snapshot_root)
        self.assertGreater(report["records"], 0)
        self.assertEqual(report["records"], manifest["totals"]["cves"])
        self.assertEqual(report["shards"], len(manifest["days"]))
        self.assertEqual(report["largest_shard_bytes"], max(day["bytes"] for day in manifest["days"]))

    def test_tamper_without_recomputing_digest_is_rejected(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        record_path = self.root / "data" / f"{day}.json"
        raw = record_path.read_bytes()
        record_path.write_bytes(raw.replace(b"Fixture", b"Tamper!", 1))
        with self.assertRaisesRegex(SnapshotValidationError, "SHA-256 mismatch"):
            validate_snapshot(self.root)

    def test_duplicate_json_keys_are_rejected_even_with_a_matching_hash(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        duplicate = b'[{"id":"CVE-2026-8001","id":"CVE-2026-8002"}]\n'
        self._update_day(day, [], raw=duplicate)
        with self.assertRaisesRegex(SnapshotValidationError, "Duplicate JSON object key"):
            validate_snapshot(self.root)

    def test_unsafe_protocol_is_rejected_after_hashes_are_updated(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        shard_path = self.root / "data" / f"{day}.json"
        records = json.loads(shard_path.read_text(encoding="utf-8"))
        records[0]["primary_url"] = "javascript:alert(1)"
        self._update_day(day, records)
        with self.assertRaisesRegex(SnapshotValidationError, r"HTTP\(S\) URL"):
            validate_snapshot(self.root)

    def test_safe_http_security_references_remain_valid(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        shard_path = self.root / "data" / f"{day}.json"
        records = json.loads(shard_path.read_text(encoding="utf-8"))
        records[0]["refs"].append({"label": "Legacy vendor archive", "url": "http://vendor.example/archive", "source": "NVD"})
        self._update_day(day, records)
        self.assertEqual(validate_snapshot(self.root)["records"], 1)

    def test_manifest_traversal_unlisted_file_and_excessive_size_are_rejected(self):
        manifest = self._manifest()
        manifest["days"][0]["path"] = "../outside.json"
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "Unexpected path"):
            validate_snapshot(self.root)

        self._create_fixture()
        (self.root / "data" / "obsolete.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotValidationError, "file set mismatch"):
            validate_snapshot(self.root)

        (self.root / "data" / "obsolete.json").unlink()
        manifest = self._manifest()
        manifest["days"][0]["bytes"] = 16 * 1024 * 1024 + 1
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "integer between"):
            validate_snapshot(self.root)

    def test_overview_must_match_the_actual_newest_feed_records(self):
        manifest = self._manifest()
        overview_path = self.root / "data" / "overview.json"
        overview = json.loads(overview_path.read_text(encoding="utf-8"))
        overview["records"][0]["title"] = "Counterfeit homepage record"
        raw = feed._json_bytes(overview)
        overview_path.write_bytes(raw)
        manifest["overview"]["bytes"] = len(raw)
        manifest["overview"]["sha256"] = hashlib.sha256(raw).hexdigest()
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "newest full-feed record"):
            validate_snapshot(self.root)


if __name__ == "__main__":
    unittest.main()
