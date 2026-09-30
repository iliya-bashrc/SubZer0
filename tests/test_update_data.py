import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_data as feed  # noqa: E402


class PaginationTests(unittest.TestCase):
    def test_nvd_walks_every_offset_page_with_rate_pause(self):
        calls = []
        sleeps = []
        pages = {
            0: {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}, {"cve": {"id": "CVE-2026-0002"}}]},
            2: {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-0003"}}]},
        }

        def request(url, headers=None):
            params = parse_qs(urlparse(url).query)
            offset = int(params["startIndex"][0])
            calls.append(params)
            return pages[offset], {}

        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        records, total, page_count = feed.iter_nvd(start, end, request, sleeps.append, page_size=2)
        self.assertEqual((len(records), total, page_count), (3, 3, 2))
        self.assertEqual([int(call["startIndex"][0]) for call in calls], [0, 2])
        self.assertEqual([float(call["resultsPerPage"][0]) for call in calls], [2.0, 2.0])
        self.assertEqual(sleeps, [feed.NVD_PAGE_PAUSE_SECONDS])
        self.assertEqual(calls[0]["pubStartDate"], ["2026-09-01T00:00:00.000"])

    def test_nvd_empty_midstream_page_fails_instead_of_claiming_coverage(self):
        pages = iter([
            ({"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]}, {}),
            ({"totalResults": 3, "vulnerabilities": []}, {}),
        ])
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        with self.assertRaises(feed.FeedError):
            feed.iter_nvd(start, end, lambda *args, **kwargs: next(pages), lambda _: None, page_size=1)

    def test_github_uses_link_cursor_until_all_advisory_pages_are_read(self):
        first_url = None
        cursor = "https://api.github.com/advisories?after=next-cursor"
        calls = []

        def request(url, headers=None):
            nonlocal first_url
            calls.append((url, headers or {}))
            if first_url is None:
                first_url = url
                return [{"ghsa_id": "GHSA-one", "cve_id": "CVE-2026-0001"}], {"Link": f'<{cursor}>; rel="next"'}
            return [{"ghsa_id": "GHSA-two", "cve_id": "CVE-2026-0002"}], {}

        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        items, pages = feed.iter_github_advisories(start, end, request, token="test-token")
        query = parse_qs(urlparse(first_url).query)
        self.assertEqual(pages, 2)
        self.assertEqual([item["ghsa_id"] for item in items], ["GHSA-one", "GHSA-two"])
        self.assertEqual(query["per_page"], ["100"])
        self.assertEqual(query["published"], ["2026-09-01..2026-09-30"])
        self.assertEqual(calls[0][1]["Authorization"], "Bearer test-token")
        self.assertEqual(calls[0][1]["X-GitHub-Api-Version"], "2026-03-10")


class NormalizeAndMergeTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)

    def test_sources_merge_once_by_cve_and_preserve_scores_products_and_provenance(self):
        nvd = [{"cve": {
            "id": "CVE-2026-1001",
            "published": "2026-09-10T11:00:00.000Z",
            "lastModified": "2026-09-12T12:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "A serious flaw in Acme Router."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:acme:router:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.2",
                "versionEndExcluding": "2.0",
            }]}]}],
            "references": [{"url": "https://vendor.example/security/advisory"}],
        }}]
        advisories = [{
            "ghsa_id": "GHSA-test",
            "cve_id": "cve-2026-1001",
            "summary": "Acme Router command injection",
            "description": "Detailed advisory text.",
            "severity": "critical",
            "published_at": "2026-09-10T11:00:00Z",
            "html_url": "https://github.com/advisories/GHSA-test",
            "references": ["https://vendor.example/security/advisory"],
            "vulnerabilities": [{
                "package": {"ecosystem": "npm", "name": "acme-router"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": "2.0.0",
            }],
        }]
        kev = [{
            "cveID": "CVE-2026-1001",
            "dateAdded": "2026-09-15",
            "vendorProject": "Acme",
            "product": "Router",
            "vulnerabilityName": "Acme Router remote code execution",
            "shortDescription": "Known exploitation observed.",
            "dueDate": "2026-09-22",
            "requiredAction": "Apply vendor updates.",
            "knownRansomwareCampaignUse": "Unknown",
        }]
        records = feed.build_records(nvd, advisories, kev, self.start, self.end)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["id"], "CVE-2026-1001")
        self.assertEqual(record["score"], 9.8)
        self.assertEqual(record["sev"], "critical")
        self.assertEqual(record["window_date"], "2026-09-15")
        self.assertEqual(record["date_basis"], "CISA KEV date added")
        self.assertEqual(record["sources"], ["NVD", "GitHub Advisory Database", "CISA KEV"])
        self.assertEqual(record["kev"]["date_added"], "2026-09-15")
        self.assertTrue(any(item["source"] == "NVD" and "1.2" in item["versions"] for item in record["affected"]))
        self.assertTrue(any(item["source"] == "GitHub Advisory Database" for item in record["affected"]))
        self.assertEqual(len([ref for ref in record["refs"] if ref["url"] == "https://vendor.example/security/advisory"]), 1)
        self.assertEqual(record["primary_url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-1001")

    def test_recent_kev_only_cve_is_included_but_old_kevs_are_not(self):
        recent = {"cveID": "CVE-2026-2001", "dateAdded": "2026-09-20", "vendorProject": "Vendor", "product": "Product"}
        old = {"cveID": "CVE-2020-2002", "dateAdded": "2020-01-01", "vendorProject": "Old", "product": "Thing"}
        records = feed.build_records([], [], [recent, old], self.start, self.end)
        self.assertEqual([item["id"] for item in records], ["CVE-2026-2001"])
        self.assertEqual(records[0]["window_date"], "2026-09-20")
        self.assertEqual(records[0]["sev"], "unknown")
        self.assertEqual(records[0]["sources"], ["CISA KEV"])

    def test_recent_advisory_with_older_cve_publication_stays_in_window_shard(self):
        advisory = {
            "ghsa_id": "GHSA-republished",
            "cve_id": "CVE-2014-5555",
            "nvd_published_at": "2014-01-02T00:00:00Z",
            "published_at": "2026-09-20T09:30:00Z",
            "summary": "A recently published GitHub advisory",
            "html_url": "https://github.com/advisories/GHSA-republished",
        }
        records = feed.build_records([], [advisory], [], self.start, self.end)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["published"], "2014-01-02T00:00:00Z")
        self.assertEqual(records[0]["activity_at"], "2026-09-20T09:30:00Z")
        self.assertEqual(records[0]["window_date"], "2026-09-20")
        self.assertEqual(records[0]["date_basis"], "GitHub advisory publication")

    def test_records_outside_exact_publication_window_are_excluded(self):
        nvd = [{"cve": {
            "id": "CVE-2026-3001",
            "published": "2026-08-31T23:59:59Z",
            "descriptions": [{"lang": "en", "value": "Outside window"}],
        }}]
        records = feed.build_records(nvd, [], [], self.start, self.end)
        self.assertEqual(records, [])

    def test_github_advisory_label_is_not_cvss_when_no_numeric_score_exists(self):
        advisory = {
            "ghsa_id": "GHSA-no-cvss",
            "cve_id": "CVE-2026-3002",
            "published_at": "2026-09-10T11:00:00Z",
            "summary": "An advisory with a severity label but no numeric score",
            "severity": "critical",
            "cvss_severities": {},
        }
        record = feed.build_records([], [advisory], [], self.start, self.end)[0]
        self.assertIsNone(record["score"])
        self.assertEqual(record["sev"], "unknown")


class EpssTests(unittest.TestCase):
    def test_csv_parser_reads_published_score_date_and_filters_to_requested_ids(self):
        csv_text = (
            "#model_version:v2026.06.15,score_date:2026-09-29T12:00:22Z\n"
            "cve,epss,percentile\n"
            "CVE-2026-0101,0.05000,0.93000\n"
            "CVE-2026-0102,0.00001,0.20000\n"
        )
        scores, score_date, updated_at = feed.parse_epss_csv(StringIO(csv_text), {"CVE-2026-0101"})
        self.assertEqual(score_date, "2026-09-29")
        self.assertEqual(updated_at, "2026-09-29T12:00:22Z")
        self.assertEqual(scores, {"CVE-2026-0101": {"score": 0.05, "percentile": 0.93}})

    def test_api_lookup_only_requests_missing_cves_and_parses_probability(self):
        calls = []

        def request(url, headers=None):
            calls.append(url)
            return {"data": [{"cve": "CVE-2026-0103", "epss": "0.25", "percentile": "0.98"}]}, {}

        scores = feed.fetch_epss_api({"CVE-2026-0103"}, request)
        self.assertEqual(len(calls), 1)
        self.assertIn("CVE-2026-0103", calls[0])
        self.assertEqual(scores["CVE-2026-0103"], {"score": 0.25, "percentile": 0.98})

    def test_recent_cache_reuses_existing_scores_and_looks_up_only_new_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "data"
            output.mkdir()
            feed._write_json(output / "epss.json", {
                "schema_version": 1,
                "updated_at": "2026-09-30T00:00:00Z",
                "checked_at": "2026-09-30T00:00:00Z",
                "score_date": "2026-09-29",
                "source_updated_at": "2026-09-29T12:00:22Z",
                "scores": {"CVE-2026-0101": {"score": 0.05, "percentile": 0.93}},
            })

            def api_request(url, headers=None):
                self.assertIn("CVE-2026-0102", url)
                return {"data": [{"cve": "CVE-2026-0102", "epss": "0.4", "percentile": "0.99"}]}, {}

            def unexpected_csv(_):
                raise AssertionError("A recently checked daily CSV should be reused")

            records = [{"id": "CVE-2026-0101"}, {"id": "CVE-2026-0102"}]
            snapshot, status = feed.build_epss_snapshot(
                records,
                output,
                datetime(2026, 9, 30, 1, tzinfo=timezone.utc),
                unexpected_csv,
                api_request,
            )
            self.assertTrue(status["ok"])
            self.assertEqual(snapshot["scores"]["CVE-2026-0101"]["score"], 0.05)
            self.assertEqual(snapshot["scores"]["CVE-2026-0102"]["score"], 0.4)

    def test_failed_optional_epss_does_not_raise_or_claim_a_zero_score(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "data"
            output.mkdir()

            def unavailable(_):
                raise RuntimeError("offline")

            snapshot, status = feed.build_epss_snapshot(
                [{"id": "CVE-2026-0104"}],
                output,
                datetime(2026, 9, 30, 1, tzinfo=timezone.utc),
                unavailable,
            )
            self.assertFalse(status["ok"])
            self.assertEqual(status["records"], 1)
            self.assertEqual(snapshot["scores"], {})


class SnapshotTests(unittest.TestCase):
    def test_manifest_advertises_every_calendar_shard_and_exact_source_coverage(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 3, tzinfo=timezone.utc)
        generated = datetime(2026, 9, 3, 1, tzinfo=timezone.utc)
        record = feed.build_records([], [], [{
            "cveID": "CVE-2026-4001", "dateAdded": "2026-09-02", "vendorProject": "Vendor", "product": "Product"
        }], start, end)[0]
        statuses = [{"name": "NVD", "ok": True}, {"name": "GitHub", "ok": True}, {"name": "CISA", "ok": True}]
        manifest, shards = feed.build_manifest([record], start, end, generated, statuses, 2, 3, 4)
        self.assertEqual(manifest["schema_version"], 2)
        self.assertTrue(manifest["complete"])
        self.assertEqual([day["date"] for day in manifest["days"]], ["2026-09-01", "2026-09-02", "2026-09-03"])
        self.assertEqual(manifest["totals"]["known_exploited"], 1)
        self.assertEqual(manifest["totals"]["cves"], sum(day["count"] for day in manifest["days"]))
        self.assertEqual(manifest["coverage"]["distinct_cve_records"], len(records := [item for shard in shards.values() for item in shard]))
        self.assertEqual(len(shards["2026-09-02"]), 1)
        self.assertEqual(manifest["coverage"]["utc_days_sharded"], 3)

    def test_snapshot_is_sharded_and_manifest_is_written(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 2, tzinfo=timezone.utc)
        generated = datetime(2026, 9, 2, 1, tzinfo=timezone.utc)
        statuses = [{"name": "NVD", "ok": True}]
        manifest, shards = feed.build_manifest([], start, end, generated, statuses, 0, 0, 0)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            feed.write_snapshot(output, manifest, shards)
            saved = json.loads((output / "manifest.json").read_text())
            self.assertEqual(saved["totals"]["cves"], 0)
            self.assertEqual(json.loads((output / "2026-09-01.json").read_text()), [])
            self.assertEqual(json.loads((output / "2026-09-02.json").read_text()), [])

    def test_manifest_rejects_records_outside_every_available_utc_shard(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 2, tzinfo=timezone.utc)
        record = {"id": "CVE-2020-9999", "window_date": "2026-08-31"}
        with self.assertRaises(feed.FeedError):
            feed.build_manifest([record], start, end, end, [], 0, 0, 0)

    def test_incomplete_source_failure_does_not_publish_partial_snapshot(self):
        def fail_on_github(url, headers=None):
            if url.startswith(feed.NVD_API):
                return {"totalResults": 0, "vulnerabilities": []}, {}
            raise feed.FeedError("GitHub unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with self.assertRaises(feed.FeedError):
                feed.refresh(output_dir=output, now=datetime(2026, 9, 30, tzinfo=timezone.utc), request_fn=fail_on_github, sleep_fn=lambda _: None)
            self.assertFalse((output / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
