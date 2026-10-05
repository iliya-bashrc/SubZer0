from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_data as feed  # noqa: E402


class PaginationTests(unittest.TestCase):
    def test_nvd_walks_every_offset_page_and_checks_constant_totals(self):
        calls = []
        sleeps = []
        pages = {
            0: {"totalResults": 3, "startIndex": 0, "resultsPerPage": 2, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-0001"}}, {"cve": {"id": "CVE-2026-0002"}},
            ]},
            2: {"totalResults": 3, "startIndex": 2, "resultsPerPage": 1, "vulnerabilities": [
                {"cve": {"id": "CVE-2026-0003"}},
            ]},
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
        self.assertEqual(sleeps, [feed.NVD_PAGE_PAUSE_SECONDS])
        self.assertEqual(calls[0]["lastModStartDate"], ["2026-09-01T00:00:00.000"])
        self.assertEqual(calls[0]["lastModEndDate"], ["2026-09-30T00:00:00.000"])

    def test_nvd_restarts_complete_query_once_when_total_changes(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        calls = []
        sleeps = []
        first_attempt = {
            0: {"totalResults": 2, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]},
            1: {"totalResults": 3, "startIndex": 1, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0002"}}]},
        }
        stable_attempt = {
            offset: {"totalResults": 3, "startIndex": offset, "resultsPerPage": 1,
                     "vulnerabilities": [{"cve": {"id": f"CVE-2026-000{offset + 1}"}}]}
            for offset in range(3)
        }

        def request(url, headers=None):
            params = parse_qs(urlparse(url).query)
            offset = int(params["startIndex"][0])
            calls.append(offset)
            return (first_attempt if len(calls) <= 2 else stable_attempt)[offset], {}

        records, total, pages = feed.iter_nvd(start, end, request, sleeps.append, page_size=1)
        self.assertEqual(([item["cve"]["id"] for item in records], total, pages),
                         (["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], 3, 3))
        self.assertEqual(calls, [0, 1, 0, 1, 2])
        self.assertEqual(len(sleeps), 4)

    def test_nvd_can_query_publication_window_explicitly(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        calls = []
        page = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]}
        feed.iter_nvd(start, end, lambda url, headers=None: (calls.append(url) or page, {}),
                      lambda _: None, date_field="published")
        query = parse_qs(urlparse(calls[0]).query)
        self.assertIn("pubStartDate", query)
        self.assertIn("pubEndDate", query)

    def test_nvd_fails_on_empty_or_changing_pages(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        pages = iter([
            ({"totalResults": 2, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]}, {}),
            ({"totalResults": 3, "startIndex": 1, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0002"}}]}, {}),
            ({"totalResults": 2, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]}, {}),
            ({"totalResults": 3, "startIndex": 1, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0002"}}]}, {}),
        ])
        with self.assertRaises(feed.FeedError):
            feed.iter_nvd(start, end, lambda *args, **kwargs: next(pages), lambda _: None, page_size=1)

        with self.assertRaises(feed.FeedError):
            feed.iter_nvd(start, end, lambda *args, **kwargs: ({"totalResults": 1, "vulnerabilities": []}, {}), lambda _: None)

        for malformed in (
            {"totalResults": 1, "startIndex": False, "resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]},
            {"totalResults": 1, "startIndex": 0, "resultsPerPage": -1, "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}]},
        ):
            with self.subTest(malformed=malformed), self.assertRaises(feed.FeedError):
                feed.iter_nvd(start, end, lambda *args, **kwargs: (malformed, {}), lambda _: None)

    def test_github_follows_only_official_link_cursor_and_preserves_token_header(self):
        cursor = "https://api.github.com/advisories?after=next-cursor"
        calls = []

        def request(url, headers=None):
            calls.append((url, headers or {}))
            if len(calls) == 1:
                return [{"ghsa_id": "GHSA-one", "cve_id": "CVE-2026-0001"}], {"Link": f'<{cursor}>; rel="next"'}
            return [{"ghsa_id": "GHSA-two", "cve_id": "CVE-2026-0002"}], {}

        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        items, pages = feed.iter_github_advisories(start, end, request, token="test-token")
        self.assertEqual(pages, 2)
        self.assertEqual([item["ghsa_id"] for item in items], ["GHSA-one", "GHSA-two"])
        self.assertEqual(calls[0][1]["Authorization"], "Bearer test-token")
        self.assertEqual(calls[0][1]["X-GitHub-Api-Version"], "2026-03-10")
        query = parse_qs(urlparse(calls[0][0]).query)
        self.assertEqual(query["per_page"], ["100"])
        self.assertEqual(query["modified"], ["2026-09-01..2026-09-30"])
        self.assertEqual(query["sort"], ["updated"])

    def test_github_rejects_off_origin_cursor_and_empty_success(self):
        bad_cursor = "https://attacker.example/advisories?after=next"
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, tzinfo=timezone.utc)
        with self.assertRaises(feed.FeedError):
            feed.iter_github_advisories(start, end, lambda *_args, **_kwargs: ([{"ghsa_id": "GHSA-one"}], {"Link": f'<{bad_cursor}>; rel="next"'}))
        with self.assertRaises(feed.FeedError):
            feed.iter_github_advisories(start, end, lambda *_args, **_kwargs: ([], {}))

    def test_cisa_requires_nonempty_count_matched_catalog(self):
        with self.assertRaises(feed.FeedError):
            feed.fetch_kev(lambda *_args, **_kwargs: ({"count": 0, "vulnerabilities": []}, {}))
        with self.assertRaises(feed.FeedError):
            feed.fetch_kev(lambda *_args, **_kwargs: ({"count": 2, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}, {}))


class NormalizationTests(unittest.TestCase):
    def test_cvss_zero_is_none_and_thresholds_are_exact(self):
        self.assertEqual(feed.severity_for(0), "none")
        self.assertEqual(feed.severity_for(None), "unknown")
        self.assertEqual(feed.severity_for(0.1), "low")
        self.assertEqual(feed.severity_for(3.9), "low")
        self.assertEqual(feed.severity_for(4.0), "medium")
        self.assertEqual(feed.severity_for(7.0), "high")
        self.assertEqual(feed.severity_for(9.0), "critical")

    def test_safe_url_accepts_real_http_references_and_rejects_active_or_credential_urls(self):
        self.assertEqual(feed._safe_url("http://example.org/advisory"), "http://example.org/advisory")
        self.assertEqual(feed._safe_url("https://example.org/advisory"), "https://example.org/advisory")
        for candidate in (
            "javascript:alert(1)", "data:text/html,hello", "file:///etc/passwd",
            "https://user:pass@example.org/", "http://@example.org/", "https://example.org/with space",
        ):
            self.assertIsNone(feed._safe_url(candidate), candidate)

    def test_nvd_and_github_cvss_are_finite_and_in_range(self):
        with self.assertRaises(feed.FeedError):
            feed._cvss({"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 99}}]}})
        bad = {
            "ghsa_id": "GHSA-bad-score", "cve_id": "CVE-2026-0001",
            "published_at": "2026-09-10T11:00:00Z", "cvss_severities": {"cvss_v3": {"score": 1e100}},
        }
        with self.assertRaises(feed.FeedError):
            feed.build_records([], [bad], [], datetime(2026, 9, 1, tzinfo=timezone.utc), datetime(2026, 9, 30, tzinfo=timezone.utc))
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        ghsa = {"ghsa_id": "GHSA-vector", "cve_id": "CVE-2026-0012", "published_at": "2026-09-12T00:00:00Z",
                "html_url": "https://github.com/advisories/GHSA-vector",
                "cvss_severities": {"cvss_v3": {"score": 8.1, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}}}
        record = feed.build_records([], [ghsa], [], start, end)[0]
        self.assertEqual((record["cvss_version"], record["cvss_source"]), ("3.1", "GitHub Advisory Database"))
        self.assertTrue(record["cvss_vector"].startswith("CVSS:3.1/"))

    def test_nvd_unprefixed_cvss2_vector_is_preserved(self):
        vector = "AV:N/AC:M/Au:N/C:P/I:P/A:P"
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        cve = {
            "id": "CVE-2026-0014", "published": "2026-09-12T00:00:00Z",
            "lastModified": "2026-09-13T00:00:00Z",
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "version": "2.0", "vectorString": vector}}]},
        }
        record = feed.build_records([{"cve": cve}], [], [], start, end)[0]
        self.assertEqual((record["cvss_version"], record["cvss_vector"], record["cvss_source"]), ("2.0", vector, "NVD"))
        prefixed = f"CVSS:2.0/{vector}"
        self.assertEqual(feed._checked_cvss_vector(prefixed, "2.0", "fixture"), prefixed)
        with self.assertRaisesRegex(feed.FeedError, "unsupported CVSS 2.0 vector"):
            feed._checked_cvss_vector("AV:X/AC:M/Au:N/C:P/I:P/A:P", "2.0", "fixture")

    def test_long_cvss4_vector_is_preserved_with_a_hard_bound(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:L/MUI:P/MVC:H/MVI:H/MVA:H/MSC:H/MSI:H/MSA:H/S:P/AU:N/R:A/V:D/RE:M/U:Green"
        self.assertGreater(len(vector), 128)
        self.assertLessEqual(len(vector), feed.MAX_CVSS_VECTOR_CHARS)
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        cve = {
            "id": "CVE-2026-0013", "published": "2026-09-12T00:00:00Z",
            "lastModified": "2026-09-13T00:00:00Z",
            "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.7, "version": "4.0", "vectorString": vector}}]},
        }
        record = feed.build_records([{"cve": cve}], [], [], start, end)[0]
        self.assertEqual(record["cvss_vector"], vector)
        self.assertEqual(record["cvss_version"], "4.0")
        cve["metrics"]["cvssMetricV40"][0]["cvssData"]["vectorString"] = vector + "A" * (feed.MAX_CVSS_VECTOR_CHARS + 1 - len(vector))
        with self.assertRaisesRegex(feed.FeedError, "character bound"):
            feed.build_records([{"cve": cve}], [], [], start, end)

    def test_sources_merge_once_and_preserve_cvss_kev_and_attribution(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        nvd = [{"cve": {
            "id": "CVE-2026-1001", "published": "2026-09-10T11:00:00.123",
            "lastModified": "2026-09-12T12:00:00",
            "descriptions": [{"lang": "en", "value": "A serious flaw in Acme Router."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "references": [{"url": "http://vendor.example/security/advisory"}],
        }}]
        advisory = {
            "ghsa_id": "GHSA-test", "cve_id": "cve-2026-1001",
            "summary": "Acme Router command injection", "published_at": "2026-09-10T11:00:00Z",
            "updated_at": "2026-09-18T14:30:00Z",
            "html_url": "https://github.com/advisories/GHSA-test",
        }
        kev = [{
            "cveID": "CVE-2026-1001", "dateAdded": "2026-09-15", "vendorProject": "Acme",
            "product": "Router", "vulnerabilityName": "Acme Router remote code execution",
            "shortDescription": "Known exploitation observed.", "dueDate": "2026-09-22",
            "requiredAction": "Apply vendor updates.", "knownRansomwareCampaignUse": "Unknown",
        }]
        records = feed.build_records(nvd, [advisory], kev, start, end)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["id"], record["score"], record["sev"]), ("CVE-2026-1001", 9.8, "critical"))
        self.assertEqual(record["published"], "2026-09-10T11:00:00.123Z")
        self.assertEqual(record["modified"], "2026-09-12T12:00:00Z")
        self.assertEqual(record["window_date"], "2026-09-18")
        self.assertEqual(record["activity_at"], "2026-09-18T14:30:00Z")
        self.assertEqual(record["date_basis"], "GitHub advisory updated")
        self.assertEqual(record["advisories"][0]["published_at"], "2026-09-10T11:00:00Z")
        self.assertEqual(record["advisories"][0]["updated_at"], "2026-09-18T14:30:00Z")
        self.assertEqual(record["sources"], ["NVD", "GitHub Advisory Database", "CISA KEV"])
        self.assertEqual(record["kev"]["date_added"], "2026-09-15")
        self.assertIn("http://vendor.example/security/advisory", [item["url"] for item in record["refs"]])
        self.assertEqual(record["primary_url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-1001")
        self.assertEqual((record["cvss_version"], record["cvss_source"]), ("3.1", "NVD"))
        self.assertEqual(record["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_modified_cve_keeps_older_publication_date(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        cve = {"id": "CVE-2021-4242", "published": "2021-04-10T09:00:00Z",
               "lastModified": "2026-09-17T12:00:00Z", "descriptions": [{"lang": "en", "value": "Updated vendor record."}]}
        record = feed.build_records([{"cve": cve}], [], [], start, end)[0]
        self.assertEqual(record["published"], "2021-04-10T09:00:00Z")
        self.assertEqual(record["modified"], "2026-09-17T12:00:00Z")
        self.assertEqual(record["window_date"], "2026-09-17")
        self.assertEqual(record["date_basis"], "NVD last modified")


class ChangeHistoryTests(unittest.TestCase):
    def test_overview_change_preview_uses_real_events_and_preserves_both_times(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 30, 23, 59, tzinfo=timezone.utc)
        record = feed.build_records([{"cve": {
            "id": "CVE-2026-8110", "published": "2026-09-10T11:00:00Z",
            "lastModified": "2026-09-18T11:00:00Z", "descriptions": [{"lang": "en", "value": "Source title."}],
        }}], [], [], start, end)[0]
        observed = "2026-09-30T20:00:00Z"
        source_time = "2026-09-28T08:15:00Z"
        history = {"events": [
            {"id": record["id"], "type": "CVSS_CHANGED", "observed_at": observed, "source_time": source_time,
             "source": "NVD", "from": 4.0, "to": 8.0},
            {"id": "CVE-2020-9999", "type": "NEW_CVE", "observed_at": observed, "source_time": None,
             "source": "NVD", "from": None, "to": {}},
        ]}
        overview = feed.build_overview([record], end, {"scores": {}}, history)
        self.assertEqual(len(overview["recent_changes"]), 1)
        self.assertEqual(overview["recent_changes"][0]["id"], record["id"])
        self.assertEqual(overview["recent_changes"][0]["observed_at"], observed)
        self.assertEqual(overview["recent_changes"][0]["source_time"], source_time)
        self.assertEqual(overview["recent_changes"][0]["source"], "NVD")

    def test_new_cve_and_reobserved_modified_cve_are_not_conflated(self):
        observed = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
        previous_capture = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
        records = [
            {"id": "CVE-2026-8001", "title": "New", "published": "2026-10-05T10:00:00Z",
             "activity_at": "2026-10-05T10:00:00Z", "date_basis": "CVE publication"},
            {"id": "CVE-2020-8002", "title": "Updated", "published": "2020-01-01T00:00:00Z",
             "activity_at": "2026-10-05T11:00:00Z", "date_basis": "NVD last modified"},
        ]
        events = feed.material_change_events([], records, None, None, observed, previous_capture)
        by_id = {event["id"]: event["type"] for event in events}
        self.assertEqual(by_id, {"CVE-2026-8001": "NEW_CVE", "CVE-2020-8002": "CVE_REOBSERVED"})

    def test_epss_score_removal_is_observed_with_the_score_set_timestamp(self):
        observed = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
        previous = [{"id": "CVE-2021-8100", "published": "2021-01-01T00:00:00Z",
                     "activity_at": "2026-10-04T12:00:00Z", "date_basis": "NVD last modified"}]
        current = [{"id": "CVE-2021-8100", "published": "2021-01-01T00:00:00Z",
                    "activity_at": "2026-10-04T12:00:00Z", "date_basis": "NVD last modified"}]
        old_epss = {"scores": {"CVE-2021-8100": {"score": 0.12, "percentile": 0.91}}}
        new_epss = {"scores": {}, "source_updated_at": "2026-10-05T11:00:00Z"}
        events = feed.material_change_events(previous, current, old_epss, new_epss, observed)
        change = next(event for event in events if event["type"] == "EPSS_CHANGED")
        self.assertEqual(change["from"], 0.12)
        self.assertIsNone(change["to"])
        self.assertEqual(change["source_time"], "2026-10-05T11:00:00Z")

    def test_full_kev_catalog_detects_old_entry_change_and_removal(self):
        observed = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
        previous = [
            {"cveID": "CVE-2019-9001", "dateAdded": "2019-03-01", "requiredAction": "Patch"},
            {"cveID": "CVE-2018-9002", "dateAdded": "2018-02-01", "requiredAction": "Remove"},
        ]
        current = [
            {"cveID": "CVE-2019-9001", "dateAdded": "2019-03-01", "requiredAction": "Upgrade"},
            {"cveID": "CVE-2026-9003", "dateAdded": "2026-10-05", "requiredAction": "Patch"},
        ]
        events = feed.material_change_events([], [], None, None, observed, observed - timedelta(days=1), previous, current)
        by_pair = {(event["id"], event["type"]) for event in events}
        self.assertEqual(by_pair, {("CVE-2019-9001", "KEV_CHANGED"), ("CVE-2018-9002", "KEV_REMOVED"), ("CVE-2026-9003", "KEV_ADDED")})


class EpssTests(unittest.TestCase):
    def test_csv_parser_reads_score_date_and_filters_ids(self):
        csv_text = (
            "#model_version:v2026.06.15,score_date:2026-09-29T12:00:22Z\n"
            "cve,epss,percentile\n"
            "CVE-2026-0101,0.05000,0.93000\n"
            "CVE-2026-0102,0.00001,0.20000\n"
        )
        scores, score_date, updated_at = feed.parse_epss_csv(io.StringIO(csv_text), {"CVE-2026-0101"})
        self.assertEqual(score_date, "2026-09-29")
        self.assertEqual(updated_at, "2026-09-29T12:00:22Z")
        self.assertEqual(scores, {"CVE-2026-0101": {"score": 0.05, "percentile": 0.93}})

    def test_csv_rejects_nan_duplicate_headers_and_invalid_target_scores(self):
        header = "# score_date:2026-09-29T12:00:22Z\n"
        for body in (
            "cve,epss,epss\nCVE-2026-0101,0.2,0.3\n",
            "cve,epss,percentile\nCVE-2026-0101,NaN,0.9\n",
        ):
            with self.subTest(body=body), self.assertRaises(feed.FeedError):
                feed.parse_epss_csv(io.StringIO(header + body), {"CVE-2026-0101"})

    def test_epss_failure_does_not_turn_missing_scores_into_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "snapshot"
            output.mkdir()

            def unavailable(_):
                raise RuntimeError("offline")

            snapshot, status = feed.build_epss_snapshot(
                [{"id": "CVE-2026-0104"}], output,
                datetime(2026, 9, 30, 1, tzinfo=timezone.utc), unavailable,
            )
            self.assertFalse(status["ok"])
            self.assertEqual(status["records"], 1)
            self.assertEqual(snapshot["scores"], {})
            self.assertIn("scores", snapshot)

    def test_epss_gzip_reader_is_bounded(self):
        payload = gzip.compress(b"# score_date:2026-09-29T12:00:22Z\ncve,epss,percentile\nCVE-2026-0101,0.1,0.5\n")
        limited = feed._BoundedReader(io.BytesIO(payload), len(payload) - 1, "compressed")
        with self.assertRaises(feed.FeedError):
            limited.read(len(payload))


class PipelineFailureTests(unittest.TestCase):
    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc).replace(microsecond=0)

    def _request_for(self, now: datetime):
        activity = feed.iso_z(now - timedelta(hours=1))
        cve = {
            "id": "CVE-2026-7001", "published": activity, "lastModified": activity,
            "descriptions": [{"lang": "en", "value": "A fixture vulnerability in Widget."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]},
            "references": [{"url": "https://vendor.example/security/7001"}],
        }
        advisory = {
            "ghsa_id": "GHSA-fixture-7001", "cve_id": "CVE-2026-7001",
            "summary": "Fixture security advisory", "published_at": activity,
            "html_url": "https://github.com/advisories/GHSA-fixture-7001",
        }
        kev = {
            "cveID": "CVE-2026-7001", "dateAdded": now.date().isoformat(),
            "vendorProject": "Fixture", "product": "Widget", "dueDate": "",
            "requiredAction": "Apply the vendor update.", "knownRansomwareCampaignUse": "Unknown",
        }

        def request(url, headers=None):
            if url.startswith(feed.NVD_API):
                offset = int(parse_qs(urlparse(url).query)["startIndex"][0])
                return ({"totalResults": 1, "startIndex": offset, "resultsPerPage": 1, "vulnerabilities": [{"cve": cve}]}, {})
            if url.startswith(feed.GITHUB_API):
                return [advisory], {}
            if url == feed.CISA_KEV:
                return {"count": 1, "vulnerabilities": [kev]}, {}
            raise AssertionError(f"Unexpected source URL: {url}")

        def epss(ids):
            return ({"CVE-2026-7001": {"score": 0.2, "percentile": 0.95}}, now.date().isoformat(), feed.iso_z(now))

        return request, epss

    def test_success_writes_only_current_static_paths_and_validation_report(self):
        now = self._now()
        request, epss = self._request_for(now)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "snapshot"
            manifest = feed.refresh(output, now, request, lambda _: None, epss_csv_loader=epss)
            self.assertTrue((output / "manifest.json").is_file())
            self.assertTrue((output / "VALIDATION.json").is_file())
            self.assertTrue((output / "data" / "overview.json").is_file())
            self.assertTrue((output / "data" / "epss.json").is_file())
            self.assertTrue((output / "data" / "search-index.json.gz").is_file())
            self.assertEqual(manifest["totals"]["cves"], 1)
            self.assertFalse((Path(temporary) / "api").exists())
            data_names = {path.name for path in (output / "data").iterdir()}
            self.assertEqual(data_names, {f"{day['date']}.json" for day in manifest["days"]} | {"overview.json", "epss.json", "search-index.json.gz", "history.json"})
            packed = (output / "data" / "search-index.json.gz").read_bytes()
            uncompressed = gzip.decompress(packed)
            self.assertEqual(hashlib.sha256(packed).hexdigest(), manifest["search_index"]["sha256"])
            self.assertEqual(len(packed), manifest["search_index"]["bytes"])
            self.assertEqual(hashlib.sha256(uncompressed).hexdigest(), manifest["search_index"]["uncompressed_sha256"])
            self.assertEqual(len(uncompressed), manifest["search_index"]["uncompressed_bytes"])
            self.assertEqual(manifest["overview"]["recent_change_count"], 0)

    def test_core_source_failure_or_empty_result_preserves_every_prior_snapshot_byte(self):
        now = self._now()
        request, epss = self._request_for(now)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "snapshot"
            feed.refresh(output, now, request, lambda _: None, epss_csv_loader=epss)
            before = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}

            def empty_nvd(url, headers=None):
                if url.startswith(feed.NVD_API):
                    return {"totalResults": 0, "vulnerabilities": []}, {}
                raise AssertionError("An empty NVD result must abort before later sources")

            with self.assertRaises(feed.FeedError):
                feed.refresh(output, now, empty_nvd, lambda _: None, epss_csv_loader=epss)
            after = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}
            self.assertEqual(after, before)

            def fail_github(url, headers=None):
                if url.startswith(feed.NVD_API):
                    return request(url, headers)
                raise feed.FeedError("GitHub unavailable")

            with self.assertRaises(feed.FeedError):
                feed.refresh(output, now, fail_github, lambda _: None, epss_csv_loader=epss)
            after_second = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}
            self.assertEqual(after_second, before)

    def test_directory_commit_rolls_back_when_replacement_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "snapshot"
            output.mkdir()
            (output / "marker").write_text("old", encoding="utf-8")
            stage = parent / ".snapshot-stage"
            stage.mkdir()
            (stage / "marker").write_text("new", encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_second_replace(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory swap error")
                return real_replace(source, target)

            with mock.patch.object(feed.os, "replace", side_effect=fail_second_replace):
                with self.assertRaises(OSError):
                    feed._commit_snapshot(stage, output)
            self.assertEqual((output / "marker").read_text(encoding="utf-8"), "old")
            self.assertTrue(stage.is_dir())

    def test_directory_commit_reports_backup_when_rollback_rename_also_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "snapshot"
            output.mkdir()
            (output / "marker").write_text("old", encoding="utf-8")
            stage = parent / ".snapshot-stage"
            stage.mkdir()
            (stage / "marker").write_text("new", encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_swap_and_restore(source, target):
                nonlocal calls
                calls += 1
                if calls in (2, 3):
                    raise OSError("simulated directory swap/rollback error")
                return real_replace(source, target)

            with mock.patch.object(feed.os, "replace", side_effect=fail_swap_and_restore):
                with self.assertRaisesRegex(feed.FeedError, "previous snapshot is preserved at") as caught:
                    feed._commit_snapshot(stage, output)

            backups = list(parent.glob(".snapshot.backup-*"))
            self.assertEqual(len(backups), 1)
            self.assertIn(str(backups[0]), str(caught.exception))
            self.assertEqual((backups[0] / "marker").read_text(encoding="utf-8"), "old")
            self.assertFalse(output.exists())
            self.assertTrue(stage.is_dir())

    def test_aggregate_upstream_json_ingress_is_bounded(self):
        budget = feed._JSONIngressBudget(limit=8)
        with self.assertRaisesRegex(feed.FeedError, "Combined upstream JSON"):
            budget.fetch(lambda *_args, **_kwargs: ({"payload": "longer than budget"}, {}), feed.NVD_API)

    def test_request_policy_rejects_official_api_redirect_targets_and_large_bodies(self):
        with self.assertRaises(feed.FeedError):
            feed.request_json("https://attacker.example/advisories")

        class Response:
            headers = {"Content-Length": "101"}
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def read(self, size=-1): return b"x" * min(size, 101)

        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.object(feed, "MAX_HTTP_JSON_BYTES", 100), mock.patch.object(feed.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(feed.FeedError):
                feed.request_json(feed.NVD_API)


if __name__ == "__main__":
    unittest.main()
