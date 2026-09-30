import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "styles.css").read_text(encoding="utf-8")
JS = (ROOT / "app.js").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


class StaticSiteTests(unittest.TestCase):
    def test_product_name_and_forbidden_invented_branding(self):
        self.assertIn("<title>SubZer0 — Vulnerability Intelligence Hub</title>", HTML)
        self.assertIn('<h1 id="page-title">SubZer0</h1>', HTML)
        self.assertNotRegex(HTML + CSS + JS + README, re.compile(r"ice\s*[×x/]\s*ember|frost signal|\barena\b|\bmatchup\b", re.I))
        self.assertNotIn("SUBZER0", HTML + CSS + JS + README)

    def test_accessible_feed_controls_loader_notice_and_detail_dialog_exist(self):
        for element_id in (
            "loader", "loader-message", "search-input", "date-from", "date-to", "apply-dates",
            "severity-filters", "sort-select", "load-more", "detail-dialog", "detail-content",
            "feed-status", "epss-freshness", "new-notice", "new-notice-text", "view-new",
        ):
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn('aria-live="polite"', HTML)
        self.assertIn('aria-label="Search and filter CVEs"', HTML)
        self.assertIn("NONE / UNRATED", HTML)

    def test_compact_footer_attribution_and_links_are_accurate(self):
        self.assertIn('href="https://t.me/RootAccessClub"', HTML)
        self.assertIn("@RootAccessClub", HTML)
        self.assertIn("© RootAccessClub", HTML)
        self.assertIn('href="https://github.com/iliya-bashrc/SubZer0"', HTML)
        self.assertNotIn("img.shields.io", HTML + README)
        self.assertIn("not endorsed or certified by the NVD", HTML)

    def test_cvss_epss_kev_and_unverified_repository_search_remain_distinct(self):
        self.assertIn("Severity score; not exploit likelihood.", HTML)
        self.assertIn("Estimated probability of observed exploitation in the next 30 days.", HTML)
        self.assertIn("CISA catalog listing for a known exploited vulnerability.", HTML)
        self.assertIn("CISA KEV / CATALOG EVIDENCE", JS)
        self.assertIn("Why it matters", JS)
        self.assertIn("0.0 · NONE", JS)
        self.assertIn("CVSS / SEVERITY", JS)
        self.assertIn("EPSS / 30-DAY PROBABILITY", JS)
        self.assertIn("GitHub repository search", JS)
        self.assertIn("unverified", (HTML + JS + README).lower())
        self.assertIn("Missing data is not a 0% forecast.", JS)
        self.assertIn("CISA Known Exploited Vulnerabilities catalog", JS)

    def test_core_source_badge_excludes_optional_epss(self):
        self.assertIn("const coreSourceNames = ['NVD CVE API 2.0'", JS)
        self.assertIn("const coreOk = coreKnown && coreSources.every", JS)
        self.assertIn("3 CORE SOURCES OK", JS)
        self.assertIn("CORE COVERAGE GAP", JS)
        self.assertNotIn("FEEDS OK", JS)
        self.assertIn("FIRST EPSS is separate probability enrichment", HTML)

    def test_severity_color_mapping_is_severity_controlled(self):
        for color in ("--critical: #ed5558", "--high: #ee9b4c", "--medium: #d8bd59", "--low: #78cde3", "--unknown: #8d999f"):
            with self.subTest(color=color):
                self.assertIn(color, CSS)
        for rule in (
            ".severity-critical { --accent: var(--critical); }",
            ".severity-high { --accent: var(--high); }",
            ".severity-medium { --accent: var(--medium); }",
            ".severity-low { --accent: var(--low); }",
            ".severity-none { --accent: var(--unknown); }",
            ".severity-unknown { --accent: var(--unknown); }",
        ):
            self.assertIn(rule, CSS)

    def test_card_age_cools_signal_and_kev_keeps_an_independent_ice_edge(self):
        self.assertIn("function cardAgeVividness(record)", JS)
        self.assertIn("const ageVividness = cardAgeVividness(record);", JS)
        self.assertIn("if (timestamp == null) return null;", JS)
        self.assertIn("class=\"cve-card severity-${severity}${record.kev ? ' kev-listed' : ''}\"", JS)
        self.assertIn("const ageStyle = ageVividness == null ? '' : ` style=\"--age-vividness:${ageVividness}%\"`;", JS)
        self.assertIn(".cve-card.kev-listed { --card-accent: var(--critical);", CSS)
        self.assertIn("color: var(--aged-severity, var(--accent));", CSS)

    def test_cards_use_subtle_pointer_hover_and_critical_only_pulse(self):
        self.assertIn("@media (hover: hover) and (pointer: fine)", CSS)
        self.assertIn(".cve-card:hover { transform: translateY(-2px);", CSS)
        self.assertIn("0 0 13px rgba(120, 205, 227, .055)", CSS)
        self.assertIn(".severity-critical::before { animation: criticalEmber 7s ease-in-out infinite; }", CSS)
        self.assertIn("@keyframes criticalEmber", CSS)
        self.assertIn(".loader-mark, .loader-readout i, .skeleton, .severity-critical::before, .quiet-button.is-checking .refresh-icon, .cve-card.filter-arrive { animation: none; }", CSS)

    def test_microinteraction_states_include_filter_loading_refresh_and_copy_feedback(self):
        self.assertIn("render({ animateCards: true });", JS)
        self.assertIn("class=\"skeleton loading-skeleton\"", JS)
        self.assertIn("await Promise.allSettled", JS)
        self.assertIn("onShardLoaded: (day, records)", JS)
        self.assertIn("appendLoadingSkeletons(days.length)", JS)
        self.assertIn("const outstanding = days.length - completedShards;", JS)
        self.assertIn("button.classList.add('is-checking')", JS)
        self.assertIn("class=\"refresh-icon\"", HTML)
        self.assertIn("animation: coldRing 2.2s linear infinite", CSS)
        self.assertIn("toast('Copied');", JS)
        self.assertIn("const duration = message === 'Copied' ? 1_800 : 4_600;", JS)
        self.assertIn(".control-panel { position: sticky;", CSS)
        self.assertIn(".cve-card.filter-arrive { animation: filterCardsIn .14s", CSS)
        self.assertIn(".skeleton.loading-skeleton { min-height: 118px; }", CSS)

    def test_mobile_first_breakpoints_touch_sizes_and_reduced_motion(self):
        self.assertIn("@media (max-width: 900px)", CSS)
        self.assertIn("@media (max-width: 720px)", CSS)
        self.assertIn("@media (max-width: 560px)", CSS)
        self.assertIn("@media (max-width: 360px)", CSS)
        self.assertIn("@media (prefers-reduced-motion: reduce)", CSS)
        self.assertIn("min-height: 44px", CSS)
        self.assertIn("grid-template-columns: 1fr", CSS)

    def test_stats_use_larger_separated_cards_and_preserve_mobile_reflow(self):
        self.assertIn(".stats { display: grid; grid-template-columns: 1.2fr repeat(3, minmax(0, 1fr)); gap: 11px;", CSS)
        self.assertIn(".stat-total .stat-value", CSS)
        self.assertIn("font-size: 40px", CSS)
        self.assertIn(".stats { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px;", CSS)
        self.assertIn(".stat-total { grid-column: 1 / -1; }", CSS)

    def test_hero_stat_count_up_runs_after_initial_data_and_respects_reduced_motion(self):
        self.assertIn("function animateCountUp(element, target)", JS)
        self.assertIn("window.matchMedia('(prefers-reduced-motion: reduce)').matches", JS)
        self.assertIn("await loadDays(newest, { deferRender: true });", JS)
        self.assertIn("render({ animateStats: true });", JS)
        self.assertIn("statAnimationFrames.size && statAnimationKey === targetKey", JS)
        self.assertIn("element.textContent = '0';", JS)
        self.assertIn("Math.max(0, Math.min(1, (now - startedAt) / duration))", JS)
        self.assertIn("<span class=\"stat-foot\">Deduplicated records</span>", HTML)

    def test_startup_is_data_aware_and_retries_without_timed_hide(self):
        self.assertIn("for (;;) {", JS)
        self.assertIn("BOOT_RETRY_MS", JS)
        self.assertIn("FETCH_TIMEOUT_MS", JS)
        self.assertIn("retryableStatuses", JS)
        self.assertIn("void loadEpssSnapshot().then", JS)
        self.assertNotIn("await loadEpssSnapshot()", JS)
        self.assertIn("setLoaderMessage(`Feed unavailable. Retrying", JS)
        self.assertNotIn("setTimeout(hideLoader", JS)
        self.assertNotIn("hideLoader();", JS[JS.index("async function refresh"):JS.index("function renderDetail")])

    def test_snapshot_change_detection_stages_records_and_requires_user_action(self):
        self.assertIn("sha256", JS)
        self.assertIn("const changed = !!previousVersion", JS)
        self.assertIn("deferRender: true", JS)
        self.assertIn("pendingFeedUpdate = true", JS)
        self.assertIn("showUpdateNotice", JS)
        self.assertIn("$('view-new').addEventListener('click', () => acceptPendingUpdate(true))", JS)
        self.assertIn("new CVE", JS)
        self.assertNotIn("window.location.reload", JS)

    def test_filters_do_not_silently_apply_a_staged_snapshot(self):
        self.assertIn("let pendingSnapshot = null;", JS)
        self.assertIn("const destination = options.stageTo || loadedByDay;", JS)
        self.assertIn("stageTo: stagedDays", JS)
        self.assertIn("if (!pendingFeedUpdate || !pendingSnapshot) return;", JS)
        self.assertNotIn("acceptPendingUpdate(false)", JS)
        self.assertIn("aria-pressed=\"true\"", HTML)
        self.assertIn("setAttribute('aria-pressed', String(selected))", JS)

    def test_manifest_and_shards_are_cache_busted_and_rendering_is_incremental(self):
        self.assertIn("const POLL_MS = 120_000", JS)
        self.assertIn("data/manifest.json?check=${Date.now()}", JS)
        self.assertIn("?v=${encodeURIComponent(version)}", JS)
        self.assertIn("const PAGE_SIZE = 24", JS)
        self.assertIn(".slice(0, visible)", JS)
        self.assertIn("const SHARD_CONCURRENCY = 4", JS)
        self.assertIn("each request reveals up to 24 more cards", README)
        self.assertIn("one skeleton per outstanding shard request", README)

    def test_static_frontend_has_no_external_runtime_and_source_specific_dates(self):
        self.assertNotIn("services.nvd.nist.gov", JS)
        self.assertNotIn("cdn.jsdelivr.net", HTML + JS)
        self.assertNotIn("fonts.googleapis.com", HTML + CSS)
        self.assertIn("ACTIVITY DATE · UTC", HTML)
        self.assertIn("GitHub advisory publication", JS)
        self.assertIn("CISA KEV date added", JS)
        self.assertIn("activity_at", JS)
        self.assertIn("runs hourly at minute 35 UTC", README)

    def test_update_schedule_pages_and_checks_are_documented_and_configured(self):
        workflow = (ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
        checks = (ROOT / ".github/workflows/checks.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "35 * * * *"', workflow)
        self.assertIn("NVD_API_KEY: ${{ secrets.NVD_API_KEY }}", workflow)
        self.assertIn("git pull --rebase origin main", workflow)
        self.assertIn("git push origin HEAD:main", workflow)
        self.assertNotIn("--force", workflow)
        self.assertIn("main", checks)
        self.assertIn("GitHub Pages is configured to publish `/` from the `main` branch", README)

    def test_poc_search_is_constructed_only_from_validated_cve_id(self):
        self.assertIn("^CVE-\\d{4,}-\\d+$", JS)
        self.assertIn("GitHub PoC search", JS)
        self.assertIn("unverified", JS.lower())


if __name__ == "__main__":
    unittest.main()
