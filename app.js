(() => {
  'use strict';

  const SNAPSHOT_BASE = 'snapshot/';
  const FETCH_CACHE = Object.freeze({ manifest: 'no-cache', data: 'default', retry: 'reload' });
  const BACKGROUND_SNAPSHOT_CHECK_MS = 15 * 60 * 1000;
  const LIMITS = Object.freeze({
    manifestBytes: 512 * 1024,
    overviewBytes: 64 * 1024,
    shardBytes: 16 * 1024 * 1024,
    epssBytes: 4 * 1024 * 1024,
    snapshotBytes: 128 * 1024 * 1024,
    records: 50_000,
    days: 31,
    fetchTimeoutMs: 12_000,
    shardConcurrency: 6
  });
  const SHA256_RE = /^[a-f0-9]{64}$/i;
  const SOURCE_LABELS = new Set(['NVD', 'GitHub Advisory Database', 'CISA KEV']);
  const SOURCE_FILTERS = new Set(['NVD', 'GitHub Advisory Database', 'CISA KEV']);
  const LATEST_PREVIEW_LIMIT = 50;
  const PAGE_SIZES = new Set([24, 48, 96]);
  const CVE_ID_RE = /^CVE-\d{4,}-\d+$/i;
  const BASE_SEVERITIES = ['critical', 'high', 'medium', 'low'];
  const VALID_SEVERITIES = new Set([...BASE_SEVERITIES, 'unrated']);
  const initialUrlParams = new URLSearchParams(window.location.search);
  const readUrlText = (key, params = initialUrlParams) => (params.get(key) || '').trim().slice(0, 200);
  const readPercentFilter = (value) => {
    if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,2})?$/.test(value)) return '';
    const numeric = Number(value);
    return Number.isFinite(numeric) && numeric >= 0 && numeric <= 100 ? String(numeric) : '';
  };
  const readCvssScoreFilter = (value) => {
    if (typeof value !== 'string' || !/^\d{1,2}(?:\.\d)?$/.test(value)) return '';
    const numeric = Number(value);
    return Number.isFinite(numeric) && numeric >= 0 && numeric <= 10 ? String(numeric) : '';
  };
  let requestedCve = initialUrlParams.get('cve');
  let requestedCveId = requestedCve && CVE_ID_RE.test(requestedCve) ? requestedCve.toUpperCase() : null;
  let requestedSearch = readUrlText('search');
  let severityParam = (initialUrlParams.get('severity') || '').toLowerCase();
  let requestedSeverity = VALID_SEVERITIES.has(severityParam) ? severityParam : 'all';
  let requestedKevOnly = (initialUrlParams.get('kev') || '').toLowerCase() === 'true';
  let requestedVendor = readUrlText('vendor');
  let requestedSource = SOURCE_FILTERS.has(initialUrlParams.get('source')) ? initialUrlParams.get('source') : 'all';
  let requestedEpssMin = readPercentFilter(initialUrlParams.get('epssMin') || '');
  let requestedCvssMin = readCvssScoreFilter(initialUrlParams.get('cvssMin') || '');
  let requestedDateFrom = initialUrlParams.get('from') || '';
  let requestedDateTo = initialUrlParams.get('to') || '';
  let requestedSize = Number(initialUrlParams.get('size'));
  let initialPageSize = PAGE_SIZES.has(requestedSize) ? requestedSize : 24;
  let requestedPageIndex = initialUrlParams.get('pageIndex') || '';
  let initialPageIndex = /^[1-9]\d{0,4}$/.test(requestedPageIndex) ? Number(requestedPageIndex) - 1 : 0;
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const tabs = $$('.nav-tab');
  const pages = new Map($$('.page').map((page) => [page.id.replace('page-', ''), page]));
  const searchInput = $('#record-search');
  const searchAnchor = $('.center-search-anchor');
  const siteHeader = $('.site-header');
  const centerPage = $('#page-center');
  const headerSearchReturn = $('#header-search-return');
  const snapshotUpdateNotice = $('#snapshot-update-notice');
  const snapshotUpdateCopy = $('#snapshot-update-copy');
  const snapshotUpdateReload = $('#snapshot-update-reload');
  const snapshotUpdateDismiss = $('#snapshot-update-dismiss');
  const overviewStatusLine = $('#overview-status');
  const overviewSourceList = $('#source-check-list');
  const latestPageList = $('#latest-page-list');
  const latestSearchInput = $('#latest-filter-search');
  const latestSourceSelect = $('#latest-filter-source');
  const latestEpssMinInput = $('#latest-filter-epss');
  const latestKevOnlyInput = $('#latest-filter-kev');
  const overviewLatestList = $('#latest-list');
  const activityChart = $('#activity-chart');
  const activityChartData = $('#activity-chart-data');
  const archiveDayList = $('#archive-day-list');
  const overviewRetryButtons = $$('.overview-retry');
  const recordList = $('#record-list');
  const snapshotLoader = $('#snapshot-loader');
  const snapshotLoaderStatus = $('#snapshot-loader-status');
  const snapshotStatusStrips = $$('[data-snapshot-status]');
  const snapshotManifestState = $('#snapshot-manifest-state');
  const snapshotEpssState = $('#snapshot-epss-state');
  const snapshotShardCount = $('#snapshot-shard-count');
  const snapshotShardProgress = $('#snapshot-shard-progress');
  const filterControls = $('#filter-controls');
  const centerDock = $('.center-dock');
  const severityDistribution = $('.severity-distribution');
  const feedView = $('#feed-view');
  const detailView = $('#detail-view');
  const detailContent = $('#detail-content');
  const status = $('#result-status');
  const dateFrom = $('#date-from');
  const dateTo = $('#date-to');
  const dateFilter = $('#date-filter');
  const dateSummary = $('#date-summary');
  const vendorFilterInput = $('#vendor-filter');
  const kevOnlyInput = $('#kev-only');
  const sourceFilterSelect = $('#source-filter');
  const epssMinimumInput = $('#epss-min');
  const cvssMinimumInput = $('#cvss-min');
  const pageSizeSelect = $('#page-size');
  const pagination = $('#pagination');
  const pageIndicator = $('#page-indicator');
  const pagePrevious = $('#page-prev');
  const pageNext = $('#page-next');

  let manifest = null;
  let manifestPromise = null;
  let snapshotCacheFallbackUsed = false;
  let lastBackgroundSnapshotCheck = 0;
  let backgroundSnapshotCheckInFlight = false;
  let noticedSnapshotGeneratedAt = '';
  let dismissedSnapshotGeneratedAt = '';
  let records = [];
  let latestSummaryRecords = [];
  let snapshotStarted = false;
  let snapshotLoading = false;
  let epssScores = Object.create(null);
  let activePage = 'overview';
  let finishActiveSwipeSettlement = () => {};
  let activeSeverity = requestedSeverity;
  let activeCveId = requestedCveId;
  let appliedFrom = '';
  let appliedTo = '';
  let pageIndex = initialPageIndex;
  let pageSize = initialPageSize;
  let matchedRecords = [];
  let lastDetailFocus = null;
  let lastScrollY = 0;
  let searchDockFrame = 0;
  let communityTypeTimer = 0;
  let communityRedirectTimer = 0;
  let communityCharacterIndex = 0;
  let recordButtons = new Map();

  const TELEGRAM_COMMAND = 'xdg-open "https://www.t.me/RootAccessClub"';
  const TELEGRAM_DESTINATION = 'https://t.me/RootAccessClub';
  const EPSS_SOURCE = 'https://www.first.org/epss/data';
  const KEV_SOURCE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
  const GITHUB_SEARCH = (id) => `https://github.com/search?q=${encodeURIComponent(`${id} poc exploit`)}&type=repositories`;
  const nf = new Intl.NumberFormat('en-US');

  class SnapshotIntegrityError extends Error {
    constructor(message) {
      super(message);
      this.name = 'SnapshotIntegrityError';
    }
  }

  function safeString(value, fallback = '') {
    return typeof value === 'string' ? value : fallback;
  }

  function safeStringList(value) {
    return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
  }

  function isCanonicalDate(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const parsed = new Date(`${value}T00:00:00Z`);
    return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
  }

  function isCanonicalTimestamp(value) {
    if (typeof value !== 'string' || value.length > 40) return false;
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return false;
    return isCanonicalDate(value.slice(0, 10)) && Number.isFinite(Date.parse(value));
  }

  function isSourceTimestamp(value) {
    if (isCanonicalTimestamp(value)) return true;
    if (typeof value !== 'string' || value.length > 32 ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/.test(value) ||
        !isCanonicalDate(value.slice(0, 10))) return false;
    return Number.isFinite(Date.parse(`${value}Z`));
  }

  function formatDate(value, fallback = 'Date unavailable') {
    const day = typeof value === 'string' ? value.slice(0, 10) : '';
    if (!isCanonicalDate(day)) return fallback;
    const parsed = new Date(`${day}T00:00:00Z`);
    return new Intl.DateTimeFormat('en', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(parsed);
  }

  function formatTimestamp(value, fallback = 'Not provided') {
    if (!isSourceTimestamp(value)) return fallback;
    const parsed = new Date(isCanonicalTimestamp(value) ? value : `${value}Z`);
    return new Intl.DateTimeFormat('en', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC', hour12: false
    }).format(parsed) + ' UTC';
  }

  function severityKey(record) {
    const severity = safeString(record?.sev).toLowerCase();
    return BASE_SEVERITIES.includes(severity) ? severity : 'unrated';
  }

  function sourceSeverity(record) {
    const severity = safeString(record?.sev).toLowerCase();
    if (severity === 'none') return 'None';
    if (severity === 'unknown') return 'Unknown';
    if (BASE_SEVERITIES.includes(severity)) return severity[0].toUpperCase() + severity.slice(1);
    return 'Not provided';
  }

  function severityName(value) {
    if (value === 'unrated' || value === 'none' || value === 'unknown') return 'Unrated';
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function makeSeverityTag(record) {
    const severity = severityKey(record);
    const tag = document.createElement('span');
    tag.className = `severity-label ${severity}`;
    tag.textContent = severityName(severity);
    if (severity === 'unrated') tag.title = `Source CVSS category: ${sourceSeverity(record)}`;
    return tag;
  }

  function isFiniteScore(value) {
    return typeof value === 'number' && Number.isFinite(value);
  }

  function getEpss(record) {
    const candidate = epssScores[record.id];
    if (!candidate || typeof candidate !== 'object') return null;
    const rawScore = candidate.score;
    if (!((typeof rawScore === 'number') || (typeof rawScore === 'string' && rawScore.trim() !== ''))) return null;
    const score = Number(rawScore);
    const rawPercentile = candidate.percentile;
    const percentile = (typeof rawPercentile === 'number' || (typeof rawPercentile === 'string' && rawPercentile.trim() !== ''))
      ? Number(rawPercentile)
      : Number.NaN;
    if (!Number.isFinite(score) || score < 0 || score > 1) return null;
    return {
      score,
      percentile: Number.isFinite(percentile) && percentile >= 0 && percentile <= 1 ? percentile : null
    };
  }

  function epssMarkedStale(candidate = manifest) {
    const status = candidate?.source_status?.find((source) => safeString(source?.name) === 'FIRST EPSS');
    const sourceUpdated = Date.parse(safeString(candidate?.epss?.source_updated_at));
    const captureGenerated = Date.parse(safeString(candidate?.generated_at));
    const age = captureGenerated - sourceUpdated;
    return status?.ok !== true || !Number.isFinite(sourceUpdated) || age < 0 || age > 36 * 60 * 60 * 1000;
  }

  function epssFreshness(candidate) {
    const scoreDate = safeString(candidate?.epss?.score_date);
    const sourceUpdated = Date.parse(safeString(candidate?.epss?.source_updated_at));
    if (!isCanonicalDate(scoreDate) || !Number.isFinite(sourceUpdated)) return 'unavailable';
    return epssMarkedStale(candidate) ? 'stale' : 'current';
  }

  function snapshotFreshnessLabel(candidate, offline = snapshotCacheFallbackUsed) {
    if (offline) return 'OFFLINE';
    const generated = Date.parse(safeString(candidate?.generated_at));
    const age = Date.now() - generated;
    const sources = Array.isArray(candidate?.source_status) ? candidate.source_status : [];
    if (!Number.isFinite(age) || age < -5 * 60 * 1000 || !sources.length ||
        sources.some((source) => source?.ok !== true) || epssMarkedStale(candidate)) return 'DEGRADED';
    if (age <= 6 * 60 * 60 * 1000) return 'FRESH';
    if (age <= 24 * 60 * 60 * 1000) return 'DELAYED';
    return 'STALE';
  }

  function setSnapshotStatus(message, state, candidate = null, verifiedTotals = null, targetPage = null) {
    snapshotStatusStrips.forEach((strip) => {
      if (targetPage && strip.closest('.page')?.id !== `page-${targetPage}`) return;
      const statusLine = $('[data-snapshot-state]', strip);
      statusLine.textContent = message;
      statusLine.dataset.state = state;

      const generated = $('[data-snapshot-generated]', strip);
      const windowStart = $('[data-snapshot-window-start]', strip);
      const windowEnd = $('[data-snapshot-window-end]', strip);
      const recordsValue = $('[data-snapshot-records]', strip);
      const kevValue = $('[data-snapshot-kev]', strip);
      const epssDate = $('[data-snapshot-epss-date]', strip);
      if (!candidate) {
        const unavailable = state === 'error' ? 'Unavailable' : 'Awaiting verification';
        generated.textContent = unavailable;
        generated.removeAttribute('datetime');
        windowStart.textContent = unavailable;
        windowStart.removeAttribute('datetime');
        windowEnd.textContent = unavailable;
        windowEnd.removeAttribute('datetime');
        if (recordsValue) recordsValue.textContent = unavailable;
        if (kevValue) kevValue.textContent = unavailable;
        epssDate.textContent = unavailable;
        epssDate.removeAttribute('datetime');
        return;
      }

      generated.dateTime = candidate.generated_at;
      generated.textContent = formatTimestamp(candidate.generated_at, 'Unavailable');
      windowStart.dateTime = candidate.window.start;
      windowStart.textContent = formatTimestamp(candidate.window.start, 'Unavailable');
      windowEnd.dateTime = candidate.window.end;
      windowEnd.textContent = formatTimestamp(candidate.window.end, 'Unavailable');
      if (recordsValue) {
        recordsValue.textContent = verifiedTotals
          ? `${nf.format(verifiedTotals.records)} verified`
          : `${nf.format(candidate.totals.cves)} in manifest`;
      }
      if (kevValue) {
        kevValue.textContent = verifiedTotals
          ? `${nf.format(verifiedTotals.kev)} verified`
          : `${nf.format(candidate.totals.known_exploited)} in manifest`;
      }

      const scoreDate = safeString(candidate.epss?.score_date);
      const freshness = epssFreshness(candidate);
      epssDate.textContent = freshness === 'unavailable'
        ? 'Unavailable'
        : `${formatDate(scoreDate)} · ${freshness === 'current' ? 'current at capture' : 'stale at capture'}`;
      if (freshness === 'unavailable') epssDate.removeAttribute('datetime');
      else epssDate.dateTime = scoreDate;
    });
  }

  function activityDate(record) {
    return safeString(record.window_date, safeString(record.activity_at).slice(0, 10));
  }

  function activityMilliseconds(record) {
    const value = safeString(record.activity_at, `${activityDate(record)}T00:00:00Z`);
    const timestamp = Date.parse(value.endsWith('Z') || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
    return Number.isFinite(timestamp) ? timestamp : 0;
  }

  function safeExternalUrl(value) {
    if (typeof value !== 'string' || value !== value.trim() || /[\u0000-\u0020\u007f]/.test(value) || !/^https?:\/\//i.test(value)) return null;
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  function addText(parent, tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = safeString(text);
    parent.append(element);
    return element;
  }

  function addLink(parent, label, url, className = 'signal-link') {
    const href = safeExternalUrl(url);
    if (!href) return null;
    const link = document.createElement('a');
    link.className = className;
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = safeString(label, 'Open source');
    parent.append(link);
    return link;
  }

  function addSignal(list, label, main, note, links = []) {
    const row = document.createElement('div');
    row.className = 'signal-row';
    row.dataset.signal = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    const term = document.createElement('dt');
    term.textContent = label;
    const description = document.createElement('dd');
    addText(description, 'span', 'signal-main', main);
    addText(description, 'span', 'signal-note', note);
    links.forEach((link) => addLink(description, link.label, link.url));
    row.append(term, description);
    list.append(row);
    return description;
  }

  function setSnapshotStats() {
    const totals = manifest.totals || {};
    $('#snapshot-total').textContent = nf.format(records.length);
    $('#snapshot-kev-total').textContent = nf.format(Number(totals.known_exploited) || 0);
    $('#snapshot-epss-total').textContent = nf.format(Number(manifest.epss?.scored_cves) || 0);

    const counts = {
      all: records.length,
      critical: Number(totals.critical) || 0,
      high: Number(totals.high) || 0,
      medium: Number(totals.medium) || 0,
      low: Number(totals.low) || 0,
      unrated: (Number(totals.none) || 0) + (Number(totals.unknown) || 0)
    };
    $$('.severity-tab [data-count]').forEach((value) => {
      value.textContent = nf.format(counts[value.dataset.count] ?? 0);
    });

    const start = safeString(manifest.window?.start).slice(0, 10);
    const end = safeString(manifest.window?.end).slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
      throw new Error('The captured manifest has no valid UTC date window.');
    }
    dateFrom.min = start;
    dateFrom.max = end;
    dateTo.min = start;
    dateTo.max = end;
    const requestedRangeIsValid = isCanonicalDate(requestedDateFrom)
      && isCanonicalDate(requestedDateTo)
      && requestedDateFrom <= requestedDateTo
      && requestedDateFrom >= start
      && requestedDateTo <= end;
    appliedFrom = requestedRangeIsValid ? requestedDateFrom : start;
    appliedTo = requestedRangeIsValid ? requestedDateTo : end;
    dateFrom.value = appliedFrom;
    dateTo.value = appliedTo;
    updateDateSummary(appliedFrom, appliedTo);

    const scoreDate = safeString(manifest.epss?.score_date, 'not supplied');
    const epssMessage = epssMarkedStale()
      ? `EPSS marked stale in this capture · ${formatDate(scoreDate)}. Missing: unscored, not 0%.`
      : `EPSS score set current at capture · ${formatDate(scoreDate)}. Missing scores are not 0%.`;
    const epssWarning = $('#epss-warning');
    if (epssWarning) {
      $('#epss-warning-copy').textContent = epssMessage;
      epssWarning.classList.toggle('is-stale', epssMarkedStale());
      epssWarning.hidden = false;
    }

    const generated = formatTimestamp(manifest.generated_at, safeString(manifest.generated_at));
    const windowText = `${formatDate(start)} to ${formatDate(end)}`;
    $('#snapshot-provenance').textContent = `Bundled published feed snapshot · generated ${generated} · ${nf.format(manifest.days.length)} manifest-listed UTC day shards · ${windowText}. ${epssMessage} No live feed request is made by this page; record and reference text is rendered safely as text.`;
  }

  function updateDateSummary(from, to) {
    dateSummary.textContent = `Activity · ${formatDate(from).replace(',', '')} — ${formatDate(to).replace(',', '')}`;
  }

  function updateAddressBar({ pushHistory = false } = {}) {
    const url = new URL(window.location.href);
    ['page', 'cve', 'search', 'severity', 'kev', 'vendor', 'source', 'epssMin', 'cvssMin', 'from', 'to', 'size', 'pageIndex']
      .forEach((key) => url.searchParams.delete(key));
    if (activePage !== 'overview' || activeCveId) url.searchParams.set('page', activePage);
    const query = searchInput.value.trim().slice(0, 200);
    if (activeCveId) url.searchParams.set('cve', activeCveId);
    if (query && query.toUpperCase() !== activeCveId) url.searchParams.set('search', query);
    if (activeSeverity !== 'all') url.searchParams.set('severity', activeSeverity);
    if (kevOnlyInput.checked) url.searchParams.set('kev', 'true');
    const vendor = vendorFilterInput.value.trim().slice(0, 200);
    if (vendor) url.searchParams.set('vendor', vendor);
    const source = SOURCE_FILTERS.has(sourceFilterSelect.value) ? sourceFilterSelect.value : 'all';
    if (source !== 'all') url.searchParams.set('source', source);
    const minimumEpss = readPercentFilter(epssMinimumInput.value.trim());
    if (minimumEpss !== '') url.searchParams.set('epssMin', minimumEpss);
    const minimumCvss = readCvssScoreFilter(cvssMinimumInput.value.trim());
    if (minimumCvss !== '') url.searchParams.set('cvssMin', minimumCvss);
    const dateRangeIsNarrowed = appliedFrom && appliedTo && dateFrom.min && dateTo.max
      && (appliedFrom !== dateFrom.min || appliedTo !== dateTo.max);
    if (dateRangeIsNarrowed) {
      url.searchParams.set('from', appliedFrom);
      url.searchParams.set('to', appliedTo);
    }
    if (pageSize !== 24) url.searchParams.set('size', String(pageSize));
    if (pageIndex > 0) url.searchParams.set('pageIndex', String(pageIndex + 1));
    const nextAddress = `${url.pathname}${url.search}${url.hash}`;
    const currentAddress = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (nextAddress !== currentAddress) {
      if (pushHistory) window.history.pushState(window.history.state, '', nextAddress);
      else window.history.replaceState(window.history.state, '', nextAddress);
    }
  }

  function restoreLocationState() {
    const params = new URLSearchParams(window.location.search);
    requestedCve = params.get('cve');
    requestedCveId = requestedCve && CVE_ID_RE.test(requestedCve) ? requestedCve.toUpperCase() : null;
    requestedSearch = readUrlText('search', params);
    severityParam = (params.get('severity') || '').toLowerCase();
    requestedSeverity = VALID_SEVERITIES.has(severityParam) ? severityParam : 'all';
    requestedKevOnly = (params.get('kev') || '').toLowerCase() === 'true';
    requestedVendor = readUrlText('vendor', params);
    requestedSource = SOURCE_FILTERS.has(params.get('source')) ? params.get('source') : 'all';
    requestedEpssMin = readPercentFilter(params.get('epssMin') || '');
    requestedCvssMin = readCvssScoreFilter(params.get('cvssMin') || '');
    requestedDateFrom = params.get('from') || '';
    requestedDateTo = params.get('to') || '';
    requestedSize = Number(params.get('size'));
    initialPageSize = PAGE_SIZES.has(requestedSize) ? requestedSize : 24;
    requestedPageIndex = params.get('pageIndex') || '';
    initialPageIndex = /^[1-9]\d{0,4}$/.test(requestedPageIndex) ? Number(requestedPageIndex) - 1 : 0;

    activeCveId = requestedCveId;
    activeSeverity = requestedSeverity;
    pageIndex = initialPageIndex;
    pageSize = initialPageSize;
    searchInput.value = requestedSearch || requestedCveId || '';
    vendorFilterInput.value = requestedVendor;
    kevOnlyInput.checked = requestedKevOnly;
    pageSizeSelect.value = String(pageSize);
    $$('.severity-tab').forEach((button) => {
      const selected = button.dataset.severity === activeSeverity;
      button.classList.toggle('is-selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });

    const pageParam = params.get('page');
    const nextPage = pages.has(pageParam)
      ? pageParam
      : pageParam === null && requestedCveId ? 'center' : 'overview';
    sourceFilterSelect.value = requestedSource;
    epssMinimumInput.value = requestedEpssMin;
    cvssMinimumInput.value = requestedCvssMin;
    switchPage(nextPage, false, { updateUrl: false, deferScroll: true, swipeTransition: true });

    if (!manifest || snapshotLoading || records.length === 0) return;
    const start = dateFrom.min;
    const end = dateTo.max;
    const requestedRangeIsValid = isCanonicalDate(requestedDateFrom)
      && isCanonicalDate(requestedDateTo)
      && requestedDateFrom <= requestedDateTo
      && requestedDateFrom >= start
      && requestedDateTo <= end;
    appliedFrom = requestedRangeIsValid ? requestedDateFrom : start;
    appliedTo = requestedRangeIsValid ? requestedDateTo : end;
    dateFrom.value = appliedFrom;
    dateTo.value = appliedTo;
    updateDateSummary(appliedFrom, appliedTo);
    renderRecords();

    if (requestedCveId) {
      if (nextPage === 'center') {
        const record = records.find((candidate) => candidate.id === requestedCveId);
        if (record && (detailView.hidden || $('#detail-heading').textContent !== requestedCveId)) {
          openDetails(record, recordButtons.get(requestedCveId));
        } else if (!record && !detailView.hidden) {
          restoreResultsView({ restoreFocus: false, restoreScroll: false });
        }
      }
    } else if (!detailView.hidden) {
      restoreResultsView({ restoreFocus: false, restoreScroll: false });
    }
    updateAddressBar();
  }

  function isCount(value, maximum = LIMITS.records) {
    return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
  }

  function isValidText(value, maximum, allowEmpty = false, multiline = false) {
    if (typeof value !== 'string' || Array.from(value).length > maximum || (!allowEmpty && !value.trim())) return false;
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code < 32 && !(multiline && [9, 10, 13].includes(code))) return false;
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return false;
      }
    }
    return true;
  }

  function severityForScore(score) {
    if (score === null) return 'unknown';
    if (score === 0) return 'none';
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return score >= 0.1 ? 'low' : 'none';
  }

  function validateManifest(candidate) {
    if (!candidate || typeof candidate !== 'object' || candidate.schema_version !== 2 || candidate.complete !== true) throw new Error('Manifest schema is incomplete.');
    if (!isCanonicalTimestamp(candidate.generated_at) || candidate.last_successful_update !== candidate.generated_at) throw new Error('Manifest timestamps are invalid.');
    const window = candidate.window;
    if (!window || window.days !== 30 || window.timezone !== 'UTC' || !isCanonicalTimestamp(window.start) || !isCanonicalTimestamp(window.end) || window.end !== candidate.generated_at) throw new Error('Manifest window is invalid.');
    const startDay = window.start.slice(0, 10);
    const endDay = window.end.slice(0, 10);
    if (!isCanonicalDate(startDay) || !isCanonicalDate(endDay)) throw new Error('Manifest window dates are invalid.');
    const daySpan = (Date.parse(`${endDay}T00:00:00Z`) - Date.parse(`${startDay}T00:00:00Z`)) / 86_400_000;
    if (daySpan !== 30 || !Array.isArray(candidate.days) || candidate.days.length !== LIMITS.days) throw new Error('Manifest does not contain the complete 31-day UTC window.');

    const totals = candidate.totals;
    const severityNames = ['critical', 'high', 'medium', 'low', 'none', 'unknown'];
    if (!totals || !isCount(totals.cves, LIMITS.records) || totals.cves === 0 || !isCount(totals.known_exploited, totals.cves)) throw new Error('Manifest totals are invalid.');
    const declaredSeverity = severityNames.reduce((sum, name) => {
      if (!isCount(totals[name], totals.cves)) throw new Error('Manifest severity totals are invalid.');
      return sum + totals[name];
    }, 0);
    if (declaredSeverity !== totals.cves) throw new Error('Manifest severity totals do not match its CVE total.');

    const coverage = candidate.coverage;
    if (!coverage || !isCount(coverage.nvd_records_returned) || !isCount(coverage.github_advisories_returned) || !isCount(coverage.cisa_kev_catalog_records) ||
        coverage.nvd_records_returned === 0 || coverage.github_advisories_returned === 0 || coverage.cisa_kev_catalog_records === 0 ||
        coverage.distinct_cve_records !== totals.cves || coverage.utc_days_sharded !== LIMITS.days || coverage.sources_complete !== true) throw new Error('Manifest source coverage is incomplete.');

    let totalBytes = 0;
    const daySeverityTotals = Object.fromEntries(severityNames.map((name) => [name, 0]));
    let dayKevTotal = 0;
    const expectedStart = Date.parse(`${startDay}T00:00:00Z`);
    let recordCount = 0;
    candidate.days.forEach((day, index) => {
      const expectedDate = new Date(expectedStart + index * 86_400_000).toISOString().slice(0, 10);
      if (!day || day.date !== expectedDate || !isCanonicalDate(day.date) || day.path !== `data/${day.date}.json`) throw new Error('A manifest-listed shard path or date is invalid.');
      if (!isCount(day.count, LIMITS.records) || !isCount(day.bytes, LIMITS.shardBytes) || day.bytes === 0 || !SHA256_RE.test(safeString(day.sha256))) throw new Error('A manifest-listed shard has invalid integrity metadata.');
      const severityCount = severityNames.reduce((sum, name) => {
        if (!isCount(day[name], day.count)) throw new Error('A shard severity count is invalid.');
        daySeverityTotals[name] += day[name];
        return sum + day[name];
      }, 0);
      if (severityCount !== day.count || !isCount(day.exploited, day.count)) throw new Error('A shard count does not match its severity or KEV totals.');
      totalBytes += day.bytes;
      dayKevTotal += day.exploited;
      recordCount += day.count;
    });
    if (recordCount !== totals.cves || dayKevTotal !== totals.known_exploited || severityNames.some((name) => daySeverityTotals[name] !== totals[name])) throw new Error('Shard totals do not match the manifest.');

    const overview = candidate.overview;
    const epss = candidate.epss;
    for (const [config, expectedPath, maxBytes] of [[overview, 'data/overview.json', LIMITS.overviewBytes], [epss, 'data/epss.json', LIMITS.epssBytes]]) {
      if (!config || config.path !== expectedPath || !isCount(config.bytes, maxBytes) || config.bytes === 0 || !SHA256_RE.test(safeString(config.sha256))) throw new Error('A manifest sidecar has invalid integrity metadata.');
      totalBytes += config.bytes;
    }
    if (totalBytes > LIMITS.snapshotBytes || !isCount(epss.scored_cves, totals.cves) || epss.records !== totals.cves) throw new Error('Manifest sidecar or total-snapshot limits are invalid.');
    if (typeof epss.score_date !== 'string' || (epss.score_date && !isCanonicalDate(epss.score_date)) || typeof epss.source_updated_at !== 'string' || typeof epss.updated_at !== 'string' || !isCanonicalTimestamp(epss.updated_at)) throw new Error('Manifest EPSS dates are invalid.');

    if (!Array.isArray(candidate.source_status) || candidate.source_status.length !== 4) throw new Error('Manifest source status is incomplete.');
    const statusNames = new Set();
    candidate.source_status.forEach((source) => {
      if (!source || typeof source.name !== 'string' || statusNames.has(source.name) || typeof source.ok !== 'boolean' ||
          (source.checked_at !== undefined && (!isCanonicalTimestamp(source.checked_at) || source.checked_at !== candidate.generated_at))) throw new Error('Manifest source status is invalid.');
      statusNames.add(source.name);
    });
    const epssStatus = candidate.source_status.find((source) => source.name === 'FIRST EPSS');
    const coreNames = ['NVD CVE API 2.0', 'GitHub Security Advisory Database', 'CISA KEV'];
    const nvdStatus = candidate.source_status.find((source) => source.name === coreNames[0]);
    const githubStatus = candidate.source_status.find((source) => source.name === coreNames[1]);
    const cisaStatus = candidate.source_status.find((source) => source.name === coreNames[2]);
    if (coreNames.some((name) => !candidate.source_status.some((source) => source.name === name && source.ok === true)) ||
        nvdStatus.records !== coverage.nvd_records_returned || !isCount(nvdStatus.pages, 1000) || nvdStatus.pages === 0 ||
        githubStatus.advisories !== coverage.github_advisories_returned || !isCount(githubStatus.pages, 250) || githubStatus.pages === 0 ||
        cisaStatus.catalog_records !== coverage.cisa_kev_catalog_records || !epssStatus ||
        epssStatus.scores !== epss.scored_cves || epssStatus.records !== totals.cves || epssStatus.score_date !== epss.score_date || epssStatus.source_updated_at !== epss.source_updated_at) throw new Error('Manifest source status does not agree with its coverage.');

    const canonicalSourceName = (name) => name === 'CISA Known Exploited Vulnerabilities catalog' ? 'CISA KEV' : name;
    if (!Array.isArray(candidate.sources) || candidate.sources.length !== 4 || candidate.sources.some((source) => !source || typeof source.name !== 'string' || !safeExternalUrl(source.url)) ||
        new Set(candidate.sources.map((source) => source.name)).size !== 4 || candidate.sources.some((source) => !statusNames.has(canonicalSourceName(source.name)))) throw new Error('Manifest source provenance is invalid.');
    if (overview.schema_version !== 2 || !isCount(overview.count, LATEST_PREVIEW_LIMIT) || overview.count !== Math.min(LATEST_PREVIEW_LIMIT, totals.cves)) throw new Error('Manifest Overview schema or count is invalid.');
    return candidate;
  }

  async function fetchBytes(path, maximum, cache = FETCH_CACHE.data, { trackCacheFallback = true } = {}) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), LIMITS.fetchTimeoutMs);
    try {
      const headers = navigator.onLine ? undefined : { 'X-SubZer0-Offline': 'true' };
      const response = await fetch(path, { signal: controller.signal, credentials: 'same-origin', cache, headers, redirect: 'error' });
      if (trackCacheFallback && response.headers.get('X-SubZer0-Cache') === 'offline-fallback') snapshotCacheFallbackUsed = true;
      if (!response.ok) throw new Error('Snapshot request failed.');
      const declaredLength = response.headers.get('content-length');
      if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximum)) throw new Error('Snapshot resource exceeds its byte limit.');
      if (!response.body || typeof response.body.getReader !== 'function') {
        const fallback = new Uint8Array(await response.arrayBuffer());
        if (fallback.byteLength > maximum) throw new Error('Snapshot resource exceeds its byte limit.');
        return fallback;
      }
      const reader = response.body.getReader();
      const chunks = [];
      let length = 0;
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        length += result.value.byteLength;
        if (length > maximum) {
          await reader.cancel();
          throw new Error('Snapshot resource exceeds its byte limit.');
        }
        chunks.push(result.value);
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      chunks.forEach((chunk) => { bytes.set(chunk, offset); offset += chunk.byteLength; });
      return bytes;
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error('Snapshot request timed out.');
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function parseJsonBytes(bytes) {
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      throw new Error('Snapshot JSON is malformed.');
    }
  }

  async function verifyBlob(bytes, config) {
    if (bytes.byteLength !== config.bytes) throw new SnapshotIntegrityError('Snapshot byte-count verification failed.');
    if (!window.crypto?.subtle?.digest) throw new Error('Snapshot integrity checks are unavailable.');
    const digest = await window.crypto.subtle.digest('SHA-256', bytes);
    const actual = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    if (actual.toLowerCase() !== config.sha256.toLowerCase()) throw new SnapshotIntegrityError('Snapshot integrity verification failed.');
  }

  async function storeVerifiedOfflineBytes(path, bytes) {
    if (!window.isSecureContext || !navigator.serviceWorker?.controller || !('caches' in window)) return;
    try {
      const url = new URL(path, document.baseURI);
      if (url.origin !== window.location.origin || !url.pathname.startsWith(new URL('.', document.baseURI).pathname)) return;
      const cache = await caches.open('subzero-offline-v1');
      await cache.put(new Request(url.href, { method: 'GET' }), new Response(bytes.slice(), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      }));
      const dayPattern = /\/snapshot\/data\/(\d{4}-\d{2}-\d{2})\.json$/;
      if (!dayPattern.test(url.pathname)) return;
      const shards = (await cache.keys()).map((request) => {
        const match = new URL(request.url).pathname.match(dayPattern);
        return match ? { request, date: match[1] } : null;
      }).filter(Boolean).sort((left, right) => left.date.localeCompare(right.date));
      await Promise.all(shards.slice(0, Math.max(0, shards.length - 40)).map(({ request }) => cache.delete(request)));
    } catch {
      // Cache storage is optional; every online and offline response is still revalidated before use.
    }
  }

  async function fetchVerifiedJson(config, maximum, cache = FETCH_CACHE.data, {
    trackCacheFallback = true, storeOffline = true, retainBytes = false, validate = null
  } = {}) {
    const path = `${SNAPSHOT_BASE}${config.path}`;
    let bytes = await fetchBytes(path, maximum, cache, { trackCacheFallback });
    try {
      await verifyBlob(bytes, config);
    } catch (error) {
      if (!(error instanceof SnapshotIntegrityError)) throw error;
      bytes = await fetchBytes(path, maximum, FETCH_CACHE.retry, { trackCacheFallback });
      await verifyBlob(bytes, config);
    }
    const payload = parseJsonBytes(bytes);
    const accepted = validate ? validate(payload) : payload;
    if (storeOffline) await storeVerifiedOfflineBytes(path, bytes);
    return retainBytes ? { payload: accepted, bytes } : accepted;
  }

  async function checkForUpdatedSnapshot({ force = false } = {}) {
    const now = Date.now();
    if (!manifest || document.hidden || backgroundSnapshotCheckInFlight ||
        (!force && now - lastBackgroundSnapshotCheck < BACKGROUND_SNAPSHOT_CHECK_MS)) return;
    backgroundSnapshotCheckInFlight = true;
    lastBackgroundSnapshotCheck = now;
    try {
      const manifestBytes = await fetchBytes(`${SNAPSHOT_BASE}manifest.json`, LIMITS.manifestBytes, FETCH_CACHE.manifest, {
        trackCacheFallback: false
      });
      const candidate = validateManifest(parseJsonBytes(manifestBytes));
      const currentTime = Date.parse(manifest.generated_at);
      const candidateTime = Date.parse(candidate.generated_at);
      if (!Number.isFinite(candidateTime) || !Number.isFinite(currentTime) || candidateTime <= currentTime ||
          candidate.generated_at === dismissedSnapshotGeneratedAt) return;
      validateOverview(await fetchVerifiedJson(candidate.overview, LIMITS.overviewBytes, FETCH_CACHE.data, {
        trackCacheFallback: false, storeOffline: false
      }), candidate);
      noticedSnapshotGeneratedAt = candidate.generated_at;
      snapshotUpdateCopy.textContent = `A newer captured snapshot is available, generated ${formatTimestamp(candidate.generated_at, 'at an unknown time')}. Its Overview index is verified; reload to verify the full archive before exploring it.`;
      snapshotUpdateNotice.hidden = false;
    } catch {
      // A background check never replaces or clears the last fully verified view.
    } finally {
      backgroundSnapshotCheckInFlight = false;
    }
  }

  function registerOfflineSupport() {
    if (!window.isSecureContext || !('serviceWorker' in navigator)) return;
    const scope = new URL('.', document.baseURI).pathname;
    navigator.serviceWorker.register(new URL('sw.js', document.baseURI), {
      scope,
      updateViaCache: 'none'
    }).catch(() => {
      // Offline storage is optional; the hash-verified network path remains available.
    });
  }

  async function getManifest() {
    if (!manifestPromise) {
      manifestPromise = (async () => {
        const bytes = await fetchBytes(`${SNAPSHOT_BASE}manifest.json`, LIMITS.manifestBytes, FETCH_CACHE.manifest);
        const candidate = validateManifest(parseJsonBytes(bytes));
        await storeVerifiedOfflineBytes(`${SNAPSHOT_BASE}manifest.json`, bytes);
        return candidate;
      })().catch((error) => {
        manifestPromise = null;
        throw error;
      });
    }
    return manifestPromise;
  }

  function validateRecord(record, expectedDay) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Snapshot contains an invalid record.');
    const required = ['id', 'title', 'desc', 'score', 'sev', 'published', 'modified', 'window_date', 'activity_at', 'date_basis', 'affected', 'refs', 'related_cves', 'advisories', 'sources', 'kev', 'primary_url'];
    if (required.some((key) => !Object.hasOwn(record, key))) throw new Error('Snapshot record is missing required fields.');
    if (!isValidText(record.id, 32) || !/^CVE-\d{4,}-\d+$/.test(record.id) || record.id !== record.id.toUpperCase()) throw new Error('Snapshot contains a non-canonical CVE identifier.');
    if (!isValidText(record.title, 512) || !isValidText(record.desc, 65_536, false, true)) throw new Error('Snapshot record text is invalid.');
    if (record.score !== null && (typeof record.score !== 'number' || !Number.isFinite(record.score) || record.score < 0 || record.score > 10)) throw new Error('Snapshot contains an invalid CVSS value.');
    if (!['critical', 'high', 'medium', 'low', 'none', 'unknown'].includes(record.sev) || record.sev !== severityForScore(record.score)) throw new Error('Snapshot severity does not match its CVSS value.');
    for (const field of ['published', 'modified']) if (record[field] !== null && !isSourceTimestamp(record[field])) throw new Error('Snapshot contains an invalid source timestamp.');
    if (!isCanonicalDate(record.window_date) || record.window_date !== expectedDay || !isSourceTimestamp(record.activity_at) || new Date(activityMilliseconds(record)).toISOString().slice(0, 10) !== expectedDay) throw new Error('Snapshot activity date does not match its shard.');
    if (!isValidText(record.date_basis, 128) || !safeExternalUrl(record.primary_url)) throw new Error('Snapshot record source details are invalid.');
    if (!Array.isArray(record.sources) || record.sources.length < 1 || record.sources.length > 8 || new Set(record.sources).size !== record.sources.length || record.sources.some((source) => !SOURCE_LABELS.has(source))) throw new Error('Snapshot source labels are invalid.');

    if (!Array.isArray(record.affected) || record.affected.length > 128 || record.affected.some((item) => !item || typeof item !== 'object' ||
        !isValidText(item.vendor, 4096, true, true) || !isValidText(item.product, 4096, true, true) || !isValidText(item.versions, 4096, true, true) || !SOURCE_LABELS.has(item.source) ||
        (Object.hasOwn(item, 'cpe') && !isValidText(item.cpe, 2048, true, true)))) throw new Error('Snapshot affected-product details are invalid.');
    if (!Array.isArray(record.refs) || record.refs.length > 64 || record.refs.some((item) => !item || typeof item !== 'object' || !isValidText(item.label, 256) || !safeExternalUrl(item.url) || !isValidText(item.source, 128) ||
        !Array.isArray(item.tags || []) || (item.tags || []).length > 16 || (item.tags || []).some((tag) => !isValidText(tag, 40)))) throw new Error('Snapshot references are invalid.');
    if (!Array.isArray(record.related_cves) || record.related_cves.length > 100 || record.related_cves.some((item) => !item || typeof item !== 'object' || !isValidText(item.id, 32) || !/^CVE-\d{4,}-\d+$/.test(item.id) || item.id !== item.id.toUpperCase() || item.id === record.id || !safeExternalUrl(item.url) || !isValidText(item.source, 128))) throw new Error('Snapshot related-CVE details are invalid.');
    if (!Array.isArray(record.advisories) || record.advisories.length > 32 || record.advisories.some((item) => !item || typeof item !== 'object' || !isValidText(item.label, 256) || !safeExternalUrl(item.url))) throw new Error('Snapshot advisory details are invalid.');
    if (record.kev !== null) {
      const kev = record.kev;
      if (!kev || typeof kev !== 'object' || Array.isArray(kev) || !isCanonicalDate(kev.date_added) || !isValidText(kev.vendor, 256, true) || !isValidText(kev.product, 256, true) ||
          (kev.due_date !== '' && !isCanonicalDate(kev.due_date)) || !isValidText(kev.due_date, 10, true) || !isValidText(kev.required_action, 4096, true, true) || !isValidText(kev.ransomware, 64, true)) throw new Error('Snapshot CISA KEV details are invalid.');
    }
    return record;
  }

  function validateOverview(payload, candidate) {
    if (!payload || typeof payload !== 'object' || payload.schema_version !== 2 || payload.generated_at !== candidate.generated_at ||
        !Array.isArray(payload.records) || payload.records.length !== Math.min(LATEST_PREVIEW_LIMIT, candidate.totals.cves)) throw new Error('Overview snapshot is invalid.');
    const expectedKeys = new Set(['id', 'title', 'sev', 'score', 'window_date', 'activity_at', 'date_basis', 'sources', 'kev_date_added', 'epss']);
    const seen = new Set();
    let previousActivity = Number.POSITIVE_INFINITY;
    payload.records.forEach((record) => {
      if (!record || typeof record !== 'object' || Array.isArray(record) || Object.keys(record).length !== expectedKeys.size ||
          Object.keys(record).some((key) => !expectedKeys.has(key)) || !isValidText(record.id, 32) || !/^CVE-\d{4,}-\d+$/.test(record.id) ||
          record.id !== record.id.toUpperCase() || seen.has(record.id) || !isValidText(record.title, 512) ||
          !['critical', 'high', 'medium', 'low', 'none', 'unknown'].includes(record.sev) ||
          (record.score !== null && (typeof record.score !== 'number' || !Number.isFinite(record.score) || record.score < 0 || record.score > 10)) ||
          record.sev !== severityForScore(record.score) || !isCanonicalDate(record.window_date) || !isSourceTimestamp(record.activity_at) ||
          !isValidText(record.date_basis, 128) || !Array.isArray(record.sources) || record.sources.length < 1 || record.sources.length > 8 ||
          record.sources.some((source) => !SOURCE_LABELS.has(source)) ||
          (record.kev_date_added !== null && !isCanonicalDate(record.kev_date_added))) throw new Error('Overview record is invalid.');
      const activity = Date.parse(isCanonicalTimestamp(record.activity_at) ? record.activity_at : `${record.activity_at}Z`);
      if (!Number.isFinite(activity) || activity > previousActivity) throw new Error('Overview records are not ordered by newest activity.');
      previousActivity = activity;
      seen.add(record.id);
      if (record.epss !== null && (!record.epss || typeof record.epss !== 'object' || Array.isArray(record.epss) ||
          Object.keys(record.epss).length !== 2 || typeof record.epss.score !== 'number' || !Number.isFinite(record.epss.score) ||
          record.epss.score < 0 || record.epss.score > 1 || typeof record.epss.percentile !== 'number' || !Number.isFinite(record.epss.percentile) ||
          record.epss.percentile < 0 || record.epss.percentile > 1)) throw new Error('Overview EPSS data is invalid.');
    });
    return payload;
  }

  function approximateSnapshotAge(timestamp) {
    const elapsed = Date.now() - Date.parse(timestamp);
    if (!Number.isFinite(elapsed)) return 'Unavailable';
    if (elapsed < 0) return 'Snapshot timestamp is ahead of this device clock';
    const minutes = Math.floor(elapsed / 60_000);
    if (minutes < 1) return 'Less than 1 minute';
    const days = Math.floor(minutes / 1_440);
    const hours = Math.floor((minutes % 1_440) / 60);
    const remainder = minutes % 60;
    if (days) return `${days}d ${hours}h`;
    if (hours) return `${hours}h ${remainder}m`;
    return `${minutes}m`;
  }

  function sourceCoverageText(source) {
    switch (source.name) {
      case 'NVD CVE API 2.0':
        return `${nf.format(source.records)} records reported across ${nf.format(source.pages)} pages`;
      case 'GitHub Security Advisory Database':
        return `${nf.format(source.advisories)} advisories reported across ${nf.format(source.pages)} pages`;
      case 'CISA KEV':
        return `${nf.format(source.catalog_records)} entries in the upstream catalog at capture`;
      case 'FIRST EPSS':
        return `${nf.format(source.scores)} of ${nf.format(source.records)} CVEs scored · score date ${source.score_date ? formatDate(source.score_date) : 'not recorded'}`;
      default:
        return 'No source-specific coverage count is recorded';
    }
  }

  function renderSourceChecks(candidate) {
    overviewSourceList.replaceChildren();
    candidate.source_status.forEach((source) => {
      const item = document.createElement('li');
      item.className = 'source-check-row';
      const identity = document.createElement('div');
      identity.className = 'source-check-row__identity';
      const name = document.createElement('strong');
      name.textContent = source.name;
      const coverage = document.createElement('span');
      coverage.textContent = sourceCoverageText(source);
      identity.append(name, coverage);

      const result = document.createElement('div');
      result.className = 'source-check-row__result';
      result.dataset.outcome = source.ok ? 'success' : 'unavailable';
      const outcome = document.createElement('strong');
      outcome.textContent = source.ok ? 'Succeeded in capture' : 'Not successful in capture';
      result.append(outcome);
      if (isCanonicalTimestamp(source.checked_at)) {
        const checkedAt = document.createElement('time');
        checkedAt.dateTime = source.checked_at;
        checkedAt.textContent = formatTimestamp(source.checked_at, 'Check time not recorded');
        result.append(checkedAt);
      } else {
        const checkedAt = document.createElement('span');
        checkedAt.textContent = 'Check time not recorded';
        result.append(checkedAt);
      }
      item.append(identity, result);
      overviewSourceList.append(item);
    });
    overviewSourceList.setAttribute('aria-busy', 'false');
    $('#source-check-age').textContent = `Approximate snapshot age at page load: ${approximateSnapshotAge(candidate.generated_at)} · uses this device's clock.`;
  }

  function renderLatestRows() {
    latestPageList.replaceChildren();
    const query = latestSearchInput.value.trim().toLocaleLowerCase();
    const source = SOURCE_FILTERS.has(latestSourceSelect.value) ? latestSourceSelect.value : 'all';
    const minimumText = readPercentFilter(latestEpssMinInput.value.trim());
    const invalidMinimum = Boolean(latestEpssMinInput.value.trim()) && minimumText === '';
    latestEpssMinInput.setAttribute('aria-invalid', String(invalidMinimum));
    const minimum = minimumText === '' ? null : Number(minimumText);
    const filtered = latestSummaryRecords.filter((record) => {
      const search = !query || [record.id, record.title, ...record.sources].join(' ').toLocaleLowerCase().includes(query);
      const sourceMatches = source === 'all' || record.sources.includes(source);
      const kevMatches = !latestKevOnlyInput.checked || record.kev_date_added !== null;
      const epssMatches = minimum === null || (record.epss !== null && record.epss.score * 100 >= minimum);
      return search && sourceMatches && kevMatches && epssMatches;
    });

    if (!filtered.length) {
      const empty = document.createElement('li');
      empty.className = 'discovery-placeholder';
      empty.textContent = latestSummaryRecords.length ? 'No verified latest records match these filters.' : 'No verified latest records are available in this snapshot.';
      latestPageList.append(empty);
    }

    filtered.forEach((record) => {
      const item = document.createElement('li');
      item.className = 'latest-page-item';
      const header = document.createElement('div');
      header.className = 'latest-page-item__header';
      const link = document.createElement('a');
      link.className = 'latest-page-item__id';
      link.href = `?page=center&cve=${encodeURIComponent(record.id)}`;
      link.setAttribute('aria-label', `Open ${record.id} in Explore`);
      link.textContent = record.id;
      header.append(link, makeSeverityTag(record));

      const title = document.createElement('p');
      title.className = 'latest-page-item__title';
      title.textContent = record.title;
      const facts = document.createElement('p');
      facts.className = 'latest-page-item__facts';
      facts.textContent = record.score === null ? 'CVSS unscored' : `CVSS ${record.score.toFixed(1)}`;
      if (record.epss) facts.textContent += ` · EPSS ${(record.epss.score * 100).toFixed(2)}%`;
      const signals = document.createElement('span');
      signals.className = 'latest-page-item__signals';
      if (record.kev_date_added) {
        const kev = addText(signals, 'span', 'latest-filter-tag', 'CISA KEV');
        kev.title = `Added to the captured CISA KEV catalog on ${record.kev_date_added}`;
      }
      record.sources.forEach((sourceName) => addText(signals, 'span', 'latest-filter-tag', sourceName));
      header.append(signals);
      const activity = document.createElement('time');
      activity.className = 'latest-page-item__activity';
      activity.dateTime = record.activity_at;
      activity.textContent = `${record.date_basis} · ${formatTimestamp(record.activity_at, 'date unavailable')}`;
      item.append(header, title, facts, activity);
      latestPageList.append(item);
    });

    latestPageList.setAttribute('aria-busy', 'false');
    const statusLine = $('#latest-page-status');
    statusLine.textContent = invalidMinimum
      ? 'Enter a minimum EPSS value from 0 to 100.'
      : `Showing ${nf.format(filtered.length)} of ${nf.format(latestSummaryRecords.length)} verified latest records. CVSS, EPSS and KEV remain separate signals.`;
  }

  function renderLatestPage(payload, candidate) {
    latestSummaryRecords = payload.records;
    const generated = $('#latest-generated-at');
    generated.dateTime = candidate.generated_at;
    generated.textContent = formatTimestamp(candidate.generated_at, 'Date unavailable');
    const newestActivity = $('#latest-activity-at');
    if (payload.records[0]) {
      newestActivity.dateTime = payload.records[0].activity_at;
      newestActivity.textContent = formatTimestamp(payload.records[0].activity_at, 'Date unavailable');
    } else {
      newestActivity.removeAttribute('datetime');
      newestActivity.textContent = 'No record in this snapshot';
    }
    $('#latest-record-count').textContent = nf.format(payload.records.length);
    latestPageList.setAttribute('aria-busy', 'true');
    renderLatestRows();
  }

  function renderArchivePage(candidate) {
    const start = candidate.window.start.slice(0, 10);
    const end = candidate.window.end.slice(0, 10);
    const startTime = $('#archive-window-start');
    const endTime = $('#archive-window-end');
    startTime.dateTime = start;
    endTime.dateTime = end;
    startTime.textContent = formatDate(start);
    endTime.textContent = formatDate(end);

    archiveDayList.replaceChildren();
    [...candidate.days].reverse().forEach((day) => {
      const item = document.createElement('li');
      item.className = 'archive-day-item';
      const details = document.createElement('div');
      details.className = 'archive-day-item__details';
      const date = document.createElement('time');
      date.dateTime = day.date;
      date.textContent = formatDate(day.date);
      const count = document.createElement('strong');
      count.textContent = `${nf.format(day.count)} CVEs`;
      const signals = document.createElement('span');
      signals.textContent = `Critical ${nf.format(day.critical)} · High ${nf.format(day.high)} · KEV ${nf.format(day.exploited)}`;
      details.append(date, count, signals);

      const link = document.createElement('a');
      link.className = 'archive-day-item__link';
      link.href = `?page=center&from=${encodeURIComponent(day.date)}&to=${encodeURIComponent(day.date)}`;
      link.setAttribute('aria-label', `Browse ${formatDate(day.date)} in Explore`);
      link.textContent = 'Browse in Explore';
      item.append(details, link);
      archiveDayList.append(item);
    });
    archiveDayList.setAttribute('aria-busy', 'false');
    $('#archive-status').textContent = `The validated manifest lists ${nf.format(candidate.days.length)} UTC days and ${nf.format(candidate.totals.cves)} CVEs in this ${formatDate(start)} to ${formatDate(end)} window. Explore verifies shard files before displaying records.`;
  }

  function renderActivityChart(candidate) {
    const namespace = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(namespace, 'svg');
    svg.setAttribute('viewBox', '0 0 720 136');
    svg.setAttribute('aria-hidden', 'true');
    const entries = candidate.days;
    const maximum = Math.max(1, ...entries.map((day) => day.count));
    const left = 38;
    const right = 716;
    const top = 18;
    const baseline = 122;
    const chartHeight = baseline - top;
    const step = (right - left) / entries.length;
    const barWidth = Math.min(12, step * 0.58);
    [top, Math.round((top + baseline) / 2), baseline].forEach((y) => {
      const line = document.createElementNS(namespace, 'line');
      line.setAttribute('x1', String(left));
      line.setAttribute('x2', String(right));
      line.setAttribute('y1', String(y));
      line.setAttribute('y2', String(y));
      line.setAttribute('class', 'chart-grid');
      svg.append(line);
    });
    entries.forEach((day, index) => {
      const height = day.count === 0 ? 1 : Math.max(2, (day.count / maximum) * chartHeight);
      const bar = document.createElementNS(namespace, 'rect');
      bar.setAttribute('x', String(left + step * index + (step - barWidth) / 2));
      bar.setAttribute('y', String(baseline - height));
      bar.setAttribute('width', String(barWidth));
      bar.setAttribute('height', String(height));
      bar.setAttribute('rx', '1');
      bar.setAttribute('class', `chart-bar${day.count === maximum && day.count > 0 ? ' is-peak' : ''}`);
      bar.dataset.count = String(day.count);
      bar.dataset.date = day.date;
      const label = document.createElementNS(namespace, 'title');
      label.textContent = `${day.date}: ${nf.format(day.count)} ${day.count === 1 ? 'record' : 'records'}`;
      bar.append(label);
      svg.append(bar);
    });
    activityChart.replaceChildren(svg);
    activityChart.dataset.verified = 'true';
    activityChart.setAttribute('aria-busy', 'false');
    activityChart.setAttribute('aria-label', `Snapshot activity: ${nf.format(candidate.totals.cves)} CVEs across ${nf.format(entries.length)} UTC date bins; the highest single-day count is ${nf.format(maximum)}.`);
    activityChartData.replaceChildren();
    entries.forEach((day) => {
      const item = document.createElement('li');
      item.textContent = `${formatDate(day.date)}: ${nf.format(day.count)} ${day.count === 1 ? 'record' : 'records'}.`;
      activityChartData.append(item);
    });
    activityChart.setAttribute('aria-describedby', 'activity-chart-data');
    $('#activity-total').textContent = `${nf.format(candidate.totals.cves)} CVEs across ${nf.format(entries.length)} dates`;
    $('#activity-day-count').textContent = `${nf.format(entries.length)} UTC dates`;
    const start = $('#activity-start');
    start.dateTime = entries[0].date;
    start.textContent = formatDate(entries[0].date);
    const end = $('#activity-end');
    end.dateTime = entries.at(-1).date;
    end.textContent = formatDate(entries.at(-1).date);
  }

  function renderOverview(payload, candidate) {
    $('#overview-total').textContent = nf.format(candidate.totals.cves);
    $('#overview-kev').textContent = nf.format(candidate.totals.known_exploited);
    $('#overview-epss').textContent = `${nf.format(candidate.epss.scored_cves)} / ${nf.format(candidate.totals.cves)}`;
    $('#overview-epss-note').textContent = `scored in the ${candidate.epss.score_date ? formatDate(candidate.epss.score_date) : 'undated'} set`;
    $('#overview-window-end').textContent = formatDate(candidate.window.end);
    renderActivityChart(candidate);
    renderSourceChecks(candidate);
    renderLatestPage(payload, candidate);

    overviewLatestList.replaceChildren();
    payload.records.slice(0, 4).forEach((record) => {
      const item = document.createElement('li');
      item.className = 'latest-preview-row';
      const link = document.createElement('a');
      link.className = 'latest-preview-row__id';
      link.href = `?page=center&cve=${encodeURIComponent(record.id)}`;
      link.textContent = record.id;
      link.setAttribute('aria-label', `Open ${record.id} in Explore`);
      const title = addText(item, 'span', 'latest-preview-row__title', record.title);
      title.title = record.title;
      const source = addText(item, 'span', 'latest-preview-row__source', record.sources.join(' · '));
      source.title = record.sources.join(', ');
      const signals = document.createElement('span');
      signals.className = 'latest-preview-row__signals';
      signals.append(makeSeverityTag(record));
      if (record.kev_date_added) addText(signals, 'span', 'record-signal-chip kev-chip', 'KEV');
      const time = document.createElement('time');
      time.dateTime = record.activity_at;
      time.textContent = formatDate(record.activity_at);
      signals.append(time);
      item.append(link, title, source, signals);
      overviewLatestList.append(item);
    });

    overviewStatusLine.textContent = `${nf.format(candidate.totals.cves)} CVE records · snapshot generated ${formatTimestamp(candidate.generated_at, 'recently')}.`;
    overviewStatusLine.classList.remove('is-error');
    overviewStatusLine.setAttribute('aria-busy', 'false');
    const captureTime = formatTimestamp(candidate.generated_at, 'unavailable');
    const offlineMessage = `OFFLINE · the last captured Overview and Latest index was verified from this browser's cache (${captureTime}). Explore still checks every requested shard before showing records.`;
    const freshness = snapshotFreshnessLabel(candidate);
    const statusMessage = snapshotCacheFallbackUsed
      ? offlineMessage
      : `${freshness} · Overview index verified. Full record shards are checked when Explore opens; this is a static capture, not a live feed.`;
    setSnapshotStatus(statusMessage, freshness.toLowerCase(), candidate, null, 'overview');
    lastBackgroundSnapshotCheck = Date.now();
    overviewLatestList.setAttribute('aria-busy', 'false');
    overviewRetryButtons.forEach((button) => { button.hidden = true; button.disabled = false; });
  }

  async function loadOverview({ retry = false } = {}) {
    const statusLine = overviewStatusLine;
    const retryHadFocus = overviewRetryButtons.includes(document.activeElement);
    if (retry) manifestPromise = null;
    overviewRetryButtons.forEach((button) => {
      button.hidden = !(retry && button === document.activeElement);
      button.disabled = true;
    });
    let candidate = null;
    statusLine.textContent = retry ? 'Retrying the snapshot manifest and Overview index…' : 'Verifying the latest static snapshot…';
    statusLine.classList.remove('is-error');
    setSnapshotStatus('Loading snapshot manifest…', 'loading', null, null, 'overview');
    statusLine.setAttribute('aria-busy', 'true');
    $('#latest-page-status').textContent = 'Verifying the snapshot index…';
    $('#archive-status').textContent = 'Waiting for the validated manifest…';
    overviewSourceList.setAttribute('aria-busy', 'true');
    latestPageList.setAttribute('aria-busy', 'true');
    archiveDayList.setAttribute('aria-busy', 'true');
    try {
      candidate = await getManifest();
      setSnapshotStatus('Manifest verified. Checking the Overview preview integrity…', 'verifying', candidate, null, 'overview');
      renderSourceChecks(candidate);
      renderArchivePage(candidate);
      const payload = await fetchVerifiedJson(candidate.overview, LIMITS.overviewBytes, retry ? FETCH_CACHE.retry : FETCH_CACHE.data, {
        validate: (overview) => validateOverview(overview, candidate)
      });
      manifest = candidate;
      renderOverview(payload, candidate);
      if (retryHadFocus) {
        const statusTarget = activePage === 'latest' ? $('#latest-page-status') : activePage === 'archive' ? $('#archive-status') : statusLine;
        statusTarget.focus({ preventScroll: true });
      }
    } catch {
      const failureState = candidate
        ? 'DEGRADED · Overview index verification failed. No unverified Overview or Latest records are shown; verified manifest source details and Archive remain. Use Try again to re-request the static data.'
        : 'DEGRADED · Snapshot manifest verification failed. No unverified source, record, or Archive content is shown. Use Try again to re-request the static data.';
      setSnapshotStatus(failureState, 'error', candidate, null, 'overview');
      statusLine.textContent = snapshotCacheFallbackUsed || navigator.onLine === false
        ? 'OFFLINE · The cache does not contain a complete verified Overview index. Reconnect and try again; no unverified records are shown.'
        : candidate
          ? 'DEGRADED · Recent CVE records could not be verified. Try again to re-request the manifest and Overview index.'
          : 'DEGRADED · Snapshot data could not be verified. Try again to re-request the manifest and Overview index.';
      statusLine.classList.add('is-error');
      if (!candidate) {
        $('#source-check-age').textContent = 'Snapshot age unavailable because the manifest could not be verified.';
        overviewSourceList.replaceChildren();
        $('#archive-status').textContent = 'Archive summaries are unavailable because the manifest could not be verified. Choose Try again to request it again.';
        archiveDayList.replaceChildren();
        $('#archive-window-start').textContent = 'Unavailable';
        $('#archive-window-end').textContent = 'Unavailable';
      } else {
        const archiveStatus = $('#archive-status');
        archiveStatus.textContent = `${archiveStatus.textContent} The Overview index could not be verified; record previews remain hidden. Choose Try again to re-request that index.`;
      }
      overviewSourceList.setAttribute('aria-busy', 'false');
      latestSummaryRecords = [];
      activityChart.replaceChildren();
      activityChart.setAttribute('aria-busy', 'false');
      activityChart.dataset.verified = 'false';
      activityChartData.replaceChildren();
      $('#activity-total').textContent = 'Activity unavailable';
      $('#activity-day-count').textContent = 'Unavailable';
      $('#activity-start').textContent = 'Unavailable';
      $('#activity-end').textContent = 'Unavailable';
      $('#overview-total').textContent = 'Unavailable';
      $('#overview-kev').textContent = 'Unavailable';
      $('#overview-epss').textContent = 'Unavailable';
      $('#overview-epss-note').textContent = 'Verification failed';
      $('#overview-window-end').textContent = 'Unavailable';
      overviewLatestList.replaceChildren();
      overviewLatestList.setAttribute('aria-busy', 'false');
      latestPageList.replaceChildren();
      latestPageList.setAttribute('aria-busy', 'false');
      $('#latest-page-status').textContent = 'The latest-record index could not be verified. Choose Try again to re-request it.';
      $('#latest-record-count').textContent = 'Unavailable';
      $('#latest-generated-at').textContent = 'Unavailable';
      $('#latest-activity-at').textContent = 'Unavailable';
      archiveDayList.setAttribute('aria-busy', 'false');
      overviewRetryButtons.forEach((button) => { button.hidden = false; button.disabled = false; });
    } finally {
      statusLine.setAttribute('aria-busy', 'false');
      latestPageList.setAttribute('aria-busy', 'false');
      archiveDayList.setAttribute('aria-busy', 'false');
      overviewSourceList.setAttribute('aria-busy', 'false');
    }
  }

  function validateRecords(dayPayloads) {
    const all = [];
    const seen = new Set();
    dayPayloads.forEach(({ day, rows }) => {
      if (!Array.isArray(rows) || rows.length !== day.count) {
        throw new Error('A captured shard does not match its manifest count.');
      }
      rows.forEach((record) => {
        validateRecord(record, day.date);
        if (seen.has(record.id)) throw new Error('Captured snapshot repeats a CVE identifier.');
        seen.add(record.id);
        all.push(record);
      });
    });
    if (all.length !== manifest.totals.cves) throw new Error('Loaded record total does not match the manifest.');
    all.sort((left, right) => activityMilliseconds(right) - activityMilliseconds(left) || right.id.localeCompare(left.id));
    return all;
  }

  async function mapWithConcurrency(items, limit, mapper) {
    const results = new Array(items.length);
    let next = 0;
    let failed = false;
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (!failed) {
        const index = next;
        next += 1;
        if (index >= items.length) return;
        try {
          results[index] = await mapper(items[index], index);
        } catch (error) {
          failed = true;
          throw error;
        }
      }
    });
    await Promise.all(workers);
    return results;
  }

  function validateEpssFile(payload, candidate, rows) {
    if (!payload || typeof payload !== 'object' || payload.schema_version !== 1 || payload.updated_at !== candidate.epss.updated_at ||
        payload.score_date !== candidate.epss.score_date || payload.source_updated_at !== candidate.epss.source_updated_at || !isCanonicalTimestamp(payload.checked_at) ||
        (payload.error !== null && !isValidText(payload.error, 2048, true, true)) || !payload.scores || typeof payload.scores !== 'object' || Array.isArray(payload.scores)) throw new Error('EPSS sidecar is invalid.');
    const ids = new Set(rows.map((record) => record.id));
    const scores = Object.keys(payload.scores);
    if (scores.length !== candidate.epss.scored_cves || scores.some((id) => {
      const value = payload.scores[id];
      return !ids.has(id) || !/^CVE-\d{4,}-\d+$/.test(id) || !value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).length !== 2 || !Object.hasOwn(value, 'score') || !Object.hasOwn(value, 'percentile') ||
        typeof value.score !== 'number' || !Number.isFinite(value.score) || value.score < 0 || value.score > 1 ||
        typeof value.percentile !== 'number' || !Number.isFinite(value.percentile) || value.percentile < 0 || value.percentile > 1;
    })) throw new Error('EPSS score values are invalid.');
    return payload.scores;
  }

  function beginSnapshotLoading() {
    snapshotLoading = true;
    setSnapshotStatus('Loading snapshot manifest…', 'loading', null, null, 'center');
    snapshotLoader.hidden = false;
    feedView.setAttribute('aria-busy', 'true');
    recordList.setAttribute('aria-busy', 'true');
    snapshotLoaderStatus.textContent = 'Waiting for the snapshot manifest.';
    snapshotManifestState.textContent = 'Waiting';
    snapshotManifestState.classList.remove('is-verified');
    snapshotEpssState.textContent = 'Waiting for daily shards';
    snapshotEpssState.classList.remove('is-verified');
    snapshotShardCount.textContent = 'Waiting for manifest';
    snapshotShardProgress.max = 1;
    snapshotShardProgress.value = 0;
    snapshotShardProgress.removeAttribute('aria-valuetext');
    snapshotShardProgress.hidden = true;
  }

  function acceptSnapshotManifest(candidate) {
    setSnapshotStatus('Manifest verified. Verifying all snapshot shards and EPSS; no records are shown until checks pass.', 'verifying', candidate, null, 'center');
    snapshotManifestState.textContent = 'Verified';
    snapshotManifestState.classList.add('is-verified');
    snapshotEpssState.textContent = 'Waiting for daily shards';
    snapshotShardProgress.max = candidate.days.length;
    snapshotShardProgress.value = 0;
    snapshotShardProgress.hidden = false;
    const progressText = `0 of ${nf.format(candidate.days.length)} daily shards verified`;
    snapshotShardProgress.setAttribute('aria-valuetext', progressText);
    snapshotShardCount.textContent = `0 of ${nf.format(candidate.days.length)} verified`;
    snapshotLoaderStatus.textContent = 'Manifest verified. Daily shards are being checked as they arrive.';
  }

  function reportVerifiedShard(count, total) {
    if (!snapshotLoading) return;
    snapshotShardProgress.value = count;
    snapshotShardProgress.setAttribute('aria-valuetext', `${nf.format(count)} of ${nf.format(total)} daily shards verified`);
    snapshotShardCount.textContent = `${nf.format(count)} of ${nf.format(total)} verified`;
  }

  function acceptSnapshotSidecar() {
    snapshotEpssState.textContent = 'Verified';
    snapshotEpssState.classList.add('is-verified');
    snapshotLoaderStatus.textContent = 'Required data verified. Preparing the record view.';
  }

  function closeSnapshotLoader() {
    snapshotLoading = false;
    snapshotLoader.hidden = true;
    feedView.setAttribute('aria-busy', 'false');
    recordList.setAttribute('aria-busy', 'false');
  }

  function validateShard(day, rows) {
    if (!Array.isArray(rows) || rows.length !== day.count) {
      throw new Error('A captured shard does not match its manifest count.');
    }
    const seen = new Set();
    rows.forEach((record) => {
      validateRecord(record, day.date);
      if (seen.has(record.id)) throw new Error('A captured shard repeats a CVE identifier.');
      seen.add(record.id);
    });
    return rows;
  }

  async function loadSnapshot() {
    try {
      manifest = await getManifest();
      acceptSnapshotManifest(manifest);
      let verifiedShardCount = 0;
      const [dayPayloads, epssResult] = await Promise.all([
        mapWithConcurrency(manifest.days, LIMITS.shardConcurrency, async (day) => {
          const rows = await fetchVerifiedJson(day, LIMITS.shardBytes, FETCH_CACHE.data, {
            validate: (payload) => validateShard(day, payload)
          });
          verifiedShardCount += 1;
          reportVerifiedShard(verifiedShardCount, manifest.days.length);
          return { day, rows };
        }),
        fetchVerifiedJson(manifest.epss, LIMITS.epssBytes, FETCH_CACHE.data, {
          storeOffline: false, retainBytes: true
        })
      ]);
      records = validateRecords(dayPayloads);
      epssScores = validateEpssFile(epssResult.payload, manifest, records);
      await storeVerifiedOfflineBytes(`${SNAPSHOT_BASE}${manifest.epss.path}`, epssResult.bytes);
      acceptSnapshotSidecar();

      setSnapshotStats();
      const freshness = snapshotFreshnessLabel(manifest);
      const fullCaptureMessage = snapshotCacheFallbackUsed
        ? `OFFLINE · all ${nf.format(manifest.days.length)} daily shards and EPSS verified against the captured manifest (${formatTimestamp(manifest.generated_at, 'unavailable')}). This is not live data.`
        : `${freshness} · snapshot verified · dated static capture · not live.`;
      setSnapshotStatus(fullCaptureMessage, freshness.toLowerCase(), manifest, {
        records: records.length,
        kev: records.filter((record) => record.kev !== null).length
      }, 'center');
      lastBackgroundSnapshotCheck = Date.now();
      renderRecords();
      updateAddressBar();
      const requestedRecord = requestedCveId ? records.find((record) => record.id === requestedCveId) : null;
      if (requestedRecord) {
        openDetails(requestedRecord, recordButtons.get(requestedCveId));
      }
      closeSnapshotLoader();
    } catch {
      records = [];
      epssScores = Object.create(null);
      const offlineFailure = snapshotCacheFallbackUsed || navigator.onLine === false;
      setSnapshotStatus(offlineFailure
        ? 'OFFLINE · snapshot is incomplete or failed integrity verification. No records are shown; reconnect before retrying.'
        : 'DEGRADED · snapshot verification failed. No records are displayed; reload to try again.', 'error', manifest, null, 'center');
      recordList.replaceChildren();
      status.textContent = offlineFailure
        ? 'OFFLINE · the cached snapshot is incomplete or does not match its manifest. No partial records are shown. Reconnect and reload to verify the full capture.'
        : 'DEGRADED · the captured CVE snapshot could not be verified. No partial records are shown. Check your connection and reload to try again.';
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'clear-filters';
      retry.textContent = 'Reload snapshot';
      retry.addEventListener('click', () => window.location.reload());
      recordList.append(retry);
      closeSnapshotLoader();
    }
  }

  function startSnapshot() {
    if (snapshotStarted) return;
    snapshotStarted = true;
    beginSnapshotLoading();
    loadSnapshot();
  }

  function searchHaystack(record) {
    const affected = Array.isArray(record.affected)
      ? record.affected.map((item) => [item?.vendor, item?.product, item?.versions, item?.cpe]
        .filter((part) => typeof part === 'string' && part.trim()).join(' ')).join(' ')
      : '';
    const kev = record.kev && typeof record.kev === 'object' ? [record.kev.vendor, record.kev.product].filter(Boolean).join(' ') : '';
    const advisories = Array.isArray(record.advisories)
      ? record.advisories.map((item) => [item?.label, item?.ghsa_id, item?.url].filter(Boolean).join(' ')).join(' ')
      : '';
    const references = Array.isArray(record.refs)
      ? record.refs.map((item) => [item?.label, item?.source, item?.url].filter(Boolean).join(' ')).join(' ')
      : '';
    return [record.id, record.title, record.desc, record.date_basis, ...safeStringList(record.sources), affected, kev, advisories, references]
      .map((part) => typeof part === 'string' ? part : '')
      .join(' ')
      .toLocaleLowerCase();
  }

  function matchesVendor(record, query) {
    if (!query) return true;
    const vendors = Array.isArray(record.affected)
      ? record.affected.map((item) => safeString(item?.vendor)).filter(Boolean)
      : [];
    if (record.kev && typeof record.kev === 'object') vendors.push(safeString(record.kev.vendor));
    return vendors.some((vendor) => vendor.toLocaleLowerCase().includes(query));
  }

  function filteredRecords() {
    const query = searchInput.value.trim().toLocaleLowerCase();
    const exactCve = CVE_ID_RE.test(query) ? query.toUpperCase() : null;
    const vendorQuery = vendorFilterInput.value.trim().toLocaleLowerCase();
    const selectedSource = SOURCE_FILTERS.has(sourceFilterSelect.value) ? sourceFilterSelect.value : 'all';
    const minimumEpssText = readPercentFilter(epssMinimumInput.value.trim());
    const minimumEpss = minimumEpssText === '' ? null : Number(minimumEpssText);
    const minimumCvssText = readCvssScoreFilter(cvssMinimumInput.value.trim());
    const minimumCvss = minimumCvssText === '' ? null : Number(minimumCvssText);
    return records.filter((record) => {
      const category = severityKey(record);
      const date = activityDate(record);
      const severityMatches = activeSeverity === 'all' || category === activeSeverity;
      const dateMatches = date >= appliedFrom && date <= appliedTo;
      const kevMatches = !kevOnlyInput.checked || Boolean(record.kev);
      const vendorMatches = matchesVendor(record, vendorQuery);
      const sourceMatches = selectedSource === 'all' || safeStringList(record.sources).includes(selectedSource);
      const epss = minimumEpss === null ? null : getEpss(record);
      const epssMatches = minimumEpss === null || (epss !== null && epss.score * 100 >= minimumEpss);
      const cvssMatches = minimumCvss === null || (isFiniteScore(record.score) && record.score >= minimumCvss);
      const textMatches = !query || (exactCve ? record.id === exactCve : searchHaystack(record).includes(query));
      return severityMatches && dateMatches && kevMatches && vendorMatches && sourceMatches && epssMatches && cvssMatches && textMatches;
    });
  }

  function appendRecord(record) {
    const category = severityKey(record);
    const row = document.createElement('article');
    row.className = `record-row severity-${category}`;
    row.setAttribute('role', 'listitem');
    row.dataset.cveId = record.id;

    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'record-open';
    open.dataset.cveId = record.id;
    open.setAttribute('aria-label', `${record.id}, ${severityName(category)} severity. Open record details.`);

    const id = addText(open, 'span', 'record-id', record.id);
    id.setAttribute('aria-hidden', 'true');

    const body = document.createElement('span');
    body.className = 'record-body';
    addText(body, 'span', 'record-title', safeString(record.title, 'Title not supplied'));
    const summary = safeString(record.desc, safeString(record.title, 'Description not supplied'));
    addText(body, 'span', 'record-summary', summary);
    const date = document.createElement('time');
    date.className = 'record-date';
    date.dateTime = activityDate(record);
    date.textContent = `${formatDate(activityDate(record))} · ${safeString(record.date_basis, 'activity date')}`;
    body.append(date);

    const signals = document.createElement('span');
    signals.className = 'record-signals';
    signals.append(makeSeverityTag(record));
    const scoreLine = document.createElement('span');
    scoreLine.className = 'record-signal-value cvss-value';
    scoreLine.textContent = isFiniteScore(record.score) ? `CVSS ${record.score.toFixed(1)}` : `CVSS — · ${sourceSeverity(record)}`;
    signals.append(scoreLine);

    const epss = getEpss(record);
    const epssLine = document.createElement('span');
    epssLine.className = `record-signal-value epss-value${epssMarkedStale() ? ' epss-stale-value' : ''}`;
    epssLine.textContent = epss ? `EPSS ${(epss.score * 100).toFixed(2)}%${epssMarkedStale() ? ' · stale' : ''}` : 'EPSS unscored';
    epssLine.title = epss
      ? `FIRST EPSS probability; score set ${safeString(manifest.epss?.score_date)}${epssMarkedStale() ? ' (marked stale)' : ''}.`
      : `No FIRST EPSS score in the captured file; missing is not 0%. Score set: ${safeString(manifest.epss?.score_date, 'not supplied')}.`;
    signals.append(epssLine);

    if (record.kev && typeof record.kev === 'object') {
      addText(signals, 'span', 'record-signal-chip kev-chip', 'CISA KEV');
    }
    if (Array.isArray(record.advisories) && record.advisories.length) {
      addText(signals, 'span', 'record-signal-chip github-chip', 'GitHub advisory');
    }

    open.append(body, signals);
    open.addEventListener('click', () => openDetails(record, open));
    row.append(open);
    recordList.append(row);
    recordButtons.set(record.id, open);
  }

  function updateResultStatus(start, end, total) {
    if (total === 0) {
      status.textContent = `No records match the current filters. ${nf.format(records.length)} records are in the captured snapshot.`;
      return;
    }
    status.textContent = `Showing ${nf.format(start + 1)}–${nf.format(end)} of ${nf.format(total)} matching records · ${nf.format(records.length)} total in snapshot.`;
  }

  function renderRecords() {
    if (!manifest || !records.length) return;
    recordButtons = new Map();
    matchedRecords = filteredRecords();
    const pageCount = Math.max(1, Math.ceil(matchedRecords.length / pageSize));
    pageIndex = Math.min(pageIndex, pageCount - 1);
    const start = pageIndex * pageSize;
    const pageRecords = matchedRecords.slice(start, start + pageSize);
    recordList.replaceChildren();
    recordList.setAttribute('aria-busy', 'false');
    recordList.setAttribute('aria-label', matchedRecords.length
      ? `CVE records ${nf.format(start + 1)} through ${nf.format(start + pageRecords.length)} of ${nf.format(matchedRecords.length)} matching records`
      : 'No matching CVE records');

    if (!pageRecords.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      addText(empty, 'p', '', 'Adjust the search, vendor, source, EPSS, KEV, severity or activity-date filters, or clear them to see more records.');
      const clear = document.createElement('button');
      clear.className = 'clear-filters';
      clear.type = 'button';
      clear.textContent = 'Clear filters';
      clear.addEventListener('click', clearFilters);
      empty.append(clear);
      recordList.append(empty);
    } else {
      pageRecords.forEach(appendRecord);
    }

    updateResultStatus(start, start + pageRecords.length, matchedRecords.length);
    pageIndicator.textContent = `Page ${pageIndex + 1} of ${pageCount}`;
    pagePrevious.disabled = pageIndex === 0;
    pageNext.disabled = pageIndex >= pageCount - 1;
    pagination.hidden = pageCount <= 1;
  }

  function clearFilters() {
    activeSeverity = 'all';
    appliedFrom = dateFrom.min;
    appliedTo = dateTo.max;
    dateFrom.value = appliedFrom;
    dateTo.value = appliedTo;
    dateFilter.open = false;
    searchInput.value = '';
    vendorFilterInput.value = '';
    kevOnlyInput.checked = false;
    sourceFilterSelect.value = 'all';
    epssMinimumInput.value = '';
    epssMinimumInput.setAttribute('aria-invalid', 'false');
    cvssMinimumInput.value = '';
    cvssMinimumInput.setAttribute('aria-invalid', 'false');
    activeCveId = null;
    requestedCve = null;
    requestedCveId = null;
    requestedDateFrom = '';
    requestedDateTo = '';
    pageIndex = 0;
    updateDateSummary(appliedFrom, appliedTo);
    $$('.severity-tab').forEach((button) => {
      const selected = button.dataset.severity === 'all';
      button.classList.toggle('is-selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    renderRecords();
    updateAddressBar();
  }

  function appendFact(list, label, value) {
    const row = document.createElement('div');
    row.className = 'detail-fact';
    addText(row, 'dt', '', label);
    addText(row, 'dd', '', safeString(value, 'Not provided'));
    list.append(row);
  }

  function createDetailTabs() {
    const nav = document.createElement('nav');
    nav.className = 'detail-tabs';
    nav.setAttribute('aria-label', 'CVE record sections');
    const sections = [
      ['Summary', 'detail-summary'], ['Why This Matters', 'detail-why'], ['Record', 'detail-record'], ['Signals', 'detail-signals'],
      ['Affected', 'detail-affected'], ['References', 'detail-references'], ['Sources', 'detail-sources']
    ];
    sections.forEach(([label, id], index) => {
      const tab = document.createElement('a');
      tab.className = 'detail-tab';
      tab.href = `#${id}`;
      tab.textContent = label;
      if (index === 0) tab.setAttribute('aria-current', 'location');
      tab.addEventListener('click', () => {
        nav.querySelectorAll('.detail-tab').forEach((candidate) => candidate.removeAttribute('aria-current'));
        tab.setAttribute('aria-current', 'location');
      });
      nav.append(tab);
    });
    return nav;
  }

  function createWhyThisMatters(record) {
    const section = document.createElement('section');
    section.className = 'detail-why';
    const heading = addText(section, 'h3', 'detail-section-heading', 'Why This Matters');
    heading.id = 'detail-why';
    addText(section, 'p', 'detail-why__intro', 'Evidence summary from this verified capture; it is not a live risk assessment.');
    const list = document.createElement('ul');
    list.className = 'detail-why__list';

    addText(list, 'li', '', isFiniteScore(record.score)
      ? `The captured CVE feed assigns CVSS ${record.score.toFixed(1)} and ${sourceSeverity(record)} source severity. Severity is not an exploitation-probability estimate.`
      : `No numeric CVSS score is present in this record; captured source category: ${sourceSeverity(record)}.`);

    const epss = getEpss(record);
    const epssDate = safeString(manifest.epss?.score_date, 'date not supplied');
    addText(list, 'li', '', epss
      ? `FIRST EPSS set dated ${formatDate(epssDate, epssDate)} estimates ${(epss.score * 100).toFixed(2)}% exploitation probability for this CVE; this is separate from CVSS severity.`
      : 'No FIRST EPSS score is present in the captured score set; unscored does not mean 0%.');

    const kev = record.kev && typeof record.kev === 'object' ? record.kev : null;
    addText(list, 'li', '', kev
      ? `CISA KEV lists this CVE in the captured catalog, added ${formatDate(kev.date_added)}.`
      : 'No CISA KEV entry is attached to this record in the capture; absence does not establish that exploitation has never occurred.');

    const affected = Array.isArray(record.affected) ? record.affected.map((item) =>
      [item?.vendor, item?.product, item?.versions].filter((part) => typeof part === 'string' && part.trim()).join(' · ')
    ).filter(Boolean).slice(0, 3) : [];
    addText(list, 'li', '', affected.length
      ? `Affected-product data supplied by the feed: ${affected.join('; ')}.`
      : 'No affected-product details are supplied in this captured record.');

    section.append(list);
    return section;
  }

  function openDetails(record, opener) {
    if (!record || !record.id) return;
    activeCveId = record.id;
    lastDetailFocus = opener || document.activeElement;
    lastScrollY = window.scrollY;
    severityDistribution.hidden = true;
    centerDock.hidden = true;
    centerDock.classList.remove('is-released');
    headerSearchReturn.hidden = true;
    feedView.hidden = true;
    detailView.hidden = false;
    detailContent.replaceChildren();

    const header = document.createElement('header');
    header.className = 'detail-header';
    const titleGroup = document.createElement('div');
    const heading = addText(titleGroup, 'h2', '', record.id);
    heading.id = 'detail-heading';
    heading.tabIndex = -1;
    const date = document.createElement('p');
    date.className = 'detail-date';
    date.textContent = `${formatDate(activityDate(record))} · ${safeString(record.date_basis, 'activity date')} · captured snapshot`;
    titleGroup.append(date);
    header.append(titleGroup, makeSeverityTag(record));

    const detailTitle = addText(detailContent, 'h3', 'detail-title', safeString(record.title, 'Title not supplied'));
    detailTitle.id = 'detail-summary';
    addText(detailContent, 'p', 'detail-description', safeString(record.desc, 'Description not supplied'));
    detailContent.prepend(header);
    detailContent.insertBefore(createDetailTabs(), detailContent.children[3] || null);
    detailContent.append(createWhyThisMatters(record));

    const factsHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Record details');
    factsHeading.id = 'detail-record';
    const facts = document.createElement('dl');
    facts.className = 'detail-facts';
    appendFact(facts, 'Activity date', formatDate(activityDate(record)));
    appendFact(facts, 'Date basis', safeString(record.date_basis, 'Not supplied'));
    appendFact(facts, 'Published', formatTimestamp(record.published));
    appendFact(facts, 'Last modified', formatTimestamp(record.modified));
    appendFact(facts, 'Feed source labels', safeStringList(record.sources).join(' · ') || 'Not supplied');
    appendFact(facts, 'CWE classification', 'Not supplied in the validated snapshot schema.');
    detailContent.append(factsHeading, facts);

    const signalHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Evidence signals');
    signalHeading.id = 'detail-signals';
    const signalList = document.createElement('dl');
    signalList.className = 'signal-list';

    const scoreText = isFiniteScore(record.score)
      ? `${record.score.toFixed(1)} · ${sourceSeverity(record)} source category`
      : `No numeric CVSS score in this record · source category ${sourceSeverity(record)}.`;
    addSignal(signalList, 'CVSS severity', scoreText,
      'CVSS describes vulnerability severity; it is not an estimate of exploitation probability. Source: CVE feed record.');

    const epss = getEpss(record);
    const epssDate = safeString(manifest.epss?.score_date, 'not supplied');
    const epssMain = epss
      ? `${(epss.score * 100).toFixed(2)}% exploitation probability${epss.percentile === null ? '' : ` · ${(epss.percentile * 100).toFixed(1)}th percentile`}.`
      : 'No EPSS score is available for this CVE in the captured score set.';
    const epssNote = `Source: FIRST EPSS, score set dated ${formatDate(epssDate)}${epssMarkedStale() ? ' (stale relative to snapshot generation)' : ' (current at snapshot generation)'}. Missing means unscored, not 0%.`;
    addSignal(signalList, 'EPSS probability', epssMain, epssNote,
      [{ label: 'FIRST EPSS data', url: EPSS_SOURCE }]);

    const kev = record.kev && typeof record.kev === 'object' ? record.kev : null;
    if (kev) {
      const kevMain = `Listed in the captured CISA KEV catalog · added ${formatDate(kev.date_added)}.`;
      const kevNotes = [
        `${safeString(kev.vendor, 'Vendor not specified')} · ${safeString(kev.product, 'product not specified')}.`,
        kev.due_date ? `Catalog due date: ${formatDate(kev.due_date)}.` : '',
        kev.ransomware ? `CISA ransomware-use field: ${safeString(kev.ransomware)}.` : ''
      ].filter(Boolean).join(' ');
      const kevDescription = addSignal(signalList, 'CISA KEV evidence', kevMain, kevNotes,
        [{ label: 'Open CISA KEV catalog', url: KEV_SOURCE }]);
      if (kev.required_action) addText(kevDescription, 'span', 'signal-note signal-extra', safeString(kev.required_action));
    } else {
      addSignal(signalList, 'CISA KEV evidence', 'No KEV listing is attached to this record in the captured feed.',
        'This describes the bundled catalog snapshot only; absence here is not a claim that exploitation has never occurred.',
        [{ label: 'Open CISA KEV catalog', url: KEV_SOURCE }]);
    }

    const advisories = Array.isArray(record.advisories) ? record.advisories : [];
    const advisoryLinks = advisories.slice(0, 4).map((advisory, index) => ({
      label: `GitHub advisory ${index + 1}`,
      url: safeString(advisory?.url)
    })).filter((link) => safeExternalUrl(link.url));
    const githubMain = advisoryLinks.length
      ? `${nf.format(advisories.length)} GitHub ${advisories.length === 1 ? 'advisory' : 'advisories'} attached to this feed record.`
      : 'No GitHub advisory is attached to this feed record.';
    const githubNote = 'Advisory records and repository search results are separate from CVSS, EPSS, and CISA KEV. A repository hit is a lead, not proof of a working PoC or exploitation.';
    const githubDescription = addSignal(signalList, 'GitHub / PoC leads', githubMain, githubNote, advisoryLinks);
    addLink(githubDescription, `Search GitHub repositories for ${record.id}`, GITHUB_SEARCH(record.id));
    detailContent.append(signalHeading, signalList);

    const affectedHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Affected products');
    affectedHeading.id = 'detail-affected';
    if (Array.isArray(record.affected) && record.affected.length) {
      const affectedList = document.createElement('ul');
      affectedList.className = 'detail-list';
      record.affected.slice(0, 30).forEach((item) => {
        const line = [item?.vendor, item?.product, item?.versions].filter((part) => typeof part === 'string' && part.trim()).join(' · ');
        if (line) addText(affectedList, 'li', '', line);
      });
      detailContent.append(affectedList);
    } else {
      addText(detailContent, 'p', 'detail-empty-copy', 'No affected-product entries are attached to this feed record.');
    }

    const refsHeading = addText(detailContent, 'h3', 'detail-section-heading', 'References in the feed');
    refsHeading.id = 'detail-references';
    if (Array.isArray(record.refs) && record.refs.length) {
      const refsList = document.createElement('ul');
      refsList.className = 'detail-list reference-list';
      record.refs.slice(0, 12).forEach((reference, index) => {
        if (!reference || typeof reference !== 'object') return;
        const item = document.createElement('li');
        const label = safeString(reference.label, `Source reference ${index + 1}`);
        const link = addLink(item, label, reference.url, 'signal-link');
        if (link) addText(item, 'span', 'reference-source', ` · ${safeString(reference.source, 'source not specified')}`);
        else addText(item, 'span', 'reference-unavailable', `${label} · link unavailable`);
        refsList.append(item);
      });
      detailContent.append(refsList);
    } else addText(detailContent, 'p', 'detail-empty-copy', 'No source-reference links are attached to this feed record.');

    const sourceRecordUrl = safeExternalUrl(record.primary_url);
    const sourceLine = document.createElement('div');
    sourceLine.className = 'detail-source-line';
    sourceLine.id = 'detail-sources';
    addText(sourceLine, 'span', '', `Record sources: ${safeStringList(record.sources).join(' · ') || 'not supplied in feed'}`);
    if (sourceRecordUrl) addLink(sourceLine, 'Open primary source record', sourceRecordUrl);
    detailContent.append(sourceLine);

    updateAddressBar();
    $('#back-to-results').focus({ preventScroll: true });
    requestAnimationFrame(() => {
      const top = detailView.getBoundingClientRect().top + window.scrollY - $('.site-header').getBoundingClientRect().height - 16;
      window.scrollTo({ top: Math.max(0, top), behavior: 'auto' });
    });
  }

  function restoreResultsView({ restoreFocus = true, restoreScroll = true } = {}) {
    detailView.hidden = true;
    activeCveId = null;
    requestedCve = null;
    requestedCveId = null;
    centerDock.hidden = false;
    severityDistribution.hidden = false;
    feedView.hidden = false;
    renderRecords();
    const restore = lastDetailFocus?.dataset?.cveId ? recordButtons.get(lastDetailFocus.dataset.cveId) : null;
    if (restoreScroll) window.scrollTo({ top: lastScrollY, behavior: 'auto' });
    if (restoreFocus) (restore || searchInput).focus({ preventScroll: true });
    lastDetailFocus = null;
    scheduleSearchDockSync();
  }

  function backToResults() {
    restoreResultsView();
    updateAddressBar();
  }

  function setSearchDockCompact(compact) {
    const nextCompact = Boolean(compact && document.activeElement !== searchInput);
    centerDock.classList.toggle('is-compact', nextCompact);
  }

  function returnToSearch() {
    if (activePage !== 'center' || centerPage.hidden || !detailView.hidden) return;
    centerDock.classList.remove('is-released');
    headerSearchReturn.hidden = true;
    const headerBottom = siteHeader.getBoundingClientRect().bottom;
    const anchorTop = searchAnchor.getBoundingClientRect().top;
    const top = Math.max(0, window.scrollY + anchorTop - headerBottom - 8);
    window.scrollTo({ top, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    searchInput.focus({ preventScroll: true });
    scheduleSearchDockSync();
  }

  function scheduleSearchDockSync() {
    if (searchDockFrame) return;
    searchDockFrame = window.requestAnimationFrame(() => {
      searchDockFrame = 0;
      const centerIsActive = activePage === 'center' && !centerPage.hidden && !centerDock.hidden;
      if (!centerIsActive) {
        centerDock.classList.remove('is-released');
        headerSearchReturn.hidden = true;
        setSearchDockCompact(false);
        return;
      }
      const headerBottom = siteHeader.getBoundingClientRect().bottom;
      const searchTop = searchAnchor.getBoundingClientRect().top;
      const alreadyCompact = centerDock.classList.contains('is-compact');
      // Keep native scroll anchoring from flapping the dock across its threshold.
      const scrollHysteresis = 48;
      const collapseThreshold = headerBottom + (alreadyCompact ? scrollHysteresis : -scrollHysteresis);
      const shouldCompact = searchTop < collapseThreshold && document.activeElement !== searchInput;
      const compactDockHeight = Number.parseFloat(getComputedStyle(centerDock).getPropertyValue('--center-dock-compact-height'))
        || centerDock.getBoundingClientRect().height;
      const releaseBoundary = headerBottom + compactDockHeight;
      const feedTop = feedView.getBoundingClientRect().top;
      const alreadyReleased = centerDock.classList.contains('is-released');
      const searchReentryBoundary = headerBottom + 4;
      const shouldRelease = alreadyReleased
        ? searchTop < searchReentryBoundary
        : feedTop <= releaseBoundary;
      centerDock.classList.toggle('is-released', shouldRelease);
      headerSearchReturn.hidden = !shouldRelease;
      setSearchDockCompact(shouldCompact);
    });
  }

  function switchPage(name, focusPage = false, options = {}) {
    if (!pages.has(name)) return;
    const pageChanged = activePage !== name;
    finishActiveSwipeSettlement();
    if (name === 'center') startSnapshot();
    const next = pages.get(name);
    const previous = pages.get(activePage);
    if (activePage === 'community' && name !== 'community') cancelCommunityTransition();
    if (previous && previous !== next) {
      if (!options.keepPreviousVisible) previous.hidden = true;
      previous.inert = true;
      previous.setAttribute('aria-hidden', 'true');
    }
    next.hidden = false;
    next.inert = false;
    next.removeAttribute('aria-hidden');
    activePage = name;
    document.body.dataset.skin = name === 'center' ? 'center' : name === 'community' ? 'glass' : 'metal';
    document.querySelector('meta[name="theme-color"]').content = name === 'community' ? '#090e12' : name === 'center' ? '#090d10' : '#080c0f';
    tabs.forEach((tab) => {
      const selected = tab.dataset.page === name;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    next.classList.remove('page-enter');
    if (!options.swipeTransition && !reducedMotion.matches) requestAnimationFrame(() => next.classList.add('page-enter'));
    if (focusPage) next.focus({ preventScroll: true });
    if (!options.deferScroll) window.scrollTo({ top: 0, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    if (options.updateUrl !== false) updateAddressBar({ pushHistory: pageChanged });
    if (name === 'center' && requestedCveId && manifest &&
        (detailView.hidden || $('#detail-heading').textContent !== requestedCveId)) {
      const requestedRecord = records.find((record) => record.id === requestedCveId);
      if (requestedRecord) openDetails(requestedRecord, recordButtons.get(requestedCveId));
    }
    scheduleSearchDockSync();
  }

  function bindSwipeNavigation() {
    const main = $('#main-content');
    if (!main || typeof window.PointerEvent !== 'function') return;

    const pageOrder = ['overview', 'latest', 'center', 'archive', 'community'];
    const blockedSelector = [
      'a[href]', 'button', 'input', 'select', 'textarea', 'option', 'summary', 'details',
      '[role="button"]', '[role="link"]', '[role="combobox"]', '[role="textbox"]',
      '[role="dialog"]', '[aria-modal="true"]', '[contenteditable]:not([contenteditable="false"])',
      '.record-list', '.record-row', '.center-dock', '.filter-controls', '.severity-distribution',
      '.pagination', '.detail-view', '.snapshot-loader', '.overview-kpis', '.overview-grid',
      '.activity-panel', '.latest-preview-row', '.latest-page-item', '.latest-list', '.source-intelligence',
    ].join(',');
    const desktopCardSelector = '.snapshot-status-strip, .snapshot-rail, .latest-list, .latest-page-list, .archive-day-list, .source-intelligence, .snapshot-summary, .overview-kpis, .overview-grid, .activity-panel, .latest-preview-row, article, .terminal-frame';
    const horizontalIntentRatio = 1.2;
    let gesture = null;
    let settlement = null;
    let suppressedClickPointerId = null;
    let suppressedClickTimer = 0;

    const hasTextSelection = () => {
      const selection = window.getSelection();
      return Boolean(selection && !selection.isCollapsed);
    };

    function hasTextAtPoint(x, y) {
      let node = null;
      let offset = 0;
      if (typeof document.caretRangeFromPoint === 'function') {
        const range = document.caretRangeFromPoint(x, y);
        node = range?.startContainer ?? null;
        offset = range?.startOffset ?? 0;
      } else if (typeof document.caretPositionFromPoint === 'function') {
        const caret = document.caretPositionFromPoint(x, y);
        node = caret?.offsetNode ?? null;
        offset = caret?.offset ?? 0;
      }
      if (!node || node.nodeType !== Node.TEXT_NODE) return false;

      const text = node.textContent || '';
      for (const index of [offset, offset - 1]) {
        if (index < 0 || index >= text.length || /\s/u.test(text[index])) continue;
        const character = document.createRange();
        character.setStart(node, index);
        character.setEnd(node, index + 1);
        for (const rect of character.getClientRects()) {
          if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return true;
        }
      }
      return false;
    }

    const isDesktopPointer = (pointerType) => pointerType === 'mouse' || pointerType === 'pen';

    function clearDraggedClickProtection() {
      window.clearTimeout(suppressedClickTimer);
      suppressedClickTimer = 0;
      suppressedClickPointerId = null;
    }

    function suppressDraggedClick(event) {
      if (suppressedClickPointerId === null || event.detail === 0) return;
      if ('pointerId' in event && event.pointerId !== suppressedClickPointerId) return;
      if (event.target instanceof Element && event.target.closest(blockedSelector)) {
        clearDraggedClickProtection();
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      clearDraggedClickProtection();
    }

    function protectAgainstDraggedClick(pointerId) {
      clearDraggedClickProtection();
      suppressedClickPointerId = pointerId;
      suppressedClickTimer = window.setTimeout(clearDraggedClickProtection, 600);
    }

    function removeSwipePresentation(page) {
      if (!page) return;
      page.classList.remove('is-swipe-tracking', 'is-swipe-settling', 'is-swipe-preview');
      page.style.removeProperty('transform');
      page.style.removeProperty('--swipe-preview-top');
    }

    function restorePreview(current) {
      const destination = current.destination;
      if (!destination) return;
      removeSwipePresentation(destination);
      destination.hidden = current.destinationWasHidden;
      destination.inert = current.destinationWasInert;
      if (current.destinationAriaHidden === null) destination.removeAttribute('aria-hidden');
      else destination.setAttribute('aria-hidden', current.destinationAriaHidden);
      current.destination = null;
      current.destinationWasHidden = null;
      current.destinationWasInert = null;
      current.destinationAriaHidden = null;
    }

    function stageDestination(current, destination) {
      if (current.destination === destination) return;
      restorePreview(current);
      if (!destination) return;

      current.destination = destination;
      current.destinationWasHidden = destination.hidden;
      current.destinationWasInert = destination.inert;
      current.destinationAriaHidden = destination.getAttribute('aria-hidden');
      destination.hidden = false;
      destination.inert = true;
      destination.setAttribute('aria-hidden', 'true');
      destination.classList.remove('page-enter');
      destination.classList.add('is-swipe-preview', 'is-swipe-tracking');
      destination.style.setProperty('--swipe-preview-top', `${current.page.offsetTop}px`);
    }

    function updateSwipePresentation(current, deltaX) {
      const index = pageOrder.indexOf(activePage);
      const direction = deltaX < 0 ? 1 : deltaX > 0 ? -1 : 0;
      const destination = direction ? pages.get(pageOrder[index + direction]) : null;
      stageDestination(current, destination);

      const canNavigate = Boolean(destination);
      const distance = Math.abs(deltaX);
      const effectiveX = canNavigate
        ? Math.sign(deltaX) * Math.min(distance, Math.min(window.innerWidth * 0.55, 320))
        : Math.sign(deltaX) * Math.min(24, distance * 0.16);
      current.page.classList.remove('page-enter');
      current.page.classList.add('is-swipe-tracking');
      current.page.style.transform = `translate3d(${effectiveX.toFixed(1)}px, 0, 0)`;
      if (destination) {
        const destinationX = effectiveX - Math.sign(deltaX) * window.innerWidth;
        destination.style.transform = `translate3d(${destinationX.toFixed(1)}px, 0, 0)`;
      }
    }

    function finishSettlement(current) {
      if (!current || settlement !== current) return;
      settlement = null;
      window.clearTimeout(current.timer);
      current.items.forEach((item) => {
        item.page.removeEventListener('transitionend', item.onEnd);
        removeSwipePresentation(item.page);
        if ('hiddenAfter' in item) item.page.hidden = item.hiddenAfter;
        if ('inertAfter' in item) item.page.inert = item.inertAfter;
        if ('ariaHiddenAfter' in item) {
          if (item.ariaHiddenAfter === null) item.page.removeAttribute('aria-hidden');
          else item.page.setAttribute('aria-hidden', item.ariaHiddenAfter);
        }
      });
      if (current.committed) window.scrollTo({ top: 0, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    }

    finishActiveSwipeSettlement = () => {
      if (settlement) finishSettlement(settlement);
    };

    function beginSettlement(items, committed = false) {
      const current = { items: [], pending: new Set(), timer: 0, committed };
      settlement = current;
      items.forEach((item) => {
        const settledItem = { ...item };
        settledItem.page.classList.remove('page-enter', 'is-swipe-tracking');
        settledItem.page.classList.add('is-swipe-settling');
        settledItem.onEnd = (event) => {
          if (event.target !== settledItem.page || event.propertyName !== 'transform') return;
          current.pending.delete(settledItem.page);
          if (current.pending.size === 0) finishSettlement(current);
        };
        settledItem.page.addEventListener('transitionend', settledItem.onEnd);
        current.items.push(settledItem);
        current.pending.add(settledItem.page);
      });
      current.timer = window.setTimeout(() => finishSettlement(current), 320);
      requestAnimationFrame(() => {
        if (settlement !== current) return;
        current.items.forEach((item) => {
          item.page.style.transform = `translate3d(${item.targetX.toFixed(1)}px, 0, 0)`;
        });
      });
    }

    function stopSettlement(page) {
      if (settlement && settlement.items.some((item) => item.page === page)) finishSettlement(settlement);
    }

    function releasePointer(current) {
      try {
        if (main.hasPointerCapture(current.pointerId)) main.releasePointerCapture(current.pointerId);
      } catch (_) {
        // The browser may already have released capture after a native scroll or cancellation.
      }
    }

    function clearGesture(shouldSettle = false) {
      const current = gesture;
      if (!current) return;
      gesture = null;
      releasePointer(current);
      stopSettlement(current.page);
      if (shouldSettle && !reducedMotion.matches) {
        const items = [{ page: current.page, targetX: 0, hiddenAfter: false }];
        if (current.destination) {
          items.push({
            page: current.destination,
            targetX: -Math.sign(current.deltaX || 1) * window.innerWidth,
            hiddenAfter: current.destinationWasHidden,
            inertAfter: current.destinationWasInert,
            ariaHiddenAfter: current.destinationAriaHidden,
          });
        }
        beginSettlement(items);
      } else {
        removeSwipePresentation(current.page);
        restorePreview(current);
      }
    }

    function onPointerDown(event) {
      const desktopPointer = isDesktopPointer(event.pointerType);
      if ((!desktopPointer && event.pointerType !== 'touch') || !event.isPrimary || event.button !== 0 || gesture) return;
      const target = event.target;
      if (!(target instanceof Element) || target.closest(blockedSelector) || hasTextSelection()) return;
      if (desktopPointer && (target.closest(desktopCardSelector) || hasTextAtPoint(event.clientX, event.clientY))) return;
      const page = target.closest('.page');
      if (!page || page.hidden || page !== pages.get(activePage)) return;
      stopSettlement(page);
      if (desktopPointer && event.cancelable) event.preventDefault();

      gesture = {
        pointerId: event.pointerId,
        pointerType: event.pointerType,
        page,
        startX: event.clientX,
        startY: event.clientY,
        startTime: event.timeStamp,
        sampleX: event.clientX,
        sampleTime: event.timeStamp,
        velocityX: 0,
        deltaX: 0,
        deltaY: 0,
        axis: 'pending',
        destination: null,
        destinationWasHidden: null,
        destinationWasInert: null,
        destinationAriaHidden: null,
      };
    }

    function onPointerMove(event) {
      if (!gesture || event.pointerId !== gesture.pointerId) return;
      if (hasTextSelection()) {
        clearGesture(true);
        return;
      }
      const current = gesture;
      if (isDesktopPointer(current.pointerType)) {
        const target = document.elementFromPoint(event.clientX, event.clientY);
        if (!(target instanceof Element) || target.closest(blockedSelector) || target.closest(desktopCardSelector) || hasTextAtPoint(event.clientX, event.clientY)) {
          clearGesture(true);
          return;
        }
      }
      const deltaX = event.clientX - current.startX;
      const deltaY = event.clientY - current.startY;
      current.deltaX = deltaX;
      current.deltaY = deltaY;

      if (current.axis === 'pending') {
        if (Math.max(Math.abs(deltaX), Math.abs(deltaY)) < 8) return;
        if (Math.abs(deltaY) >= Math.abs(deltaX) * horizontalIntentRatio) {
          clearGesture();
          return;
        }
        if (Math.abs(deltaX) < Math.abs(deltaY) * horizontalIntentRatio) return;
        current.axis = 'horizontal';
        current.page.classList.remove('page-enter');
        try {
          main.setPointerCapture(current.pointerId);
        } catch (_) {
          // Continue tracking while the pointer remains over the main content.
        }
      }

      const now = event.timeStamp;
      const elapsed = now - current.sampleTime;
      const sampleDelta = event.clientX - current.sampleX;
      if (elapsed > 0 && Math.abs(sampleDelta) > 0) {
        current.velocityX = sampleDelta / elapsed;
        current.sampleX = event.clientX;
        current.sampleTime = now;
      }

      if (reducedMotion.matches) {
        removeSwipePresentation(current.page);
        restorePreview(current);
        return;
      }
      updateSwipePresentation(current, deltaX);
    }

    function onPointerUp(event) {
      if (!gesture || event.pointerId !== gesture.pointerId) return;
      // A selection can exist before its selectionchange callback is delivered.
      if (hasTextSelection()) {
        clearGesture(true);
        return;
      }
      const current = gesture;
      const deltaX = event.clientX - current.startX;
      const deltaY = event.clientY - current.startY;
      current.deltaX = deltaX;
      current.deltaY = deltaY;
      const elapsed = event.timeStamp - current.sampleTime;
      const sampleDelta = event.clientX - current.sampleX;
      if (elapsed > 0 && Math.abs(sampleDelta) > 0) current.velocityX = sampleDelta / elapsed;
      if (current.axis === 'horizontal' && !reducedMotion.matches) updateSwipePresentation(current, deltaX);

      const index = pageOrder.indexOf(activePage);
      const direction = deltaX < 0 ? 1 : -1;
      const destination = pageOrder[index + direction];
      const touchPointer = current.pointerType === 'touch';
      const threshold = touchPointer
        ? Math.min(100, window.innerWidth * 0.2)
        : Math.min(140, Math.max(96, window.innerWidth * 0.1));
      const freshVelocity = event.timeStamp - current.sampleTime <= 120;
      const fastSwipe = touchPointer
        && Math.abs(deltaX) >= 28
        && freshVelocity
        && Math.abs(current.velocityX) >= 0.65
        && Math.sign(current.velocityX) === Math.sign(deltaX);
      const clearlyHorizontal = Math.abs(deltaX) >= Math.abs(deltaY) * horizontalIntentRatio;
      const shouldNavigate = current.axis === 'horizontal'
        && clearlyHorizontal
        && Boolean(destination)
        && (Math.abs(deltaX) >= threshold || fastSwipe);

      if (!shouldNavigate) {
        clearGesture(true);
        return;
      }

      gesture = null;
      releasePointer(current);
      stopSettlement(current.page);
      const destinationPage = current.destination;
      if (!touchPointer) protectAgainstDraggedClick(current.pointerId);
      if (reducedMotion.matches || !destinationPage) {
        removeSwipePresentation(current.page);
        restorePreview(current);
        switchPage(destination);
        return;
      }

      switchPage(destination, false, { keepPreviousVisible: true, deferScroll: true, swipeTransition: true });
      beginSettlement([
        {
          page: current.page,
          targetX: Math.sign(deltaX) * window.innerWidth,
          hiddenAfter: true,
          inertAfter: true,
          ariaHiddenAfter: 'true',
        },
        { page: destinationPage, targetX: 0, hiddenAfter: false, inertAfter: false, ariaHiddenAfter: null },
      ], true);
    }

    document.addEventListener('click', suppressDraggedClick, true);
    main.addEventListener('pointerdown', onPointerDown, { passive: false });
    document.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('pointerup', onPointerUp, { passive: true });
    document.addEventListener('pointercancel', () => clearGesture(true), { passive: true });
    main.addEventListener('selectstart', () => {
      if (!gesture) return;
      if (isDesktopPointer(gesture.pointerType)) {
        if (hasTextSelection() || hasTextAtPoint(gesture.startX, gesture.startY)) clearGesture(true);
        return;
      }
      clearGesture(true);
    }, true);
    document.addEventListener('selectionchange', () => {
      if (gesture && hasTextSelection()) clearGesture(true);
    });
    window.addEventListener('blur', () => clearGesture(true));
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) clearGesture(true);
    });
  }

  function moveNavTab(currentIndex, delta) {
    const nextIndex = (currentIndex + delta + tabs.length) % tabs.length;
    const nextTab = tabs[nextIndex];
    nextTab.focus();
    switchPage(nextTab.dataset.page);
  }

  function cancelCommunityTransition() {
    if (communityTypeTimer) window.clearTimeout(communityTypeTimer);
    if (communityRedirectTimer) window.clearTimeout(communityRedirectTimer);
    communityTypeTimer = 0;
    communityRedirectTimer = 0;
    communityCharacterIndex = 0;

    const cta = $('#telegram-cta');
    if (cta?.dataset.transitioning !== 'true') return;
    delete cta.dataset.transitioning;
    cta.removeAttribute('aria-disabled');
    $('#terminal-command').textContent = '';
    $('#terminal-status').hidden = true;
    $('#terminal-announcement').textContent = '';
  }

  function finishTelegramCommand() {
    communityTypeTimer = 0;
    $('#terminal-command').textContent = TELEGRAM_COMMAND;
    const terminalStatus = $('#terminal-status');
    terminalStatus.textContent = 'Opening Telegram channel…';
    terminalStatus.hidden = false;
    $('#terminal-announcement').textContent = `Command typed: ${TELEGRAM_COMMAND}. Opening Telegram channel…`;
    communityRedirectTimer = window.setTimeout(() => {
      window.location.assign(TELEGRAM_DESTINATION);
    }, 700);
  }

  function handleTelegramClick(event) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    const cta = event.currentTarget;
    if (cta.dataset.transitioning === 'true') return;

    cta.dataset.transitioning = 'true';
    cta.setAttribute('aria-disabled', 'true');
    $('#terminal-command').textContent = '';
    $('#terminal-status').hidden = true;
    $('#terminal-announcement').textContent = '';
    communityCharacterIndex = 0;

    if (reducedMotion.matches) {
      finishTelegramCommand();
      return;
    }

    const typeNextCharacter = () => {
      communityCharacterIndex += 1;
      $('#terminal-command').textContent = TELEGRAM_COMMAND.slice(0, communityCharacterIndex);
      if (communityCharacterIndex >= TELEGRAM_COMMAND.length) {
        finishTelegramCommand();
        return;
      }
      communityTypeTimer = window.setTimeout(typeNextCharacter, 18);
    };
    typeNextCharacter();
  }

  function bind() {
    snapshotUpdateReload.addEventListener('click', () => window.location.reload());
    snapshotUpdateDismiss.addEventListener('click', () => {
      dismissedSnapshotGeneratedAt = noticedSnapshotGeneratedAt;
      snapshotUpdateNotice.hidden = true;
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) checkForUpdatedSnapshot();
    });
    window.addEventListener('online', () => checkForUpdatedSnapshot({ force: true }));
    window.setInterval(() => checkForUpdatedSnapshot(), BACKGROUND_SNAPSHOT_CHECK_MS);
    window.addEventListener('scroll', scheduleSearchDockSync, { passive: true });
    window.addEventListener('resize', scheduleSearchDockSync, { passive: true });
    searchInput.addEventListener('focus', () => {
      if (centerDock.classList.contains('is-released')) {
        centerDock.classList.remove('is-released');
        headerSearchReturn.hidden = true;
      }
      setSearchDockCompact(false);
    });
    searchInput.addEventListener('blur', scheduleSearchDockSync);
    scheduleSearchDockSync();

    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => switchPage(tab.dataset.page));
      tab.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowRight') { event.preventDefault(); moveNavTab(index, 1); }
        if (event.key === 'ArrowLeft') { event.preventDefault(); moveNavTab(index, -1); }
        if (event.key === 'Home') { event.preventDefault(); tabs[0].focus(); switchPage(tabs[0].dataset.page); }
        if (event.key === 'End') { event.preventDefault(); tabs[tabs.length - 1].focus(); switchPage(tabs[tabs.length - 1].dataset.page); }
      });
    });
    $('#explore-cves').addEventListener('click', () => switchPage('center'));
    overviewRetryButtons.forEach((button) => button.addEventListener('click', () => loadOverview({ retry: true })));
    $('.wordmark').addEventListener('click', (event) => {
      event.preventDefault();
      switchPage('overview');
    });
    headerSearchReturn.addEventListener('click', returnToSearch);
    $('#back-to-results').addEventListener('click', backToResults);
    $('#telegram-cta').addEventListener('click', handleTelegramClick);
    bindSwipeNavigation();
    window.addEventListener('popstate', restoreLocationState);
    document.addEventListener('click', (event) => {
      const link = event.target instanceof Element ? event.target.closest('a[href]') : null;
      if (!link) return;
      let destination;
      try { destination = new URL(link.href); } catch { return; }
      if (destination.origin !== window.location.origin || destination.pathname !== window.location.pathname || !destination.searchParams.has('page')) return;
      if (destination.hash && destination.search === window.location.search) return;
      event.preventDefault();
      window.history.pushState(null, '', destination);
      restoreLocationState();
    });

    searchInput.value = requestedSearch || requestedCveId || '';
    vendorFilterInput.value = requestedVendor;
    kevOnlyInput.checked = requestedKevOnly;
    sourceFilterSelect.value = requestedSource;
    epssMinimumInput.value = requestedEpssMin;
    cvssMinimumInput.value = requestedCvssMin;
    pageSizeSelect.value = String(pageSize);
    $$('.severity-tab').forEach((button) => {
      const selected = button.dataset.severity === activeSeverity;
      button.classList.toggle('is-selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });

    searchInput.addEventListener('input', () => {
      activeCveId = null;
      requestedCve = null;
      requestedCveId = null;
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    searchInput.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      searchInput.blur();
    });

    vendorFilterInput.addEventListener('input', () => {
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    sourceFilterSelect.addEventListener('change', () => {
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    epssMinimumInput.addEventListener('input', () => {
      const minimum = readPercentFilter(epssMinimumInput.value.trim());
      const invalid = Boolean(epssMinimumInput.value.trim()) && minimum === '';
      epssMinimumInput.setAttribute('aria-invalid', String(invalid));
      if (invalid) {
        status.textContent = 'Enter an EPSS minimum from 0 to 100. Unscored records are excluded when a minimum is set.';
        return;
      }
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    cvssMinimumInput.addEventListener('input', () => {
      const minimum = readCvssScoreFilter(cvssMinimumInput.value.trim());
      const invalid = Boolean(cvssMinimumInput.value.trim()) && minimum === '';
      cvssMinimumInput.setAttribute('aria-invalid', String(invalid));
      if (invalid) {
        status.textContent = 'Enter a CVSS minimum from 0 to 10. Records without a numeric CVSS score are excluded when a minimum is set.';
        return;
      }
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    kevOnlyInput.addEventListener('change', () => {
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    const renderLatestOnFilter = () => {
      if (latestSummaryRecords.length) renderLatestRows();
    };
    latestSearchInput.addEventListener('input', renderLatestOnFilter);
    latestSourceSelect.addEventListener('change', renderLatestOnFilter);
    latestEpssMinInput.addEventListener('input', renderLatestOnFilter);
    latestKevOnlyInput.addEventListener('change', renderLatestOnFilter);

    $$('.severity-tab').forEach((button) => {
      button.addEventListener('click', () => {
        activeSeverity = button.dataset.severity;
        $$('.severity-tab').forEach((candidate) => {
          const selected = candidate === button;
          candidate.classList.toggle('is-selected', selected);
          candidate.setAttribute('aria-pressed', String(selected));
        });
        pageIndex = 0;
        renderRecords();
        updateAddressBar();
      });
    });

    $('#date-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const from = dateFrom.value;
      const to = dateTo.value;
      if (!from || !to || from > to) {
        status.textContent = 'Choose a valid activity-date range with From on or before To.';
        (from > to ? dateFrom : dateTo).focus();
        return;
      }
      appliedFrom = from;
      appliedTo = to;
      pageIndex = 0;
      updateDateSummary(from, to);
      dateFilter.open = false;
      renderRecords();
      updateAddressBar();
    });

    dateFilter.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || !dateFilter.open) return;
      event.preventDefault();
      dateFilter.open = false;
      dateSummary.focus();
    });

    pageSizeSelect.addEventListener('change', () => {
      const nextSize = Number(pageSizeSelect.value);
      if (!PAGE_SIZES.has(nextSize)) return;
      pageSize = nextSize;
      pageIndex = 0;
      renderRecords();
      updateAddressBar();
    });
    pagePrevious.addEventListener('click', () => {
      if (pageIndex === 0) return;
      pageIndex -= 1;
      renderRecords();
      updateAddressBar();
      pagePrevious.focus({ preventScroll: true });
    });
    pageNext.addEventListener('click', () => {
      if ((pageIndex + 1) * pageSize >= matchedRecords.length) return;
      pageIndex += 1;
      renderRecords();
      updateAddressBar();
      pageNext.focus({ preventScroll: true });
      $('#result-status').scrollIntoView({ block: 'nearest', behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    });

    document.addEventListener('keydown', (event) => {
      const target = document.activeElement;
      const typing = target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
      if (event.key === '/' && !typing && activePage === 'center' && detailView.hidden) {
        event.preventDefault();
        returnToSearch();
      }
      if (event.key === 'Escape' && !detailView.hidden) backToResults();
    });

    const initialPage = initialUrlParams.get('page');
    if (initialPage && pages.has(initialPage)) switchPage(initialPage, false, { updateUrl: false });
    else if (!initialPage && requestedCveId) switchPage('center', false, { updateUrl: false });
  }

  registerOfflineSupport();
  bind();
  loadOverview();
  if (activePage === 'center') startSnapshot();
})();
