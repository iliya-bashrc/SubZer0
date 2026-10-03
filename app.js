(() => {
  'use strict';

  const SNAPSHOT_BASE = 'snapshot/';
  const FETCH_CACHE = Object.freeze({ manifest: 'no-cache', data: 'default', retry: 'reload' });
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
  const PAGE_SIZES = new Set([24, 48, 96]);
  const CVE_ID_RE = /^CVE-\d{4,}-\d+$/i;
  const BASE_SEVERITIES = ['critical', 'high', 'medium', 'low'];
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const tabs = $$('.nav-tab');
  const pages = new Map($$('.page').map((page) => [page.id.replace('page-', ''), page]));
  const searchInput = $('#record-search');
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
  const pageSizeSelect = $('#page-size');
  const pagination = $('#pagination');
  const pageIndicator = $('#page-indicator');
  const pagePrevious = $('#page-prev');
  const pageNext = $('#page-next');
  const feedObserver = 'IntersectionObserver' in window
    ? new IntersectionObserver((entries) => {
      entries.forEach((entry) => entry.target.classList.toggle('effect-visible', entry.isIntersecting));
    }, { root: null, rootMargin: '0px', threshold: 0.12 })
    : null;

  let manifest = null;
  let manifestPromise = null;
  let records = [];
  let snapshotStarted = false;
  let snapshotLoading = false;
  let epssScores = Object.create(null);
  let activePage = 'overview';
  let activeSeverity = 'all';
  let appliedFrom = '';
  let appliedTo = '';
  let pageIndex = 0;
  let pageSize = 24;
  let matchedRecords = [];
  let lastDetailFocus = null;
  let lastScrollY = 0;
  let communityTypeTimer = 0;
  let communityRedirectTimer = 0;
  let communityCharacterIndex = 0;
  let recordButtons = new Map();
  const requestedCve = new URLSearchParams(window.location.search).get('cve');
  const requestedCveId = requestedCve && CVE_ID_RE.test(requestedCve) ? requestedCve.toUpperCase() : null;

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
    const age = Date.now() - sourceUpdated;
    return status?.ok !== true || !Number.isFinite(sourceUpdated) || age < 0 || age > 36 * 60 * 60 * 1000;
  }

  function epssFreshness(candidate) {
    const scoreDate = safeString(candidate?.epss?.score_date);
    const sourceUpdated = Date.parse(safeString(candidate?.epss?.source_updated_at));
    if (!isCanonicalDate(scoreDate) || !Number.isFinite(sourceUpdated)) return 'unavailable';
    return epssMarkedStale(candidate) ? 'stale' : 'current';
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
        recordsValue.textContent = unavailable;
        kevValue.textContent = unavailable;
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
      recordsValue.textContent = verifiedTotals
        ? `${nf.format(verifiedTotals.records)} verified`
        : `${nf.format(candidate.totals.cves)} in manifest`;
      kevValue.textContent = verifiedTotals
        ? `${nf.format(verifiedTotals.kev)} verified`
        : `${nf.format(candidate.totals.known_exploited)} in manifest`;

      const scoreDate = safeString(candidate.epss?.score_date);
      const freshness = epssFreshness(candidate);
      epssDate.textContent = freshness === 'unavailable'
        ? 'Unavailable'
        : `${formatDate(scoreDate)} · ${freshness}`;
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
    appliedFrom = start;
    appliedTo = end;
    dateFrom.min = start;
    dateFrom.max = end;
    dateFrom.value = start;
    dateTo.min = start;
    dateTo.max = end;
    dateTo.value = end;
    updateDateSummary(start, end);

    const scoreDate = safeString(manifest.epss?.score_date, 'not supplied');
    const epssMessage = epssMarkedStale()
      ? `FIRST EPSS scores are dated ${formatDate(scoreDate)} and marked stale by the captured manifest. Missing scores remain unscored—not 0%.`
      : `FIRST EPSS score set date: ${formatDate(scoreDate)}. A missing score is not 0%.`;
    const epssWarning = $('#epss-warning');
    if (epssWarning) {
      epssWarning.textContent = epssMessage;
      epssWarning.classList.toggle('is-stale', epssMarkedStale());
      epssWarning.hidden = false;
    }

    const generated = formatTimestamp(manifest.generated_at, safeString(manifest.generated_at));
    const windowText = `${formatDate(start)} to ${formatDate(end)}`;
    $('#snapshot-provenance').textContent = `Bundled published feed snapshot · generated ${generated} · ${nf.format(manifest.days.length)} manifest-listed UTC day shards · ${windowText}. ${epssMessage} No live feed request is made by this page; record and reference text is rendered safely as text.`;
  }

  function updateDateSummary(from, to) {
    dateSummary.textContent = `Activity date · ${formatDate(from).replace(',', '')} — ${formatDate(to).replace(',', '')}`;
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
    if (!isCount(overview.count, 3) || overview.count !== Math.min(3, totals.cves)) throw new Error('Manifest Overview count is invalid.');
    return candidate;
  }

  async function fetchBytes(path, maximum, cache = FETCH_CACHE.data) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), LIMITS.fetchTimeoutMs);
    try {
      const response = await fetch(path, { signal: controller.signal, credentials: 'same-origin', cache, redirect: 'error' });
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

  async function fetchVerifiedJson(config, maximum) {
    const path = `${SNAPSHOT_BASE}${config.path}`;
    let bytes = await fetchBytes(path, maximum, FETCH_CACHE.data);
    try {
      await verifyBlob(bytes, config);
    } catch (error) {
      if (!(error instanceof SnapshotIntegrityError)) throw error;
      bytes = await fetchBytes(path, maximum, FETCH_CACHE.retry);
      await verifyBlob(bytes, config);
    }
    return parseJsonBytes(bytes);
  }

  async function getManifest() {
    if (!manifestPromise) {
      manifestPromise = (async () => {
        const bytes = await fetchBytes(`${SNAPSHOT_BASE}manifest.json`, LIMITS.manifestBytes, FETCH_CACHE.manifest);
        return validateManifest(parseJsonBytes(bytes));
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
    if (!payload || typeof payload !== 'object' || payload.schema_version !== 1 || payload.generated_at !== candidate.generated_at || !Array.isArray(payload.records) || payload.records.length !== Math.min(3, candidate.totals.cves)) throw new Error('Overview snapshot is invalid.');
    payload.records.forEach((record) => {
      if (!record || !isValidText(record.id, 32) || !/^CVE-\d{4,}-\d+$/.test(record.id) || record.id !== record.id.toUpperCase() || !isValidText(record.title, 512) ||
          !['critical', 'high', 'medium', 'low', 'none', 'unknown'].includes(record.sev) ||
          (record.score !== null && (typeof record.score !== 'number' || !Number.isFinite(record.score) || record.score < 0 || record.score > 10)) || record.sev !== severityForScore(record.score) ||
          !isCanonicalDate(record.window_date) || !isSourceTimestamp(record.activity_at) || !isValidText(record.date_basis, 128) || !Array.isArray(record.sources) ||
          record.sources.length < 1 || record.sources.length > 8 || record.sources.some((source) => !SOURCE_LABELS.has(source))) throw new Error('Overview record is invalid.');
    });
    return payload;
  }

  function renderOverview(payload, candidate) {
    const recordsForCards = payload.records;
    const cards = $$('.ui-stage [data-overview-card]');
    recordsForCards.forEach((record, index) => {
      const card = cards[index];
      if (!card) return;
      const severity = ['critical', 'high', 'medium', 'low'].includes(record.sev) ? record.sev : 'unrated';
      const tag = card.querySelector('.severity-tag');
      tag.className = `severity-tag ${severity}`;
      tag.textContent = severityName(severity);
      if (index < 2) {
        card.querySelector('.layer-kicker').textContent = `Record · ${record.id}`;
        card.querySelector('.layer-mainline strong').textContent = record.title;
        card.querySelector('.layer-foot').textContent = `${record.score === null ? 'CVSS unscored' : `CVSS ${record.score.toFixed(1)}`} / ${formatDate(record.window_date)}`;
      } else {
        card.querySelector('.layer-kicker').textContent = `CVE record · ${record.sources.join(' · ')}`;
        card.querySelector('.layer-mainline strong').textContent = record.id;
        card.querySelector('.layer-description').textContent = record.title;
        const foot = card.querySelector('.layer-foot-row');
        const score = document.createElement('span');
        score.textContent = record.score === null ? 'CVSS unscored' : `CVSS ${record.score.toFixed(1)}`;
        const source = document.createElement('span');
        source.textContent = record.sources[0];
        const time = document.createElement('time');
        time.dateTime = record.window_date;
        time.textContent = formatDate(record.window_date);
        foot.replaceChildren(score, source, time);
      }
      card.hidden = false;
    });
    cards.slice(recordsForCards.length).forEach((card) => { card.hidden = true; });

    const latest = $('#latest-list');
    latest.replaceChildren();
    recordsForCards.forEach((record) => {
      const item = document.createElement('li');
      const link = document.createElement('a');
      link.className = 'latest-id';
      link.href = `?page=center&cve=${encodeURIComponent(record.id)}`;
      link.textContent = record.id;
      const severity = ['critical', 'high', 'medium', 'low'].includes(record.sev) ? record.sev : 'unrated';
      const tag = document.createElement('span');
      tag.className = `severity-tag ${severity}`;
      tag.textContent = severityName(severity);
      const time = document.createElement('time');
      time.dateTime = record.window_date;
      time.textContent = formatDate(record.window_date);
      item.append(link, tag, time);
      latest.append(item);
    });
    const generatedTime = $('#overview-generated-at');
    const time = document.createElement('time');
    time.dateTime = candidate.generated_at;
    time.textContent = formatTimestamp(candidate.generated_at, 'Date unavailable');
    generatedTime.replaceChildren(time);
    $('#overview-status').textContent = `${nf.format(candidate.totals.cves)} CVE records · snapshot updated ${formatTimestamp(candidate.generated_at, 'recently')}.`;
    $('#overview-status').classList.remove('is-error');
    $('#overview-status').setAttribute('aria-busy', 'false');
    setSnapshotStatus('Overview preview verified. Full shard integrity is checked when CVE Center opens; this is a static snapshot, not a live feed.', 'preview', candidate, null, 'overview');
    $('.ui-stage').setAttribute('aria-busy', 'false');
    $('#latest-list').setAttribute('aria-busy', 'false');
  }

  async function loadOverview() {
    const statusLine = $('#overview-status');
    let candidate = null;
    setSnapshotStatus('Loading snapshot manifest…', 'loading', null, null, 'overview');
    statusLine.setAttribute('aria-busy', 'true');
    try {
      candidate = await getManifest();
      setSnapshotStatus('Manifest verified. Checking the Overview preview integrity…', 'verifying', candidate, null, 'overview');
      const payload = validateOverview(await fetchVerifiedJson(candidate.overview, LIMITS.overviewBytes), candidate);
      manifest = candidate;
      renderOverview(payload, candidate);
    } catch {
      setSnapshotStatus('Snapshot verification failed. No verified Overview records are shown; reload to try again.', 'error', candidate, null, 'overview');
      statusLine.textContent = 'Recent CVE data could not be verified. Reload the page to try again.';
      statusLine.classList.add('is-error');
      $('.ui-stage').setAttribute('aria-busy', 'false');
      $$('.ui-stage [data-overview-card]').forEach((card) => { card.hidden = true; });
      $('#latest-list').replaceChildren();
      $('#latest-list').setAttribute('aria-busy', 'false');
      $('#overview-generated-at').textContent = 'Unavailable';
    } finally {
      statusLine.setAttribute('aria-busy', 'false');
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
      const [dayPayloads, epssFile] = await Promise.all([
        mapWithConcurrency(manifest.days, LIMITS.shardConcurrency, async (day) => {
          const rows = validateShard(day, await fetchVerifiedJson(day, LIMITS.shardBytes));
          verifiedShardCount += 1;
          reportVerifiedShard(verifiedShardCount, manifest.days.length);
          return { day, rows };
        }),
        fetchVerifiedJson(manifest.epss, LIMITS.epssBytes)
      ]);
      records = validateRecords(dayPayloads);
      epssScores = validateEpssFile(epssFile, manifest, records);
      acceptSnapshotSidecar();

      setSnapshotStats();
      setSnapshotStatus('Snapshot verified. This is a dated static capture, not a live feed.', 'verified', manifest, {
        records: records.length,
        kev: records.filter((record) => record.kev !== null).length
      }, 'center');
      renderRecords();
      if (requestedCveId && matchedRecords.length === 1 && matchedRecords[0].id === requestedCveId) {
        openDetails(matchedRecords[0], recordButtons.get(requestedCveId));
      }
      closeSnapshotLoader();
    } catch {
      records = [];
      epssScores = Object.create(null);
      setSnapshotStatus('Snapshot verification failed. No records are displayed; reload to try again.', 'error', manifest, null, 'center');
      recordList.replaceChildren();
      status.textContent = 'The captured CVE snapshot could not be verified. No partial records are shown. Check your connection and reload to try again.';
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
    const affected = Array.isArray(record.affected) ? record.affected.map((item) => [item?.vendor, item?.product, item?.versions].filter(Boolean).join(' ')).join(' ') : '';
    return [record.id, record.title, record.desc, record.date_basis, ...safeStringList(record.sources), affected]
      .map((part) => typeof part === 'string' ? part : '')
      .join(' ')
      .toLocaleLowerCase();
  }

  function filteredRecords() {
    const query = searchInput.value.trim().toLocaleLowerCase();
    const exactCve = CVE_ID_RE.test(query) ? query.toUpperCase() : null;
    return records.filter((record) => {
      const category = severityKey(record);
      const date = activityDate(record);
      const severityMatches = activeSeverity === 'all' || category === activeSeverity;
      const dateMatches = date >= appliedFrom && date <= appliedTo;
      const textMatches = !query || (exactCve ? record.id === exactCve : searchHaystack(record).includes(query));
      return severityMatches && dateMatches && textMatches;
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

    const effects = document.createElement('span');
    effects.className = 'record-effects';
    effects.setAttribute('aria-hidden', 'true');
    ['fleck-a', 'fleck-b', 'fleck-c'].forEach((name) => {
      const fleck = document.createElement('span');
      fleck.className = `record-fleck ${name}`;
      effects.append(fleck);
    });

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

    open.append(effects, body, signals);
    open.addEventListener('click', () => openDetails(record, open));
    row.append(open);
    recordList.append(row);
    recordButtons.set(record.id, open);
    if (feedObserver) feedObserver.observe(row);
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
    recordButtons.forEach((button) => {
      const row = button.closest('.record-row');
      if (row && feedObserver) feedObserver.unobserve(row);
    });
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
      addText(empty, 'p', '', 'Adjust the severity or activity-date range, or clear the search to see more records.');
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
    pageIndex = 0;
    updateDateSummary(appliedFrom, appliedTo);
    $$('.severity-tab').forEach((button) => {
      const selected = button.dataset.severity === 'all';
      button.classList.toggle('is-selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    renderRecords();
  }

  function appendFact(list, label, value) {
    const row = document.createElement('div');
    row.className = 'detail-fact';
    addText(row, 'dt', '', label);
    addText(row, 'dd', '', safeString(value, 'Not provided'));
    list.append(row);
  }

  function openDetails(record, opener) {
    if (!record || !record.id) return;
    lastDetailFocus = opener || document.activeElement;
    lastScrollY = window.scrollY;
    if (feedObserver) $$('.record-row.effect-visible').forEach((row) => row.classList.remove('effect-visible'));
    severityDistribution.hidden = true;
    centerDock.hidden = true;
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

    addText(detailContent, 'h3', 'detail-title', safeString(record.title, 'Title not supplied'));
    addText(detailContent, 'p', 'detail-description', safeString(record.desc, 'Description not supplied'));
    detailContent.prepend(header);

    const factsHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Record details');
    const facts = document.createElement('dl');
    facts.className = 'detail-facts';
    appendFact(facts, 'Activity date', formatDate(activityDate(record)));
    appendFact(facts, 'Date basis', safeString(record.date_basis, 'Not supplied'));
    appendFact(facts, 'Published', formatTimestamp(record.published));
    appendFact(facts, 'Last modified', formatTimestamp(record.modified));
    appendFact(facts, 'Feed source labels', safeStringList(record.sources).join(' · ') || 'Not supplied');
    detailContent.append(factsHeading, facts);

    const signalHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Evidence signals');
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
    const epssNote = `Source: FIRST EPSS, score set dated ${formatDate(epssDate)}${epssMarkedStale() ? ' (marked stale in the captured manifest)' : ''}. Missing means unscored, not 0%.`;
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

    if (Array.isArray(record.affected) && record.affected.length) {
      const affectedHeading = addText(detailContent, 'h3', 'detail-section-heading', 'Affected products');
      const affectedList = document.createElement('ul');
      affectedList.className = 'detail-list';
      record.affected.slice(0, 30).forEach((item) => {
        const line = [item?.vendor, item?.product, item?.versions].filter((part) => typeof part === 'string' && part.trim()).join(' · ');
        if (line) addText(affectedList, 'li', '', line);
      });
      detailContent.append(affectedHeading, affectedList);
    }

    if (Array.isArray(record.refs) && record.refs.length) {
      const refsHeading = addText(detailContent, 'h3', 'detail-section-heading', 'References in the feed');
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
      detailContent.append(refsHeading, refsList);
    }

    const sourceRecordUrl = safeExternalUrl(record.primary_url);
    const sourceLine = document.createElement('div');
    sourceLine.className = 'detail-source-line';
    addText(sourceLine, 'span', '', `Record sources: ${safeStringList(record.sources).join(' · ') || 'not supplied in feed'}`);
    if (sourceRecordUrl) addLink(sourceLine, 'Open primary source record', sourceRecordUrl);
    detailContent.append(sourceLine);

    $('#back-to-results').focus({ preventScroll: true });
    requestAnimationFrame(() => {
      const top = detailView.getBoundingClientRect().top + window.scrollY - $('.site-header').getBoundingClientRect().height - 16;
      window.scrollTo({ top: Math.max(0, top), behavior: 'auto' });
    });
  }

  function backToResults() {
    detailView.hidden = true;
    centerDock.hidden = false;
    severityDistribution.hidden = false;
    feedView.hidden = false;
    renderRecords();
    window.scrollTo({ top: lastScrollY, behavior: 'auto' });
    const restore = lastDetailFocus?.dataset?.cveId ? recordButtons.get(lastDetailFocus.dataset.cveId) : null;
    (restore || searchInput).focus({ preventScroll: true });
  }

  function switchPage(name, focusPage = false, options = {}) {
    if (!pages.has(name)) return;
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
  }

  function bindSwipeNavigation() {
    const main = $('#main-content');
    if (!main || typeof window.PointerEvent !== 'function') return;

    const pageOrder = ['overview', 'center', 'community'];
    const blockedSelector = [
      'a[href]', 'button', 'input', 'select', 'textarea', 'option', 'summary', 'details',
      '[role="button"]', '[role="link"]', '[role="combobox"]', '[role="textbox"]',
      '[role="dialog"]', '[aria-modal="true"]', '[contenteditable]:not([contenteditable="false"])',
      '.record-list', '.record-row', '.center-dock', '.filter-controls', '.severity-distribution',
      '.pagination', '.detail-view', '.snapshot-loader', '.ui-stage',
    ].join(',');
    const horizontalIntentRatio = 1.2;
    let gesture = null;
    let settlement = null;

    const hasTextSelection = () => {
      const selection = window.getSelection();
      return Boolean(selection && !selection.isCollapsed);
    };

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
      if (event.pointerType !== 'touch' || !event.isPrimary || event.button !== 0 || gesture) return;
      const target = event.target;
      if (!(target instanceof Element) || target.closest(blockedSelector) || hasTextSelection()) return;
      const page = target.closest('.page');
      if (!page || page.hidden || page !== pages.get(activePage)) return;
      stopSettlement(page);

      gesture = {
        pointerId: event.pointerId,
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
      const threshold = Math.min(100, window.innerWidth * 0.2);
      const freshVelocity = event.timeStamp - current.sampleTime <= 120;
      const fastSwipe = Math.abs(deltaX) >= 28
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

    main.addEventListener('pointerdown', onPointerDown, { passive: true });
    document.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('pointerup', onPointerUp, { passive: true });
    document.addEventListener('pointercancel', () => clearGesture(true), { passive: true });
    main.addEventListener('selectstart', () => clearGesture(true), true);
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
    $('#back-to-results').addEventListener('click', backToResults);
    $('#telegram-cta').addEventListener('click', handleTelegramClick);
    bindSwipeNavigation();

    searchInput.addEventListener('input', () => {
      pageIndex = 0;
      renderRecords();
    });

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
    });

    pageSizeSelect.addEventListener('change', () => {
      const nextSize = Number(pageSizeSelect.value);
      if (!PAGE_SIZES.has(nextSize)) return;
      pageSize = nextSize;
      pageIndex = 0;
      renderRecords();
    });
    pagePrevious.addEventListener('click', () => {
      if (pageIndex === 0) return;
      pageIndex -= 1;
      renderRecords();
      pagePrevious.focus({ preventScroll: true });
    });
    pageNext.addEventListener('click', () => {
      if ((pageIndex + 1) * pageSize >= matchedRecords.length) return;
      pageIndex += 1;
      renderRecords();
      pageNext.focus({ preventScroll: true });
      $('#result-status').scrollIntoView({ block: 'nearest', behavior: reducedMotion.matches ? 'auto' : 'smooth' });
    });

    document.addEventListener('keydown', (event) => {
      const target = document.activeElement;
      const typing = target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
      if (event.key === '/' && !typing && activePage === 'center' && detailView.hidden) {
        event.preventDefault();
        searchInput.focus();
      }
      if (event.key === 'Escape' && !detailView.hidden) backToResults();
    });

    const stage = $('.ui-stage');
    const finePointer = window.matchMedia('(pointer: fine) and (min-width: 801px)');
    if (stage && finePointer.matches && !reducedMotion.matches) {
      const layers = $$('[data-depth]', stage);
      stage.addEventListener('pointermove', (event) => {
        const bounds = stage.getBoundingClientRect();
        const nx = (event.clientX - bounds.left) / bounds.width - .5;
        const ny = (event.clientY - bounds.top) / bounds.height - .5;
        layers.forEach((layer) => {
          const depth = Number(layer.dataset.depth || 0);
          layer.style.setProperty('--pointer-x', `${(nx * depth * 8).toFixed(2)}px`);
          layer.style.setProperty('--pointer-y', `${(ny * depth * 5).toFixed(2)}px`);
          layer.style.transform = 'translate3d(var(--pointer-x), var(--pointer-y), 0)';
        });
      });
      stage.addEventListener('pointerleave', () => layers.forEach((layer) => {
        layer.style.removeProperty('--pointer-x');
        layer.style.removeProperty('--pointer-y');
        layer.style.removeProperty('transform');
      }));
    }

    const initialPage = new URLSearchParams(window.location.search).get('page');
    if (requestedCveId) searchInput.value = requestedCveId;
    if (initialPage === 'center' || requestedCveId) switchPage('center');
    else if (initialPage === 'community') switchPage('community');
  }

  bind();
  loadOverview();
  if (activePage === 'center') startSnapshot();
})();
