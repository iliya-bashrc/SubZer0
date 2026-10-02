(() => {
  'use strict';

  const SNAPSHOT_BASE = 'snapshot/';
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
  let records = [];
  let snapshotStarted = false;
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

  function safeString(value, fallback = '') {
    return typeof value === 'string' ? value : fallback;
  }

  function safeStringList(value) {
    return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
  }

  function formatDate(value, fallback = 'Date unavailable') {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(value)) return fallback;
    const parsed = new Date(`${value.slice(0, 10)}T00:00:00Z`);
    if (Number.isNaN(parsed.getTime())) return fallback;
    return new Intl.DateTimeFormat('en', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(parsed);
  }

  function formatTimestamp(value, fallback = 'Not provided') {
    if (typeof value !== 'string' || !value) return fallback;
    const parsed = new Date(value.endsWith('Z') || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
    if (Number.isNaN(parsed.getTime())) return fallback;
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

  function epssMarkedStale() {
    return manifest?.source_status?.find((source) => safeString(source?.name) === 'FIRST EPSS')?.ok === false;
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
    if (typeof value !== 'string') return null;
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || !url.hostname) return null;
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

  function validateManifest(candidate) {
    if (!candidate || candidate.schema_version !== 2 || candidate.complete !== true) {
      throw new Error('The bundled feed manifest is incomplete or unsupported.');
    }
    if (!Array.isArray(candidate.days) || candidate.days.length === 0) {
      throw new Error('The bundled manifest contains no day shards.');
    }
    candidate.days.forEach((day) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(safeString(day?.date)) || day.path !== `data/${day.date}.json`) {
        throw new Error('A manifest-listed shard path is invalid.');
      }
    });
    return candidate;
  }

  async function fetchJson(path) {
    const response = await fetch(path);
    if (!response.ok) throw new Error(`Local snapshot file could not be read (${response.status}).`);
    return response.json();
  }

  function validateRecords(dayPayloads) {
    const all = [];
    const seen = new Set();
    dayPayloads.forEach(({ day, rows }) => {
      if (!Array.isArray(rows) || rows.length !== day.count) {
        throw new Error(`The captured ${day.date} shard does not match its manifest count.`);
      }
      rows.forEach((record) => {
        if (!record || !CVE_ID_RE.test(safeString(record.id))) {
          throw new Error(`The captured ${day.date} shard contains an invalid CVE record.`);
        }
        const normalizedId = record.id.toUpperCase();
        if (seen.has(normalizedId)) throw new Error(`The captured snapshot repeats ${normalizedId}.`);
        seen.add(normalizedId);
        if (!['critical', 'high', 'medium', 'low', 'none', 'unknown'].includes(safeString(record.sev).toLowerCase())) {
          throw new Error(`The captured snapshot has an unexpected severity for ${normalizedId}.`);
        }
        record.id = normalizedId;
        all.push(record);
      });
    });
    if (all.length !== Number(manifest.totals?.cves)) {
      throw new Error(`Loaded ${nf.format(all.length)} records, but the manifest declares ${nf.format(Number(manifest.totals?.cves) || 0)}.`);
    }
    all.sort((left, right) => activityMilliseconds(right) - activityMilliseconds(left) || right.id.localeCompare(left.id));
    return all;
  }

  async function loadSnapshot() {
    try {
      manifest = validateManifest(await fetchJson(`${SNAPSHOT_BASE}manifest.json`));
      const dayPayloads = await Promise.all(manifest.days.map(async (day) => ({
        day,
        rows: await fetchJson(`${SNAPSHOT_BASE}${day.path}`)
      })));
      records = validateRecords(dayPayloads);

      const epssPath = manifest.epss?.path;
      if (epssPath !== 'data/epss.json') throw new Error('The captured EPSS file path is invalid.');
      const epssFile = await fetchJson(`${SNAPSHOT_BASE}${epssPath}`);
      epssScores = epssFile && epssFile.scores && typeof epssFile.scores === 'object' && !Array.isArray(epssFile.scores)
        ? epssFile.scores
        : Object.create(null);

      setSnapshotStats();
      renderRecords();
      if (requestedCveId && matchedRecords.length === 1 && matchedRecords[0].id === requestedCveId) {
        openDetails(matchedRecords[0], recordButtons.get(requestedCveId));
      }
    } catch (error) {
      recordList.setAttribute('aria-busy', 'false');
      recordList.replaceChildren();
      status.textContent = `The local snapshot could not be loaded: ${safeString(error?.message, 'unknown error')}`;
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'clear-filters';
      retry.textContent = 'Retry loading snapshot';
      retry.addEventListener('click', () => window.location.reload());
      recordList.append(retry);
    }
  }

  function startSnapshot() {
    if (snapshotStarted) return;
    snapshotStarted = true;
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

  function switchPage(name, focusPage = false) {
    if (!pages.has(name)) return;
    if (name === 'center') startSnapshot();
    const next = pages.get(name);
    const previous = pages.get(activePage);
    if (activePage === 'community' && name !== 'community') cancelCommunityTransition();
    if (previous && previous !== next) previous.hidden = true;
    next.hidden = false;
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
    if (!reducedMotion.matches) requestAnimationFrame(() => next.classList.add('page-enter'));
    if (focusPage) next.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: reducedMotion.matches ? 'auto' : 'smooth' });
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
  if (activePage === 'center') startSnapshot();
})();
