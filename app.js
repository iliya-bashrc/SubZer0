'use strict';

(() => {
  const PAGE_SIZE = 24;
  const MAX_DOM_RECORDS = 200;
  const POLL_MS = 120_000;
  const SHARD_CONCURRENCY = 4;
  const FETCH_TIMEOUT_MS = 20_000;
  const BOOT_RETRY_MS = 3_000;
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 };
  const $ = (id) => document.getElementById(id);
  const feedList = $('feed-list');
  const loadedByDay = new Map();
  const loadJobs = new Map();
  const allRecords = new Map();
  let manifest = null;
  let epssSnapshot = null;
  let epssVersion = '';
  let lastBrowserCheck = null;
  let lastSnapshotVersion = '';
  let state = { from: '', to: '', severity: 'all', query: '', sort: 'new', exactHours: null, vendor: '', product: '', absoluteZero: false, group: 'none' };
  let visible = PAGE_SIZE;
  let windowStart = 0;
  let polling = false;
  let searchTimer = 0;
  let searchGeneration = 0;
  let toastTimer = 0;
  let booted = false;
  let pendingFeedUpdate = false;
  let pendingSnapshot = null;
  let statAnimationKey = '';
  const statAnimationFrames = new Map();
  const pendingNewIds = new Set();
  const pendingCriticalIds = new Set();
  let preAbsoluteSeverity = 'all';
  const storedStars = readStored('subzero:stars', []);
  const storedRead = readStored('subzero:read', []);
  const starredIds = new Set(Array.isArray(storedStars) ? storedStars.map(cveId).filter(Boolean) : []);
  const readIds = new Set(Array.isArray(storedRead) ? storedRead.map(cveId).filter(Boolean) : []);
  let savedViews = readStored('subzero:views', []);
  let watchlist = readStored('subzero:watchlist', []);
  let compactCards = readStored('subzero:compact', false) === true;
  let facets = { vendors: [], products: [], product_pairs: [] };
  let retainedHistory = null;
  let exportBusy = false;
  const githubPocCache = new Map();

  const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);

  function readStored(key, fallback) {
    try {
      const value = window.localStorage.getItem(key);
      return value == null ? fallback : JSON.parse(value);
    } catch (_) {
      return fallback;
    }
  }

  function writeStored(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (_) {
      toast('This browser could not save the local preference.', 'warning');
      return false;
    }
  }

  function isTextTarget(target) {
    return !!target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.getAttribute?.('role') === 'textbox');
  }

  function normalizeFacet(value) {
    return String(value || '').trim().toLocaleLowerCase();
  }

  function cveId(value) {
    const id = String(value || '').trim().toUpperCase();
    return /^CVE-\d{4,}-\d+$/.test(id) ? id : '';
  }

  function safeUrl(value) {
    try {
      const parsed = new URL(String(value || ''), window.location.href);
      return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : '';
    } catch (_) {
      return '';
    }
  }

  function pocUrl(id) {
    return `https://github.com/search?q=${encodeURIComponent(`${id} poc exploit`)}&type=repositories`;
  }

  function cvssSeverity(score) {
    if (score == null || score === '' || !Number.isFinite(Number(score)) || Number(score) < 0 || Number(score) > 10) return 'unknown';
    const value = Number(score);
    if (value === 0) return 'none';
    if (value >= 9) return 'critical';
    if (value >= 7) return 'high';
    if (value >= 4) return 'medium';
    return value >= 0.1 ? 'low' : 'none';
  }

  function epssFor(id) {
    const value = epssSnapshot?.scores?.[id];
    if (!value || value.score == null || value.score === '' || !Number.isFinite(Number(value.score)) || Number(value.score) < 0 || Number(value.score) > 1) return null;
    const percentile = value.percentile == null || value.percentile === '' ? null : Number(value.percentile);
    return { score: Number(value.score), percentile: Number.isFinite(percentile) ? percentile : null };
  }

  function priorityScore(record, id = cveId(record.id)) {
    const components = [];
    const weights = { cvss: 25, epss: 25, kev: 25, poc: 15, recency: 10 };
    const cvss = Number(record.score);
    if (record.score != null && Number.isFinite(cvss) && cvss >= 0 && cvss <= 10) {
      components.push({ key: 'CVSS', value: cvss * 10, weight: weights.cvss, note: 'CVSS base score ÷ 10 × 100' });
    }
    const epss = epssFor(id);
    if (epss) components.push({ key: 'EPSS', value: epss.score * 100, weight: weights.epss, note: 'FIRST EPSS probability × 100' });
    const cisa = (manifest?.source_status || []).find((source) => source.name === 'CISA KEV');
    if (cisa?.ok === true) components.push({ key: 'CISA KEV', value: record.kev ? 100 : 0, weight: weights.kev, note: 'Listed = 100; not listed = 0 in this catalog snapshot' });
    const taggedExploit = (record.refs || []).some((ref) => ref.source === 'NVD' && Array.isArray(ref.tags) && ref.tags.some((tag) => String(tag).toLowerCase() === 'exploit'));
    if (taggedExploit) components.push({ key: 'PoC reference', value: 60, weight: weights.poc, note: 'NVD reference tagged Exploit; code itself is not validated' });
    const timestamp = parseTime(record.activity_at) || parseTime(record.window_date) || parseTime(record.published);
    if (timestamp != null) {
      const ageDays = Math.max(0, Math.min(30, (Date.now() - timestamp) / 86_400_000));
      components.push({ key: 'Recency', value: 100 * (1 - ageDays / 30), weight: weights.recency, note: 'Linear decay from activity timestamp over 30 days' });
    }
    const availableWeight = components.reduce((sum, item) => sum + item.weight, 0);
    const value = components.length >= 3 && availableWeight > 0
      ? Math.round(components.reduce((sum, item) => sum + item.value * item.weight, 0) / availableWeight * 10) / 10
      : null;
    return { value, components, available: components.length, total: 5, missing: ['CVSS', 'EPSS', 'CISA KEV', 'PoC reference', 'Recency'].filter((key) => !components.some((item) => item.key === key)) };
  }

  function epssPercent(value) {
    if (!value) return 'not available';
    const percentage = value.score * 100;
    return percentage > 0 && percentage < 0.1 ? '<0.1%' : `${percentage.toFixed(percentage >= 10 ? 1 : 2).replace(/0+$/, '').replace(/\.$/, '')}%`;
  }

  function telegramShareUrl(record, id) {
    const score = record.score == null ? 'not rated' : Number(record.score).toFixed(1);
    const severity = cvssSeverity(record.score);
    const epss = epssFor(id);
    const lines = [
      `SubZer0 · ${id}`,
      record.title || id,
      `CVSS ${score} · ${severity === 'unknown' ? 'UNRATED' : severity === 'none' ? 'NONE' : severity.toUpperCase()} severity`,
      `EPSS ${epss ? `${epssPercent(epss)} estimated 30-day probability` : 'not available in this snapshot'}`,
      record.kev ? 'Listed in CISA KEV (known-exploited catalog)' : 'Not listed in the current CISA KEV snapshot',
      'GitHub PoC search: unverified',
      `Source: ${safeUrl(record.primary_url) || `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`}`
    ];
    return `https://t.me/share/url?url=${encodeURIComponent(window.location.href.split('#')[0])}&text=${encodeURIComponent(lines.join('\n'))}`;
  }

  function parseTime(value) {
    const result = value ? Date.parse(value) : NaN;
    return Number.isFinite(result) ? result : null;
  }

  function wait(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  async function fetchResponse(url, options = {}, attempts = 3) {
    const retryableStatuses = new Set([408, 425, 429, 500, 502, 503, 504]);
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        if (response.ok) return response;
        const error = new Error(`Request returned ${response.status}`);
        error.status = response.status;
        if (!retryableStatuses.has(response.status) || attempt === attempts - 1) throw error;
        const retryAfter = Number(response.headers?.get?.('Retry-After'));
        await wait(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(5_000, retryAfter * 1000) : 400 * (2 ** attempt));
      } catch (error) {
        lastError = error;
        const retryable = error.name === 'AbortError' || !error.status || retryableStatuses.has(error.status);
        if (!retryable || attempt === attempts - 1) throw error;
        await wait(400 * (2 ** attempt));
      } finally {
        window.clearTimeout(timeout);
      }
    }
    throw lastError || new Error('Request failed');
  }

  async function fetchJson(url, options = {}, attempts = 3) {
    const response = await fetchResponse(url, options, attempts);
    return response.json();
  }

  function fmtDate(value) {
    if (!value) return 'DATE UNKNOWN';
    const parsed = new Date(value.length === 10 ? `${value}T00:00:00Z` : value);
    if (Number.isNaN(parsed.getTime())) return 'DATE UNKNOWN';
    return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit', timeZone: 'UTC' }).format(parsed);
  }

  function fmtTimestamp(value) {
    const parsed = parseTime(value);
    if (parsed == null) return '—';
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short'
    }).format(new Date(parsed));
  }

  function relativeTime(value) {
    const timestamp = parseTime(value);
    if (timestamp == null) return 'unknown time';
    const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60_000));
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  function hideLoader() {
    if (!booted) booted = true;
    const loader = $('loader');
    if (!loader || loader.classList.contains('done')) return;
    loader.classList.add('done');
  }

  function setLoaderMessage(message) {
    const element = $('loader-message');
    if (element) element.textContent = message;
  }

  function sourceName(name) {
    if (name === 'GitHub Advisory Database') return 'GitHub advisories';
    if (name === 'NVD CVE API 2.0') return 'NVD CVE API 2.0';
    if (name === 'CISA KEV') return 'CISA KEV';
    return name || 'Source';
  }

  function setStatus(message, kind = '') {
    const element = $('feed-status');
    if (!element) return;
    element.textContent = message;
    element.className = `feed-status${kind ? ` ${kind}` : ''}`;
  }

  function toast(message, kind = '') {
    const element = $('toast');
    element.textContent = message;
    element.className = `toast show${kind ? ` ${kind}` : ''}`;
    window.clearTimeout(toastTimer);
    const duration = message === 'Copied' ? 1_800 : 4_600;
    toastTimer = window.setTimeout(() => element.classList.remove('show'), duration);
  }

  async function fetchManifest() {
    const url = `data/manifest.json?check=${Date.now()}`;
    const value = await fetchJson(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
    if (value.schema_version !== 2 || !Array.isArray(value.days) || !value.window || !value.totals) {
      throw new Error('Feed index has an unsupported schema');
    }
    if (!parseTime(value.generated_at) || !parseTime(value.window.start) || !parseTime(value.window.end) || !value.days.length) {
      throw new Error('Feed index is missing valid timestamps or date shards');
    }
    const seenDays = new Set();
    for (const item of value.days) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(String(item.date || '')) || seenDays.has(item.date) ||
          !new RegExp(`^data/${item.date}\\.json$`).test(String(item.path || '')) ||
          !Number.isInteger(Number(item.count)) || Number(item.count) < 0) {
        throw new Error('Feed index contains an invalid date shard');
      }
      if (item.sha256 && !/^[a-f0-9]{64}$/i.test(item.sha256)) throw new Error(`Feed index contains an invalid fingerprint for ${item.date}`);
      seenDays.add(item.date);
    }
    return value;
  }

  async function fetchDay(day, version, sourceManifest = manifest) {
    const jobKey = `${day}:${version}`;
    if (loadJobs.has(jobKey)) return loadJobs.get(jobKey);
    const summary = sourceManifest.days.find((item) => item.date === day);
    if (!summary || !summary.path) return [];
    const job = (async () => {
      const url = `${summary.path}?v=${encodeURIComponent(version)}`;
      const payload = await fetchJson(url, { cache: 'default', headers: { Accept: 'application/json' } });
      if (!Array.isArray(payload)) throw new Error(`Invalid feed shard for ${day}`);
      return payload;
    })();
    loadJobs.set(jobKey, job);
    try {
      return await job;
    } finally {
      loadJobs.delete(jobKey);
    }
  }

  function rebuildRecords() {
    allRecords.clear();
    for (const values of loadedByDay.values()) {
      for (const record of values) {
        const id = cveId(record.id);
        if (id) allRecords.set(id, record);
      }
    }
  }

  function showUpdateNotice(message) {
    const text = $('new-notice-text');
    const notice = $('new-notice');
    if (!text || !notice) return;
    text.textContent = message;
    notice.hidden = false;
  }

  function triggerCriticalAmbient(count) {
    if (count < 1 || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    document.body.classList.remove('critical-arrival');
    void document.body.offsetWidth;
    document.body.classList.add('critical-arrival');
    window.setTimeout(() => document.body.classList.remove('critical-arrival'), 1_700);
  }

  function acceptPendingUpdate(resetWindow = false) {
    if (!pendingFeedUpdate || !pendingSnapshot) return;
    const newCount = pendingNewIds.size;
    const newCriticalCount = pendingCriticalIds.size;
    const staged = pendingSnapshot;
    pendingFeedUpdate = false;
    pendingSnapshot = null;
    pendingNewIds.clear();
    pendingCriticalIds.clear();
    $('new-notice').hidden = true;
    manifest = staged.manifest;
    lastSnapshotVersion = manifest.generated_at || lastSnapshotVersion;
    for (const [day, records] of staged.days) loadedByDay.set(day, records);
    const currentDays = new Set(manifest.days.map((day) => day.date));
    for (const day of [...loadedByDay.keys()]) {
      if (!currentDays.has(day)) loadedByDay.delete(day);
    }
    rebuildRecords();
    renderSources();
    setDateBounds();
    if (resetWindow && manifest) {
      state.from = String(manifest.window.start).slice(0, 10);
      state.to = String(manifest.window.end).slice(0, 10);
      state.severity = 'all';
      state.query = '';
      state.sort = 'new';
      state.exactHours = null;
      state.vendor = '';
      state.product = '';
      state.absoluteZero = false;
      state.group = 'none';
      visible = PAGE_SIZE;
      windowStart = 0;
      $('search-input').value = '';
      $('sort-select').value = 'new';
      $('date-from').value = state.from;
      $('date-to').value = state.to;
      document.querySelectorAll('.severity-filter').forEach((element) => {
        const selected = element.dataset.severity === 'all';
        element.classList.toggle('active', selected);
        element.setAttribute('aria-pressed', String(selected));
      });
      document.querySelectorAll('.quick-ranges button').forEach((element) => {
        const selected = element.dataset.days === '30';
        element.classList.toggle('selected', selected);
        element.setAttribute('aria-pressed', String(selected));
      });
      updateControlState();
    }
    render();
    refreshTimestamp();
    setStatus(newCount ? `${newCount} new CVE${newCount === 1 ? '' : 's'} now included in the feed.` : 'Updated feed data is now displayed.', 'success');
    if (newCriticalCount) {
      triggerCriticalAmbient(newCriticalCount);
      toast(`${newCriticalCount} new Critical CVE${newCriticalCount === 1 ? '' : 's'} applied after your confirmation.`);
    }
    void loadFacets();
    void loadRetainedHistory();
    void loadEpssSnapshot(true).then(() => {
      if (booted && manifest) render();
    });
  }

  async function fetchDays(days, version, sourceManifest = manifest, onShardLoaded = null) {
    const uniqueDays = [...new Set(days)].filter((day) => sourceManifest.days.some((item) => item.date === day));
    const entries = [];
    for (let offset = 0; offset < uniqueDays.length; offset += SHARD_CONCURRENCY) {
      const batch = uniqueDays.slice(offset, offset + SHARD_CONCURRENCY);
      const settled = await Promise.allSettled(batch.map(async (day) => {
        const records = await fetchDay(day, version, sourceManifest);
        if (onShardLoaded) await onShardLoaded(day, records);
        return [day, records];
      }));
      const failures = settled.filter((result) => result.status === 'rejected');
      entries.push(...settled.filter((result) => result.status === 'fulfilled').map((result) => result.value));
      if (failures.length) throw failures[0].reason;
    }
    return entries;
  }

  async function loadDays(days, options = {}) {
    const force = options.force === true;
    const sourceManifest = options.sourceManifest || manifest;
    const destination = options.stageTo || loadedByDay;
    const uniqueDays = [...new Set(days)].filter((day) => sourceManifest.days.some((item) => item.date === day));
    const pending = uniqueDays.filter((day) => force || !destination.has(day));
    if (!pending.length) return;
    const entries = await fetchDays(pending, sourceManifest.generated_at, sourceManifest, options.onShardLoaded);
    entries.forEach(([day, records]) => destination.set(day, records));
    if (!options.deferRender) {
      if (destination === loadedByDay) rebuildRecords();
      render();
    }
  }

  function rangeDays() {
    if (!manifest) return [];
    return manifest.days.filter((item) => item.date >= state.from && item.date <= state.to).map((item) => item.date);
  }

  function recordInRange(record) {
    const day = String(record.window_date || '').slice(0, 10);
    if (!day || day < state.from || day > state.to) return false;
    if (state.exactHours === 24) {
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
      const activity = parseTime(record.activity_at) || parseTime(record.published);
      if (activity != null) return activity >= cutoff && activity <= Date.now();
      const added = record.kev && parseTime(record.kev.date_added);
      return added != null && added >= Date.parse(new Date(cutoff).toISOString().slice(0, 10)) && added <= Date.now();
    }
    return true;
  }

  function selectedRecords() {
    const query = state.query.trim().toLocaleLowerCase();
    const matching = [...allRecords.values()].filter((record) => {
      if (!recordInRange(record)) return false;
      const severity = cvssSeverity(record.score);
      if (state.severity !== 'all' && !(state.severity === 'unknown' && ['none', 'unknown'].includes(severity)) && severity !== state.severity) return false;
      if (state.absoluteZero && !(severity === 'critical' && !!record.kev)) return false;
      const affected = record.affected || [];
      if (state.vendor && state.product) {
        if (!affected.some((item) => normalizeFacet(item.vendor) === normalizeFacet(state.vendor) && normalizeFacet(item.product) === normalizeFacet(state.product))) return false;
      } else if (state.vendor && !affected.some((item) => normalizeFacet(item.vendor) === normalizeFacet(state.vendor))) return false;
      else if (state.product && !affected.some((item) => normalizeFacet(item.product) === normalizeFacet(state.product))) return false;
      if (!query) return true;
      const products = affected.map((item) => `${item.vendor || ''} ${item.product || ''} ${item.versions || ''}`).join(' ');
      const searchable = `${record.id || ''} ${record.title || ''} ${record.desc || ''} ${products} ${(record.sources || []).join(' ')}`;
      return searchable.toLocaleLowerCase().includes(query);
    });
    matching.sort((a, b) => {
      const dateDelta = (parseTime(a.activity_at) || parseTime(a.window_date) || parseTime(a.published) || 0) - (parseTime(b.activity_at) || parseTime(b.window_date) || parseTime(b.published) || 0);
      if (state.sort === 'old') return dateDelta || a.id.localeCompare(b.id);
      if (state.sort === 'hot') return (SEVERITY_ORDER[cvssSeverity(a.score)] ?? 4) - (SEVERITY_ORDER[cvssSeverity(b.score)] ?? 4) || -dateDelta;
      if (state.sort === 'priority') return (priorityScore(b).value ?? -1) - (priorityScore(a).value ?? -1) || -dateDelta;
      return -dateDelta || a.id.localeCompare(b.id);
    });
    return matching;
  }

  function summaryForSelection() {
    if (!manifest) return { count: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0, exploited: 0 };
    if (state.exactHours === 24) {
      const items = [...allRecords.values()].filter((record) => recordInRange(record));
      return {
        count: items.length,
        critical: items.filter((item) => cvssSeverity(item.score) === 'critical').length,
        high: items.filter((item) => cvssSeverity(item.score) === 'high').length,
        medium: items.filter((item) => cvssSeverity(item.score) === 'medium').length,
        low: items.filter((item) => cvssSeverity(item.score) === 'low').length,
        none: items.filter((item) => cvssSeverity(item.score) === 'none').length,
        unknown: items.filter((item) => cvssSeverity(item.score) === 'unknown').length,
        exploited: items.filter((item) => !!item.kev).length
      };
    }
    const selected = manifest.days.filter((item) => item.date >= state.from && item.date <= state.to);
    return selected.reduce((result, item) => {
      result.count += item.count || 0;
      result.critical += item.critical || 0;
      result.high += item.high || 0;
      result.medium += item.medium || 0;
      result.low += item.low || 0;
      result.none += item.none || 0;
      result.unknown += item.unknown || 0;
      result.exploited += item.exploited || 0;
      return result;
    }, { count: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, unknown: 0, exploited: 0 });
  }

  function setDateBounds() {
    if (!manifest) return;
    const min = String(manifest.window.start).slice(0, 10);
    const max = String(manifest.window.end).slice(0, 10);
    ['date-from', 'date-to'].forEach((id) => {
      $(id).min = min;
      $(id).max = max;
    });
    if (!state.from || !state.to) {
      state.from = min;
      state.to = max;
      $('date-from').value = min;
      $('date-to').value = max;
    } else {
      if (state.from < min) state.from = min;
      if (state.to > max) state.to = max;
      $('date-from').value = state.from;
      $('date-to').value = state.to;
    }
    $('window-start').textContent = fmtDate(min);
    $('window-end').textContent = fmtDate(max);
  }

  function refreshTimestamp() {
    if (!manifest) return;
    const generated = manifest.last_successful_update || manifest.generated_at;
    const age = parseTime(generated);
    $('snapshot-time').textContent = age == null ? 'Snapshot time unavailable' : `Last successful update · ${fmtTimestamp(generated)}`;
    $('snapshot-meta').textContent = age == null ? 'The feed did not provide a valid timestamp' : `Snapshot ${relativeTime(generated)} · checked ${lastBrowserCheck ? relativeTime(new Date(lastBrowserCheck).toISOString()) : 'just now'}`;
    const indicator = $('feed-indicator');
    const text = $('feed-indicator-text');
    const sourceComplete = manifest.complete === true && manifest.coverage && manifest.coverage.sources_complete === true;
    indicator.classList.toggle('stale', age != null && Date.now() - age > 90 * 60_000);
    indicator.classList.toggle('error', !sourceComplete || age == null);
    text.textContent = !sourceComplete ? 'SOURCE GAP' : age != null && Date.now() - age > 90 * 60_000 ? 'AGING SNAPSHOT' : 'SNAPSHOT READY';
    const generatedLabel = age == null ? 'Snapshot age unknown' : `Snapshot ${relativeTime(generated)} · browser check ${lastBrowserCheck ? relativeTime(new Date(lastBrowserCheck).toISOString()) : 'now'}`;
    const meta = $('snapshot-meta');
    if (meta) meta.textContent = generatedLabel;
    const epssFreshness = $('epss-freshness');
    if (epssFreshness) {
      const scoreDate = manifest.epss?.score_date;
      const scoreTime = manifest.epss?.source_updated_at;
      epssFreshness.textContent = scoreDate ? `DAILY · ${fmtDate(scoreDate)}` : 'No dated score set';
      epssFreshness.title = scoreTime ? `FIRST EPSS source timestamp: ${fmtTimestamp(scoreTime)}` : 'FIRST EPSS source timestamp unavailable';
    }
    if (age != null && Date.now() - age > 90 * 60_000) setStatus('The last successful snapshot is older than 90 minutes. Keeping the last complete data while checks continue.', 'warning');
    else if (!sourceComplete) setStatus('One or more sources did not report complete coverage in this snapshot.', 'warning');
    else if (rangeDays().every((day) => loadedByDay.has(day))) setStatus(`Last complete snapshot ${relativeTime(generated)} · browser checks every 2 minutes.`, 'success');
  }

  function renderSources() {
    if (!manifest) return;
    const list = $('source-list');
    const statuses = new Map((manifest.source_status || []).map((item) => [item.name, item]));
    const sourceDefs = manifest.sources || [];
    const statusAliases = { 'CISA Known Exploited Vulnerabilities catalog': 'CISA KEV' };
    const statusFor = (source) => statuses.get(source.name) || statuses.get(statusAliases[source.name]) || {};
    list.innerHTML = sourceDefs.map((source) => {
      const status = statusFor(source);
      const ok = status.ok === true;
      let facts = '';
      if (source.name === 'NVD CVE API 2.0') facts = `${Number(status.records || 0).toLocaleString()} records · ${Number(status.pages || 0)} pages`;
      else if (source.name === 'GitHub Security Advisory Database') facts = `${Number(status.advisories || 0).toLocaleString()} advisories · ${Number(status.pages || 0)} pages`;
      else if (source.name === 'FIRST EPSS') facts = status.score_date ? `${Number(status.scores || 0).toLocaleString()} scores · dated ${status.score_date}` : 'Daily probability snapshot unavailable';
      else facts = `${Number(status.catalog_records || 0).toLocaleString()} catalog entries`;
      return `<li><i class="source-state-dot${ok ? '' : ' warning'}"></i><span><a href="${esc(safeUrl(source.url))}" target="_blank" rel="noopener noreferrer">${esc(source.name)}</a><span class="source-facts">${esc(ok ? facts : 'Coverage unavailable')}</span></span></li>`;
    }).join('');
    const coreSourceNames = ['NVD CVE API 2.0', 'GitHub Security Advisory Database', 'CISA KEV'];
    const coreSources = coreSourceNames.map((name) => sourceDefs.find((source) => (statusAliases[source.name] || source.name) === name));
    const coreKnown = coreSources.every(Boolean);
    const coreOk = coreKnown && coreSources.every((source) => statusFor(source).ok === true);
    const badge = $('source-state');
    badge.textContent = !coreKnown ? 'CORE STATUS MISSING' : coreOk ? '3 CORE SOURCES OK' : 'CORE COVERAGE GAP';
    badge.className = `source-state${coreOk ? '' : ' warning'}`;
    $('window-caption').textContent = `${Number(manifest.coverage?.utc_days_sharded || 0)} UTC date shards · ${Number(manifest.coverage?.distinct_cve_records || 0).toLocaleString()} deduplicated records · NVD, GitHub and CISA gate coverage; EPSS is optional enrichment.`;
  }

  async function loadFacets() {
    const path = manifest?.facets?.path;
    if (typeof path !== 'string' || !path.startsWith('data/') || path.includes('..')) return;
    try {
      const value = await fetchJson(`${path}?v=${encodeURIComponent(manifest.generated_at || '')}`, { cache: 'default', headers: { Accept: 'application/json' } });
      if (value.schema_version !== 1 || !Array.isArray(value.vendors) || !Array.isArray(value.products)) return;
      facets = {
        vendors: [...new Set(value.vendors.filter((item) => typeof item === 'string' && item.length <= 160))],
        products: [...new Set(value.products.filter((item) => typeof item === 'string' && item.length <= 200))],
        product_pairs: Array.isArray(value.product_pairs) ? value.product_pairs.filter((item) => item && typeof item.vendor === 'string' && typeof item.product === 'string') : []
      };
      for (const [id, values] of [['vendor-suggestions', facets.vendors], ['product-suggestions', facets.products]]) {
        const list = $(id);
        list.replaceChildren(...values.map((value) => {
          const option = document.createElement('option');
          option.value = value;
          return option;
        }));
      }
    } catch (_) {
      // Facets are optional indexes; the feed itself remains usable.
    }
  }

  function canonicalFacet(value, values) {
    const candidate = normalizeFacet(value);
    return values.find((item) => normalizeFacet(item) === candidate) || '';
  }

  function restorePermalink() {
    const params = new URLSearchParams(window.location.search);
    const min = String(manifest?.window?.start || '').slice(0, 10);
    const max = String(manifest?.window?.end || '').slice(0, 10);
    const isDate = (value) => /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
    const from = params.get('from') || '';
    const to = params.get('to') || '';
    if (isDate(from) && isDate(to) && from <= to && from >= min && to <= max) {
      state.from = from;
      state.to = to;
    }
    const severities = ['all', 'critical', 'high', 'medium', 'low', 'unknown'];
    if (severities.includes(params.get('severity'))) state.severity = params.get('severity');
    const sorts = ['new', 'old', 'hot', 'priority'];
    if (sorts.includes(params.get('sort'))) state.sort = params.get('sort');
    state.absoluteZero = params.get('az') === '1';
    if (state.absoluteZero) {
      preAbsoluteSeverity = state.severity;
      state.severity = 'critical';
    }
    if (['none', 'vendor', 'product'].includes(params.get('group'))) state.group = params.get('group');
    state.vendor = canonicalFacet(params.get('vendor') || '', facets.vendors);
    state.product = canonicalFacet(params.get('product') || '', facets.products);
    if (state.vendor && state.product && facets.product_pairs.length && !facets.product_pairs.some((item) => normalizeFacet(item.vendor) === normalizeFacet(state.vendor) && normalizeFacet(item.product) === normalizeFacet(state.product))) state.product = '';
    compactCards = params.get('compact') === '1' || (params.has('compact') ? false : compactCards);
    updateControlState();
  }

  function updateControlState() {
    if ($('date-from') && state.from) $('date-from').value = state.from;
    if ($('date-to') && state.to) $('date-to').value = state.to;
    if ($('search-input')) $('search-input').value = state.query;
    if ($('vendor-filter')) $('vendor-filter').value = state.vendor;
    if ($('product-filter')) $('product-filter').value = state.product;
    if ($('sort-select')) $('sort-select').value = state.sort;
    if ($('group-select')) $('group-select').value = state.group;
    document.querySelectorAll('.severity-filter').forEach((element) => {
      const selected = element.dataset.severity === state.severity;
      element.classList.toggle('active', selected);
      element.setAttribute('aria-pressed', String(selected));
    });
    if ($('absolute-zero')) $('absolute-zero').setAttribute('aria-pressed', String(state.absoluteZero));
    if ($('compact-toggle')) $('compact-toggle').setAttribute('aria-pressed', String(compactCards));
    document.body.classList.toggle('compact-cards', compactCards);
  }

  function renderSavedViews() {
    if (!Array.isArray(savedViews)) savedViews = [];
    const select = $('saved-view-select');
    const selected = select.value;
    select.replaceChildren(new Option('No saved view selected', ''));
    savedViews.forEach((view, index) => select.add(new Option(String(view.name || `View ${index + 1}`), String(view.id || index))));
    select.value = [...select.options].some((option) => option.value === selected) ? selected : '';
    $('apply-view').disabled = !select.value;
    $('delete-view').disabled = !select.value;
  }

  function currentView(name) {
    return {
      id: `view-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      name,
      from: state.from,
      to: state.to,
      severity: state.severity,
      query: state.query,
      sort: state.sort,
      vendor: state.vendor,
      product: state.product,
      absoluteZero: state.absoluteZero,
      group: state.group,
      compact: compactCards,
      preAbsoluteSeverity
    };
  }

  function saveCurrentView() {
    const name = $('saved-view-name').value.trim().slice(0, 40);
    if (!name) {
      $('saved-view-name').focus();
      setToolStatus('Enter a name for this saved view.');
      return;
    }
    savedViews = Array.isArray(savedViews) ? savedViews : [];
    const existing = savedViews.findIndex((view) => String(view.name || '').toLocaleLowerCase() === name.toLocaleLowerCase());
    const view = currentView(name);
    if (existing >= 0) savedViews.splice(existing, 1);
    savedViews.unshift(view);
    savedViews = savedViews.slice(0, 20);
    writeStored('subzero:views', savedViews);
    renderSavedViews();
    $('saved-view-select').value = view.id;
    renderSavedViews();
    $('saved-view-name').value = '';
    setToolStatus(`Saved “${name}” on this browser.`);
  }

  function selectedSavedView() {
    return savedViews.find((view, index) => String(view.id || index) === $('saved-view-select').value);
  }

  function applySelectedView() {
    const view = selectedSavedView();
    if (!view) return;
    state = { ...state, ...view, exactHours: null };
    state.query = String(view.query || '').slice(0, 200);
    compactCards = view.compact === true;
    preAbsoluteSeverity = ['all', 'critical', 'high', 'medium', 'low', 'unknown'].includes(view.preAbsoluteSeverity) ? view.preAbsoluteSeverity : 'all';
    updateControlState();
    visible = PAGE_SIZE;
    windowStart = 0;
    setRange(state.from, state.to);
    setToolStatus(`Applied “${view.name}”.`);
  }

  function deleteSelectedView() {
    const view = selectedSavedView();
    if (!view) return;
    savedViews = savedViews.filter((item) => item !== view);
    writeStored('subzero:views', savedViews);
    renderSavedViews();
    setToolStatus(`Deleted “${view.name}” from this browser.`);
  }

  function setToolStatus(message) {
    const status = $('tool-status');
    if (status) status.textContent = message;
  }

  function watchPair(vendor, product) {
    const cleanVendor = String(vendor || '').trim().slice(0, 160);
    const cleanProduct = String(product || '').trim().slice(0, 200);
    if (!cleanVendor || !cleanProduct) return;
    const existing = Array.isArray(watchlist) ? watchlist : [];
    const index = existing.findIndex((item) => normalizeFacet(item.vendor) === normalizeFacet(cleanVendor) && normalizeFacet(item.product) === normalizeFacet(cleanProduct));
    if (index >= 0) existing.splice(index, 1);
    else existing.unshift({ vendor: cleanVendor, product: cleanProduct });
    watchlist = existing.slice(0, 200);
    writeStored('subzero:watchlist', watchlist);
    renderWatchlist();
    setToolStatus(index >= 0 ? 'Removed from the local watchlist.' : 'Added to the local watchlist.');
  }

  function renderWatchlist() {
    const list = $('watchlist-list');
    if (!list) return;
    watchlist = Array.isArray(watchlist) ? watchlist.filter((item) => item && item.vendor && item.product) : [];
    $('watchlist-empty').hidden = watchlist.length > 0;
    list.innerHTML = watchlist.map((item, index) => `<li><button type="button" class="watch-filter" data-action="watch-filter" data-index="${index}">${esc(item.vendor)} / ${esc(item.product)}</button><button type="button" class="watch-remove" data-action="watch-remove" data-index="${index}" aria-label="Remove ${esc(item.vendor)} ${esc(item.product)} from local watchlist">×</button></li>`).join('');
  }

  function buildPermalink() {
    const url = new URL(window.location.href);
    url.search = '';
    url.hash = '';
    const params = new URLSearchParams();
    if (state.from && state.to) { params.set('from', state.from); params.set('to', state.to); }
    if (state.severity !== 'all') params.set('severity', state.severity);
    if (state.sort !== 'new') params.set('sort', state.sort);
    if (state.absoluteZero) params.set('az', '1');
    if (state.group !== 'none') params.set('group', state.group);
    if (state.vendor && canonicalFacet(state.vendor, facets.vendors)) params.set('vendor', canonicalFacet(state.vendor, facets.vendors));
    if (state.product && canonicalFacet(state.product, facets.products)) params.set('product', canonicalFacet(state.product, facets.products));
    if (compactCards) params.set('compact', '1');
    url.search = params.toString();
    return url.toString();
  }

  async function copyPermalink() {
    const link = buildPermalink();
    try {
      await copyText(link);
      setToolStatus('Share link copied. The free-text search is not included.');
      toast('Share link copied.');
    } catch (_) {
      setToolStatus(link);
      toast('Clipboard blocked; the share link is shown in the tool status.', 'warning');
    }
  }

  async function loadRetainedHistory() {
    const path = manifest?.history?.path;
    if (typeof path !== 'string' || !path.startsWith('data/') || path.includes('..')) {
      renderHistory();
      return;
    }
    try {
      const value = await fetchJson(`${path}?v=${encodeURIComponent(manifest.generated_at || '')}`, { cache: 'default', headers: { Accept: 'application/json' } });
      if (value.schema_version !== 1 || !Array.isArray(value.events) || !Array.isArray(value.snapshots)) throw new Error('Unsupported retained history');
      retainedHistory = value;
    } catch (_) {
      retainedHistory = null;
    }
    renderHistory();
  }

  function renderHistory() {
    const badge = $('changes-coverage');
    const caption = $('changes-caption');
    const list = $('recent-changes-list');
    if (!badge || !caption || !list) return;
    if (!retainedHistory) {
      badge.textContent = 'NOT AVAILABLE';
      badge.classList.add('warning');
      caption.textContent = 'No retained comparison file is available; no change or trend is inferred.';
      list.innerHTML = '<li>Historical comparison unavailable.</li>';
      return;
    }
    const snapshots = retainedHistory.snapshots.filter((item) => item && parseTime(item.observed_at));
    const orderedSnapshots = snapshots.slice().sort((a, b) => parseTime(a.observed_at) - parseTime(b.observed_at));
    const coverage = orderedSnapshots.length
      ? `${orderedSnapshots.length} complete snapshots from ${fmtTimestamp(orderedSnapshots[0].observed_at)} to ${fmtTimestamp(orderedSnapshots[orderedSnapshots.length - 1].observed_at)}; up to ${Number(retainedHistory.retention_days) || 30} days are retained.`
      : 'No complete snapshots are retained yet.';
    const cutoff = Date.now() - 48 * 60 * 60_000;
    const events = retainedHistory.events.filter((item) => item && parseTime(item.observed_at) >= cutoff).sort((a, b) => parseTime(b.observed_at) - parseTime(a.observed_at));
    badge.textContent = `${snapshots.length} SNAPSHOTS`;
    badge.classList.remove('warning');
    caption.textContent = events.length
      ? `${coverage} ${events.length.toLocaleString()} measured CVE change${events.length === 1 ? '' : 's'} in the last 48 hours of retained comparisons.`
      : `${coverage} No material changes detected in the available 48-hour comparisons. This is not an attention or popularity measure.`;
    const labels = { severity: 'CVSS severity changed', kev_added: 'Entered CISA KEV', kev_removed: 'Removed from CISA KEV', epss_jump: 'Material EPSS change' };
    list.innerHTML = events.slice(0, 6).map((item) => {
      const id = cveId(item.id);
      if (!id) return '';
      let detail = '';
      if (item.type === 'severity') detail = `${String(item.from || 'UNRATED').toUpperCase()} → ${String(item.to || 'UNRATED').toUpperCase()}`;
      else if (item.type === 'epss_jump') detail = `${Number(item.from).toFixed(3)} → ${Number(item.to).toFixed(3)}`;
      else detail = fmtTimestamp(item.observed_at);
      return `<li><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a><span><strong>${esc(labels[item.type] || 'Source change')}</strong><small>${esc(detail)} · ${esc(relativeTime(item.observed_at))}</small></span></li>`;
    }).join('') || '<li>No material changes recorded in the retained window.</li>';
  }

  function renderStats({ countUp = false } = {}) {
    if (!manifest) return;
    const summary = summaryForSelection();
    const counts = [
      ['stat-total', summary.count],
      ['stat-critical', summary.critical],
      ['stat-high', summary.high],
      ['stat-kev', summary.exploited]
    ];
    const targetKey = counts.map(([, value]) => Number(value || 0)).join(':');
    const animate = countUp && !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const currentAnimationStillMatches = !countUp && statAnimationFrames.size && statAnimationKey === targetKey;
    if (!currentAnimationStillMatches) {
      statAnimationFrames.forEach((frame) => window.cancelAnimationFrame(frame));
      statAnimationFrames.clear();
      if (animate) {
        statAnimationKey = targetKey;
        counts.forEach(([id, value]) => animateCountUp($(id), Number(value || 0)));
      } else {
        statAnimationKey = '';
        counts.forEach(([id, value]) => { $(id).textContent = Number(value || 0).toLocaleString(); });
      }
    }
    $('stat-window-label').textContent = state.exactHours === 24 ? '/ LAST 24 HOURS' : ` / ${state.from === String(manifest.window.start).slice(0, 10) && state.to === String(manifest.window.end).slice(0, 10) ? '30 DAY WINDOW' : 'UTC DATE WINDOW'}`;
    const known = summary.critical + summary.high + summary.medium + summary.low + summary.none + summary.unknown;
    const pct = (value) => known ? `${Math.max(value > 0 ? 1.2 : 0, value / known * 100)}%` : '0%';
    $('meter-critical').style.width = pct(summary.critical);
    $('meter-high').style.width = pct(summary.high);
    $('meter-medium').style.width = pct(summary.medium);
    $('meter-low').style.width = pct(summary.low);
    $('meter-neutral').style.width = pct(summary.none + summary.unknown);
  }

  function animateCountUp(element, target) {
    const duration = 620;
    const startedAt = performance.now();
    element.textContent = '0';
    const step = (now) => {
      const progress = Math.max(0, Math.min(1, (now - startedAt) / duration));
      const eased = 1 - Math.pow(1 - progress, 3);
      element.textContent = Math.round(target * eased).toLocaleString();
      if (progress < 1) statAnimationFrames.set(element, window.requestAnimationFrame(step));
      else {
        statAnimationFrames.delete(element);
        if (!statAnimationFrames.size) statAnimationKey = '';
      }
    };
    statAnimationFrames.set(element, window.requestAnimationFrame(step));
  }

  function cardProduct(item) {
    const name = [item.vendor, item.product].filter(Boolean).join(' / ') || item.product || item.vendor || 'Product details';
    return `<span class="product-chip"><strong>${esc(name)}</strong>${item.versions ? ` · ${esc(item.versions)}` : ''}</span>`;
  }

  function cardAgeVividness(record) {
    const timestamp = parseTime(record.activity_at) || parseTime(record.window_date) || parseTime(record.published);
    if (timestamp == null) return null;
    const ageDays = Math.max(0, Math.min(30, (Date.now() - timestamp) / 86_400_000));
    return Math.round(100 - (ageDays / 30) * 68);
  }

  function cardHtml(record) {
    const id = cveId(record.id);
    if (!id) return '';
    const scoreValue = record.score == null || !Number.isFinite(Number(record.score)) ? null : Number(record.score);
    const severity = cvssSeverity(scoreValue);
    const ageVividness = cardAgeVividness(record);
    const ageStyle = ageVividness == null ? '' : ` style="--age-vividness:${ageVividness}%"`;
    const primary = safeUrl(record.primary_url) || `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
    const products = (record.affected || []).slice(0, 2).map(cardProduct).join('');
    const sources = (record.sources || []).map(sourceName).join(' · ') || 'CVE record';
    const activity = record.date_basis === 'CISA KEV date added'
      ? `KEV ADDED ${fmtDate(record.kev?.date_added || record.window_date)}`
      : record.date_basis === 'GitHub advisory publication'
        ? `ADVISORY ${fmtDate(record.window_date)}`
        : `PUBLISHED ${fmtDate(record.published || record.window_date)}`;
    const score = scoreValue == null ? '—' : scoreValue.toFixed(1);
    const epss = epssFor(id);
    const priority = priorityScore(record, id);
    const priorityHtml = priority.value == null
      ? `<div class="priority-chip unavailable" title="At least 3 of 5 sourced inputs are required; missing: ${esc(priority.missing.join(', '))}"><strong>COMPOSITE PRIORITY</strong><span>Not enough inputs</span><small>Custom · ${priority.available}/5</small></div>`
      : `<div class="priority-chip" title="Custom SubZer0 triage heuristic; not an official score. Available inputs: ${esc(priority.components.map((item) => `${item.key} ${item.value.toFixed(1)}`).join(' · '))}"><strong>COMPOSITE PRIORITY</strong><span>${priority.value.toFixed(1)} <small>/ 100</small></span><small>Custom · ${priority.available}/5 inputs</small></div>`;
    const epssHtml = epss
      ? `<span class="epss-chip" title="FIRST EPSS estimated probability for observed exploitation in the next 30 days"><i class="epss-dot"></i><strong>EPSS</strong><b>${esc(epssPercent(epss))}</b><small>30D PROBABILITY</small></span>`
      : '<span class="epss-chip unavailable" title="No EPSS score is present; this is not a zero probability"><i class="epss-dot"></i><strong>EPSS</strong><b>—</b><small>NOT AVAILABLE</small></span>';
    const severityLabel = severity === 'unknown' ? 'UNRATED' : severity.toUpperCase();
    const share = telegramShareUrl(record, id);
    const starred = starredIds.has(id);
    const isRead = readIds.has(id);
    return `<article class="cve-card severity-${severity}${record.kev ? ' kev-listed' : ''}${isRead ? ' is-read' : ''}" data-cve-id="${esc(id)}" tabindex="-1"${ageStyle}>
      <div class="card-head"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>
        <span class="severity-badge ${esc(severity)}">${esc(severityLabel)}</span>${record.kev ? '<span class="kev-badge" title="Listed in the CISA Known Exploited Vulnerabilities catalog">CISA KEV · LISTED</span>' : ''}
        <span class="cvss-score"><span>${esc(score)}</span><small>CVSS · SEVERITY</small></span></div>
      ${epssHtml}
      ${priorityHtml}
      <h3 class="card-title">${esc(record.title || id)}</h3>
      <p class="card-description">${esc(record.desc || 'No source summary is available yet. Review the linked primary records and advisories.')}</p>
      ${products ? `<div class="affected-preview" aria-label="Affected products">${products}</div>` : ''}
      <div class="card-meta"><span class="meta-date">${esc(activity)}</span><i class="meta-divider"></i><span>${record.affected?.length ? `${record.affected.length} affected product${record.affected.length === 1 ? '' : 's'}` : 'Product details not provided'}</span><i class="meta-divider"></i><span class="source-label">${esc(sources)}</span></div>
      <div class="card-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy ID</button><button class="card-action" type="button" data-action="detail" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⌕</span> Details</button><button class="card-action local-toggle${starred ? ' selected' : ''}" type="button" data-action="star" data-id="${esc(id)}" aria-pressed="${starred}" aria-label="${starred ? 'Remove star from' : 'Star'} ${esc(id)}">${starred ? '★ Starred' : '☆ Star'}</button><button class="card-action local-toggle" type="button" data-action="read" data-id="${esc(id)}" aria-pressed="${isRead}" aria-label="Mark ${esc(id)} as ${isRead ? 'unread' : 'read'}">${isRead ? 'Mark unread' : 'Mark read'}</button><a class="card-action telegram-share" href="${esc(share)}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">➤</span> Share to Telegram</a><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> GitHub repository search <small>UNVERIFIED LEADS</small></a></div>
    </article>`;
  }

  function groupValue(record, key) {
    const affected = (record.affected || []).filter((item) => String(item[key] || '').trim());
    affected.sort((a, b) => {
      const rank = { NVD: 0, 'GitHub Advisory Database': 1, 'CISA KEV': 2 };
      return (rank[a.source] ?? 9) - (rank[b.source] ?? 9) || String(a.vendor || '').localeCompare(String(b.vendor || '')) || String(a.product || '').localeCompare(String(b.product || ''));
    });
    const item = affected[0];
    if (!item) return key === 'vendor' ? 'Vendor not specified' : 'Product not specified';
    return key === 'vendor' ? item.vendor : `${item.product} · ${item.vendor || 'Vendor not specified'}`;
  }

  function renderGroupedCards(records) {
    if (state.group === 'none') return records.map(cardHtml).join('');
    const key = state.group === 'vendor' ? 'vendor' : 'product';
    const groups = new Map();
    records.forEach((record) => {
      const label = groupValue(record, key);
      if (!groups.has(label)) groups.set(label, []);
      groups.get(label).push(record);
    });
    return [...groups].map(([label, items]) => `<section class="feed-group"><h3>${esc(state.group === 'vendor' ? 'Vendor' : 'Product')} · ${esc(label)} <small>${items.length} CVE${items.length === 1 ? '' : 's'}</small></h3>${items.map(cardHtml).join('')}</section>`).join('');
  }

  function render({ animateCards = false, animateStats = false } = {}) {
    if (!manifest) return;
    renderStats({ countUp: animateStats });
    const matches = selectedRecords();
    const completeRange = rangeDays().every((day) => loadedByDay.has(day));
    const isSearching = state.query.trim().length > 0;
    const needsCompleteRange = isSearching || !!state.vendor || !!state.product || state.absoluteZero || state.sort !== 'new';
    let total;
    if (needsCompleteRange || state.exactHours === 24) total = matches.length;
    else if (state.severity === 'all') total = summaryForSelection().count;
    else total = manifest.days.filter((item) => item.date >= state.from && item.date <= state.to).reduce((sum, item) => sum + (state.severity === 'unknown' ? Number(item.none || 0) + Number(item.unknown || 0) : Number(item[state.severity] || 0)), 0);
    const renderCount = Math.min(visible, MAX_DOM_RECORDS);
    const pageRecords = matches.slice(windowStart, windowStart + renderCount);
    const countLabel = needsCompleteRange && !completeRange
      ? `Showing ${pageRecords.length.toLocaleString()} loaded · scanning selected dates`
      : total > windowStart + renderCount ? `Showing ${Math.min(renderCount, matches.length).toLocaleString()} of ${total.toLocaleString()}` : `${total.toLocaleString()} records`;
    $('feed-count').textContent = needsCompleteRange && !completeRange ? '…' : total.toLocaleString();
    $('feed-list').innerHTML = renderGroupedCards(pageRecords);
    $('feed-list').setAttribute('aria-busy', 'false');
    if (animateCards && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      feedList.querySelectorAll('.cve-card').forEach((card) => {
        card.classList.add('filter-arrive');
        card.addEventListener('animationend', () => card.classList.remove('filter-arrive'), { once: true });
      });
    }
    const noLoadedRecords = matches.length === 0;
    const couldLoadMore = !completeRange && !needsCompleteRange;
    $('empty-state').hidden = !(noLoadedRecords && completeRange);
    const button = $('load-more');
    const hasNextCards = matches.length > windowStart + renderCount;
    button.hidden = !(hasNextCards || couldLoadMore);
    button.disabled = false;
    if (hasNextCards && visible >= MAX_DOM_RECORDS) {
      button.innerHTML = `<span>SHOW NEXT 24</span><small>DOM capped at ${MAX_DOM_RECORDS}; use filters or export for the full range</small><b aria-hidden="true">↓</b>`;
    } else if (hasNextCards) {
      button.innerHTML = `<span>LOAD MORE</span><small>${countLabel}</small><b aria-hidden="true">↓</b>`;
    } else if (couldLoadMore) {
      button.innerHTML = `<span>LOAD OLDER CVEs</span><small>${loadedByDay.size} of ${rangeDays().length} date shards loaded</small><b aria-hidden="true">↓</b>`;
    }
    if (needsCompleteRange && completeRange) setStatus(`Filters cover all ${rangeDays().length} selected UTC date shards.`, 'success');
    else if (needsCompleteRange && !completeRange) setStatus(`Loading all ${rangeDays().length} selected date shards to complete these filters…`);
    else if (!state.query && !completeRange && noLoadedRecords) setStatus('Loading records for this date range…');
    else if (!state.query && !completeRange && matches.length) setStatus(`Showing recent records first · ${loadedByDay.size} of ${rangeDays().length} date shards loaded.`);
    else if (!state.query && !completeRange) setStatus('All selected dates loaded.');
    $('coverage-note').textContent = state.exactHours === 24 ? 'Last 24 hours · UTC · CISA date-added is date-granular' : `${state.from} → ${state.to} UTC · NVD + GitHub advisories + CISA KEV`;
  }

  function setRange(from, to, exactHours = null) {
    if (!manifest) return;
    const min = String(manifest.window.start).slice(0, 10);
    const max = String(manifest.window.end).slice(0, 10);
    if (!from || !to || from > to || from < min || to > max) {
      toast('Choose a UTC date range inside the available 30-day window.', 'warning');
      return;
    }
    state.from = from;
    state.to = to;
    state.exactHours = exactHours;
    searchGeneration += 1;
    const rangeGeneration = searchGeneration;
    visible = PAGE_SIZE;
    windowStart = 0;
    $('date-from').value = from;
    $('date-to').value = to;
    document.querySelectorAll('.quick-ranges button').forEach((button) => {
      const selected = button.dataset.days === (exactHours === 24 ? '1' : '');
      button.classList.toggle('selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
    render({ animateCards: true });
    const days = rangeDays().slice(-2).reverse();
    if (state.query || state.vendor || state.product || state.absoluteZero || state.sort !== 'new') loadAllSelectedDays(rangeGeneration).catch(showLoadError);
    else loadDays(days).then(() => render()).catch(showLoadError);
  }

  async function loadAllSelectedDays(generation) {
    const days = rangeDays().reverse();
    const missing = days.filter((day) => !loadedByDay.has(day));
    if (!missing.length) return;
    setStatus(`Searching all ${days.length} date shards…`);
    for (let i = 0; i < missing.length; i += SHARD_CONCURRENCY) {
      if (generation !== searchGeneration) return;
      await loadDays(missing.slice(i, i + SHARD_CONCURRENCY));
    }
    if (generation === searchGeneration) {
      render();
      const purpose = state.query ? 'Search covers' : state.vendor || state.product ? 'Exact vendor/product filters cover' : state.absoluteZero ? 'Absolute Zero mode covers' : 'Selected view covers';
      setStatus(`${purpose} all ${days.length} selected UTC date shards.`, 'success');
    }
  }

  function showLoadError(error) {
    setStatus(`Some feed data could not be loaded: ${error.message || 'network error'}. Retry with “Load older CVEs”.`, 'error');
  }

  function appendLoadingSkeletons(count) {
    feedList.setAttribute('aria-busy', 'true');
    feedList.insertAdjacentHTML('beforeend', Array.from({ length: count }, () => '<div class="skeleton loading-skeleton" aria-hidden="true"></div>').join(''));
  }

  async function loadEpssSnapshot(force = false) {
    const config = manifest?.epss;
    if (!config?.path || typeof config.path !== 'string' || !config.path.startsWith('data/') || config.path.includes('..')) {
      epssSnapshot = null;
      epssVersion = '';
      return;
    }
    const version = String(config.updated_at || config.score_date || manifest.generated_at || '');
    if (!force && version && version === epssVersion) return;
    try {
      const value = await fetchJson(`${config.path}?v=${encodeURIComponent(version)}`, { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (value.schema_version !== 1 || !value.scores || typeof value.scores !== 'object' || Array.isArray(value.scores)) throw new Error('EPSS snapshot has an unsupported schema');
      epssSnapshot = value;
      epssVersion = version;
    } catch (_) {
      // Keep the last usable optional score set; missing data is not zero.
    }
  }

  async function refresh(options = {}) {
    if (polling || (document.hidden && !options.force)) return;
    polling = true;
    const button = $('refresh-button');
    if (options.force) {
      button.disabled = true;
      button.classList.add('is-checking');
      button.setAttribute('aria-busy', 'true');
    }
    const priorPending = pendingSnapshot;
    const previousManifest = priorPending?.manifest || manifest;
    const previousVersion = lastSnapshotVersion;
    const previousDataByDay = new Map(loadedByDay);
    if (priorPending) {
      for (const [day, records] of priorPending.days) previousDataByDay.set(day, records);
    }
    const previousLoadedDays = new Set(previousDataByDay.keys());
    try {
      const next = await fetchManifest();
      const nextVersion = next.generated_at || '';
      const changed = !!previousVersion && nextVersion !== previousVersion;
      let changedDataDays = [];
      let refreshDays = [];
      let newIds = [];
      let uncertainChangedDays = [];
      const stagedDays = new Map(priorPending?.days || []);

      if (changed) {
        const oldSummaries = new Map((previousManifest?.days || []).map((item) => [item.date, item]));
        const summaryChanged = (oldItem, newItem) => {
          if (!oldItem) return Number(newItem.count || 0) > 0;
          if (oldItem.sha256 && newItem.sha256) return oldItem.sha256 !== newItem.sha256;
          return ['count', 'critical', 'high', 'medium', 'low', 'none', 'unknown', 'exploited']
            .some((key) => Number(oldItem[key] || 0) !== Number(newItem[key] || 0));
        };
        changedDataDays = next.days.filter((item) => summaryChanged(oldSummaries.get(item.date), item)).map((item) => item.date);
        const currentDays = new Set(next.days.map((item) => item.date));
        const unversionedLoadedDays = [...previousLoadedDays].filter((day) => {
          const oldItem = oldSummaries.get(day);
          const newItem = next.days.find((item) => item.date === day);
          return newItem && (!oldItem?.sha256 || !newItem.sha256);
        });
        const recentDays = next.days.slice(-2).map((item) => item.date);
        refreshDays = [...new Set([...changedDataDays, ...unversionedLoadedDays, ...recentDays])]
          .filter((day) => currentDays.has(day));
        setStatus('A newer feed snapshot is available. Checking changed date shards…');
        await loadDays(refreshDays, { force: true, deferRender: true, sourceManifest: next, stageTo: stagedDays });

        const detected = new Set();
        for (const day of refreshDays) {
          const oldSummary = oldSummaries.get(day);
          const oldRecords = previousDataByDay.get(day) || [];
          const newRecords = stagedDays.get(day) || [];
          if (previousLoadedDays.has(day) || !oldSummary || Number(oldSummary.count || 0) === 0) {
            const oldIds = new Set(oldRecords.map((item) => cveId(item.id)));
            for (const record of newRecords) {
              const id = cveId(record.id);
              if (id && !oldIds.has(id)) {
                detected.add(id);
                if (cvssSeverity(record.score) === 'critical') pendingCriticalIds.add(id);
              }
            }
          } else if (changedDataDays.includes(day)) {
            uncertainChangedDays.push(day);
          }
        }
        newIds = [...detected];
      }

      const contentChanged = changed && (changedDataDays.length > 0 || uncertainChangedDays.length > 0 || newIds.length > 0);
      if (priorPending || contentChanged) {
        pendingSnapshot = { manifest: next, days: stagedDays };
        pendingFeedUpdate = true;
        newIds.forEach((id) => pendingNewIds.add(id));
        const count = pendingNewIds.size;
        const changedShards = Math.max(changedDataDays.length, uncertainChangedDays.length);
        const message = count
          ? `${count} new CVE${count === 1 ? '' : 's'} detected. Your current results stay in place until you select View updates.`
          : `Feed data changed in ${changedShards} date shard${changedShards === 1 ? '' : 's'}. Your current results stay in place until you select View updates.`;
        showUpdateNotice(message);
        if (contentChanged) {
          toast(count
            ? `${count} new CVE${count === 1 ? '' : 's'} ready. Current results remain unchanged until you apply updates.`
            : 'Feed data changed. Current results remain unchanged; select View updates to apply it.');
        }
      } else {
        manifest = next;
        setDateBounds();
        renderSources();
        void loadEpssSnapshot().then(() => {
          if (booted && manifest) render();
        });
      }

      lastSnapshotVersion = nextVersion;
      lastBrowserCheck = Date.now();
      if (pendingFeedUpdate) {
        refreshTimestamp();
        setStatus('A newer feed snapshot is ready. Current results remain unchanged until you select View updates.', 'warning');
      } else {
        render();
        refreshTimestamp();
      }
    } catch (error) {
      lastBrowserCheck = Date.now();
      $('feed-indicator').classList.add('error');
      $('feed-indicator-text').textContent = 'CHECK FAILED';
      setStatus(`Could not verify a fresh snapshot: ${error.message || 'network error'}. The last loaded records remain available.`, 'error');
      if (options.force) toast('Feed check failed. Retrying automatically.', 'warning');
    } finally {
      polling = false;
      button.disabled = false;
      button.classList.remove('is-checking');
      button.removeAttribute('aria-busy');
    }
  }

  function renderDetail(id) {
    const record = allRecords.get(id);
    if (!record) {
      toast('Load this date range before opening the full record.', 'warning');
      return;
    }
    const dialog = $('detail-dialog');
    const severity = cvssSeverity(record.score);
    const primary = safeUrl(record.primary_url) || `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
    const score = severity === 'unknown' ? 'CVSS score not provided by the available sources' : `CVSS ${Number(record.score).toFixed(1)} · ${severity.toUpperCase()} severity`;
    const activity = record.date_basis === 'CISA KEV date added'
      ? `CISA added this record to KEV on ${fmtDate(record.kev?.date_added || record.window_date)}.`
      : record.date_basis === 'GitHub advisory publication'
        ? `GitHub advisory published ${fmtDate(record.window_date)}${record.published ? ` · CVE publication ${fmtTimestamp(record.published)}` : ''}.`
        : `Published ${fmtTimestamp(record.published)}${record.modified ? ` · last modified ${fmtTimestamp(record.modified)}` : ''}.`;
    const products = (record.affected || []).length ? (record.affected || []).map((item) => {
      const vendor = String(item.vendor || '').trim();
      const product = String(item.product || '').trim();
      const pairWatched = watchlist.some((entry) => normalizeFacet(entry.vendor) === normalizeFacet(vendor) && normalizeFacet(entry.product) === normalizeFacet(product));
      const cpe = item.source === 'NVD' && /^cpe:2\.3:/i.test(String(item.cpe || '')) ? `<code class="cpe-value">${esc(item.cpe)}</code>` : '';
      const watch = vendor && product ? `<button class="watch-product-button" type="button" data-action="watch-product" data-vendor="${esc(vendor)}" data-product="${esc(product)}" aria-pressed="${pairWatched}">${pairWatched ? 'Remove from local watchlist' : 'Watch vendor / product'}</button>` : '';
      return `<div class="detail-product"><strong>${esc([vendor, product].filter(Boolean).join(' / ') || 'Product')}</strong><span>${esc(item.versions || 'Version details not specified')} · ${esc(item.source || 'Source record')}</span>${cpe}${watch}</div>`;
    }).join('') : '<p class="detail-description">Affected product/version details were not provided in the available records.</p>';
    const epss = epssFor(id);
    const percentile = epss?.percentile == null ? '' : ` · P${Math.round(epss.percentile * 100)} relative percentile rank`;
    const epssDetail = epss
      ? `${epssPercent(epss)} estimated chance that exploitation activity will be observed in the next 30 days${percentile}. Score set dated ${fmtDate(epssSnapshot?.score_date || manifest.epss?.score_date)}.`
      : 'No EPSS score is available in this snapshot. Missing data is not a 0% forecast.';
    const kevDetail = record.kev
      ? `Listed in CISA KEV · added ${fmtDate(record.kev.date_added || record.window_date)}. ${record.kev.required_action || 'CISA identifies this as a known exploited vulnerability.'}${record.kev.due_date ? ` Due date: ${record.kev.due_date}.` : ''}${record.kev.ransomware && record.kev.ransomware.toLowerCase() !== 'unknown' ? ` Ransomware campaign use: ${record.kev.ransomware}.` : ''}`
      : 'Not listed in the current CISA KEV snapshot. Absence from this catalog is not proof that exploitation has never occurred.';
    const poc = `GitHub repository search matches are unverified leads and do not prove a working exploit or exploitation.`;
    const signalCards = `<section class="detail-section"><h3>Why it matters</h3><div class="signal-grid"><article class="signal-card signal-cvss severity-${esc(severity)}"><strong>CVSS / SEVERITY</strong><span>${esc(severity === 'unknown' ? 'UNRATED' : severity === 'none' ? '0.0 · NONE' : `${Number(record.score).toFixed(1)} · ${severity.toUpperCase()}`)}</span><small>Severity only; this is not an exploitation probability.</small></article><article class="signal-card signal-epss"><strong>EPSS / 30-DAY PROBABILITY</strong><span>${esc(epss ? epssPercent(epss) : 'Not available')}</span><small>${esc(epssDetail)}</small></article><article class="signal-card signal-kev"><strong>CISA KEV / CATALOG EVIDENCE</strong><span>${record.kev ? 'LISTED' : 'NOT LISTED'}</span><small>${esc(kevDetail)}</small></article><article class="signal-card signal-poc"><strong>GITHUB PoC / SEARCH LEAD</strong><span>UNVERIFIED</span><small>${esc(poc)}</small></article></div></section>`;
    const priority = priorityScore(record, id);
    const priorityDetail = `<section class="detail-section"><h3>Composite priority · custom 0–100</h3><p class="detail-description">${priority.value == null ? 'Not calculated: fewer than 3 of 5 inputs are available.' : `${priority.value.toFixed(1)} · ${priority.available}/5 inputs available. Available component weights are renormalized; this is a triage heuristic, not an official score.`}</p><div class="priority-breakdown">${priority.components.map((item) => `<div><strong>${esc(item.key)} · ${item.weight}%</strong><span>${item.value.toFixed(1)} / 100</span><small>${esc(item.note)}</small></div>`).join('')}${priority.missing.map((item) => `<div class="missing-component"><strong>${esc(item)} · not available</strong><span>Weight omitted</span><small>Missing data is uncertainty, not a zero.</small></div>`).join('')}</div><a class="method-link" href="#methodology" data-action="close-methodology">Scoring formula and limitations</a></section>`;
    const kev = record.kev ? `<section class="detail-section"><h3>CISA KEV catalog detail</h3><div class="kev-callout"><strong>Known exploited vulnerability listing</strong><p>${esc(kevDetail)}</p></div></section>` : '';
    const refs = [...(record.advisories || []).map((item) => ({ label: item.label || 'Security advisory', url: item.url })), ...(record.refs || [])]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index).slice(0, 14);
    const links = [{ label: record.sources?.includes('NVD') ? 'Primary record · NVD' : 'CVE Program record', url: primary }, { label: 'FIRST EPSS data and method', url: 'https://www.first.org/epss/data' }, ...refs.map((item) => ({ ...item, label: item.source === 'NVD' && item.tags?.some((tag) => String(tag).toLowerCase() === 'exploit') ? `NVD-tagged Exploit reference · unverified · ${item.label || 'Reference'}` : item.label }))]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index);
    const linkedFromNormalizedData = (record.related_cves || []).filter((item) => {
      if (item.source !== 'NVD reference') return false;
      const idValue = cveId(item.id);
      try {
        const url = new URL(item.url);
        const nvdId = url.hostname === 'nvd.nist.gov' ? url.pathname.match(/^\/vuln\/detail\/(CVE-\d{4,}-\d+)$/i)?.[1] : null;
        const cveOrgId = (url.hostname === 'www.cve.org' || url.hostname === 'cve.org') && url.pathname.replace(/\/$/, '') === '/CVERecord' ? cveId(url.searchParams.get('id')) : null;
        return !!idValue && idValue === cveId(nvdId || cveOrgId);
      } catch (_) { return false; }
    }).map((item) => item.id);
    const linkedFromLegacyReferences = (record.refs || []).filter((item) => item.source === 'NVD').flatMap((item) => {
      try {
        const url = new URL(item.url);
        const pathId = url.hostname === 'nvd.nist.gov' ? url.pathname.match(/\/vuln\/detail\/(CVE-\d{4,}-\d+)/i)?.[1] : null;
        const cveOrgId = (url.hostname === 'www.cve.org' || url.hostname === 'cve.org') && url.pathname.replace(/\/$/, '') === '/CVERecord' ? url.searchParams.get('id') : null;
        return [pathId || cveOrgId];
      } catch (_) { return []; }
    });
    const nvdLinkedCves = [...new Set([...linkedFromNormalizedData, ...linkedFromLegacyReferences].map(cveId).filter((linked) => linked && linked !== id))];
    const relatedLinks = nvdLinkedCves.length
      ? `<section class="detail-section"><h3>CVE links explicitly present in NVD references</h3><p class="detail-description">The source links these CVE records; no relationship type is inferred.</p><div class="detail-links">${nvdLinkedCves.map((linked) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(linked)}" target="_blank" rel="noopener noreferrer">↗ ${esc(linked)} · NVD record</a>`).join('')}</div></section>`
      : '';
    const severityLabel = severity === 'unknown' ? 'UNRATED' : severity.toUpperCase();
    const share = telegramShareUrl(record, id);
    $('detail-content').innerHTML = `<div class="detail-id-row"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a><span class="severity-badge ${esc(severity)}">${esc(severityLabel)}</span>${record.kev ? '<span class="kev-badge">CISA KEV · LISTED</span>' : ''}</div>
      <h2 id="detail-title">${esc(record.title || id)}</h2><p class="detail-score">${esc(score)} · ${esc(activity)}</p><p class="detail-description">${esc(record.desc || 'No summary has been published by the available sources.')}</p>
      ${signalCards}
      ${priorityDetail}
      <section class="detail-section"><h3>Affected products and versions</h3><div class="detail-products">${products}</div></section>
      ${relatedLinks}
      ${kev}
      <section class="detail-section"><h3>Source records and references</h3><div class="detail-links">${links.map((item) => `<a class="${item.source === 'NVD' && item.tags?.some((tag) => String(tag).toLowerCase() === 'exploit') ? 'nvd-exploit-reference' : ''}" href="${esc(safeUrl(item.url))}" target="_blank" rel="noopener noreferrer">↗ ${esc(item.label || 'Reference')}</a>`).join('') || '<span class="detail-description">No source links provided.</span>'}</div></section>
      <section class="detail-section"><h3>Record attribution</h3><div class="detail-sources">${(record.sources || []).map((source) => `<span class="detail-source">${esc(source)}</span>`).join('') || '<span class="detail-source">CVE record</span>'}</div></section>
      <section class="detail-section github-search-section"><h3>GitHub repository search</h3><p class="detail-description">${esc(poc)} The on-demand count is the API’s raw query-match count, not the number of verified PoCs.</p><button class="card-action" type="button" data-action="poc-count" data-id="${esc(id)}">Check current repository matches</button><p id="poc-search-status" class="poc-search-status" role="status" aria-live="polite">Not checked. Search absence is not proof that no public PoC exists.</p><ul id="poc-search-results" class="poc-search-results"></ul></section>
      <div class="detail-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy CVE ID</button><a class="card-action telegram-share" href="${esc(share)}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">➤</span> Share to Telegram</a><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> Open GitHub search <small>UNVERIFIED LEADS</small></a></div>`;
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  }

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    const field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (!copied) throw new Error('Clipboard permission unavailable');
  }

  async function copyId(id) {
    try {
      await copyText(id);
      toast('Copied');
    } catch (_) {
      toast('Clipboard access was blocked by this browser.', 'warning');
    }
  }

  function csvCell(value) {
    let text = String(value == null ? '' : value);
    if (/^[\s\u0000-\u001f]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  }

  async function exportFiltered(format) {
    if (exportBusy) return;
    exportBusy = true;
    const buttons = [$('export-json'), $('export-csv')];
    buttons.forEach((button) => { button.disabled = true; button.setAttribute('aria-busy', 'true'); });
    setToolStatus('Loading every selected date shard before export…');
    try {
      const generation = ++searchGeneration;
      await loadAllSelectedDays(generation);
      if (!rangeDays().every((day) => loadedByDay.has(day))) throw new Error('Some selected date shards could not be loaded.');
      const records = selectedRecords();
      const filters = { from: state.from, to: state.to, severity: state.severity, vendor: state.vendor, product: state.product, absoluteZero: state.absoluteZero };
      let body;
      let mime;
      let extension;
      if (format === 'csv') {
        const headers = ['id', 'title', 'cvss_score', 'cvss_severity', 'epss_probability', 'cisa_kev_listed', 'composite_priority_custom', 'priority_inputs_available', 'activity_at', 'vendor_product_sources', 'primary_url'];
        const rows = records.map((record) => {
          const id = cveId(record.id);
          const priority = priorityScore(record, id);
          const affected = (record.affected || []).map((item) => `${item.vendor || ''} / ${item.product || ''} (${item.versions || ''}) [${item.source || 'source unknown'}]`).join(' | ');
          return [id, record.title, record.score, cvssSeverity(record.score), epssFor(id)?.score ?? '', !!record.kev, priority.value ?? '', `${priority.available}/5`, record.activity_at || record.published || '', affected, safeUrl(record.primary_url) || ''];
        });
        body = [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n');
        mime = 'text/csv;charset=utf-8';
        extension = 'csv';
      } else {
        body = JSON.stringify({ schema_version: 1, exported_at: new Date().toISOString(), filters, note: 'Composite priority is a custom heuristic; a missing component is not zero. CVSS, EPSS, KEV and PoC evidence remain separate.', records: records.map((record) => ({ ...record, subzero_priority_custom: priorityScore(record) })) }, null, 2);
        mime = 'application/json;charset=utf-8';
        extension = 'json';
      }
      const blob = new Blob([body], { type: mime });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `subzero-filtered-${state.from || 'all'}-${state.to || 'dates'}.${extension}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      setToolStatus(`${records.length.toLocaleString()} filtered records downloaded as ${extension.toUpperCase()}.`);
    } catch (error) {
      setToolStatus(`Export stopped: ${error.message || 'selected feed data could not be loaded'}`);
      toast('Export could not be completed. Retry after the feed loads.', 'warning');
    } finally {
      exportBusy = false;
      buttons.forEach((button) => { button.disabled = false; button.removeAttribute('aria-busy'); });
    }
  }

  async function loadGithubRepositoryMatches(id, button) {
    const output = $('poc-search-status');
    const results = $('poc-search-results');
    if (!output || !results) return;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    output.textContent = 'Requesting current GitHub repository search…';
    results.replaceChildren();
    try {
      let payload = githubPocCache.get(id);
      if (!payload) {
        const query = `${id} exploit OR PoC in:name,description,readme`;
        const url = `https://api.github.com/search/repositories?${new URLSearchParams({ q: query, per_page: '3' })}`;
        payload = await fetchJson(url, { cache: 'no-store', headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } }, 1);
        if (!Number.isInteger(payload.total_count) || !Array.isArray(payload.items)) throw new Error('GitHub returned an unexpected search response');
        githubPocCache.set(id, payload);
      }
      output.textContent = `${Number(payload.total_count).toLocaleString()} GitHub repository search match${payload.total_count === 1 ? '' : 'es'}; unreviewed leads, not verified PoCs. Search absence is not proof none exist.`;
      results.innerHTML = payload.items.slice(0, 3).map((item) => {
        const repoUrl = safeUrl(item.html_url);
        if (!repoUrl) return '';
        const owner = String(item.owner?.login || 'Repository');
        const description = String(item.description || 'No repository description.').slice(0, 200);
        const stars = Number.isFinite(Number(item.stargazers_count)) ? Number(item.stargazers_count).toLocaleString() : '—';
        return `<li><a href="${esc(repoUrl)}" target="_blank" rel="noopener noreferrer">${esc(owner)}/${esc(item.name || '')}</a><span>${esc(description)}</span><small>${stars} stars · unverified search result</small></li>`;
      }).join('');
    } catch (error) {
      output.textContent = `GitHub search count unavailable (${error.status === 403 ? 'rate limit or access restriction' : 'network or API error'}). This is not evidence that no PoC exists.`;
    } finally {
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }

  function bindEvents() {
    const resetWindow = () => { visible = PAGE_SIZE; windowStart = 0; };
    const loadForFilters = () => {
      window.clearTimeout(searchTimer);
      const generation = ++searchGeneration;
      if (state.query || state.vendor || state.product || state.absoluteZero || state.sort !== 'new') {
        searchTimer = window.setTimeout(() => loadAllSelectedDays(generation).catch(showLoadError), 180);
      }
    };
    const setFacetFilter = (key, raw) => {
      const values = key === 'vendor' ? facets.vendors : facets.products;
      const input = $(key === 'vendor' ? 'vendor-filter' : 'product-filter');
      const canonical = canonicalFacet(raw, values);
      state[key] = canonical;
      resetWindow();
      if (raw.trim() && !canonical) setToolStatus(`Choose an exact ${key} from the source-backed suggestions, or clear this field.`);
      render({ animateCards: true });
      loadForFilters();
      if (input.value !== raw) input.value = raw;
    };
    renderSavedViews();
    renderWatchlist();
    updateControlState();
    $('severity-filters').addEventListener('click', (event) => {
      const button = event.target.closest('[data-severity]');
      if (!button) return;
      state.severity = button.dataset.severity;
      if (state.absoluteZero && state.severity !== 'critical') state.absoluteZero = false;
      updateControlState();
      resetWindow();
      render({ animateCards: true });
    });
    $('sort-select').addEventListener('change', (event) => {
      state.sort = event.target.value;
      updateControlState();
      resetWindow();
      render({ animateCards: true });
      loadForFilters();
    });
    $('search-input').addEventListener('input', (event) => {
      state.query = event.target.value.trim();
      resetWindow();
      render({ animateCards: true });
      loadForFilters();
    });
    $('vendor-filter').addEventListener('input', (event) => setFacetFilter('vendor', event.target.value));
    $('product-filter').addEventListener('input', (event) => setFacetFilter('product', event.target.value));
    $('group-select').addEventListener('change', (event) => {
      state.group = ['none', 'vendor', 'product'].includes(event.target.value) ? event.target.value : 'none';
      resetWindow();
      render();
    });
    $('absolute-zero').addEventListener('click', () => {
      if (!state.absoluteZero) {
        preAbsoluteSeverity = state.severity;
        state.absoluteZero = true;
        state.severity = 'critical';
      } else {
        state.absoluteZero = false;
        state.severity = preAbsoluteSeverity || 'all';
      }
      updateControlState();
      resetWindow();
      render({ animateCards: true });
      loadForFilters();
    });
    $('compact-toggle').addEventListener('click', () => {
      compactCards = !compactCards;
      updateControlState();
      writeStored('subzero:compact', compactCards);
    });
    $('save-view').addEventListener('click', saveCurrentView);
    $('saved-view-select').addEventListener('change', () => {
      $('apply-view').disabled = !selectedSavedView();
      $('delete-view').disabled = !selectedSavedView();
    });
    $('apply-view').addEventListener('click', applySelectedView);
    $('delete-view').addEventListener('click', deleteSelectedView);
    $('copy-permalink').addEventListener('click', copyPermalink);
    $('export-json').addEventListener('click', () => exportFiltered('json'));
    $('export-csv').addEventListener('click', () => exportFiltered('csv'));
    $('apply-dates').addEventListener('click', () => setRange($('date-from').value, $('date-to').value));
    $('date-from').addEventListener('keydown', (event) => { if (event.key === 'Enter') setRange($('date-from').value, $('date-to').value); });
    $('date-to').addEventListener('keydown', (event) => { if (event.key === 'Enter') setRange($('date-from').value, $('date-to').value); });
    document.querySelectorAll('.quick-ranges button').forEach((button) => button.addEventListener('click', () => {
      if (!manifest) return;
      const days = Number(button.dataset.days);
      const max = String(manifest.window.end).slice(0, 10);
      const min = String(manifest.window.start).slice(0, 10);
      const fromDate = new Date(`${max}T00:00:00Z`);
      if (days === 30) fromDate.setTime(Date.parse(`${min}T00:00:00Z`));
      else fromDate.setUTCDate(fromDate.getUTCDate() - (days === 1 ? 1 : Math.max(0, days - 1)));
      const candidate = fromDate.toISOString().slice(0, 10);
      setRange(candidate < min ? min : candidate, max, days === 1 ? 24 : null);
      document.querySelectorAll('.quick-ranges button').forEach((element) => {
        const selected = element === button;
        element.classList.toggle('selected', selected);
        element.setAttribute('aria-pressed', String(selected));
      });
    }));
    $('view-new').addEventListener('click', () => acceptPendingUpdate(true));
    $('refresh-button').addEventListener('click', () => refresh({ force: true }));
    $('load-more').addEventListener('click', async () => {
      const button = $('load-more');
      button.disabled = true;
      const visibleMatches = selectedRecords().length;
      if (visibleMatches > windowStart + Math.min(visible, MAX_DOM_RECORDS)) {
        if (visible < MAX_DOM_RECORDS) visible = Math.min(MAX_DOM_RECORDS, visible + PAGE_SIZE);
        else windowStart = Math.min(windowStart + PAGE_SIZE, Math.max(0, visibleMatches - MAX_DOM_RECORDS));
        render();
        return;
      }
      const days = rangeDays().filter((day) => !loadedByDay.has(day)).reverse().slice(0, 3);
      if (days.length) {
        const loadingLabel = '<span>LOADING OLDER RECORDS…</span><small>Please wait</small><b aria-hidden="true">·</b>';
        let completedShards = 0;
        button.innerHTML = loadingLabel;
        button.setAttribute('aria-busy', 'true');
        appendLoadingSkeletons(days.length);
        try {
          await loadDays(days, {
            deferRender: true,
            onShardLoaded: (day, records) => {
              loadedByDay.set(day, records);
              completedShards += 1;
              rebuildRecords();
              render();
              const outstanding = days.length - completedShards;
              if (outstanding) appendLoadingSkeletons(outstanding);
              button.disabled = true;
              button.setAttribute('aria-busy', 'true');
              button.innerHTML = loadingLabel;
            }
          });
          rebuildRecords();
          visible = Math.min(MAX_DOM_RECORDS, visible + PAGE_SIZE);
          render();
        } catch (error) {
          feedList.querySelectorAll('.loading-skeleton').forEach((skeleton) => skeleton.remove());
          feedList.setAttribute('aria-busy', 'false');
          render();
          showLoadError(error);
          button.disabled = false;
        } finally {
          button.disabled = false;
          button.removeAttribute('aria-busy');
        }
      }
    });
    feedList.addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]');
      if (!action) return;
      const id = cveId(action.dataset.id);
      if (!id) return;
      if (action.dataset.action === 'copy') copyId(id);
      if (action.dataset.action === 'detail') renderDetail(id);
      if (action.dataset.action === 'star') {
        if (starredIds.has(id)) starredIds.delete(id); else starredIds.add(id);
        writeStored('subzero:stars', [...starredIds]);
        render();
        feedList.querySelector(`[data-action="star"][data-id="${id}"]`)?.focus();
      }
      if (action.dataset.action === 'read') {
        if (readIds.has(id)) readIds.delete(id); else readIds.add(id);
        writeStored('subzero:read', [...readIds]);
        render();
        feedList.querySelector(`[data-action="read"][data-id="${id}"]`)?.focus();
      }
    });
    $('detail-content').addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]');
      if (!action) return;
      if (action.dataset.action === 'copy') copyId(cveId(action.dataset.id));
      if (action.dataset.action === 'poc-count') loadGithubRepositoryMatches(cveId(action.dataset.id), action);
      if (action.dataset.action === 'watch-product') {
        const vendor = action.dataset.vendor;
        const product = action.dataset.product;
        watchPair(vendor, product);
        const watching = watchlist.some((item) => normalizeFacet(item.vendor) === normalizeFacet(vendor) && normalizeFacet(item.product) === normalizeFacet(product));
        action.setAttribute('aria-pressed', String(watching));
        action.textContent = watching ? 'Remove from local watchlist' : 'Watch vendor / product';
      }
      if (action.dataset.action === 'close-methodology') {
        event.preventDefault();
        $('detail-dialog').close();
        $('methodology').scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', `${window.location.pathname}${window.location.search}#methodology`);
      }
    });
    $('workspace-tools').addEventListener('click', (event) => {
      const action = event.target.closest('[data-action]');
      if (!action) return;
      const index = Number(action.dataset.index);
      if (action.dataset.action === 'watch-remove' && Number.isInteger(index)) {
        watchlist.splice(index, 1);
        writeStored('subzero:watchlist', watchlist);
        renderWatchlist();
        setToolStatus('Removed from the local watchlist.');
      }
      if (action.dataset.action === 'watch-filter' && Number.isInteger(index) && watchlist[index]) {
        state.vendor = canonicalFacet(watchlist[index].vendor, facets.vendors);
        state.product = canonicalFacet(watchlist[index].product, facets.products);
        state.query = '';
        updateControlState();
        resetWindow();
        render({ animateCards: true });
        loadForFilters();
        $('feed').scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
    $('dialog-close').addEventListener('click', () => $('detail-dialog').close());
    $('detail-dialog').addEventListener('click', (event) => {
      if (event.target === $('detail-dialog')) $('detail-dialog').close();
    });
    document.addEventListener('keydown', (event) => {
      const target = document.activeElement;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.key === '/' && !isTextTarget(target)) {
        event.preventDefault();
        $('search-input').focus();
        return;
      }
      if (isTextTarget(target) || $('detail-dialog').open || !['j', 'k', 'c'].includes(event.key.toLocaleLowerCase())) return;
      const cards = [...feedList.querySelectorAll('.cve-card')];
      const activeCard = target.closest?.('.cve-card');
      if (event.key.toLocaleLowerCase() === 'c') {
        const id = cveId(activeCard?.dataset.cveId);
        if (id) { event.preventDefault(); copyId(id); }
        return;
      }
      if (!cards.length) return;
      const current = activeCard ? cards.indexOf(activeCard) : -1;
      const next = event.key.toLocaleLowerCase() === 'j' ? Math.min(cards.length - 1, current < 0 ? 0 : current + 1) : Math.max(0, current < 0 ? cards.length - 1 : current - 1);
      event.preventDefault();
      cards[next].focus();
    });
  }

  async function boot() {
    bindEvents();
    let retry = BOOT_RETRY_MS;
    for (;;) {
      try {
        setLoaderMessage('Loading vulnerability feed…');
        manifest = await fetchManifest();
        await loadFacets();
        restorePermalink();
        setDateBounds();
        renderSources();
        const selectedDays = rangeDays();
        let newest = selectedDays.slice().reverse().filter((day) => Number(manifest.days.find((item) => item.date === day)?.count) > 0).slice(0, 2);
        if (!newest.length) newest = selectedDays.slice(-2).reverse();
        await loadDays(newest, { deferRender: true });
        rebuildRecords();
        render({ animateStats: true });
        void loadEpssSnapshot().then(() => {
          if (booted && manifest) render();
        });
        void loadRetainedHistory();
        lastSnapshotVersion = manifest.generated_at || '';
        lastBrowserCheck = Date.now();
        refreshTimestamp();
        setLoaderMessage('Feed ready');
        hideLoader();
        if (state.query || state.vendor || state.product || state.absoluteZero || state.sort !== 'new') {
          const generation = ++searchGeneration;
          void loadAllSelectedDays(generation).catch(showLoadError);
        }
        break;
      } catch (error) {
        $('feed-list').setAttribute('aria-busy', 'true');
        $('feed-indicator').classList.add('error');
        $('feed-indicator-text').textContent = 'FEED UNAVAILABLE';
        setStatus(`Feed request failed: ${error.message || 'network error'}. Retrying automatically.`, 'warning');
        setLoaderMessage(`Feed unavailable. Retrying in ${Math.ceil(retry / 1000)} seconds…`);
        await wait(retry);
        retry = Math.min(retry * 2, 60_000);
      }
    }
    window.setInterval(() => refresh(), POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refresh();
    });
  }

  boot();
})();
