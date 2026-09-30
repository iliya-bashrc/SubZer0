'use strict';

(() => {
  const PAGE_SIZE = 24;
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
  let state = { from: '', to: '', severity: 'all', query: '', sort: 'new', exactHours: null };
  let visible = PAGE_SIZE;
  let polling = false;
  let searchTimer = 0;
  let searchGeneration = 0;
  let toastTimer = 0;
  let booted = false;
  let pendingFeedUpdate = false;
  const pendingNewIds = new Set();

  const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);

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
    toastTimer = window.setTimeout(() => element.classList.remove('show'), 4600);
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

  function acceptPendingUpdate(resetWindow = false) {
    if (!pendingFeedUpdate) return;
    const newCount = pendingNewIds.size;
    pendingFeedUpdate = false;
    pendingNewIds.clear();
    $('new-notice').hidden = true;
    rebuildRecords();
    if (resetWindow && manifest) {
      state.from = String(manifest.window.start).slice(0, 10);
      state.to = String(manifest.window.end).slice(0, 10);
      state.severity = 'all';
      state.query = '';
      state.sort = 'new';
      state.exactHours = null;
      visible = PAGE_SIZE;
      $('search-input').value = '';
      $('sort-select').value = 'new';
      $('date-from').value = state.from;
      $('date-to').value = state.to;
      document.querySelectorAll('.severity-filter').forEach((element) => element.classList.toggle('active', element.dataset.severity === 'all'));
      document.querySelectorAll('.quick-ranges button').forEach((element) => element.classList.toggle('selected', element.dataset.days === '30'));
    }
    render();
    refreshTimestamp();
    setStatus(newCount ? `${newCount} new CVE${newCount === 1 ? '' : 's'} now included in the feed.` : 'Updated feed data is now displayed.', 'success');
  }

  async function fetchDays(days, version, sourceManifest = manifest) {
    const uniqueDays = [...new Set(days)].filter((day) => sourceManifest.days.some((item) => item.date === day));
    const entries = [];
    for (let offset = 0; offset < uniqueDays.length; offset += SHARD_CONCURRENCY) {
      const batch = uniqueDays.slice(offset, offset + SHARD_CONCURRENCY);
      const result = await Promise.all(batch.map(async (day) => [day, await fetchDay(day, version, sourceManifest)]));
      entries.push(...result);
    }
    return entries;
  }

  async function loadDays(days, options = {}) {
    const force = options.force === true;
    const sourceManifest = options.sourceManifest || manifest;
    const uniqueDays = [...new Set(days)].filter((day) => sourceManifest.days.some((item) => item.date === day));
    const pending = uniqueDays.filter((day) => force || !loadedByDay.has(day));
    if (!pending.length) return;
    const entries = await fetchDays(pending, sourceManifest.generated_at, sourceManifest);
    entries.forEach(([day, records]) => loadedByDay.set(day, records));
    if (!options.deferRender) {
      rebuildRecords();
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
      if (!query) return true;
      const products = (record.affected || []).map((item) => `${item.vendor || ''} ${item.product || ''} ${item.versions || ''}`).join(' ');
      const searchable = `${record.id || ''} ${record.title || ''} ${record.desc || ''} ${products} ${(record.sources || []).join(' ')}`;
      return searchable.toLocaleLowerCase().includes(query);
    });
    matching.sort((a, b) => {
      const dateDelta = (parseTime(a.activity_at) || parseTime(a.window_date) || parseTime(a.published) || 0) - (parseTime(b.activity_at) || parseTime(b.window_date) || parseTime(b.published) || 0);
      if (state.sort === 'old') return dateDelta || a.id.localeCompare(b.id);
      if (state.sort === 'hot') return (SEVERITY_ORDER[cvssSeverity(a.score)] ?? 4) - (SEVERITY_ORDER[cvssSeverity(b.score)] ?? 4) || -dateDelta;
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
    const allOk = sourceDefs.length > 0 && sourceDefs.every((source) => statusFor(source).ok === true);
    const badge = $('source-state');
    badge.textContent = allOk ? `${sourceDefs.length} FEEDS OK` : 'PARTIAL';
    badge.className = `source-state${allOk ? '' : ' warning'}`;
    $('window-caption').textContent = `${Number(manifest.coverage?.utc_days_sharded || 0)} UTC date shards · ${Number(manifest.coverage?.distinct_cve_records || 0).toLocaleString()} deduplicated records · NVD, GitHub and CISA gate coverage; EPSS is optional enrichment.`;
  }

  function renderStats() {
    if (!manifest) return;
    const summary = summaryForSelection();
    $('stat-total').textContent = Number(summary.count || 0).toLocaleString();
    $('stat-critical').textContent = Number(summary.critical || 0).toLocaleString();
    $('stat-high').textContent = Number(summary.high || 0).toLocaleString();
    $('stat-kev').textContent = Number(summary.exploited || 0).toLocaleString();
    $('stat-window-label').textContent = state.exactHours === 24 ? '/ LAST 24 HOURS' : ` / ${state.from === String(manifest.window.start).slice(0, 10) && state.to === String(manifest.window.end).slice(0, 10) ? '30 DAY WINDOW' : 'UTC DATE WINDOW'}`;
    const known = summary.critical + summary.high + summary.medium + summary.low + summary.none + summary.unknown;
    const pct = (value) => known ? `${Math.max(value > 0 ? 1.2 : 0, value / known * 100)}%` : '0%';
    $('meter-critical').style.width = pct(summary.critical);
    $('meter-high').style.width = pct(summary.high);
    $('meter-medium').style.width = pct(summary.medium);
    $('meter-low').style.width = pct(summary.low);
    $('meter-neutral').style.width = pct(summary.none + summary.unknown);
  }

  function cardProduct(item) {
    const name = [item.vendor, item.product].filter(Boolean).join(' / ') || item.product || item.vendor || 'Product details';
    return `<span class="product-chip"><strong>${esc(name)}</strong>${item.versions ? ` · ${esc(item.versions)}` : ''}</span>`;
  }

  function cardHtml(record, index) {
    const id = cveId(record.id);
    if (!id) return '';
    const scoreValue = record.score == null || !Number.isFinite(Number(record.score)) ? null : Number(record.score);
    const severity = cvssSeverity(scoreValue);
    const bandHeat = { critical: 0.95, high: 0.75, medium: 0.5, low: 0.28, unknown: 0.06 }[severity];
    const heat = scoreValue == null ? bandHeat : Math.max(bandHeat * 0.72, Math.min(1, scoreValue / 10));
    const mix = Math.round(32 + heat * 49);
    const washMix = Math.round(heat * 11);
    const glow = Math.min(0.72, 0.12 + heat * 0.5).toFixed(2);
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
    const epssHtml = epss
      ? `<span class="epss-chip" title="FIRST EPSS estimated probability for observed exploitation in the next 30 days"><i class="epss-dot"></i><strong>EPSS</strong><b>${esc(epssPercent(epss))}</b><small>30D PROBABILITY</small></span>`
      : '<span class="epss-chip unavailable" title="No EPSS score is present; this is not a zero probability"><i class="epss-dot"></i><strong>EPSS</strong><b>—</b><small>NOT AVAILABLE</small></span>';
    const severityLabel = severity === 'unknown' ? 'UNRATED' : severity.toUpperCase();
    const share = telegramShareUrl(record, id);
    return `<article class="cve-card severity-${severity}" style="--heat:${heat.toFixed(2)};--mix:${mix}%;--wash-mix:${washMix}%;--glow-opacity:${glow};animation-delay:${Math.min(index, 5) * 18}ms">
      <div class="card-head"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>
        <span class="severity-badge ${esc(severity)}">${esc(severityLabel)}</span>${record.kev ? '<span class="kev-badge" title="Listed in the CISA Known Exploited Vulnerabilities catalog">CISA KEV · LISTED</span>' : ''}
        <span class="cvss-score"><span>${esc(score)}</span><small>CVSS · SEVERITY</small></span></div>
      ${epssHtml}
      <h3 class="card-title">${esc(record.title || id)}</h3>
      <p class="card-description">${esc(record.desc || 'No source summary is available yet. Review the linked primary records and advisories.')}</p>
      ${products ? `<div class="affected-preview" aria-label="Affected products">${products}</div>` : ''}
      <div class="card-meta"><span class="meta-date">${esc(activity)}</span><i class="meta-divider"></i><span>${record.affected?.length ? `${record.affected.length} affected product${record.affected.length === 1 ? '' : 's'}` : 'Product details not provided'}</span><i class="meta-divider"></i><span class="source-label">${esc(sources)}</span></div>
      <div class="card-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy ID</button><button class="card-action" type="button" data-action="detail" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⌕</span> Details</button><a class="card-action telegram-share" href="${esc(share)}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">➤</span> Share to Telegram</a><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> GitHub PoC search <small>UNVERIFIED</small></a></div>
    </article>`;
  }

  function render() {
    if (!manifest) return;
    renderStats();
    const matches = selectedRecords();
    const completeRange = rangeDays().every((day) => loadedByDay.has(day));
    const isSearching = state.query.trim().length > 0;
    let total;
    if (isSearching || state.exactHours === 24) total = matches.length;
    else if (state.severity === 'all') total = summaryForSelection().count;
    else total = manifest.days.filter((item) => item.date >= state.from && item.date <= state.to).reduce((sum, item) => sum + (state.severity === 'unknown' ? Number(item.none || 0) + Number(item.unknown || 0) : Number(item[state.severity] || 0)), 0);
    const countLabel = total > visible ? `Showing ${Math.min(visible, matches.length).toLocaleString()} of ${total.toLocaleString()}` : `${total.toLocaleString()} records`;
    $('feed-count').textContent = total.toLocaleString();
    $('feed-list').innerHTML = matches.slice(0, visible).map(cardHtml).join('');
    $('feed-list').setAttribute('aria-busy', 'false');
    const noLoadedRecords = matches.length === 0;
    const couldLoadMore = !completeRange && !isSearching;
    $('empty-state').hidden = !(noLoadedRecords && completeRange);
    const button = $('load-more');
    button.hidden = !(matches.length > visible || couldLoadMore);
    button.disabled = false;
    if (matches.length > visible) {
      button.innerHTML = `<span>LOAD MORE</span><small>${countLabel}</small><b aria-hidden="true">↓</b>`;
    } else if (couldLoadMore) {
      button.innerHTML = `<span>LOAD OLDER CVEs</span><small>${loadedByDay.size} of ${rangeDays().length} date shards loaded</small><b aria-hidden="true">↓</b>`;
    }
    if (state.query && isSearching && completeRange) setStatus(`Search covers all ${rangeDays().length} selected UTC date shards.`, 'success');
    else if (!state.query && !completeRange && noLoadedRecords) setStatus('Loading records for this date range…');
    else if (!state.query && !completeRange && matches.length) setStatus(`Showing recent records first · ${loadedByDay.size} of ${rangeDays().length} date shards loaded.`);
    else if (!state.query && !completeRange) setStatus('All selected dates loaded.');
    $('coverage-note').textContent = state.exactHours === 24 ? 'Last 24 hours · UTC · CISA date-added is date-granular' : `${state.from} → ${state.to} UTC · NVD + GitHub advisories + CISA KEV`;
  }

  function setRange(from, to, exactHours = null) {
    if (!manifest) return;
    acceptPendingUpdate(false);
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
    $('date-from').value = from;
    $('date-to').value = to;
    document.querySelectorAll('.quick-ranges button').forEach((button) => button.classList.toggle('selected', button.dataset.days === (exactHours === 24 ? '1' : '')));
    render();
    const days = rangeDays().slice(-2).reverse();
    if (state.query || state.sort !== 'new') loadAllSelectedDays(rangeGeneration).catch(showLoadError);
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
      const purpose = state.query ? 'Search covers' : 'Full-range sort covers';
      setStatus(`${purpose} all ${days.length} selected UTC date shards.`, 'success');
    }
  }

  function showLoadError(error) {
    setStatus(`Some feed data could not be loaded: ${error.message || 'network error'}. Retry with “Load older CVEs”.`, 'error');
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
      epssSnapshot = null;
      epssVersion = '';
    }
  }

  async function refresh(options = {}) {
    if (polling || (document.hidden && !options.force)) return;
    polling = true;
    const button = $('refresh-button');
    if (options.force) button.disabled = true;
    const previousManifest = manifest;
    const previousVersion = lastSnapshotVersion;
    const previousLoadedDays = new Set(loadedByDay.keys());
    const previousDataByDay = new Map(loadedByDay);
    try {
      const next = await fetchManifest();
      const nextVersion = next.generated_at || '';
      const changed = !!previousVersion && nextVersion !== previousVersion;
      let changedDataDays = [];
      let refreshDays = [];
      let newIds = [];
      let uncertainChangedDays = [];

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
        await loadDays(refreshDays, { force: true, deferRender: true, sourceManifest: next });

        const detected = new Set();
        for (const day of refreshDays) {
          const oldSummary = oldSummaries.get(day);
          const oldRecords = previousDataByDay.get(day) || [];
          const newRecords = loadedByDay.get(day) || [];
          if (previousLoadedDays.has(day) || !oldSummary || Number(oldSummary.count || 0) === 0) {
            const oldIds = new Set(oldRecords.map((item) => cveId(item.id)));
            for (const record of newRecords) {
              const id = cveId(record.id);
              if (id && !oldIds.has(id)) detected.add(id);
            }
          } else if (changedDataDays.includes(day)) {
            uncertainChangedDays.push(day);
          }
        }
        newIds = [...detected];
      }

      manifest = next;
      lastSnapshotVersion = nextVersion;
      lastBrowserCheck = Date.now();
      setDateBounds();
      await loadEpssSnapshot();
      const currentDays = new Set(manifest.days.map((day) => day.date));
      for (const day of [...loadedByDay.keys()]) {
        if (!currentDays.has(day)) loadedByDay.delete(day);
      }
      renderSources();

      if (changed) {
        newIds.forEach((id) => pendingNewIds.add(id));
        const shouldDefer = newIds.length > 0 || uncertainChangedDays.length > 0;
        if (shouldDefer) {
          pendingFeedUpdate = true;
          const count = pendingNewIds.size;
          const otherChanges = uncertainChangedDays.length
            ? ` Additional changes were found in ${uncertainChangedDays.length} previously unloaded shard${uncertainChangedDays.length === 1 ? '' : 's'}.`
            : '';
          showUpdateNotice(count
            ? `${count} new CVE${count === 1 ? '' : 's'} detected. Select View updates to apply the refreshed feed.${otherChanges}`
            : `Feed data changed in ${uncertainChangedDays.length} date shard${uncertainChangedDays.length === 1 ? '' : 's'}. Select View updates to apply it.`);
        } else if (!pendingFeedUpdate) {
          rebuildRecords();
          setStatus('The snapshot updated; no new CVE IDs were found in checked shards.', 'success');
        } else {
          const count = pendingNewIds.size;
          showUpdateNotice(count ? `${count} new CVE${count === 1 ? '' : 's'} detected. Select View updates to apply the refreshed feed.` : 'Feed updates are ready. Select View updates to apply them.');
        }
      }
      render();
      refreshTimestamp();
    } catch (error) {
      lastBrowserCheck = Date.now();
      $('feed-indicator').classList.add('error');
      $('feed-indicator-text').textContent = 'CHECK FAILED';
      setStatus(`Could not verify a fresh snapshot: ${error.message || 'network error'}. The last loaded records remain available.`, 'error');
      if (options.force) toast('Feed check failed. Retrying automatically.', 'warning');
    } finally {
      polling = false;
      button.disabled = false;
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
    const products = (record.affected || []).length ? (record.affected || []).map((item) => `<div class="detail-product"><strong>${esc([item.vendor, item.product].filter(Boolean).join(' / ') || 'Product')}</strong><span>${esc(item.versions || 'Version details not specified')} · ${esc(item.source || 'Source record')}</span></div>`).join('') : '<p class="detail-description">Affected product/version details were not provided in the available records.</p>';
    const epss = epssFor(id);
    const percentile = epss?.percentile == null ? '' : ` · P${Math.round(epss.percentile * 100)} relative percentile rank`;
    const epssDetail = epss
      ? `${epssPercent(epss)} estimated chance that exploitation activity will be observed in the next 30 days${percentile}. Score set dated ${fmtDate(epssSnapshot?.score_date || manifest.epss?.score_date)}.`
      : 'No EPSS score is available in this snapshot. Missing data is not a 0% forecast.';
    const kevDetail = record.kev
      ? `Listed in CISA KEV · added ${fmtDate(record.kev.date_added || record.window_date)}. ${record.kev.required_action || 'CISA identifies this as a known exploited vulnerability.'}${record.kev.due_date ? ` Due date: ${record.kev.due_date}.` : ''}${record.kev.ransomware && record.kev.ransomware.toLowerCase() !== 'unknown' ? ` Ransomware campaign use: ${record.kev.ransomware}.` : ''}`
      : 'Not listed in the current CISA KEV snapshot. Absence from this catalog is not proof that exploitation has never occurred.';
    const poc = `GitHub repository search for ${id} · results are unverified and do not prove exploitation.`;
    const signalCards = `<section class="detail-section"><h3>Why it matters</h3><div class="signal-grid"><article class="signal-card signal-cvss severity-${esc(severity)}"><strong>CVSS / SEVERITY</strong><span>${esc(severity === 'unknown' ? 'UNRATED' : severity === 'none' ? '0.0 · NONE' : `${Number(record.score).toFixed(1)} · ${severity.toUpperCase()}`)}</span><small>Severity only; this is not an exploitation probability.</small></article><article class="signal-card signal-epss"><strong>EPSS / 30-DAY PROBABILITY</strong><span>${esc(epss ? epssPercent(epss) : 'Not available')}</span><small>${esc(epssDetail)}</small></article><article class="signal-card signal-kev"><strong>CISA KEV / CATALOG EVIDENCE</strong><span>${record.kev ? 'LISTED' : 'NOT LISTED'}</span><small>${esc(kevDetail)}</small></article><article class="signal-card signal-poc"><strong>GITHUB PoC / SEARCH LEAD</strong><span>UNVERIFIED</span><small>${esc(poc)}</small></article></div></section>`;
    const kev = record.kev ? `<section class="detail-section"><h3>CISA KEV catalog detail</h3><div class="kev-callout"><strong>Known exploited vulnerability listing</strong><p>${esc(kevDetail)}</p></div></section>` : '';
    const refs = [...(record.advisories || []).map((item) => ({ label: item.label || 'Security advisory', url: item.url })), ...(record.refs || [])]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index).slice(0, 14);
    const links = [{ label: record.sources?.includes('NVD') ? 'Primary record · NVD' : 'CVE Program record', url: primary }, { label: 'FIRST EPSS data and method', url: 'https://www.first.org/epss/data' }, ...refs]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index);
    const severityLabel = severity === 'unknown' ? 'UNRATED' : severity.toUpperCase();
    const share = telegramShareUrl(record, id);
    $('detail-content').innerHTML = `<div class="detail-id-row"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a><span class="severity-badge ${esc(severity)}">${esc(severityLabel)}</span>${record.kev ? '<span class="kev-badge">CISA KEV · LISTED</span>' : ''}</div>
      <h2 id="detail-title">${esc(record.title || id)}</h2><p class="detail-score">${esc(score)} · ${esc(activity)}</p><p class="detail-description">${esc(record.desc || 'No summary has been published by the available sources.')}</p>
      ${signalCards}
      <section class="detail-section"><h3>Affected products and versions</h3><div class="detail-products">${products}</div></section>
      ${kev}
      <section class="detail-section"><h3>Source records and references</h3><div class="detail-links">${links.map((item) => `<a href="${esc(safeUrl(item.url))}" target="_blank" rel="noopener noreferrer">↗ ${esc(item.label || 'Reference')}</a>`).join('') || '<span class="detail-description">No source links provided.</span>'}</div></section>
      <section class="detail-section"><h3>Record attribution</h3><div class="detail-sources">${(record.sources || []).map((source) => `<span class="detail-source">${esc(source)}</span>`).join('') || '<span class="detail-source">CVE record</span>'}</div></section>
      <div class="detail-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy CVE ID</button><a class="card-action telegram-share" href="${esc(share)}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">➤</span> Share to Telegram</a><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> GitHub PoC search <small>UNVERIFIED</small></a></div>`;
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  }

  async function copyId(id) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(id);
      } else {
        const field = document.createElement('textarea');
        field.value = id;
        field.setAttribute('readonly', '');
        field.style.position = 'fixed';
        field.style.opacity = '0';
        document.body.appendChild(field);
        field.select();
        const copied = document.execCommand('copy');
        field.remove();
        if (!copied) throw new Error('Clipboard permission unavailable');
      }
      toast(`${id} copied to clipboard.`);
    } catch (_) {
      toast('Clipboard access was blocked by this browser.', 'warning');
    }
  }

  function bindEvents() {
    $('severity-filters').addEventListener('click', (event) => {
      const button = event.target.closest('[data-severity]');
      if (!button) return;
      acceptPendingUpdate(false);
      state.severity = button.dataset.severity;
      document.querySelectorAll('.severity-filter').forEach((element) => element.classList.toggle('active', element === button));
      visible = PAGE_SIZE;
      render();
    });
    $('sort-select').addEventListener('change', (event) => {
      acceptPendingUpdate(false);
      state.sort = event.target.value;
      render();
      if (state.sort !== 'new' && !rangeDays().every((day) => loadedByDay.has(day))) {
        const generation = ++searchGeneration;
        loadAllSelectedDays(generation).catch(showLoadError);
      }
    });
    $('search-input').addEventListener('input', (event) => {
      acceptPendingUpdate(false);
      state.query = event.target.value.trim();
      visible = PAGE_SIZE;
      render();
      window.clearTimeout(searchTimer);
      const generation = ++searchGeneration;
      if (state.query) searchTimer = window.setTimeout(() => loadAllSelectedDays(generation).catch(showLoadError), 260);
    });
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
      document.querySelectorAll('.quick-ranges button').forEach((element) => element.classList.toggle('selected', element === button));
    }));
    $('view-new').addEventListener('click', () => acceptPendingUpdate(true));
    $('refresh-button').addEventListener('click', () => refresh({ force: true }));
    $('load-more').addEventListener('click', async () => {
      acceptPendingUpdate(false);
      const button = $('load-more');
      button.disabled = true;
      const visibleMatches = selectedRecords().length;
      if (visibleMatches > visible) {
        visible += PAGE_SIZE;
        render();
        return;
      }
      const days = rangeDays().filter((day) => !loadedByDay.has(day)).reverse().slice(0, 3);
      if (days.length) {
        button.innerHTML = '<span>LOADING OLDER RECORDS…</span><small>Please wait</small><b aria-hidden="true">·</b>';
        try {
          await loadDays(days);
          visible += PAGE_SIZE;
          render();
        } catch (error) {
          showLoadError(error);
          button.disabled = false;
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
    });
    $('detail-content').addEventListener('click', (event) => {
      const action = event.target.closest('[data-action="copy"]');
      if (action) copyId(cveId(action.dataset.id));
    });
    $('dialog-close').addEventListener('click', () => $('detail-dialog').close());
    $('detail-dialog').addEventListener('click', (event) => {
      if (event.target === $('detail-dialog')) $('detail-dialog').close();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
        event.preventDefault();
        $('search-input').focus();
      }
    });
  }

  async function boot() {
    bindEvents();
    let retry = BOOT_RETRY_MS;
    for (;;) {
      try {
        setLoaderMessage('Loading vulnerability feed…');
        manifest = await fetchManifest();
        setDateBounds();
        await loadEpssSnapshot();
        renderSources();
        renderStats();
        let newest = manifest.days.slice().reverse().filter((item) => Number(item.count) > 0).slice(0, 2).map((item) => item.date);
        if (!newest.length) newest = manifest.days.slice(-2).map((item) => item.date).reverse();
        await loadDays(newest);
        render();
        lastSnapshotVersion = manifest.generated_at || '';
        lastBrowserCheck = Date.now();
        refreshTimestamp();
        setLoaderMessage('Feed ready');
        hideLoader();
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
