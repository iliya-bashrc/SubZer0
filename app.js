'use strict';

(() => {
  const PAGE_SIZE = 24;
  const POLL_MS = 120_000;
  const SHARD_CONCURRENCY = 4;
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const $ = (id) => document.getElementById(id);
  const feedList = $('feed-list');
  const loadedByDay = new Map();
  const loadJobs = new Map();
  const allRecords = new Map();
  const loaderStartedAt = Date.now();
  let manifest = null;
  let lastBrowserCheck = null;
  let lastSnapshotVersion = '';
  let state = { from: '', to: '', severity: 'all', query: '', sort: 'new', exactHours: null };
  let visible = PAGE_SIZE;
  let polling = false;
  let searchTimer = 0;
  let searchGeneration = 0;
  let toastTimer = 0;
  let booted = false;

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

  function parseTime(value) {
    const result = value ? Date.parse(value) : NaN;
    return Number.isFinite(result) ? result : null;
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
    const wait = Math.max(0, 680 - (Date.now() - loaderStartedAt));
    window.setTimeout(() => loader.classList.add('done'), wait);
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
    const response = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Feed index request returned ${response.status}`);
    const value = await response.json();
    if (value.schema_version !== 2 || !Array.isArray(value.days) || !value.window || !value.totals) {
      throw new Error('Feed index has an unsupported schema');
    }
    return value;
  }

  async function fetchDay(day, version) {
    const jobKey = `${day}:${version}`;
    if (loadJobs.has(jobKey)) return loadJobs.get(jobKey);
    const summary = manifest.days.find((item) => item.date === day);
    if (!summary || !summary.path) return [];
    const job = (async () => {
      const url = `${summary.path}?v=${encodeURIComponent(version)}`;
      const response = await fetch(url, { cache: 'default', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error(`Could not load ${day} (${response.status})`);
      const payload = await response.json();
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

  async function loadDays(days, options = {}) {
    const force = options.force === true;
    const uniqueDays = [...new Set(days)].filter((day) => manifest.days.some((item) => item.date === day));
    const pending = uniqueDays.filter((day) => force || !loadedByDay.has(day));
    if (!pending.length) return;
    const batchSize = Math.max(1, Math.min(SHARD_CONCURRENCY, pending.length));
    for (let offset = 0; offset < pending.length; offset += batchSize) {
      const batch = pending.slice(offset, offset + batchSize);
      const entries = await Promise.all(batch.map(async (day) => [day, await fetchDay(day, manifest.generated_at)]));
      entries.forEach(([day, records]) => loadedByDay.set(day, records));
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
      if (state.severity !== 'all' && record.sev !== state.severity) return false;
      if (!query) return true;
      const products = (record.affected || []).map((item) => `${item.vendor || ''} ${item.product || ''} ${item.versions || ''}`).join(' ');
      const searchable = `${record.id || ''} ${record.title || ''} ${record.desc || ''} ${products} ${(record.sources || []).join(' ')}`;
      return searchable.toLocaleLowerCase().includes(query);
    });
    matching.sort((a, b) => {
      const dateDelta = (parseTime(a.activity_at) || parseTime(a.window_date) || parseTime(a.published) || 0) - (parseTime(b.activity_at) || parseTime(b.window_date) || parseTime(b.published) || 0);
      if (state.sort === 'old') return dateDelta || a.id.localeCompare(b.id);
      if (state.sort === 'hot') return (SEVERITY_ORDER[a.sev] ?? 4) - (SEVERITY_ORDER[b.sev] ?? 4) || -dateDelta;
      return -dateDelta || a.id.localeCompare(b.id);
    });
    return matching;
  }

  function summaryForSelection() {
    if (!manifest) return { count: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, exploited: 0 };
    if (state.exactHours === 24) {
      const items = [...allRecords.values()].filter((record) => recordInRange(record));
      return {
        count: items.length,
        critical: items.filter((item) => item.sev === 'critical').length,
        high: items.filter((item) => item.sev === 'high').length,
        medium: items.filter((item) => item.sev === 'medium').length,
        low: items.filter((item) => item.sev === 'low').length,
        unknown: items.filter((item) => item.sev === 'unknown').length,
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
      result.unknown += item.unknown || 0;
      result.exploited += item.exploited || 0;
      return result;
    }, { count: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, exploited: 0 });
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
    if (age != null && Date.now() - age > 90 * 60_000) setStatus('The last successful snapshot is older than 90 minutes. Keeping the last complete data while checks continue.', 'warning');
    else if (!sourceComplete) setStatus('One or more sources did not report complete coverage in this snapshot.', 'warning');
    else if (rangeDays().every((day) => loadedByDay.has(day))) setStatus(`Last complete snapshot ${relativeTime(generated)} · browser checks every 2 minutes.`, 'success');
  }

  function renderSources() {
    if (!manifest) return;
    const list = $('source-list');
    const statuses = new Map((manifest.source_status || []).map((item) => [item.name, item]));
    const sourceDefs = manifest.sources || [];
    list.innerHTML = sourceDefs.map((source) => {
      const status = statuses.get(source.name) || {};
      const ok = status.ok === true;
      let facts = '';
      if (source.name === 'NVD CVE API 2.0') facts = `${Number(status.records || 0).toLocaleString()} records · ${Number(status.pages || 0)} pages`;
      else if (source.name === 'GitHub Security Advisory Database') facts = `${Number(status.advisories || 0).toLocaleString()} advisories · ${Number(status.pages || 0)} pages`;
      else facts = `${Number(status.catalog_records || 0).toLocaleString()} catalog entries`;
      return `<li><i class="source-state-dot${ok ? '' : ' warning'}"></i><span><a href="${esc(safeUrl(source.url))}" target="_blank" rel="noopener noreferrer">${esc(source.name)}</a><span class="source-facts">${esc(ok ? facts : 'Coverage unavailable')}</span></span></li>`;
    }).join('');
    const allOk = sourceDefs.length > 0 && sourceDefs.every((source) => statuses.get(source.name)?.ok === true);
    const badge = $('source-state');
    badge.textContent = allOk ? `${sourceDefs.length} FEEDS OK` : 'PARTIAL';
    badge.className = `source-state${allOk ? '' : ' warning'}`;
    $('window-caption').textContent = `${Number(manifest.coverage?.utc_days_sharded || 0)} UTC date shards · ${Number(manifest.coverage?.distinct_cve_records || 0).toLocaleString()} deduplicated records · all sources required for a successful snapshot.`;
  }

  function renderStats() {
    if (!manifest) return;
    const summary = summaryForSelection();
    $('stat-total').textContent = Number(summary.count || 0).toLocaleString();
    $('stat-critical').textContent = Number(summary.critical || 0).toLocaleString();
    $('stat-high').textContent = Number(summary.high || 0).toLocaleString();
    $('stat-kev').textContent = Number(summary.exploited || 0).toLocaleString();
    $('stat-window-label').textContent = state.exactHours === 24 ? '/ LAST 24 HOURS' : ` / ${state.from === String(manifest.window.start).slice(0, 10) && state.to === String(manifest.window.end).slice(0, 10) ? '30 DAY WINDOW' : 'UTC DATE WINDOW'}`;
    const known = summary.critical + summary.high + summary.medium + summary.low;
    const pct = (value) => known ? `${Math.max(value > 0 ? 1.2 : 0, value / known * 100)}%` : '0%';
    $('meter-critical').style.width = pct(summary.critical);
    $('meter-high').style.width = pct(summary.high);
    $('meter-medium').style.width = pct(summary.medium);
    $('meter-low').style.width = pct(summary.low);
  }

  function cardProduct(item) {
    const name = [item.vendor, item.product].filter(Boolean).join(' / ') || item.product || item.vendor || 'Product details';
    return `<span class="product-chip"><strong>${esc(name)}</strong>${item.versions ? ` · ${esc(item.versions)}` : ''}</span>`;
  }

  function cardHtml(record, index) {
    const id = cveId(record.id);
    if (!id) return '';
    const severity = SEVERITY_ORDER[record.sev] == null ? 'unknown' : record.sev;
    const hot = severity === 'critical' || severity === 'high';
    const heatClass = severity === 'critical' ? 'heat-critical' : severity === 'high' ? 'heat-high' : '';
    const primary = safeUrl(record.primary_url) || `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
    const products = (record.affected || []).slice(0, 2).map(cardProduct).join('');
    const sources = (record.sources || []).map(sourceName).join(' · ') || 'CVE record';
    const activity = record.date_basis === 'CISA KEV date added'
      ? `KEV ADDED ${fmtDate(record.kev?.date_added || record.window_date)}`
      : record.date_basis === 'GitHub advisory publication'
        ? `ADVISORY ${fmtDate(record.window_date)}`
        : `PUBLISHED ${fmtDate(record.published || record.window_date)}`;
    const score = record.score == null || !Number.isFinite(Number(record.score)) ? '—' : Number(record.score).toFixed(1);
    return `<article class="cve-card ${heatClass}" style="animation-delay:${Math.min(index, 5) * 24}ms">
      <div class="card-head"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>
        <span class="severity-badge ${esc(severity)}">${esc(severity)}</span>${record.kev ? '<span class="kev-badge">KNOWN EXPLOITED</span>' : ''}
        <span class="cvss-score">${esc(score)}<span class="score-caption"> CVSS</span></span></div>
      <h3 class="card-title">${esc(record.title || id)}</h3>
      <p class="card-description">${esc(record.desc || 'No source summary is available yet. Review the linked primary records and advisories.')}</p>
      ${products ? `<div class="affected-preview" aria-label="Affected products">${products}</div>` : ''}
      <div class="card-meta"><span class="meta-date">${esc(activity)}</span><i class="meta-divider"></i><span>${record.affected?.length ? `${record.affected.length} affected product${record.affected.length === 1 ? '' : 's'}` : 'Product details not provided'}</span><i class="meta-divider"></i><span class="source-label">${esc(sources)}</span></div>
      <div class="card-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy CVE ID</button><button class="card-action" type="button" data-action="detail" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⌕</span> View details</button><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> GitHub PoC search <small>UNVERIFIED</small></a></div>
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
    else total = manifest.days.filter((item) => item.date >= state.from && item.date <= state.to).reduce((sum, item) => sum + Number(item[state.severity] || 0), 0);
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

  async function refresh(options = {}) {
    if (polling || (document.hidden && !options.force)) return;
    polling = true;
    const button = $('refresh-button');
    if (options.force) button.disabled = true;
    const wasLoaded = new Set(loadedByDay.keys());
    const previousIdsByDay = new Map(loadedByDay);
    const previousVersion = lastSnapshotVersion;
    try {
      const next = await fetchManifest();
      lastBrowserCheck = Date.now();
      const changed = previousVersion && next.generated_at !== previousVersion;
      manifest = next;
      lastSnapshotVersion = next.generated_at || '';
      setDateBounds();
      const currentDays = new Set(manifest.days.map((day) => day.date));
      for (const day of [...loadedByDay.keys()]) {
        if (!currentDays.has(day)) loadedByDay.delete(day);
      }
      renderSources();
      if (changed) {
        const latestDays = manifest.days.slice(-2).map((item) => item.date).reverse();
        const refreshDays = [...new Set([...wasLoaded].filter((day) => currentDays.has(day)).concat(latestDays))];
        setStatus('New snapshot found; refreshing the date shards already in view…');
        await loadDays(refreshDays, { force: true });
        const newIds = [];
        for (const day of refreshDays) {
          const oldIds = new Set((previousIdsByDay.get(day) || []).map((item) => cveId(item.id)));
          const values = loadedByDay.get(day) || [];
          for (const record of values) {
            const id = cveId(record.id);
            if (id && wasLoaded.has(day) && !oldIds.has(id)) newIds.push(id);
          }
        }
        const uniqueNew = [...new Set(newIds)];
        if (uniqueNew.length) {
          const crit = uniqueNew.find((id) => allRecords.get(id)?.sev === 'critical');
          toast(crit ? `${uniqueNew.length} new CVE${uniqueNew.length === 1 ? '' : 's'} · critical: ${crit}` : `${uniqueNew.length} new CVE${uniqueNew.length === 1 ? '' : 's'} in the refreshed snapshot`);
        } else {
          setStatus(`Snapshot refreshed ${relativeTime(manifest.generated_at)} · no new IDs in the shards previously open.`, 'success');
        }
      } else {
        render();
      }
      render();
      refreshTimestamp();
    } catch (error) {
      lastBrowserCheck = Date.now();
      if (!manifest) {
        $('feed-list').innerHTML = '';
        $('empty-state').hidden = false;
        $('empty-state').querySelector('strong').textContent = 'The feed is temporarily unavailable.';
        $('empty-state').querySelector('p').textContent = 'The dashboard will retry automatically; check the source status again shortly.';
      }
      $('feed-indicator').classList.add('error');
      $('feed-indicator-text').textContent = manifest ? 'CHECK FAILED' : 'FEED UNAVAILABLE';
      setStatus(`Could not verify a fresh snapshot: ${error.message || 'network error'}. The last loaded records remain available.`, 'error');
      if (options.force) toast('Feed check failed. Retrying automatically.', 'warning');
    } finally {
      polling = false;
      button.disabled = false;
      hideLoader();
    }
  }

  function renderDetail(id) {
    const record = allRecords.get(id);
    if (!record) {
      toast('Load this date range before opening the full record.', 'warning');
      return;
    }
    const dialog = $('detail-dialog');
    const severity = SEVERITY_ORDER[record.sev] == null ? 'unknown' : record.sev;
    const primary = safeUrl(record.primary_url) || `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
    const score = record.score == null ? 'CVSS score not provided by the available sources' : `CVSS ${Number(record.score).toFixed(1)} · ${severity.toUpperCase()}`;
    const activity = record.date_basis === 'CISA KEV date added'
      ? `CISA added this record to KEV on ${fmtDate(record.kev?.date_added || record.window_date)}.`
      : record.date_basis === 'GitHub advisory publication'
        ? `GitHub advisory published ${fmtDate(record.window_date)}${record.published ? ` · CVE publication ${fmtTimestamp(record.published)}` : ''}.`
        : `Published ${fmtTimestamp(record.published)}${record.modified ? ` · last modified ${fmtTimestamp(record.modified)}` : ''}.`;
    const products = (record.affected || []).length ? (record.affected || []).map((item) => `<div class="detail-product"><strong>${esc([item.vendor, item.product].filter(Boolean).join(' / ') || 'Product')}</strong><span>${esc(item.versions || 'Version details not specified')} · ${esc(item.source || 'Source record')}</span></div>`).join('') : '<p class="detail-description">Affected product/version details were not provided in the available records.</p>';
    const kev = record.kev ? `<section class="detail-section"><h3>Exploitation signal · CISA KEV</h3><div class="kev-callout"><strong>Known exploited vulnerability</strong><p>${esc(record.kev.required_action || 'CISA lists this CVE in the Known Exploited Vulnerabilities catalog.')}${record.kev.due_date ? ` Due date: ${esc(record.kev.due_date)}.` : ''}${record.kev.ransomware ? ` Ransomware campaign use: ${esc(record.kev.ransomware)}.` : ''}</p></div></section>` : '';
    const refs = [...(record.advisories || []).map((item) => ({ label: item.label || 'Security advisory', url: item.url })), ...(record.refs || [])]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index).slice(0, 14);
    const links = [{ label: record.sources?.includes('NVD') ? 'Primary record · NVD' : 'CVE Program record', url: primary }, ...refs]
      .filter((item, index, all) => safeUrl(item.url) && all.findIndex((other) => other.url === item.url) === index);
    $('detail-content').innerHTML = `<div class="detail-id-row"><a class="cve-id" href="${esc(primary)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a><span class="severity-badge ${esc(severity)}">${esc(severity)}</span>${record.kev ? '<span class="kev-badge">KNOWN EXPLOITED</span>' : ''}</div>
      <h2 id="detail-title">${esc(record.title || id)}</h2><p class="detail-score">${esc(score)} · ${esc(activity)}</p><p class="detail-description">${esc(record.desc || 'No summary has been published by the available sources.')}</p>
      <section class="detail-section"><h3>Affected products and versions</h3><div class="detail-products">${products}</div></section>
      ${kev}
      <section class="detail-section"><h3>Source records and references</h3><div class="detail-links">${links.map((item) => `<a href="${esc(safeUrl(item.url))}" target="_blank" rel="noopener noreferrer">↗ ${esc(item.label || 'Reference')}</a>`).join('') || '<span class="detail-description">No source links provided.</span>'}</div></section>
      <section class="detail-section"><h3>Record attribution</h3><div class="detail-sources">${(record.sources || []).map((source) => `<span class="detail-source">${esc(source)}</span>`).join('') || '<span class="detail-source">CVE record</span>'}</div></section>
      <div class="detail-actions"><button class="card-action" type="button" data-action="copy" data-id="${esc(id)}"><span class="action-icon" aria-hidden="true">⧉</span> Copy CVE ID</button><a class="card-action poc-action" href="${esc(pocUrl(id))}" target="_blank" rel="noopener noreferrer"><span class="action-icon" aria-hidden="true">↗</span> GitHub PoC search <small>UNVERIFIED</small></a></div>`;
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
      state.severity = button.dataset.severity;
      document.querySelectorAll('.severity-filter').forEach((element) => element.classList.toggle('active', element === button));
      visible = PAGE_SIZE;
      render();
    });
    $('sort-select').addEventListener('change', (event) => {
      state.sort = event.target.value;
      render();
      if (state.sort !== 'new' && !rangeDays().every((day) => loadedByDay.has(day))) {
        const generation = ++searchGeneration;
        loadAllSelectedDays(generation).catch(showLoadError);
      }
    });
    $('search-input').addEventListener('input', (event) => {
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
    $('refresh-button').addEventListener('click', () => refresh({ force: true }));
    $('load-more').addEventListener('click', async () => {
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
    setTimeout(hideLoader, 3500);
    try {
      manifest = await fetchManifest();
      lastSnapshotVersion = manifest.generated_at || '';
      lastBrowserCheck = Date.now();
      setDateBounds();
      renderSources();
      renderStats();
      const newest = rangeDays().slice(-2).reverse();
      await loadDays(newest);
      render();
      refreshTimestamp();
      hideLoader();
    } catch (error) {
      $('feed-list').innerHTML = '';
      $('feed-list').setAttribute('aria-busy', 'false');
      $('empty-state').hidden = false;
      $('empty-state').querySelector('strong').textContent = 'The feed is temporarily unavailable.';
      $('empty-state').querySelector('p').textContent = 'This page will retry automatically once the static snapshot is reachable.';
      $('feed-indicator').classList.add('error');
      $('feed-indicator-text').textContent = 'FEED UNAVAILABLE';
      setStatus(`Could not open the feed index: ${error.message || 'network error'}.`, 'error');
      hideLoader();
    }
    window.setInterval(() => refresh(), POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refresh();
    });
  }

  boot();
})();
