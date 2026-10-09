/**
 * SubZer0 data layer — typed access to the verified snapshot published by
 * scripts/update_data.py (manifest + day shards + search index + EPSS sidecar).
 *
 * Integrity model preserved from the verified engine: every fetched asset is
 * SHA-256-checked against the manifest before its content is trusted.
 * If any check fails, the layer fails closed (throws) rather than serving
 * unverified data.
 */

export const SNAPSHOT_BASE = '/snapshot';

export interface ManifestDay {
  date: string;
  count: number;
  bytes: number;
  sha256: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
  unknown: number;
  exploited: number;
  path: string;
}

export interface Manifest {
  schema_version: number;
  generated_at: string;
  last_successful_update: string;
  window: { days: number; start: string; end: string; timezone: string; semantics: string };
  complete: boolean;
  totals: {
    cves: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    none: number;
    unknown: number;
    known_exploited: number;
  };
  coverage: Record<string, unknown>;
  sources: { name: string; url: string }[];
  source_status: {
    name: string;
    ok: boolean;
    pages?: number;
    records?: number;
    advisories?: number;
    catalog_records?: number;
    scores?: number;
    score_date?: string;
    checked_at: string;
    note?: string;
  }[];
  days: ManifestDay[];
  epss: { path: string; bytes: number; sha256: string; score_date: string; scored_cves: number; records: number };
  overview: { path: string; bytes: number; sha256: string; count: number };
  search_index: { path: string; bytes: number; sha256: string; count: number };
  shard_map: { path: string; bytes: number; sha256: string; count: number };
}

/** search_index.json tuple (schema v1, producer-defined order) */
export type IndexTuple = [
  id: string,
  title: string,
  sev: 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown',
  score: number,
  kev: 0 | 1,
  epss: number | null,
  activity_date: string,
  published_date: string,
  products: string,
];

export interface CveListItem {
  id: string;
  title: string;
  sev: IndexTuple[2];
  score: number;
  kev: boolean;
  epss: number | null;
  activityDate: string;
  publishedDate: string;
  products: string;
}

export interface CveRef {
  label: string;
  url: string;
  source?: string;
  tags?: string[];
}

export interface CveAffected {
  vendor: string;
  product: string;
  versions?: string;
  source?: string;
  cpe?: string;
}

export interface CveRecord {
  id: string;
  title: string;
  desc: string;
  score: number | null;
  sev: IndexTuple[2];
  published: string;
  modified: string;
  window_date: string;
  activity_at: string;
  date_basis: string;
  affected: CveAffected[];
  refs: CveRef[];
  related_cves?: string[];
  advisories?: { label: string; url: string }[];
  sources?: string[];
  kev?: {
    date_added: string;
    vendor: string;
    product: string;
    due_date?: string;
    required_action?: string;
    ransomware?: string;
  } | null;
  primary_url?: string;
  /** EPSS score is joined client-side from the verified epss.json sidecar. */
  epss?: number | null;
}

export function toListItem(t: IndexTuple): CveListItem {
  return {
    id: t[0],
    title: t[1],
    sev: t[2],
    score: t[3],
    kev: t[4] === 1,
    epss: t[5],
    activityDate: t[6],
    publishedDate: t[7],
    products: t[8],
  };
}

/* ------------------------------------------------------------------ */
/* Integrity helpers                                                   */
/* ------------------------------------------------------------------ */

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Fetch any snapshot asset and verify its SHA-256. Fails closed. Exported for callers. */
export async function fetchVerifiedJson(path: string, expected: string): Promise<unknown> {
  const res = await fetch(path, { cache: 'force-cache' });
  if (!res.ok) throw new Error(`Snapshot asset unavailable: ${path} (${res.status})`);
  const buf = await res.arrayBuffer();
  const hex = await sha256Hex(buf);
  if (hex.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`Integrity check failed for ${path}`);
  }
  const text = new TextDecoder().decode(buf);
  return JSON.parse(text);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

export async function loadManifest(): Promise<Manifest> {
  const res = await fetch(`${SNAPSHOT_BASE}/manifest.json`, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`Manifest unavailable (${res.status})`);
  return (await res.json()) as Manifest;
}

export async function loadSearchIndex(manifest: Manifest): Promise<IndexTuple[]> {
  return (await fetchVerifiedJson(
    `${SNAPSHOT_BASE}/data/search_index.json`,
    manifest.search_index.sha256,
  )) as IndexTuple[];
}

export async function loadDayShard(manifest: Manifest, date: string): Promise<CveRecord[]> {
  const day = manifest.days.find((d) => d.date === date);
  if (!day) throw new Error(`No verified shard for ${date}`);
  const shard = (await fetchVerifiedJson(
    `${SNAPSHOT_BASE}/${day.path}`,
    day.sha256,
  )) as Record<string, CveRecord>;
  return Object.values(shard);
}

/** Full CVE lookup: fetch the owning day shard, verify, extract the record. */
export async function getCve(manifest: Manifest, shardMap: Record<string, string>, id: string): Promise<CveRecord> {
  const date = shardMap[id];
  if (!date) throw new Error(`Unknown CVE id: ${id}`);
  const records = await loadDayShard(manifest, date);
  const record = records.find((r) => r.id === id);
  if (!record) throw new Error(`CVE ${id} not found in verified shard ${date}`);
  return record;
}

/* ------------------------------------------------------------------ */
/* Search + filters (Section 8 data contract)                          */
/* ------------------------------------------------------------------ */

export interface Filters {
  severities: Set<IndexTuple[2]>;
  kev: 'any' | 'yes' | 'no';
  epssMin: number; // 0.0 – 1.0
  poc: 'any' | 'yes' | 'no';
  publishedFrom: string | null; // YYYY-MM-DD
  publishedTo: string | null;
}

export const DEFAULT_FILTERS: Filters = {
  severities: new Set(),
  kev: 'any',
  epssMin: 0,
  poc: 'any',
  publishedFrom: null,
  publishedTo: null,
};

/**
 * Full-text search over the verified index (id, title, products) + filters.
 * Runs on the main thread against the in-memory index (15k rows is fine);
 * callers should pass a useDeferredValue query.
 */
export function search(
  index: CveListItem[],
  query: string,
  filters: Filters,
  pocIds: Set<string> | null,
): CveListItem[] {
  const q = query.trim().toLowerCase();
  const terms = q.length > 0 ? q.split(/\s+/) : [];
  const out: CveListItem[] = [];
  for (const item of index) {
    if (filters.severities.size > 0 && !filters.severities.has(item.sev)) continue;
    if (filters.kev === 'yes' && !item.kev) continue;
    if (filters.kev === 'no' && item.kev) continue;
    if (item.epss == null || item.epss < filters.epssMin) {
      if (filters.epssMin > 0) continue;
    }
    if (filters.poc !== 'any' && pocIds) {
      const has = pocIds.has(item.id);
      if (filters.poc === 'yes' && !has) continue;
      if (filters.poc === 'no' && has) continue;
    }
    if (filters.publishedFrom && item.publishedDate < filters.publishedFrom) continue;
    if (filters.publishedTo && item.publishedDate > filters.publishedTo) continue;
    if (terms.length > 0) {
      const hay = `${item.id} ${item.title} ${item.products}`.toLowerCase();
      if (!terms.every((t) => hay.includes(t))) continue;
    }
    out.push(item);
  }
  return out;
}
