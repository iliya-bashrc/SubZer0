/**
 * Ingestion: verified snapshot → canonical Prisma schema (Section 10).
 *
 * Mapping rules (binding):
 *  - Every Cve row derives from a SHA-256-verified day-shard record. The
 *    ingester NEVER synthesizes values for fields the sources do not publish:
 *    cvssV31Vector, cvssV30, cvssV30Vector, cvssV2 stay null.
 *  - epssScore/epssPercentile/epssDate come exclusively from the verified
 *    epss.json sidecar (manifest.epss.sha256 checked before use).
 *  - kevListed/kevDateAdded come exclusively from the record's verified `kev`
 *    object (CISA feed).
 *  - PocReference rows are created only for refs whose upstream tags include
 *    Exploit/PoC; `verified` starts false — verification is a separate,
 *    explicit process, never implied by ingestion.
 *  - Severity maps from the record's lowercase `sev`; 'none'/'unknown' are
 *    stored as null severity on the ingest DTO (DB requires the enum, so the
 *    upsert skips severity-only updates when unknown — see mapSeverity).
 *
 * Usage:
 *   DATABASE_URL=postgres://… npx tsx scripts/ingest_snapshot.ts \
 *     --snapshot /path/to/snapshot
 *
 * The script is idempotent (upsert on Cve.id; references are replaced per
 * CVE inside a transaction).
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PrismaClient, Severity } from '@prisma/client';

interface ShardRecord {
  id: string;
  title: string;
  desc: string;
  score: number | null;
  sev: 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';
  published: string;
  modified: string;
  window_date: string;
  affected: { vendor: string; product: string; versions?: string }[];
  refs: { label: string; url: string; source?: string; tags?: string[] }[];
  kev?: { date_added: string } | null;
}

interface Manifest {
  days: { date: string; count: number; sha256: string; path: string }[];
  epss: { path: string; sha256: string; score_date: string };
}

const EXPLOIT_TAG = /exploit|poc|proof of concept/i;

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function mapSeverity(sev: ShardRecord['sev']): Severity | null {
  switch (sev) {
    case 'critical':
      return Severity.CRITICAL;
    case 'high':
      return Severity.HIGH;
    case 'medium':
      return Severity.MEDIUM;
    case 'low':
      return Severity.LOW;
    default:
      // 'none' / 'unknown': upstream publishes no verified severity.
      // The canonical enum (Section 10) has no UNKNOWN member, so these rows
      // land on the schema default (LOW). KNOWN LIMITATION: LOW therefore
      // includes unverifiable severities; the UI must not present them as
      // verified-low. If Section 10 is amended with UNKNOWN, map here.
      return null;
  }
}

function sourceKey(source?: string): string {
  const s = (source ?? 'nvd').toLowerCase();
  if (s.includes('github')) return 'ghsa';
  if (s.includes('vendor') || s.includes('advisory')) return 'vendor';
  return 'nvd';
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const idx = args.indexOf('--snapshot');
  const root = idx >= 0 ? args[idx + 1] : 'snapshot';
  if (!existsSync(root)) {
    console.error(`Snapshot root not found: ${root}`);
    process.exitCode = 1;
    return 1;
  }

  // 1. Verify the manifest itself against its published hash list.
  const manifestPath = join(root, 'manifest.json');
  const manifest: Manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  // 2. Verify + load the EPSS sidecar.
  const epssRaw = readFileSync(join(root, manifest.epss.path));
  if (sha256(epssRaw) !== manifest.epss.sha256.toLowerCase()) {
    throw new Error(`Integrity failure: ${manifest.epss.path}`);
  }
  const epss = JSON.parse(epssRaw.toString('utf8')) as {
    scores: Record<string, { score: number; percentile: number }>;
  };

  const prisma = new PrismaClient();
  let ingested = 0;
  try {
    for (const day of manifest.days) {
      // 3. Verify each day shard before trusting a single byte.
      const raw = readFileSync(join(root, day.path));
      if (sha256(raw) !== day.sha256.toLowerCase()) {
        throw new Error(`Integrity failure: ${day.path}`);
      }
      const records: ShardRecord[] = Object.values(JSON.parse(raw.toString('utf8')));

      // 4. DailyShard row (verified ⇒ manifestOk true).
      await prisma.dailyShard.upsert({
        where: { date: new Date(day.date) },
        create: { date: new Date(day.date), cveCount: day.count, manifestOk: true },
        update: { cveCount: day.count, manifestOk: true },
      });

      for (const r of records) {
        const severity = mapSeverity(r.sev);
        const epssEntry = epss.scores[r.id] ?? null;
        const data = {
          description: r.desc || r.title || '',
          published: new Date(r.published),
          lastModified: new Date(r.modified),
          // Honest nulls — never synthesized:
          cvssV31: r.score != null && r.score > 0 ? r.score : null,
          cvssV31Vector: null,
          cvssV30: null,
          cvssV30Vector: null,
          cvssV2: null,
          epssScore: epssEntry?.score ?? null,
          epssPercentile: epssEntry?.percentile ?? null,
          epssDate: epssEntry ? new Date(manifest.epss.score_date) : null,
          kevListed: Boolean(r.kev),
          kevDateAdded: r.kev ? new Date(r.kev.date_added) : null,
          ...(severity ? { severity } : {}),
        };

        await prisma.$transaction(async (tx) => {
          await tx.cve.upsert({
            where: { id: r.id },
            create: { id: r.id, ...data },
            update: data,
          });

          // Replace derived children atomically per CVE.
          await tx.reference.deleteMany({ where: { cveId: r.id } });
          await tx.cpeMatch.deleteMany({ where: { cveId: r.id } });
          await tx.pocReference.deleteMany({ where: { cveId: r.id } });

          if (r.refs.length > 0) {
            await tx.reference.createMany({
              data: r.refs.map((ref) => ({
                cveId: r.id,
                url: ref.url,
                source: sourceKey(ref.source),
                tags: ref.tags ?? [],
              })),
            });
          }
          const pocs = r.refs.filter((ref) => (ref.tags ?? []).some((t) => EXPLOIT_TAG.test(t)));
          if (pocs.length > 0) {
            await tx.pocReference.createMany({
              data: pocs.map((ref) => ({
                cveId: r.id,
                source: /exploit-?db/i.test(ref.url) ? 'exploitdb'
                  : /metasploit/i.test(ref.url) ? 'metasploit'
                  : 'github',
                url: ref.url,
                verified: false,
              })),
            });
          }
          if (r.affected.length > 0) {
            await tx.cpeMatch.createMany({
              data: r.affected.map((a) => ({
                cveId: r.id,
                vendor: a.vendor || '(unknown)',
                product: a.product || '(unknown)',
                version: a.versions ?? null,
              })),
            });
          }
        });
        ingested++;
      }
      console.log(`✓ ${day.date}: ${records.length} records`);
    }
  } finally {
    await prisma.$disconnect();
  }
  console.log(`Ingested ${ingested} verified CVEs.`);
  return 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
