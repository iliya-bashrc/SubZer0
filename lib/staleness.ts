/**
 * Snapshot staleness detection (Phase 3).
 *
 * The updater runs every 6 hours. If the newest manifest timestamp is older
 * than 36h, several consecutive scheduled runs have failed — the visitor
 * should be told the data may be outdated. Conservative by design: a missing
 * or unparseable timestamp counts as stale (fail-closed, like the rest of
 * the data layer).
 */
export const STALE_DATA_THRESHOLD_HOURS = 36;

export function isSnapshotStale(
  generatedAt: string | null | undefined,
  nowMs: number = Date.now(),
): boolean {
  if (!generatedAt) return true;
  const t = Date.parse(generatedAt);
  if (Number.isNaN(t)) return true;
  return nowMs - t >= STALE_DATA_THRESHOLD_HOURS * 3600_000;
}

/** Banner copy: short, factual, points at the last successful refresh. */
export function staleBannerCopy(
  generatedAt: string | null | undefined,
  nowMs: number = Date.now(),
): string {
  let when = 'an unknown time';
  if (generatedAt) {
    const d = new Date(generatedAt);
    if (!Number.isNaN(d.getTime())) when = d.toISOString().slice(0, 10);
  }
  return (
    `Data may be outdated — the last successful update finished on ${when}. ` +
    'Verified records are still shown with full integrity checks.'
  );
}
