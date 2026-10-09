/**
 * SubZer0 — canonical copyright / disclaimer / version constants (Section 12).
 * English is the canonical language; Persian localization is a future feature.
 */

export const COPYRIGHT = {
  year: 2026,
  holder: 'SubZer0',
  authors: ['@BugCod3', '@RootAccessClub'],
  line: '© 2026 SubZer0 — by @BugCod3 & @RootAccessClub. All rights reserved.',
} as const;

export const DISCLAIMER =
  'SubZer0 is built for educational and ethical security research only. ' +
  'Exploit and payload references are provided for learning purposes. ' +
  'Do not use against systems you do not own or have explicit permission to test.';

export const VERSION = 'v1.0.0';

/** Reserved for the future share/export feature (Section 12, integration point 3). */
export interface ExportMeta {
  exportedAt: string | null; // ISO 8601
  exportedBy: string | null; // handle of the exporting user
}
