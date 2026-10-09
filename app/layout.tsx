import type { Metadata } from 'next';
import { Inter, Inter_Tight, JetBrains_Mono } from 'next/font/google';
import { AppShell } from '@/components/shell/AppShell';
import { SnapshotProvider } from '@/components/SnapshotProvider';
import { SiteFooter } from '@/components/shell/SiteFooter';
import './globals.css';

/* STEP 1 — typography: Inter (UI), Inter Tight (display headings),
   JetBrains Mono (data values only). Swapped by next/font, no FOUT. */
const inter = Inter({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-inter',
  display: 'swap',
});
const interTight = Inter_Tight({
  subsets: ['latin'],
  weight: ['600', '700'],
  variable: '--font-inter-tight',
  display: 'swap',
});
const jetbrains = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-jetbrains',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SubZer0 — CVE Intelligence Platform',
  description: 'CVE intelligence & vulnerability research. Educational security research by @BugCod3 and @RootAccessClub.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${interTight.variable} ${jetbrains.variable}`}>
      <body>
        <SnapshotProvider>
          {children}
          {/* Section 12: global footer — always visible, never a modal backdrop. */}
          <SiteFooter />
        </SnapshotProvider>
      </body>
    </html>
  );
}
