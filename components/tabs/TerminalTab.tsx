'use client';

import { Terminal } from '@/components/terminal/Terminal';

/** Kept for compatibility; AppShell now mounts Terminal directly. */
export function TerminalTab() {
  return (
    <div className="flex h-full items-start justify-center overflow-y-auto overscroll-contain px-4 py-6"
         style={{ touchAction: 'pan-y' }}>
      <Terminal />
    </div>
  );
}
