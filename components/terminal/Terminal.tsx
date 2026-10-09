'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useReducedMotion } from 'framer-motion';
import { useIsMobile } from '@/lib/useIsMobile';

const TYPE_SPEED = 45;     // Section 6 canonical
const BOOT_DELAY = 700;    // Section 6 canonical
const REDIRECT_DELAY = 1000; // Section 6 canonical

/**
 * Terminal (Section 6). Desktop: framed window card. Mobile: app-style
 * full-height surface — no fake window chrome, command chips docked in
 * the thumb zone above the bottom tab bar.
 * Canonical command semantics unchanged:
 * ./info ./help ./bugcod3 ./rootaccessclub ./clear
 */

const ASCII_ART = `███████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗
██╔════╝██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═████╗
███████╗██║   ██║██████╔╝  ███╔╝ █████╗  ██████╔╝██║██╔██║
╚════██║██║   ██║██╔══██╗ ███╔╝  ██╔══╝  ██╔══██╗████╔╝██║
███████║╚██████╔╝██████╔╝███████╗███████╗██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ `;

type CmdDef = { name: string; description: string; href?: string };

const COMMANDS: CmdDef[] = [
  { name: './info',           description: 'Display platform information' },
  { name: './help',           description: 'List available commands' },
  { name: './bugcod3',        description: 'Open @BugCod3 on Telegram',        href: 'https://t.me/BugCod3' },
  { name: './rootaccessclub', description: 'Open @RootAccessClub on Telegram', href: 'https://t.me/RootAccessClub' },
  { name: './clear',          description: 'Clear terminal buffer' },
];

type Block =
  | { id: string; type: 'prompt'; text: string }
  | { id: string; type: 'ascii' }
  | { id: string; type: 'info' }
  | { id: string; type: 'help' };

type Phase = 'boot' | 'ready' | 'executing';

let _uid = 0;
const nextId = () => `b-${++_uid}`;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function Terminal() {
  const isMobile = useIsMobile();
  // null on first client paint: render the desktop framing (matches SSR output).
  return isMobile ? <MobileTerminal /> : <DesktopTerminal />;
}

/* ============ desktop: framed window (original behavior) ============ */

function DesktopTerminal() {
  const { Buffer, CommandBar } = useTerminalCore();
  return (
    <div className="flex h-full items-start justify-center overflow-y-auto overscroll-contain px-4 py-10"
         style={{ touchAction: 'pan-y' }}>
      <div className="w-full max-w-4xl mx-auto rounded-xl overflow-hidden
                      border border-line bg-bg-elevated">
        {/* slim header strip — no traffic-light chrome */}
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-line">
          <span className="text-[11px] text-ink-3">user@subzero — tty1</span>
          <span className="flex items-center gap-1.5 text-[10px] font-medium text-medium">
            <span className="h-1.5 w-1.5 rounded-full bg-medium" />
            LIVE
          </span>
        </div>
        <Buffer height={520} />
        <CommandBar framed />
      </div>
    </div>
  );
}

/* ============ mobile: app-style full-height terminal ============ */

function MobileTerminal() {
  const { Buffer, CommandBar } = useTerminalCore();
  return (
    <div className="flex h-full flex-col bg-bg">
      {/* slim status strip replaces the faux macOS chrome (dead weight on a phone) */}
      <div className="flex items-center justify-between border-b border-line-soft px-4 py-2">
        <span className="font-mono text-[11px] text-ink-3">user@subzero — tty1</span>
        <span className="flex items-center gap-1.5 text-[10px] font-medium text-medium">
          <span className="h-1.5 w-1.5 rounded-full bg-medium" />
          LIVE
        </span>
      </div>

      <Buffer className="min-h-0 flex-1" />

      {/* command chips docked in the thumb zone, respecting the home indicator */}
      <div className="border-t border-line-soft bg-bg-raised/60 px-3 pt-2.5
                      pb-[calc(0.625rem+env(safe-area-inset-bottom,0px))]">
        <CommandBar />
      </div>
    </div>
  );
}

/* ============ shared terminal logic ============ */

function useTerminalCore() {
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [typed, setTyped] = useState('');
  const [phase, setPhase] = useState<Phase>('boot');
  const scrollRef = useRef<HTMLDivElement>(null);
  const bootedRef = useRef(false);
  const reduceMotion = useReducedMotion();
  const typeDelay = reduceMotion ? 0 : TYPE_SPEED;

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [blocks, typed]);

  const typeText = useCallback(async (text: string, cancel: { v: boolean }) => {
    setTyped('');
    for (let i = 1; i <= text.length; i++) {
      if (cancel.v) return;
      setTyped(text.slice(0, i));
      await sleep(typeDelay);
    }
  }, [typeDelay]);

  useEffect(() => {
    if (bootedRef.current) return;
    bootedRef.current = true;
    const cancel = { v: false };
    (async () => {
      await sleep(reduceMotion ? 0 : BOOT_DELAY);
      if (cancel.v) return;
      await typeText('./info', cancel);
      if (cancel.v) return;
      setBlocks((b) => [...b, { id: nextId(), type: 'prompt', text: './info' }]);
      setTyped('');
      await sleep(250);
      setBlocks((b) => [...b, { id: nextId(), type: 'ascii' }]);
      await sleep(reduceMotion ? 0 : 700);
      setBlocks((b) => [...b, { id: nextId(), type: 'info' }]);
      await sleep(300);
      setPhase('ready');
    })();
    return () => { cancel.v = true; };
  }, [typeText]);

  const runCommand = useCallback(
    async (cmd: CmdDef) => {
      if (phase !== 'ready') return;
      setPhase('executing');
      await typeText(cmd.name, { v: false });
      setBlocks((b) => [...b, { id: nextId(), type: 'prompt', text: cmd.name }]);
      setTyped('');
      await sleep(200);
      if (cmd.name === './clear') { setBlocks([]); setPhase('ready'); return; }
      if (cmd.name === './help')  { setBlocks((b) => [...b, { id: nextId(), type: 'help' }]); setPhase('ready'); return; }
      if (cmd.name === './info')  {
        setBlocks((b) => [...b, { id: nextId(), type: 'ascii' }]);
        await sleep(500);
        setBlocks((b) => [...b, { id: nextId(), type: 'info' }]);
        setPhase('ready');
        return;
      }
      if (cmd.href) { await sleep(REDIRECT_DELAY); window.location.href = cmd.href; return; }
      setPhase('ready');
    },
    [phase, typeText]
  );

  function Buffer({ height, className = '' }: { height?: number; className?: string }) {
    return (
      <div ref={scrollRef}
           className={`terminal-scroll px-4 py-4 font-mono text-[13px]
                      leading-relaxed text-ink/90 overflow-y-auto ${className}`}
           style={{ ...(height ? { height } : {}), touchAction: 'pan-y' }}>
        {blocks.map((b) => <BlockView key={b.id} block={b} />)}
        <Line><Prompt /><span>{typed}</span><Cursor /></Line>
      </div>
    );
  }

  function CommandBar({ framed = false }: { framed?: boolean }) {
    return (
      <div className={framed ? 'border-t border-line bg-bg-elevated px-4 py-3' : ''}>
        <div className="flex flex-wrap gap-2">
          {COMMANDS.filter((c) => c.name !== './info').map((c) => (
            <button key={c.name} onClick={() => runCommand(c)} disabled={phase !== 'ready'}
              className="px-3 py-1.5 rounded-md bg-bg-hover
                         hover:enabled:bg-bg-elevated hover:enabled:text-accent
                         active:enabled:bg-accent-soft active:enabled:text-accent
                         text-[12px] font-mono text-ink-2
                         transition-colors duration-150
                         disabled:opacity-40 disabled:cursor-not-allowed">
              {c.name}
            </button>
          ))}
        </div>
      </div>
    );
  }

  return { Buffer, CommandBar };
}

/* ============ block rendering (shared by both layouts) ============ */

function Line({ children }: { children: React.ReactNode }) {
  return <div className="flex items-start whitespace-pre-wrap break-words">{children}</div>;
}
function Prompt() {
  return (<>
    <span className="text-medium">user@subzero</span>
    <span className="text-ink-3">:</span>
    <span className="text-accent">~/SubZer0</span>
    <span className="text-ink-3">{'$ '}</span>
  </>);
}
function Cursor() {
  return <span className="terminal-cursor inline-block w-[7px] h-[14px]
                       bg-accent/90 ml-0.5 align-middle" />;
}
function AsciiBlock() {
  // 58 glyph columns: at ~6px/char this is ~350px, so 9px keeps it inside a
  // 360px viewport; wider phones get 10–11px. Horizontal scroll is the fallback.
  return (<pre aria-hidden="true" className="my-2 max-w-full overflow-x-auto text-accent/80
                          text-[9px] xs:text-[10px] sm:text-[11px]
                          leading-[1.1] whitespace-pre select-all">{ASCII_ART}</pre>);
}
function InfoBlock() {
  return (
    <div className="my-3 rounded-lg border border-line bg-bg-elevated p-4">
      {/* Section 12: copyright/disclaimer must also appear in the terminal info block. */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-ink font-semibold">SubZer0</div>
          <div className="text-ink-2 text-[12px]">
            CVE Intelligence &amp; Vulnerability Research
          </div>
        </div>
        <div className="text-[12px] text-ink-3 font-mono">v1.0.0</div>
      </div>
      <div className="my-3 h-px bg-line" />
      <dl className="grid grid-cols-[84px_1fr] gap-y-1.5 text-[12px]">
        <dt className="text-ink-3">Status</dt>
        <dd className="flex items-center gap-2 text-ink font-medium">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full
                             rounded-full bg-medium opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-medium" />
          </span>
          ONLINE
        </dd>
        <dt className="text-ink-3">Creators</dt>
        <dd className="text-ink-2">@BugCod3 · @RootAccessClub</dd>
        <dt className="text-ink-3">Purpose</dt>
        <dd className="text-ink-2">Educational security research</dd>
      </dl>
      <div className="mt-3 select-text font-mono text-[11px] text-ink-3">
        © 2026 SubZer0 · Educational use only
      </div>
    </div>
  );
}
function HelpBlock() {
  return (
    <div className="my-2 space-y-1 text-[12px]">
      <div className="text-ink-3">Available commands:</div>
      {COMMANDS.map((c) => (
        <div key={c.name} className="grid grid-cols-[132px_1fr] gap-3 sm:grid-cols-[190px_1fr]">
          <span className="text-accent">{c.name}</span>
          <span className="text-ink-2">{c.description}</span>
        </div>
      ))}
    </div>
  );
}
function BlockView({ block }: { block: Block }) {
  switch (block.type) {
    case 'prompt': return <Line><Prompt /><span>{block.text}</span></Line>;
    case 'ascii':  return <AsciiBlock />;
    case 'info':   return <InfoBlock />;
    case 'help':   return <HelpBlock />;
  }
}
