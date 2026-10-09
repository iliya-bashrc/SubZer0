'use client';

import dynamic from 'next/dynamic';
import { useCallback, useRef, useState } from 'react';
import { Swiper, SwiperSlide } from 'swiper/react';
import { A11y, Keyboard, Mousewheel, Pagination } from 'swiper/modules';
import type { Swiper as SwiperClass } from 'swiper';
import { useReducedMotion } from 'framer-motion';

import 'swiper/css';
import 'swiper/css/pagination';

import { useGlobalHotkeys, requestSearchFocus } from '@/lib/hotkeys';
import { Terminal } from '@/components/terminal/Terminal';
import { SubZeroMark } from '@/components/shell/SubZeroMark';

/** Code splitting (Section 11): each tab is a separate chunk, client-only. */
const Briefing = dynamic(() => import('@/components/tabs/Briefing').then((m) => m.Briefing), {
  ssr: false,
});
const Research = dynamic(() => import('@/components/tabs/Research').then((m) => m.Research), {
  ssr: false,
});
const Dossier = dynamic(() => import('@/components/tabs/Dossier').then((m) => m.Dossier), {
  ssr: false,
});

const TABS = ['Briefing', 'Research', 'Dossier', 'Terminal'] as const;

export function AppShell() {
  const [active, setActive] = useState(0);
  const swiperRef = useRef<SwiperClass | null>(null);
  const reduceMotion = useReducedMotion();

  const goTo = useCallback((index: number) => {
    swiperRef.current?.slideTo(index);
  }, []);

  useGlobalHotkeys({
    onTab: goTo,
    onSearch: () => {
      goTo(1); // Research owns the search field
      requestSearchFocus();
    },
  });

  return (
    <div className="flex h-dvh flex-col text-ink">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <h1 className="visually-hidden">SubZer0 — CVE Intelligence Platform</h1>

      {/* Desktop navbar: 56px, blur, elevated-bg active tab (spec STEP 2) */}
      <nav
        aria-label="Destinations"
        className="relative z-20 hidden h-14 items-center gap-1 border-b border-line
                   bg-[oklch(0.14_0.005_240/0.8)] px-4 backdrop-blur-[20px] sm:flex"
      >
        <span className="mr-3 flex items-center gap-2">
          <SubZeroMark size={20} />
          <span className="font-display text-[15px] font-semibold text-ink">SubZer0</span>
        </span>
        {TABS.map((t, i) => (
          <button
            key={t}
            type="button"
            onClick={() => goTo(i)}
            aria-current={i === active ? 'page' : undefined}
            title="Ctrl+1..4 to switch"
            className={`rounded-md px-3.5 py-2 text-[13px] font-medium transition-colors ${
              i === active
                ? 'bg-bg-raised text-ink'
                : 'text-ink-2 hover:bg-bg-hover hover:text-ink'
            }`}
          >
            {t}
          </button>
        ))}
        <button
          type="button"
          onClick={() => {
            goTo(1);
            requestSearchFocus();
          }}
          title="Search (Ctrl+K)"
          aria-label="Search (Ctrl+K)"
          className="ml-auto rounded-md px-2.5 py-1.5 font-mono text-[11px] text-ink-3
                     transition-colors hover:bg-bg-hover hover:text-ink-2"
        >
          Ctrl+K
        </button>
      </nav>

      <Swiper
        modules={[A11y, Keyboard, Mousewheel, Pagination]}
        onSwiper={(s) => (swiperRef.current = s)}
        onSlideChange={(s) => setActive(s.activeIndex)}
        slidesPerView={1}
        speed={reduceMotion ? 0 : 300}
        threshold={8}
        resistanceRatio={0.7}
        preventClicks
        preventClicksPropagation
        mousewheel={{ forceToAxis: true, sensitivity: 0.6, thresholdDelta: 30 }}
        keyboard={{ enabled: true, onlyInViewport: true }}
        pagination={{ clickable: true, el: '.swiper-pagination-custom' }}
        noSwipingClass="swiper-no-swiping"
        a11y={{
          enabled: true,
          prevSlideMessage: 'Previous destination',
          nextSlideMessage: 'Next destination',
        }}
        className="min-h-0 w-full flex-1"
      >
        <SwiperSlide aria-label="Briefing"><Briefing /></SwiperSlide>
        <SwiperSlide aria-label="Research"><Research /></SwiperSlide>
        <SwiperSlide aria-label="Dossier"><Dossier /></SwiperSlide>
        <SwiperSlide aria-label="Terminal"><Terminal /></SwiperSlide>
      </Swiper>

      <div className="swiper-pagination-custom hidden justify-center gap-2 py-2.5 sm:flex" />

      {/* Mobile: bottom tab bar (kept per user; restyled to navbar language) */}
      <nav
        aria-label="Destinations"
        className="bottom-tabbar relative z-20 flex sm:hidden"
      >
        {TABS.map((t, i) => {
          const on = i === active;
          return (
            <button
              key={t}
              type="button"
              onClick={() => goTo(i)}
              aria-current={on ? 'page' : undefined}
              aria-label={t}
              className={`flex flex-1 flex-col items-center gap-1 py-2 text-[10px]
                          font-medium transition-colors ${
                on ? 'text-accent' : 'text-ink-3 hover:text-ink-2'
              }`}
            >
              <TabIcon name={t} active={on} />
              {t}
            </button>
          );
        })}
      </nav>

      <main id="main-content" className="visually-hidden" tabIndex={-1}>
        {/* Skip-link target: the active destination lives inside the Swiper above. */}
      </main>
    </div>
  );
}

/** Compact 20px line icons (Lucide paths), currentColor so the active tint applies. */
function TabIcon({ name, active }: { name: string; active: boolean }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: '0 0 24 24',
    fill: 'none' as const,
    stroke: 'currentColor',
    strokeWidth: active ? 2 : 1.5,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };
  if (name === 'Briefing') {
    // lucide "layout-dashboard"-like stats glyph
    return (
      <svg {...common}>
        <path d="M4 19V5" />
        <path d="M4 19h16" />
        <path d="M8 19v-6M12 19V8M16 19v-4" />
      </svg>
    );
  }
  if (name === 'Research') {
    return (
      <svg {...common}>
        <circle cx="11" cy="11" r="6" />
        <path d="m20 20-3.5-3.5" />
      </svg>
    );
  }
  if (name === 'Dossier') {
    return (
      <svg {...common}>
        <path d="M6 3h8l4 4v14H6z" />
        <path d="M14 3v4h4" />
        <path d="M9 13h6M9 17h4" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 9 3 3-3 3M12.5 15H17" />
    </svg>
  );
}
