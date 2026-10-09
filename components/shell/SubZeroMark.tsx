/**
 * SubZer0 logo mark — ice crystal, 20px, --accent. The only custom SVG
 * allowed by the redesign spec (everywhere else: Lucide).
 */
export function SubZeroMark({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="text-accent shrink-0"
    >
      {/* six-armed ice crystal */}
      <path d="M12 2v20" />
      <path d="m4 7 16 10" />
      <path d="m20 7L4 17" />
      {/* small branches on the vertical arm */}
      <path d="m12 6-2.5-1.8M12 6l2.5-1.8" />
      <path d="m12 18-2.5 1.8M12 18l2.5 1.8" />
    </svg>
  );
}
