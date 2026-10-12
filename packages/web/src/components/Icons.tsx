import { useId, type SVGProps } from 'react';

type P = SVGProps<SVGSVGElement> & { size?: number };
const base = (size: number, p: P) => ({ width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true, ...p });

export const I = {
  grid: ({ size = 20, ...p }: P) => <svg {...base(size, p)}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></svg>,
  overview: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 10h18M9 10v10" /></svg>,
  findings: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></svg>,
  components: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5" /></svg>,
  evidence: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M7 3h7l5 5v13H7z" /><path d="M14 3v5h5M10 13h6M10 17h6" /></svg>,
  reports: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 14l3-3 2 2 3-4M8 18h8" /></svg>,
  settings: ({ size = 20, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z" /></svg>,
  help: ({ size = 20, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 015 0c0 1.5-2.5 2-2.5 3.5M12 17h.01" /></svg>,
  refresh: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M21 12a9 9 0 11-3-6.7" /><path d="M21 3v6h-6" /></svg>,
  arrow: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M5 12h14M13 6l6 6-6 6" /></svg>,
  chevron: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M9 6l6 6-6 6" /></svg>,
  check: ({ size = 14, ...p }: P) => <svg {...base(size, p)}><path d="M5 12l4 4L19 7" /></svg>,
  info: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>,
  alert: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></svg>,
  clock: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>,
  eye: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></svg>,
  doc: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M7 3h7l5 5v13H7z" /><path d="M14 3v5h5M10 13h6M10 17h6" /></svg>,
  cube: ({ size = 28, ...p }: P) => <svg {...base(size, p)}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5" /></svg>,
  close: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M6 6l12 12M18 6L6 18" /></svg>,
  lock: ({ size = 14, ...p }: P) => <svg {...base(size, p)}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 018 0v4" /></svg>,
  unlock: ({ size = 14, ...p }: P) => <svg {...base(size, p)}><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 017.7-1.5" /></svg>,
  download: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M12 4v11M7 10l5 5 5-5M4 20h16" /></svg>,
  plus: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M12 5v14M5 12h14" /></svg>,
  trash: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" /></svg>,
  user: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0116 0" /></svg>,
  users: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0113 0M16 4.5a3.5 3.5 0 010 7M21.5 20a6.5 6.5 0 00-4.5-6.2" /></svg>,
  key: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><circle cx="8" cy="15" r="4.5" /><path d="M11.5 11.5L20 3M16 7l2.5 2.5M13.5 9.5l2 2" /></svg>,
  shield: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z" /><path d="M9 12l2 2 4-4" /></svg>,
  scale: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3v18M5 21h14M3 7h18M6 7l-3 7a3 3 0 006 0zM18 7l-3 7a3 3 0 006 0z" /></svg>,
  flag: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M5 21V4h11l-1.5 4L16 12H5" /></svg>,
  logout: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M10 4H5v16h5M14 8l5 4-5 4M19 12H9" /></svg>,
  copy: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5h10" /></svg>,
  mail: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 7l9 6 9-6" /></svg>,
  edit: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><path d="M4 20h4l10-10-4-4L4 16zM13 7l4 4" /></svg>,
  portfolio: ({ size = 20, ...p }: P) => <svg {...base(size, p)}><rect x="3" y="7" width="18" height="13" rx="2" /><path d="M9 7V5a2 2 0 012-2h2a2 2 0 012 2v2M3 12h18" /></svg>,
  list: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" /></svg>,
  login: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M14 4h5v16h-5M4 12h11M11 8l4 4-4 4" /></svg>,
  chevronDown: ({ size = 14, ...p }: P) => <svg {...base(size, p)}><path d="M6 9l6 6 6-6" /></svg>,
  calendar: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><rect x="3" y="5" width="18" height="16" rx="2" /><path d="M3 10h18M8 3v4M16 3v4" /></svg>,
  decide: ({ size = 18, ...p }: P) => <svg {...base(size, p)}><path d="M12 3v4M12 7l-6 5M12 7l6 5" /><circle cx="6" cy="16" r="3" /><circle cx="18" cy="16" r="3" /></svg>,
  map: ({ size = 20, ...p }: P) => <svg {...base(size, p)}><circle cx="5" cy="6" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="M7.2 7.2l3.6 8.6M16.8 7.2l-3.6 8.6M7.5 6h9" /></svg>,
  globe: ({ size = 16, ...p }: P) => <svg {...base(size, p)}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z" /></svg>,
};

/** The brand mark: a bold gradient N whose diagonal reads as a forward chevron. */
export function Wordmark({ size = 28 }: { size?: number }) {
  const id = useId().replace(/[^a-zA-Z0-9]/g, '');
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" aria-hidden="true">
      <defs>
        <linearGradient id={`nf-${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#60a5fa" />
          <stop offset="0.55" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#1d4ed8" />
        </linearGradient>
      </defs>
      <path d="M4 78V2h18l34 46V2h18v76H58L22 32v46z" fill={`url(#nf-${id})`} />
    </svg>
  );
}
