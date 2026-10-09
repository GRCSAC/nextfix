import type { Health } from '../api.ts';
import { I } from '../components/Icons.tsx';

export type Theme = 'dark' | 'light' | 'system';

export function applyTheme(t: Theme) {
  const root = document.documentElement;
  if (t === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', t);
}

export function readTheme(): Theme {
  try {
    const v = localStorage.getItem('nextfix.theme');
    return v === 'light' || v === 'system' ? v : 'dark';
  } catch {
    return 'dark';
  }
}

export function Settings({ theme, onTheme, health }: { theme: Theme; onTheme: (t: Theme) => void; health?: Health }) {
  return (
    <div className="stack">
      <section className="card">
        <h2>Appearance</h2>
        <div className="seg" role="group" aria-label="Theme">
          {(['dark', 'light', 'system'] as Theme[]).map((t) => (
            <button key={t} type="button" aria-pressed={theme === t} onClick={() => onTheme(t)}>{t === 'system' ? 'Match OS' : t.charAt(0).toUpperCase() + t.slice(1)}</button>
          ))}
        </div>
      </section>
      <section className="card">
        <h2>Data</h2>
        <dl className="kv">
          <dt>Scan history</dt><dd className="mono">{health?.dbPath ?? '—'}</dd>
          <dt>Advisory cache</dt><dd className="mono">{health?.cachePath ?? '—'}</dd>
          <dt>Version</dt><dd>NextFix {health?.version ?? ''}</dd>
        </dl>
        <p className="hint">Scans run on this machine. The only outbound requests are advisory lookups to OSV, FIRST EPSS and CISA KEV, and those are cached locally.</p>
      </section>
      <section className="card">
        <h2>Team access</h2>
        <p className="sub">Single sign-on, roles and an audit log are on the roadmap. Until then, start the server with <code>--host 0.0.0.0</code> to share the dashboards on a trusted network.</p>
        <p className="hint"><I.info /> Sharing without authentication exposes scan results to anyone on that network.</p>
      </section>
    </div>
  );
}
