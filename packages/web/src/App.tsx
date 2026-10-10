import { Component as ReactComponent, useCallback, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from 'react';
import { api, type Health, type Integrations, type ListReport, type ScanDiff, type ScanMeta, type ScanReport, type Settings as SettingsValues, type Target, type TicketMap } from './api.ts';
import { I, Wordmark } from './components/Icons.tsx';
import { Overview } from './views/Overview.tsx';
import { Findings } from './views/Findings.tsx';
import { Components } from './views/Components.tsx';
import { Evidence } from './views/Evidence.tsx';
import { Reports } from './views/Reports.tsx';
import { Apps } from './views/Apps.tsx';
import { Settings, applyTheme, readTheme, type Theme } from './views/Settings.tsx';
import { dateTime } from './format.ts';
import './plumbing.css';

type Page = 'overview' | 'findings' | 'components' | 'evidence' | 'reports' | 'apps' | 'settings';
const PAGE_IDS: Page[] = ['overview', 'findings', 'components', 'evidence', 'reports', 'apps', 'settings'];
const PAGES: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <I.overview /> },
  { id: 'findings', label: 'Findings', icon: <I.findings /> },
  { id: 'components', label: 'Components', icon: <I.components /> },
  { id: 'evidence', label: 'Evidence', icon: <I.evidence /> },
  { id: 'reports', label: 'Reports', icon: <I.reports /> },
];

interface Route { page: Page; id?: string; query: Record<string, string> }

/** `#/findings/<id>?decision=Act&tier=reachable&q=lodash`. Anything malformed falls back to the overview. */
function readHash(): Route {
  try {
    const raw = location.hash.replace(/^#\/?/, '');
    const [pathPart, qs] = raw.split('?');
    const [p, ...rest] = (pathPart ?? '').split('/');
    const alias: Record<string, Page> = { exec: 'overview', fix: 'findings' };
    const page = (PAGE_IDS.includes(p as Page) ? p : alias[p ?? ''] ?? 'overview') as Page;
    const query: Record<string, string> = {};
    new URLSearchParams(qs ?? '').forEach((v, k) => { if (v) query[k] = v; });
    return { page, id: rest.length ? decodeURIComponent(rest.join('/')) : undefined, query };
  } catch {
    return { page: 'overview', query: {} };
  }
}

function hashFor(page: Page, id?: string, query?: Record<string, string>) {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(query ?? {})) if (v) clean[k] = v;
  const qs = Object.keys(clean).length ? `?${new URLSearchParams(clean).toString()}` : '';
  return id ? `#/${page}/${encodeURIComponent(id)}${qs}` : `#/${page}${qs}`;
}

/** The list report lacks the advisory text; views written against the engine's ScanReport get it filled as empty. */
function asScanReport(r: ListReport): ScanReport {
  return { ...r, findings: r.findings.map((f) => ({ ...f, advisory: { ...f.advisory, details: '' } })) } as ScanReport;
}

function elapsedLabel(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  if (m >= 60) return `${Math.floor(m / 60)} h ${m % 60} min`;
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

const isAbort = (e: unknown) => e instanceof DOMException && e.name === 'AbortError';
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}

/** Catches render errors anywhere below and offers a reload instead of a blank page. */
class ErrorBoundary extends ReactComponent<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('NextFix dashboard error', error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="hero" role="alert">
          <h1>Something went wrong</h1>
          <p>The dashboard hit an error it could not recover from: {this.state.error.message}</p>
          <button type="button" className="btn primary" onClick={() => location.reload()}><I.refresh /> Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function Dashboard() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<number | null>(() => {
    try { const v = localStorage.getItem('nextfix.target'); return v ? Number(v) : null; } catch { return null; }
  });
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [report, setReport] = useState<ListReport | null>(null);
  const [diff, setDiff] = useState<ScanDiff | undefined>();
  const [route, setRoute] = useState<Route>(readHash);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | undefined>();
  const [settings, setSettings] = useState<SettingsValues | undefined>();
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [now, setNow] = useState(() => Date.now());
  const [cancelling, setCancelling] = useState(false);
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => { applyTheme(theme); try { localStorage.setItem('nextfix.theme', theme); } catch { /* ignore */ } }, [theme]);
  useEffect(() => {
    const onHash = () => setRoute(readHash());
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  }, []);

  const go = useCallback((page: string, id?: string, query?: Record<string, string>) => { location.hash = hashFor(page as Page, id, query); }, []);
  /** Filters live in the hash so reload, share and Back work; `replace` keeps keystrokes out of the history. */
  const setQuery = useCallback((query: Record<string, string>, replace = false) => {
    const r = readHash();
    const hash = hashFor(r.page, r.id, query);
    if (replace) {
      history.replaceState(null, '', hash);
      setRoute(readHash());
    } else if (location.hash !== hash) location.hash = hash;
  }, []);

  const loadTargets = useCallback(async () => {
    const list = await api.targets();
    setTargets(list);
    return list;
  }, []);

  const [tickets, setTickets] = useState<TicketMap>({});
  const [integrations, setIntegrations] = useState<Integrations>({});
  const loadTickets = useCallback(async (id: number) => {
    setTickets(await api.tickets(id).catch(() => ({})));
  }, []);
  const loadIntegrations = useCallback(async () => {
    setIntegrations(await api.integrations().catch(() => ({})));
  }, []);

  // Only the newest load may update the screen: a slower earlier response is abandoned.
  const loadSeq = useRef(0);
  const loadAbort = useRef<AbortController | null>(null);
  const loadTarget = useCallback(async (id: number) => {
    loadAbort.current?.abort();
    const ac = new AbortController();
    loadAbort.current = ac;
    const seq = ++loadSeq.current;
    const current = () => seq === loadSeq.current && !ac.signal.aborted;
    try {
      const [ticketMap, list] = await Promise.all([api.tickets(id, ac.signal).catch((e) => { if (isAbort(e)) throw e; return {}; }), api.scans(id, ac.signal)]);
      if (!current()) return;
      setTickets(ticketMap);
      setScans(list);
      const last = list[list.length - 1];
      if (!last) {
        setReport(null);
        setDiff(undefined);
        return;
      }
      const [r, d] = await Promise.all([api.report(last.id, ac.signal), api.diff(last.id, ac.signal).catch(() => undefined)]);
      if (!current()) return;
      setReport(r);
      setDiff(d);
    } catch (e) {
      if (isAbort(e) || !current()) return;
      throw e;
    }
  }, []);

  const pollHealth = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setNow(Date.now());
      return h;
    } catch {
      return undefined;
    }
  }, []);

  useEffect(() => {
    pollHealth();
    loadIntegrations();
    api.settings().then(setSettings).catch(() => {});
    loadTargets().then((list) => {
      const chosen = list.find((t) => t.id === targetId) ?? list[0];
      if (chosen) {
        setTargetId(chosen.id);
        loadTarget(chosen.id).catch((e) => setError(message(e)));
      } else setTargetId(null);
    }).catch((e) => setError(message(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { try { if (targetId) localStorage.setItem('nextfix.target', String(targetId)); } catch { /* ignore */ } }, [targetId]);

  // While a scan runs (here or on another tab/server) poll every 2 s, otherwise every 30 s; a returning tab polls at once.
  const scanning = health?.scanning ?? null;
  const scanActive = !!busy || scanning !== null;
  useEffect(() => {
    const t = setInterval(() => { if (document.visibilityState !== 'hidden') pollHealth(); }, scanActive ? 2000 : 30_000);
    return () => clearInterval(t);
  }, [scanActive, pollHealth]);
  useEffect(() => {
    const refresh = () => { if (document.visibilityState !== 'hidden') pollHealth(); };
    addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      removeEventListener('focus', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [pollHealth]);
  // A scan started elsewhere has just finished: pick up its results.
  const wasScanning = useRef(false);
  useEffect(() => {
    const is = scanning !== null;
    if (wasScanning.current && !is && !busy) {
      loadTargets().then(() => { if (targetId) return loadTarget(targetId); }).catch((e) => setError(message(e)));
    }
    wasScanning.current = is;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanning !== null, busy]);

  const selectTarget = async (id: number) => {
    setTargetId(id);
    setError(null);
    if (route.page === 'apps' || route.id) go('overview');
    await loadTarget(id).catch((e) => setError(message(e)));
  };

  /** A cancelled scan is news, not an error. */
  const scanFailed = (e: unknown) => {
    const m = message(e);
    if (m === 'Scan cancelled') setNotice('Scan cancelled.');
    else setError(m);
  };

  const addTarget = async (dir: string) => {
    setBusy(`Scanning ${dir}…`);
    setError(null);
    setNotice(null);
    try {
      pollHealth();
      const res = await api.addTarget(dir);
      await loadTargets();
      setTargetId(res.target.id);
      await loadTarget(res.target.id);
      go('overview');
    } catch (e) {
      scanFailed(e);
    } finally {
      setBusy(null);
      pollHealth();
    }
  };

  const removeTarget = async (id: number) => {
    setError(null);
    try {
      await api.removeTarget(id);
      const list = await loadTargets();
      const next = list[0];
      if (id === targetId) {
        setTargetId(next?.id ?? null);
        if (next) await loadTarget(next.id); else { setReport(null); setScans([]); setDiff(undefined); }
      }
    } catch (e) {
      setError(message(e));
    }
  };

  const rescan = async () => {
    if (!targetId) return;
    setBusy('Scanning…');
    setError(null);
    setNotice(null);
    try {
      pollHealth();
      await api.rescan(targetId);
      await loadTargets();
      await loadTarget(targetId);
    } catch (e) {
      scanFailed(e);
    } finally {
      setBusy(null);
      pollHealth();
    }
  };

  const cancelScan = async () => {
    setCancelling(true);
    try {
      await api.cancelScan();
    } catch (e) {
      setError(message(e));
    } finally {
      setCancelling(false);
    }
  };

  const current = targets?.find((t) => t.id === targetId);
  const lastScan = scans[scans.length - 1];
  const viewReport = useMemo(() => (report ? asScanReport(report) : null), [report]);
  const firstSeen = useMemo(() => {
    const out: Record<string, string> = {};
    for (const f of report?.findings ?? []) if (f.firstSeenAt) out[f.id] = f.firstSeenAt;
    return out;
  }, [report]);
  const s = report?.summary;
  const actionable = s ? s.byDecision.Act + s.byDecision.Attend : 0;
  const showTabs = !!current && !!report;

  const scanningName = scanning ? (scanning.targetId === null ? 'on another server' : targets?.find((t) => t.id === scanning.targetId)?.name ?? 'application') : '';
  const scanLabel = busy ?? (scanning ? `Scanning ${scanningName}…` : null);
  const elapsed = scanning ? elapsedLabel(now - Date.parse(scanning.startedAt)) : null;

  const railItems: { id: Page; label: string; icon: React.ReactNode }[] = [
    { id: 'apps', label: 'Apps', icon: <I.grid /> },
    { id: 'settings', label: 'Settings', icon: <I.settings /> },
  ];

  return (
    <div className="shell">
      <a className="skip-link" href="#main" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>Skip to content</a>
      <nav className="rail" aria-label="Sections">
        <a className="rail-brand" href="#/overview" aria-label="NextFix"><Wordmark size={30} /></a>
        {railItems.map((r) => (
          <a key={r.id} className={`rail-item ${route.page === r.id ? 'active' : ''}`} href={hashFor(r.id)}>{r.icon}<span>{r.label}</span></a>
        ))}
        <span className="grow" />
        <a className="rail-item" href="https://github.com/GRCSAC/nextfix#readme" target="_blank" rel="noreferrer"><I.help /><span>Help</span></a>
      </nav>

      <div className="main">
        <header className="topbar">
          <div className="topbar-inner">
            <a className="wordmark" href="#/overview"><Wordmark size={24} /><span>Next<b>Fix</b></span></a>
            {targets && targets.length > 0 && (
              <select className="target-select" aria-label="Application" value={targetId ?? ''} onChange={(e) => selectTarget(Number(e.target.value))}>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name ?? t.dir}</option>)}
              </select>
            )}
            {showTabs && (
              <nav className="tabs" aria-label="Pages">
                {PAGES.map((p) => <a key={p.id} className={route.page === p.id ? 'active' : ''} href={hashFor(p.id)}>{p.icon}<span>{p.label}</span></a>)}
                <a className={`mobile-only ${route.page === 'apps' ? 'active' : ''}`} href={hashFor('apps')}><I.grid size={18} /><span>Apps</span></a>
                <a className={`mobile-only ${route.page === 'settings' ? 'active' : ''}`} href={hashFor('settings')}><I.settings size={18} /><span>Settings</span></a>
              </nav>
            )}
            <span className="grow" />
            <span className="version muted small">v{health?.version ?? ''}</span>
          </div>
        </header>

        <main className="page" id="main" ref={mainRef} tabIndex={-1}>
          {scanLabel && (
            <div className="banner" role="status">
              <span className="spin" aria-hidden="true" />
              <span className="grow">
                {scanLabel}
                {scanning && <span className="banner-stage"> · {scanning.stage}{elapsed ? ` · ${elapsed}` : ''}</span>}
              </span>
              {scanning && scanning.targetId !== null && (
                <button type="button" className="btn small" onClick={cancelScan} disabled={cancelling}>{cancelling ? 'Cancelling…' : 'Cancel'}</button>
              )}
            </div>
          )}
          {notice && <div className="banner" role="status">{notice} <button type="button" className="btn ghost small" onClick={() => setNotice(null)} aria-label="Dismiss"><I.close /></button></div>}
          {error && <div className="banner error-banner" role="alert">{error}</div>}

          {targets === null ? (
            <p className="empty">Loading…</p>
          ) : route.page === 'apps' || !current ? (
            targets.length === 0 && route.page !== 'apps' ? (
              <Welcome onAdd={addTarget} busy={!!busy} />
            ) : (
              <Apps targets={targets} currentId={targetId} busy={!!busy} onSelect={selectTarget} onAdd={addTarget} onRemove={removeTarget} />
            )
          ) : route.page === 'settings' ? (
            <Settings theme={theme} onTheme={setTheme} health={health} integrations={integrations} onIntegrationsChange={loadIntegrations} settings={settings} onSettingsChange={setSettings} />
          ) : !report || !viewReport || !lastScan ? (
            <div className="hero">
              <h1>{current.name ?? current.dir}</h1>
              <p>This application has not been scanned yet.</p>
              <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}><I.refresh /> Run the first scan</button>
            </div>
          ) : (
            <>
              <div className="app-head">
                <span className="icon-box big"><I.cube /></span>
                <div className="grow">
                  <div className="app-title"><h1>{report.target.name ?? report.target.dir}</h1><span className="tag ok"><I.check /> Scanned</span></div>
                  <div className="muted small">Last scan {dateTime(report.generatedAt)} · NextFix v{report.tool.version} · {report.summary.components} components</div>
                </div>
                {s && (
                  <div className="app-summary">
                    <strong>{s.findings} findings across {s.components} components. {actionable} need action.</strong>
                    <span className="muted"> The rest are unreachable, unused, or not shipped, and each one carries a reason you can hand to an auditor.</span>
                  </div>
                )}
                <button type="button" className="btn primary" onClick={rescan} disabled={scanActive}><I.refresh /> {scanActive ? 'Scanning…' : 'Scan again'}</button>
              </div>
              {route.page === 'overview' && <Overview report={viewReport} targetId={current.id} scans={scans} diff={diff} go={go} />}
              {route.page === 'findings' && <Findings report={viewReport} firstSeen={firstSeen} scanId={lastScan.id} targetId={current.id} selectedId={route.id} query={route.query} tickets={tickets} integrations={integrations} onSelect={(id) => go('findings', id, route.query)} onQuery={setQuery} onTicketsChange={() => loadTickets(current.id)} />}
              {route.page === 'components' && <Components report={viewReport} go={go} />}
              {route.page === 'evidence' && <Evidence report={viewReport} scanId={lastScan.id} query={route.query} go={go} />}
              {route.page === 'reports' && <Reports report={viewReport} scans={scans} scanId={lastScan.id} />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

function Welcome({ onAdd, busy }: { onAdd: (dir: string) => void; busy: boolean }) {
  const [dir, setDir] = useState('');
  return (
    <div className="hero">
      <div className="tagline">Find › Prioritize › Fix › Prove</div>
      <h1>From findings to fixes.</h1>
      <p>Point NextFix at a Node.js project with a <code>package-lock.json</code>, or a Python project with pinned <code>requirements.txt</code>, <code>Pipfile.lock</code>, <code>poetry.lock</code> or <code>uv.lock</code>. It works out which vulnerabilities are reachable and exposed, and tells you what to fix first.</p>
      <form onSubmit={(e) => { e.preventDefault(); if (dir.trim()) onAdd(dir.trim()); }}>
        <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" autoFocus />
        <button type="submit" className="btn primary" disabled={busy || !dir.trim()}>Scan</button>
      </form>
      <p className="hint">Nothing leaves your machine except advisory lookups to OSV, FIRST EPSS and CISA KEV.</p>
    </div>
  );
}
