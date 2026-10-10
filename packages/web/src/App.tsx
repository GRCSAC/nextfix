import { Component as ReactComponent, useCallback, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from 'react';
import { api, setUnauthorizedHandler, type Exception, type Health, type Integrations, type ListReport, type Role, type ScanDiff, type ScanMeta, type ScanReport, type Session, type Settings as SettingsValues, type Target, type TicketMap } from './api.ts';
import { I, Wordmark } from './components/Icons.tsx';
import { UserMenu } from './components/UserMenu.tsx';
import { Overview } from './views/Overview.tsx';
import { Findings } from './views/Findings.tsx';
import { Components } from './views/Components.tsx';
import { Evidence } from './views/Evidence.tsx';
import { Reports } from './views/Reports.tsx';
import { Apps } from './views/Apps.tsx';
import { Portfolio } from './views/Portfolio.tsx';
import { Settings, applyTheme, readTheme, type SettingsSection, type Theme } from './views/Settings.tsx';
import { LoginPage, SetupPage } from './views/Auth.tsx';
import { applyExceptions, latestByFinding, pendingCount } from './exceptions.ts';
import { dateTime } from './format.ts';
import './plumbing.css';
import './team.css';

type Page = 'overview' | 'findings' | 'components' | 'evidence' | 'reports' | 'apps' | 'settings' | 'portfolio';
const PAGE_IDS: Page[] = ['overview', 'findings', 'components', 'evidence', 'reports', 'apps', 'settings', 'portfolio'];
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
      <Shell />
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

type Gate = { state: 'loading' } | { state: 'error'; text: string } | { state: 'setup' } | { state: 'login'; session: Session; notice?: string } | { state: 'in'; session: Session };

/**
 * Decides what the page is: the setup form on first run, the sign-in page when the server
 * wants a user and there is none, otherwise the dashboard. A 401 from any later call brings
 * the sign-in page back and remembers the hash so sign-in returns to the same place.
 */
function Shell() {
  const [gate, setGate] = useState<Gate>({ state: 'loading' });
  const [theme, setTheme] = useState<Theme>(readTheme);
  const returnTo = useRef<string | null>(null);
  useEffect(() => { applyTheme(theme); try { localStorage.setItem('nextfix.theme', theme); } catch { /* ignore */ } }, [theme]);

  const place = useCallback((s: Session, notice?: string) => {
    if (s.setupRequired) setGate({ state: 'setup' });
    else if (s.authMode !== 'none' && !s.user) setGate({ state: 'login', session: s, notice });
    else setGate({ state: 'in', session: s });
  }, []);

  useEffect(() => {
    api.session().then((s) => place(s)).catch((e) => setGate({ state: 'error', text: message(e) }));
    setUnauthorizedHandler(() => {
      returnTo.current = location.hash;
      api.session().then((s) => place(s, 'Your session has ended. Sign in again to continue.')).catch(() => setGate({ state: 'login', session: { setupRequired: false, authMode: 'local' }, notice: 'Your session has ended. Sign in again to continue.' }));
    });
    return () => setUnauthorizedHandler(null);
  }, [place]);

  const signedIn = (s: Session) => {
    place(s);
    if (returnTo.current) { location.hash = returnTo.current; returnTo.current = null; }
  };
  const signOut = async () => {
    try { await api.logout(); } catch { /* the session is gone either way */ }
    returnTo.current = null;
    api.session().then((s) => place(s)).catch((e) => setGate({ state: 'error', text: message(e) }));
  };

  if (gate.state === 'loading') return <p className="empty center">Loading…</p>;
  if (gate.state === 'error') return <div className="hero" role="alert"><h1>Cannot reach the server</h1><p>{gate.text}</p><button type="button" className="btn primary" onClick={() => location.reload()}><I.refresh /> Retry</button></div>;
  if (gate.state === 'setup') return <SetupPage onDone={signedIn} />;
  if (gate.state === 'login') return <LoginPage session={gate.session} notice={gate.notice} onDone={signedIn} />;
  return <Dashboard key={gate.session.user?.id ?? 'local'} session={gate.session} theme={theme} onTheme={setTheme} onSignOut={signOut} />;
}

function Dashboard({ session, theme, onTheme, onSignOut }: { session: Session; theme: Theme; onTheme: (t: Theme) => void; onSignOut: () => void }) {
  const role: Role = session.authMode === 'none' ? 'admin' : session.user?.role ?? 'viewer';
  const canScan = role !== 'viewer';
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [targetId, setTargetId] = useState<number | null>(() => {
    try { const v = localStorage.getItem('nextfix.target'); return v ? Number(v) : null; } catch { return null; }
  });
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [report, setReport] = useState<ListReport | null>(null);
  const [diff, setDiff] = useState<ScanDiff | undefined>();
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [route, setRoute] = useState<Route>(readHash);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | undefined>();
  const [settings, setSettings] = useState<SettingsValues | undefined>();
  const [now, setNow] = useState(() => Date.now());
  const [cancelling, setCancelling] = useState(false);
  const mainRef = useRef<HTMLElement>(null);

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
  const loadExceptions = useCallback(async (id: number) => {
    setExceptions(await api.exceptions(id).catch(() => []));
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
      const soft = <T,>(fallback: T) => (e: unknown) => { if (isAbort(e)) throw e; return fallback; };
      const [ticketMap, exc, list] = await Promise.all([api.tickets(id, ac.signal).catch(soft({} as TicketMap)), api.exceptions(id, ac.signal).catch(soft([] as Exception[])), api.scans(id, ac.signal)]);
      if (!current()) return;
      setTickets(ticketMap);
      setExceptions(exc);
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
      // With several applications the portfolio is the front door; a deep link is left alone.
      if (list.length > 1 && (location.hash === '' || location.hash === '#' || location.hash === '#/')) go('portfolio');
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
    if (route.page === 'apps' || route.page === 'portfolio' || route.id) go('overview');
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

  const updateTarget = (t: Target) => setTargets((list) => (list ?? []).map((x) => (x.id === t.id ? { ...x, ...t } : x)));

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
  const byFinding = useMemo(() => latestByFinding(exceptions), [exceptions]);
  // Findings a person set aside leave the work queue everywhere the report is drawn.
  const { report: viewReport, accepted } = useMemo(() => (report ? applyExceptions(asScanReport(report), byFinding) : { report: null, accepted: new Set<string>() }), [report, byFinding]);
  const firstSeen = useMemo(() => {
    const out: Record<string, string> = {};
    for (const f of report?.findings ?? []) if (f.firstSeenAt) out[f.id] = f.firstSeenAt;
    return out;
  }, [report]);
  const s = viewReport?.summary;
  const actionable = s ? s.byDecision.Act + s.byDecision.Attend : 0;
  const pending = pendingCount(exceptions);
  const showTabs = !!current && !!report && route.page !== 'portfolio';
  const home = (targets?.length ?? 0) > 1 ? hashFor('portfolio') : hashFor('overview');

  const scanningName = scanning ? (scanning.targetId === null ? 'on another server' : targets?.find((t) => t.id === scanning.targetId)?.name ?? 'application') : '';
  const scanLabel = busy ?? (scanning ? `Scanning ${scanningName}…` : null);
  const elapsed = scanning ? elapsedLabel(now - Date.parse(scanning.startedAt)) : null;

  const railItems: { id: Page; label: string; icon: React.ReactNode }[] = [
    { id: 'portfolio', label: 'Portfolio', icon: <I.portfolio /> },
    { id: 'apps', label: 'Apps', icon: <I.grid /> },
    { id: 'settings', label: 'Settings', icon: <I.settings /> },
  ];

  return (
    <div className="shell">
      <a className="skip-link" href="#main" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>Skip to content</a>
      <nav className="rail" aria-label="Sections">
        <a className="rail-brand" href={home} aria-label="NextFix"><Wordmark size={30} /></a>
        {railItems.map((r) => (
          <a key={r.id} className={`rail-item ${route.page === r.id ? 'active' : ''}`} href={hashFor(r.id)}>{r.icon}<span>{r.label}</span></a>
        ))}
        <span className="grow" />
        <a className="rail-item" href="https://github.com/GRCSAC/nextfix#readme" target="_blank" rel="noreferrer"><I.help /><span>Help</span></a>
      </nav>

      <div className="main">
        <header className="topbar">
          <div className="topbar-inner">
            <a className="wordmark" href={home}><Wordmark size={24} /><span>Next<b>Fix</b></span></a>
            {targets && targets.length > 0 && route.page !== 'portfolio' && (
              <select className="target-select" aria-label="Application" value={targetId ?? ''} onChange={(e) => selectTarget(Number(e.target.value))}>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name ?? t.dir}</option>)}
              </select>
            )}
            {showTabs && (
              <nav className="tabs" aria-label="Pages">
                {PAGES.map((p) => <a key={p.id} className={route.page === p.id ? 'active' : ''} href={hashFor(p.id)}>{p.icon}<span>{p.label}</span>{p.id === 'findings' && pending > 0 && <span className="tab-badge" title={`${pending} exception${pending === 1 ? '' : 's'} awaiting approval`}>{pending}<span className="sr-only"> exceptions awaiting approval</span></span>}</a>)}
                <a className={`mobile-only ${route.page === 'portfolio' ? 'active' : ''}`} href={hashFor('portfolio')}><I.portfolio size={18} /><span>Portfolio</span></a>
                <a className={`mobile-only ${route.page === 'apps' ? 'active' : ''}`} href={hashFor('apps')}><I.grid size={18} /><span>Apps</span></a>
                <a className={`mobile-only ${route.page === 'settings' ? 'active' : ''}`} href={hashFor('settings')}><I.settings size={18} /><span>Settings</span></a>
              </nav>
            )}
            {!showTabs && targets && targets.length > 0 && (
              <nav className="tabs mobile-nav" aria-label="Pages">
                <a className={`mobile-only ${route.page === 'portfolio' ? 'active' : ''}`} href={hashFor('portfolio')}><I.portfolio size={18} /><span>Portfolio</span></a>
                <a className={`mobile-only ${route.page === 'apps' ? 'active' : ''}`} href={hashFor('apps')}><I.grid size={18} /><span>Apps</span></a>
                <a className={`mobile-only ${route.page === 'settings' ? 'active' : ''}`} href={hashFor('settings')}><I.settings size={18} /><span>Settings</span></a>
              </nav>
            )}
            <span className="grow" />
            <span className="version muted small">v{health?.version ?? ''}</span>
            {session.user && <UserMenu user={session.user} onSignOut={onSignOut} />}
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
              {scanning && scanning.targetId !== null && canScan && (
                <button type="button" className="btn small" onClick={cancelScan} disabled={cancelling}>{cancelling ? 'Cancelling…' : 'Cancel'}</button>
              )}
            </div>
          )}
          {notice && <div className="banner" role="status">{notice} <button type="button" className="btn ghost small" onClick={() => setNotice(null)} aria-label="Dismiss"><I.close /></button></div>}
          {error && <div className="banner error-banner" role="alert">{error}</div>}

          {targets === null ? (
            <p className="empty">Loading…</p>
          ) : route.page === 'portfolio' ? (
            <Portfolio onOpen={(id) => { selectTarget(id); }} />
          ) : route.page === 'settings' ? (
            <Settings theme={theme} onTheme={onTheme} health={health} integrations={integrations} onIntegrationsChange={loadIntegrations} settings={settings} onSettingsChange={setSettings} role={role} authMode={session.authMode} me={session.user} section={(route.id as SettingsSection) ?? 'general'} go={go} />
          ) : route.page === 'apps' || !current ? (
            targets.length === 0 && route.page !== 'apps' ? (
              canScan ? <Welcome onAdd={addTarget} busy={!!busy} /> : <div className="hero"><h1>No applications yet</h1><p>An analyst or administrator adds the first application under Apps; its dashboards appear here.</p></div>
            ) : (
              <Apps targets={targets} currentId={targetId} busy={!!busy} role={role} onSelect={selectTarget} onAdd={addTarget} onRemove={removeTarget} onUpdated={updateTarget} />
            )
          ) : !report || !viewReport || !lastScan ? (
            <div className="hero">
              <h1>{current.name ?? current.dir}</h1>
              <p>This application has not been scanned yet.</p>
              {canScan ? <button type="button" className="btn primary" onClick={rescan} disabled={!!busy}><I.refresh /> Run the first scan</button> : <p className="hint">Viewers cannot start scans; ask an analyst or administrator.</p>}
            </div>
          ) : (
            <>
              <div className="app-head">
                <span className="icon-box big"><I.cube /></span>
                <div className="grow">
                  <div className="app-title"><h1>{report.target.name ?? report.target.dir}</h1><span className="tag ok"><I.check /> Scanned</span></div>
                  <div className="muted small">Last scan {dateTime(report.generatedAt)} · NextFix v{report.tool.version} · {report.summary.components} components{current.owner ? ` · owner ${current.owner}` : ''}</div>
                </div>
                {s && (
                  <div className="app-summary">
                    <strong>{s.findings} findings across {s.components} components. {actionable} need action.</strong>
                    <span className="muted"> The rest are unreachable, unused, not shipped{accepted.size ? ', or set aside by a person' : ''}, and each one carries a reason you can hand to an auditor.</span>
                  </div>
                )}
                {canScan && <button type="button" className="btn primary" onClick={rescan} disabled={scanActive}><I.refresh /> {scanActive ? 'Scanning…' : 'Scan again'}</button>}
              </div>
              {route.page === 'overview' && <Overview report={viewReport} targetId={current.id} scans={scans} diff={diff} exceptions={exceptions} accepted={accepted} go={go} />}
              {route.page === 'findings' && <Findings report={viewReport} firstSeen={firstSeen} scanId={lastScan.id} targetId={current.id} selectedId={route.id} query={route.query} tickets={tickets} integrations={integrations} role={role} exceptions={byFinding} accepted={accepted} onSelect={(id) => go('findings', id, route.query)} onQuery={setQuery} onTicketsChange={() => loadTickets(current.id)} onExceptionsChange={() => loadExceptions(current.id)} />}
              {route.page === 'components' && <Components report={viewReport} go={go} />}
              {route.page === 'evidence' && <Evidence report={viewReport} scanId={lastScan.id} query={route.query} exceptions={exceptions} go={go} />}
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
      <p>Point NextFix at a Node.js project (<code>package-lock.json</code>, <code>yarn.lock</code> or <code>pnpm-lock.yaml</code>), a Python project with pinned requirements or a lockfile, a Go module, or a folder with a container image or SBOM in its config. It works out which vulnerabilities are reachable and exposed, and tells you what to fix first.</p>
      <form onSubmit={(e) => { e.preventDefault(); if (dir.trim()) onAdd(dir.trim()); }}>
        <input type="text" value={dir} onChange={(e) => setDir(e.target.value)} placeholder="C:\path\to\your\app" aria-label="Project folder" autoFocus />
        <button type="submit" className="btn primary" disabled={busy || !dir.trim()}>Scan</button>
      </form>
      <p className="hint">Nothing leaves your machine except advisory lookups to OSV, FIRST EPSS and CISA KEV.</p>
    </div>
  );
}
