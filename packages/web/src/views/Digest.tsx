import { useEffect, useState } from 'react';
import { api, type DigestChannel, type DigestSettings } from '../api.ts';
import { I } from '../components/Icons.tsx';
import { Modal } from '../components/Modal.tsx';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const CHANNELS: { id: DigestChannel | null; label: string; help: string }[] = [
  { id: null, label: 'Off', help: 'No weekly message.' },
  { id: 'email', label: 'Email', help: 'Through your own SMTP server.' },
  { id: 'slack', label: 'Slack', help: 'An incoming webhook in a channel.' },
  { id: 'teams', label: 'Microsoft Teams', help: 'An incoming webhook in a channel.' },
];

const EMPTY: DigestSettings = { channel: null, weekday: 1, hour: 8 };

/** Settings → Weekly digest: where the posture summary goes and when. */
export function DigestPage() {
  const [d, setD] = useState<DigestSettings | null>(null);
  const [secrets, setSecrets] = useState<{ smtpPassword: string; slackWebhook: string; teamsWebhook: string }>({ smtpPassword: '', slackWebhook: '', teamsWebhook: '' });
  const [to, setTo] = useState('');
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [preview, setPreview] = useState<{ subject: string; text: string } | null>(null);
  useEffect(() => { api.digest().then((s) => { setD(s); setTo((s.email?.to ?? []).join(', ')); }).catch((e) => setStatus({ ok: false, text: message(e) })); }, []);

  const edit = (patch: Partial<DigestSettings>) => { setD((cur) => ({ ...(cur ?? EMPTY), ...patch })); setDirty(true); };
  const editEmail = (patch: Partial<NonNullable<DigestSettings['email']>>) => { setD((cur) => { const c = cur ?? EMPTY; return { ...c, email: { to: [], from: '', smtpHost: '', smtpPort: 587, smtpUser: '', hasPassword: false, secure: true, ...c.email, ...patch } }; }); setDirty(true); };

  const save = async () => {
    if (!d) return null;
    setBusy('save');
    setStatus(null);
    try {
      const body = { ...d, email: d.channel === 'email' ? { ...(d.email ?? { from: '', smtpHost: '', smtpPort: 587, smtpUser: '', hasPassword: false, secure: true }), to: to.split(',').map((s) => s.trim()).filter(Boolean) } : d.email, smtpPassword: secrets.smtpPassword || undefined, slackWebhook: secrets.slackWebhook || undefined, teamsWebhook: secrets.teamsWebhook || undefined };
      const saved = await api.saveDigest(body);
      setD(saved);
      setTo((saved.email?.to ?? []).join(', '));
      setSecrets({ smtpPassword: '', slackWebhook: '', teamsWebhook: '' });
      setDirty(false);
      setStatus({ ok: true, text: 'Saved' });
      return saved;
    } catch (e) {
      setStatus({ ok: false, text: message(e) });
      return null;
    } finally {
      setBusy(null);
    }
  };
  const test = async () => {
    if (dirty && !(await save())) return;
    setBusy('test');
    setStatus(null);
    try {
      const r = await api.testDigest();
      setStatus({ ok: r.ok, text: r.message });
    } catch (e) {
      setStatus({ ok: false, text: message(e) });
    } finally {
      setBusy(null);
    }
  };
  const show = async () => {
    setBusy('preview');
    setStatus(null);
    try {
      setPreview(await api.previewDigest());
    } catch (e) {
      setStatus({ ok: false, text: message(e) });
    } finally {
      setBusy(null);
    }
  };

  if (!d) return <section className="card"><p className="empty">{status ? status.text : 'Loading…'}</p></section>;
  return (
    <div className="stack">
      <section className="card">
        <div className="card-head"><div><h2>Weekly digest</h2><p className="sub">One message a week with the posture of every application, what needs action, and what waits on an approval.</p></div></div>
        <fieldset className="choice-set row">
          <legend>Send it by</legend>
          {CHANNELS.map((c) => <label key={String(c.id)} className={`choice ${d.channel === c.id ? 'on' : ''}`}><input type="radio" name="channel" checked={d.channel === c.id} onChange={() => edit({ channel: c.id })} /><span><strong>{c.label}</strong><span className="muted small">{c.help}</span></span></label>)}
        </fieldset>

        {d.channel === 'email' && (
          <div className="grid two" style={{ marginTop: 12 }}>
            <label className="field span-2"><span>To <span className="muted">(comma-separated)</span></span><input type="text" value={to} onChange={(e) => { setTo(e.target.value); setDirty(true); }} placeholder="security@acme.com, cto@acme.com" autoComplete="off" /></label>
            <label className="field"><span>From</span><input type="text" value={d.email?.from ?? ''} onChange={(e) => editEmail({ from: e.target.value })} placeholder="nextfix@acme.com" autoComplete="off" /></label>
            <label className="field"><span>SMTP host</span><input type="text" value={d.email?.smtpHost ?? ''} onChange={(e) => editEmail({ smtpHost: e.target.value })} placeholder="smtp.acme.com" autoComplete="off" /></label>
            <label className="field"><span>SMTP port</span><input type="number" inputMode="numeric" min={1} max={65535} value={d.email?.smtpPort ?? 587} onChange={(e) => editEmail({ smtpPort: Number(e.target.value) })} /></label>
            <label className="field"><span>SMTP user</span><input type="text" value={d.email?.smtpUser ?? ''} onChange={(e) => editEmail({ smtpUser: e.target.value })} autoComplete="off" /></label>
            <label className="field"><span>SMTP password</span><input type="password" value={secrets.smtpPassword} onChange={(e) => { setSecrets((s) => ({ ...s, smtpPassword: e.target.value })); setDirty(true); }} placeholder={d.email?.hasPassword ? '•••••••• (saved; leave blank to keep)' : ''} autoComplete="new-password" /></label>
            <label className="check field-check"><input type="checkbox" checked={d.email?.secure ?? true} onChange={(e) => editEmail({ secure: e.target.checked })} /> Use TLS (STARTTLS or implicit)</label>
          </div>
        )}
        {d.channel === 'slack' && (
          <label className="field" style={{ marginTop: 12 }}><span>Slack incoming webhook URL</span><input type="password" value={secrets.slackWebhook} onChange={(e) => { setSecrets((s) => ({ ...s, slackWebhook: e.target.value })); setDirty(true); }} placeholder={d.slack?.hasWebhook ? '•••••••• (saved; leave blank to keep)' : 'https://hooks.slack.com/services/…'} autoComplete="off" /><span className="hint">Slack → Apps → Incoming Webhooks → Add to a channel.</span></label>
        )}
        {d.channel === 'teams' && (
          <label className="field" style={{ marginTop: 12 }}><span>Teams incoming webhook URL</span><input type="password" value={secrets.teamsWebhook} onChange={(e) => { setSecrets((s) => ({ ...s, teamsWebhook: e.target.value })); setDirty(true); }} placeholder={d.teams?.hasWebhook ? '•••••••• (saved; leave blank to keep)' : 'https://….webhook.office.com/webhookb2/…'} autoComplete="off" /><span className="hint">Channel → Manage channel → Connectors → Incoming Webhook (or a Workflows webhook).</span></label>
        )}

        {d.channel && (
          <div className="when">
            <label className="field"><span>Every</span><select value={d.weekday} onChange={(e) => edit({ weekday: Number(e.target.value) })}>{WEEKDAYS.map((w, i) => <option key={w} value={i}>{w}</option>)}</select></label>
            <label className="field"><span>At</span><select value={d.hour} onChange={(e) => edit({ hour: Number(e.target.value) })}>{Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}</select></label>
            <span className="hint">Server local time.</span>
          </div>
        )}

        <div className="actions">
          <button type="button" className="btn primary" disabled={!!busy || !dirty} onClick={save}>{busy === 'save' ? 'Saving…' : 'Save'}</button>
          <button type="button" className="btn" disabled={!!busy || !d.channel} title={d.channel ? (dirty ? 'Saves first, then sends one message now' : 'Sends one message now') : 'Choose a channel first'} onClick={test}><I.mail /> {busy === 'test' ? 'Sending…' : 'Send test'}</button>
          <button type="button" className="btn" disabled={!!busy} onClick={show}><I.eye /> {busy === 'preview' ? 'Building…' : 'Preview'}</button>
          {status && <span className={status.ok ? 'hint' : 'error'} role="status">{status.text}</span>}
        </div>
      </section>
      {preview && (
        <Modal title="Digest preview" onClose={() => setPreview(null)} wide>
          <p className="pkg">{preview.subject}</p>
          <pre className="digest-text">{preview.text}</pre>
          <div className="actions"><button type="button" className="btn" onClick={() => setPreview(null)}>Close</button></div>
        </Modal>
      )}
    </div>
  );
}
