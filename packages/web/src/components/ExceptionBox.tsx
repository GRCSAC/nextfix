import { useState } from 'react';
import { api, type Exception, type ExceptionKind, type Role } from '../api.ts';
import { EXCEPTION_KINDS, KIND_META, STATUS_META, exceptionRights, isExpired } from '../exceptions.ts';
import { I } from './Icons.tsx';
import { Modal } from './Modal.tsx';
import { dateTime, shortDate } from '../format.ts';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function KindIcon({ kind, size = 16 }: { kind: ExceptionKind; size?: number }) {
  const Icon = I[KIND_META[kind].icon];
  return <Icon size={size} />;
}

interface Props {
  findingId: string;
  targetId: number;
  role: Role;
  /** The newest exception for this finding, if any. */
  exception?: Exception;
  onChange: () => void;
}

/**
 * The "Set aside with a reason" section of a finding: the current exception with its reason,
 * who proposed and approved it and when it runs out, the admin's inline approve / reject /
 * revoke, and the button that opens the proposal form.
 */
export function ExceptionBox({ findingId, targetId, role, exception, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const rights = exceptionRights(role);
  const e = exception;
  const status = e ? (e.status === 'approved' && isExpired(e) ? 'expired' : e.status) : undefined;
  const active = e && (status === 'pending' || status === 'approved');

  const act = async (st: 'approved' | 'rejected' | 'revoked') => {
    if (!e) return;
    setBusy(st);
    setError(null);
    try {
      await api.updateException(e.id, { status: st });
      onChange();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="exception">
      <h3>Set aside by a person</h3>
      {e && status ? (
        <div className={`exc-card s-${status}`}>
          <div className="exc-head">
            <span className="exc-kind"><KindIcon kind={e.kind} /> {KIND_META[e.kind].label}</span>
            <span className={`tag st-${STATUS_META[status].cls}`}>{STATUS_META[status].label}</span>
          </div>
          <p className="exc-reason">{e.reason}</p>
          <dl className="kv exc-meta">
            <dt>Proposed</dt><dd>{e.proposedBy} · {dateTime(e.createdAt)}</dd>
            {e.approvedBy && <><dt>{status === 'rejected' ? 'Rejected' : status === 'revoked' ? 'Revoked' : 'Approved'}</dt><dd>{e.approvedBy} · {dateTime(e.updatedAt)}</dd></>}
            <dt>Expires</dt><dd>{e.expiresAt ? `${shortDate(e.expiresAt)}${status === 'expired' ? ' (passed)' : ''}` : 'no expiry'}</dd>
          </dl>
          {active && (
            <div className="actions">
              {status === 'pending' && <>
                <button type="button" className="btn small primary" disabled={!rights.approve || !!busy} title={rights.approve ? 'Set the finding aside; it leaves the work queue' : rights.why} onClick={() => act('approved')}><I.check /> {busy === 'approved' ? 'Approving…' : 'Approve'}</button>
                <button type="button" className="btn small" disabled={!rights.approve || !!busy} title={rights.approve ? 'Keep the finding in the work queue' : rights.why} onClick={() => act('rejected')}><I.close /> {busy === 'rejected' ? 'Rejecting…' : 'Reject'}</button>
              </>}
              {status === 'approved' && <button type="button" className="btn small" disabled={!rights.approve || !!busy} title={rights.approve ? 'Put the finding back in the work queue' : rights.why} onClick={() => act('revoked')}>{busy === 'revoked' ? 'Revoking…' : 'Revoke'}</button>}
              {error && <span className="error">{error}</span>}
            </div>
          )}
          {!active && rights.propose && <div className="actions"><button type="button" className="btn small" onClick={() => setOpen(true)}>Propose again</button></div>}
        </div>
      ) : (
        <div className="actions" style={{ marginTop: 4 }}>
          {rights.propose ? (
            <button type="button" className="btn small" onClick={() => setOpen(true)}><I.shield /> Set aside with a reason</button>
          ) : (
            <span className="hint">{rights.why}.</span>
          )}
          <span className="hint">{role === 'admin' ? 'Accepted risk, false positive or mitigated elsewhere; your approval takes effect at once.' : 'Accepted risk, false positive or mitigated elsewhere; an administrator approves it.'}</span>
        </div>
      )}
      {open && <ProposeModal findingId={findingId} targetId={targetId} role={role} onClose={() => setOpen(false)} onDone={() => { setOpen(false); onChange(); }} />}
    </section>
  );
}

function ProposeModal({ findingId, targetId, role, onClose, onDone }: { findingId: string; targetId: number; role: Role; onClose: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<ExceptionKind>('accepted-risk');
  const [reason, setReason] = useState('');
  const [expires, setExpires] = useState('');
  const [approveNow, setApproveNow] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const admin = role === 'admin';
  const today = new Date().toISOString().slice(0, 10);
  const ready = reason.trim().length >= 10 && !busy;
  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.proposeException(targetId, { findingId, kind, reason: reason.trim(), expiresAt: expires ? new Date(`${expires}T23:59:59`).toISOString() : undefined });
      if (admin && approveNow) await api.updateException(created.id, { status: 'approved' });
      onDone();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Set aside with a reason" onClose={onClose}>
      <form className="auth-form" onSubmit={submit} noValidate>
        <fieldset className="choice-set">
          <legend>Why</legend>
          {EXCEPTION_KINDS.map((k) => (
            <label key={k} className={`choice ${kind === k ? 'on' : ''}`}><input type="radio" name="kind" checked={kind === k} onChange={() => setKind(k)} /><span><strong><KindIcon kind={k} size={14} /> {KIND_META[k].label}</strong><span className="muted small">{KIND_META[k].help}</span></span></label>
          ))}
        </fieldset>
        <label className="field"><span>Reason <span className="muted">(what an auditor should read)</span></span><textarea rows={4} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Which control blocks the attack, or why the path cannot be taken, and where that is documented." autoFocus /><span className="hint">At least 10 characters. It goes into the VEX export and the audit log.</span></label>
        <label className="field"><span>Expires <span className="muted">(optional)</span></span><input type="date" value={expires} min={today} onChange={(e) => setExpires(e.target.value)} /><span className="hint">The finding returns to the work queue after this date, and it shows up under Decide 30 days before.</span></label>
        {admin && <label className="check"><input type="checkbox" checked={approveNow} onChange={(e) => setApproveNow(e.target.checked)} /> Approve now (otherwise it waits for an approval)</label>}
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={!ready}>{busy ? 'Saving…' : admin && approveNow ? 'Set aside' : 'Propose'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Modal>
  );
}
