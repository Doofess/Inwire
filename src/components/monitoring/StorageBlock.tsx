import { useId, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import type { MonitoringClient } from '../../services/monitoring/client';
import type { DiscardScope, LocationReply } from '../../services/monitoring/control';
import { MONITORING_FOLDER, RETENTION_OFF_NOTE, type RetentionDraft, type SourceDraft } from './monitoringCopy';
import { BUTTON_SECONDARY, INPUT, INPUT_SURFACE, Note } from './parts';

type Say = { tone: 'neutral' | 'bad'; text: string };
type FolderAnswer = { ok: Extract<LocationReply, { ok: true }> } | { fail: string };

/** A sub-section's title inside the source form: the size of the sheet's block titles, set apart by the rule above it. */
const SECTION_TITLE = 'text-[13px] font-semibold text-foreground';

/** The text of a datetime-local value as epoch milliseconds, or null while it is empty or unreadable. */
const dateMs = (value: string): number | null => {
  if (value === '') return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
};

/**
 * The Storage section of the source form: where the history is kept, how much
 * of it, and when raw evidence expires. It lives inside the form and the form
 * owns the drafts; this holds only what is not a draft (the folder shown and
 * the line that answers Change…). A folder change is immediate, like any
 * dialog; the rest waits for Save or Start.
 *
 * Every button here is `type="button"`, so none submits the form.
 */
export function StorageBlock({ client, locked, location, onFolderChanged, limit, retention }: {
  client: MonitoringClient;
  /** Collecting, or a request pending: nothing here can change. */
  locked: boolean;
  /** The folder the saved config reads, or null for the default folder. */
  location: string | null;
  /** A new folder was chosen; `readOnly` is whether its data is damaged, so Start must stay off. */
  onFolderChanged: (readOnly: boolean) => void;
  limit: {
    draft: Pick<SourceDraft, 'limit' | 'unit'>; error: string | undefined;
    edit: (patch: Partial<SourceDraft>) => void; show: () => void;
  };
  retention: { draft: RetentionDraft; error: string | undefined; edit: (patch: Partial<RetentionDraft>) => void };
}) {
  const id = useId();
  const [folder, setFolder] = useState<{ path: string; isDefault: boolean } | null>(null);
  const [folderSay, setFolderSay] = useState<FolderAnswer | null>(null);
  const [asking, setAsking] = useState(false);

  const shownPath = folder?.path ?? location ?? MONITORING_FOLDER;
  const isDefault = folder?.isDefault ?? location === null;

  const choose = async (intent: 'pick' | 'default') => {
    setAsking(true);
    setFolderSay(null);
    try {
      const reply = await client.chooseLocation(intent);
      if (reply.ok) {
        setFolder({ path: reply.displayPath, isDefault: reply.isDefaultLocation });
        setFolderSay({ ok: reply });
        onFolderChanged(reply.inspect.kind === 'adopt-read-only');
      } else if (reply.reason !== 'cancelled') {
        setFolderSay({ fail: reply.message });
      }
    } finally {
      setAsking(false);
    }
  };

  const off = locked || asking;
  const rd = retention.draft;

  return (
    <fieldset className="m-0 min-w-0 space-y-3 border-0 border-t border-border p-0 pt-3" disabled={off}>
      <legend className="sr-only">Storage</legend>
      <h3 aria-hidden className={SECTION_TITLE}>Storage</h3>

      <div className="min-w-0 space-y-1.5">
        <p id={`${id}-folder-label`} className="text-xs font-semibold text-foreground">Kept in</p>
        <p aria-labelledby={`${id}-folder-label`} className="break-all font-mono text-xs leading-relaxed text-foreground">
          {shownPath}
          {isDefault && <span className="font-sans text-muted-foreground"> (default)</span>}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className={BUTTON_SECONDARY} onClick={() => void choose('pick')}>
            {asking ? 'Choosing…' : 'Change…'}
          </button>
          {!isDefault && (
            <button type="button" className={BUTTON_SECONDARY} onClick={() => void choose('default')}>
              Use the default folder
            </button>
          )}
        </div>
        <FolderSay say={folderSay} />
      </div>

      <div className="min-w-0 space-y-1">
        <label htmlFor={`${id}-limit`} className="block text-xs font-semibold text-foreground">Keep up to</label>
        <div className="flex min-w-0 gap-1.5">
          <input id={`${id}-limit`} className={`${INPUT} min-w-0 flex-1`} value={limit.draft.limit} inputMode="decimal"
            autoComplete="off" aria-invalid={limit.error !== undefined} aria-describedby={`${id}-limit-err`}
            onChange={(e) => limit.edit({ limit: e.target.value })} onBlur={limit.show} />
          <select aria-label="Storage unit" className={`${INPUT_SURFACE} w-[4.5rem] shrink-0 font-sans`}
            value={limit.draft.unit} onChange={(e) => limit.edit({ unit: e.target.value as SourceDraft['unit'] })}>
            <option value="GiB">GiB</option>
            <option value="MiB">MiB</option>
          </select>
        </div>
        <p id={`${id}-limit-err`} className="text-[11px] leading-snug text-danger" hidden={!limit.error}>{limit.error}</p>
      </div>

      <div className="min-w-0 space-y-1.5">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs text-foreground">
          <label className="inline-flex cursor-pointer items-center gap-2 font-semibold">
            <input type="checkbox" className="h-3.5 w-3.5 accent-primary" checked={rd.keep}
              onChange={(e) => retention.edit({ keep: e.target.checked })} />
            Keep raw evidence for
          </label>
          <input aria-label="Days of raw evidence" className={`${INPUT_SURFACE} w-16`} value={rd.days} inputMode="numeric"
            autoComplete="off" disabled={!rd.keep} aria-invalid={rd.keep && retention.error !== undefined}
            aria-describedby={`${id}-keep-err`} onChange={(e) => retention.edit({ days: e.target.value })} />
          <span className="text-muted-foreground">days</span>
        </div>
        {!rd.keep && <p className="text-[11px] leading-snug text-muted-foreground">{RETENTION_OFF_NOTE}.</p>}
        <p id={`${id}-keep-err`} className="text-[11px] leading-snug text-danger" hidden={!(rd.keep && retention.error)}>
          {retention.error}
        </p>
      </div>

      <div role="radiogroup" aria-labelledby={`${id}-limit-rule`} className="min-w-0 space-y-1.5">
        <p id={`${id}-limit-rule`} className="text-xs font-semibold text-foreground">At the storage limit</p>
        {([['stop', 'Stop recording'], ['expire-oldest', 'Expire the oldest raw evidence']] as const).map(([value, text]) => (
          <label key={value} className="flex cursor-pointer items-center gap-2 text-xs text-foreground">
            <input type="radio" name={`${id}-at-limit`} className="h-3.5 w-3.5 accent-primary" checked={rd.atLimit === value}
              onChange={() => retention.edit({ atLimit: value })} />
            {text}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/**
 * Discard, below the form's Start and Save because it is not a draft: it acts
 * at once, after main's own confirmation, which states what goes and what
 * stays. The sheet adds no confirm of its own.
 */
export function DiscardControl({ client, locked }: {
  client: MonitoringClient;
  /** Collecting, or a request pending: main would refuse it as busy. */
  locked: boolean;
}) {
  const [scope, setScope] = useState<'all' | 'before'>('all');
  const [before, setBefore] = useState('');
  const [discarding, setDiscarding] = useState(false);
  const [say, setSay] = useState<Say | null>(null);

  const beforeMs = dateMs(before);
  const discard = async () => {
    const target: DiscardScope | null = scope === 'all' ? { scope: 'all' }
      : beforeMs === null ? null : { scope: 'before', beforeMs };
    if (target === null) return;
    setDiscarding(true);
    setSay(null);
    try {
      const reply = await client.discard(target);
      if (reply.ok) {
        const n = reply.removedSegments;
        setSay({ tone: 'neutral', text: `Discarded ${n} ${n === 1 ? 'segment' : 'segments'}.` });
      } else if (reply.reason !== 'cancelled') {
        setSay({ tone: 'bad', text: reply.message });
      }
    } finally {
      setDiscarding(false);
    }
  };

  return (
    <fieldset className="m-0 min-w-0 space-y-2 border-0 border-t border-border p-0 pt-3" disabled={locked || discarding}>
      <legend className="sr-only">Discard</legend>
      <h3 aria-hidden className={SECTION_TITLE}>Discard</h3>
      <div className="flex flex-wrap items-center gap-2">
        <select aria-label="Discard" className={`${INPUT_SURFACE} font-sans`} value={scope}
          onChange={(e) => { setScope(e.target.value as 'all' | 'before'); setSay(null); }}>
          <option value="all">All monitoring data</option>
          <option value="before">Evidence before a date</option>
        </select>
        {scope === 'before' && (
          <input type="datetime-local" aria-label="Discard evidence before" className={`${INPUT_SURFACE} font-sans`}
            value={before} onChange={(e) => { setBefore(e.target.value); setSay(null); }} />
        )}
        <button type="button" className={BUTTON_SECONDARY} disabled={scope === 'before' && beforeMs === null}
          onClick={() => void discard()}>
          {discarding ? 'Discarding…' : 'Discard…'}
        </button>
      </div>
      {say && (
        <p role={say.tone === 'bad' ? 'alert' : 'status'}
          className={`text-xs ${say.tone === 'bad' ? 'text-danger' : 'text-muted-foreground'}`}>{say.text}</p>
      )}
    </fieldset>
  );
}

function FolderSay({ say }: { say: FolderAnswer | null }) {
  if (say === null) return null;
  // Main's refusal already names what it found (the first few, then "and N more").
  if ('fail' in say) return <p role="alert" className="text-xs text-danger">{say.fail}</p>;
  const { inspect } = say.ok;
  if (inspect.kind === 'adopt-read-only') {
    return (
      <Note tone="warn" icon={<TriangleAlert className="h-4 w-4" />} role="note">
        <p>
          This folder’s monitoring data is damaged after one point, so it is open read-only: history up to the damage
          is shown, Start is off, and nothing in the folder is changed.
        </p>
        {inspect.problem && <p className="break-words text-muted-foreground">{inspect.problem}</p>}
      </Note>
    );
  }
  const tail = inspect.truncatedTailBytes !== null && inspect.truncatedTailBytes > 0
    ? ` Its unfinished last write (${inspect.truncatedTailBytes} bytes) was cut off, as any open does.` : '';
  return (
    <p role="status" className="text-xs text-muted-foreground">
      {inspect.kind === 'new'
        ? 'New monitoring data will be kept here.'
        : `The monitoring data already in this folder is in use.${tail}`}
    </p>
  );
}
