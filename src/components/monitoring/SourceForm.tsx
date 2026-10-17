import { useEffect, useId, useState } from 'react';
import { Play, ShieldAlert, Square } from 'lucide-react';
import type { MonitoringClient } from '../../services/monitoring/client';
import type { MonitoringState } from '../../services/monitoring/state';
import type { SourceConfig } from '../../services/monitoring/types';
import { draftFromConfig, readDraft, sameConfig, type FieldErrors, type SourceDraft } from './monitoringCopy';
import { BUTTON_PRIMARY, BUTTON_SECONDARY, INPUT, INPUT_SURFACE, Note } from './parts';

type Busy = 'load' | 'save' | 'start' | 'stop' | null;

/**
 * The one exporter, the one local address and port, and how much history to
 * keep - with Save, Start and Stop.
 *
 * The listener state it acts on is `state.intake.listener`, never Start's own
 * answer (R7.4): a reply that comes back `{ok:false}` after the status already
 * said listening is a late reply, not a failure, and the form says so quietly.
 */
export function SourceForm({ client, state, onConfig }: {
  client: MonitoringClient;
  state: MonitoringState;
  /** The saved source, as the rest of the sheet needs it (the recipe, the meter). */
  onConfig: (config: SourceConfig | null) => void;
}) {
  const id = useId();
  const [saved, setSaved] = useState<SourceConfig | null>(null);
  const [draft, setDraft] = useState<SourceDraft>(() => draftFromConfig(null));
  const [busy, setBusy] = useState<Busy>('load');
  const [shown, setShown] = useState<Set<keyof FieldErrors>>(new Set());
  const [message, setMessage] = useState<{ tone: 'neutral' | 'bad'; text: string } | null>(null);
  // The config a Start was last pressed with on this page: the firewall note
  // is for the first Start of a source, which is when Windows asks.
  const [startedWith, setStartedWith] = useState<SourceConfig | null>(null);

  useEffect(() => {
    let live = true;
    void client.getConfig().then((reply) => {
      if (!live) return;
      setBusy(null);
      if (!reply.ok) { setMessage({ tone: 'bad', text: reply.message }); return; }
      setSaved(reply.config);
      setDraft(draftFromConfig(reply.config));
      onConfig(reply.config);
    });
    return () => { live = false; };
    // Once per mount: the saved source is read when the sheet opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  const listener = state.intake?.listener ?? 'stopped';
  const running = listener === 'listening' || listener === 'starting';
  const { config, errors } = readDraft(draft);
  const dirty = config === null || !sameConfig(config, saved);
  const fieldError = (name: keyof FieldErrors): string | undefined => (shown.has(name) ? errors[name] : undefined);
  const show = (name: keyof FieldErrors) => setShown((s) => (s.has(name) ? s : new Set(s).add(name)));
  const showAll = () => setShown(new Set(['exporterIPv4', 'bindIPv4', 'port', 'limit']));
  const edit = (patch: Partial<SourceDraft>) => { setDraft((d) => ({ ...d, ...patch })); setMessage(null); };

  const persist = async (next: SourceConfig): Promise<boolean> => {
    const reply = await client.saveConfig(next);
    if (!reply.ok) { setMessage({ tone: 'bad', text: `Not saved: ${reply.message}` }); return false; }
    setSaved(reply.config);
    onConfig(reply.config);
    return true;
  };

  const save = async () => {
    showAll();
    if (config === null) return;
    setBusy('save');
    if (await persist(config)) setMessage({ tone: 'neutral', text: 'Saved.' });
    setBusy(null);
  };

  const start = async () => {
    showAll();
    if (config === null) return;
    setBusy('start');
    setMessage(null);
    try {
      if (dirty && !(await persist(config))) return;
      const connected = await client.ensureConnected();
      if (!connected.ok) { setMessage({ tone: 'bad', text: connected.message }); return; }
      setStartedWith(config);
      const result = await client.start(config);
      if (!result.ok) {
        // The status is the truth; the reply only says how the request went.
        if (client.state.intake?.listener === 'listening') {
          setMessage({ tone: 'neutral', text: 'Start’s reply came late; the listener is running.' });
        } else {
          setMessage({ tone: 'bad', text: result.message });
        }
      }
    } finally {
      setBusy(null);
    }
  };

  const stop = async () => {
    setBusy('stop');
    setMessage(null);
    const result = await client.stop();
    if (!result.ok && client.state.intake?.listener !== 'stopped') setMessage({ tone: 'bad', text: result.message });
    setBusy(null);
  };

  const firstStart = !running && (startedWith === null || config === null || !sameConfig(startedWith, config));
  const locked = running || busy !== null;

  return (
    <form
      className="space-y-3"
      noValidate
      onSubmit={(e) => { e.preventDefault(); void (running ? stop() : start()); }}
      aria-describedby={running ? `${id}-locked` : undefined}
    >
      <Field id={`${id}-exp`} label="Exporter" hint="The router or switch whose exports are accepted. Every other sender is refused."
        error={fieldError('exporterIPv4')}>
        <input id={`${id}-exp`} className={INPUT} value={draft.exporterIPv4} inputMode="decimal" placeholder="192.168.1.1"
          autoComplete="off" spellCheck={false} disabled={locked}
          aria-invalid={fieldError('exporterIPv4') !== undefined}
          aria-describedby={`${id}-exp-hint ${id}-exp-err`}
          onChange={(e) => edit({ exporterIPv4: e.target.value })} onBlur={() => show('exporterIPv4')} />
      </Field>
      <Field id={`${id}-bind`} label="Listen on" hint="The address of this PC that the exporter sends to."
        error={fieldError('bindIPv4')}>
        <input id={`${id}-bind`} className={INPUT} value={draft.bindIPv4} inputMode="decimal" placeholder="192.168.1.20"
          autoComplete="off" spellCheck={false} disabled={locked}
          aria-invalid={fieldError('bindIPv4') !== undefined}
          aria-describedby={`${id}-bind-hint ${id}-bind-err`}
          onChange={(e) => edit({ bindIPv4: e.target.value })} onBlur={() => show('bindIPv4')} />
      </Field>
      <div className="grid grid-cols-[6rem_minmax(0,1fr)] gap-3">
        <Field id={`${id}-port`} label="Port" error={fieldError('port')}>
          <input id={`${id}-port`} className={INPUT} value={draft.port} inputMode="numeric" autoComplete="off" disabled={locked}
            aria-invalid={fieldError('port') !== undefined} aria-describedby={`${id}-port-err`}
            onChange={(e) => edit({ port: e.target.value })} onBlur={() => show('port')} />
        </Field>
        <Field id={`${id}-limit`} label="Keep up to" error={fieldError('limit')}>
          <div className="flex min-w-0 gap-1.5">
            <input id={`${id}-limit`} className={`${INPUT} min-w-0 flex-1`} value={draft.limit} inputMode="decimal" autoComplete="off" disabled={locked}
              aria-invalid={fieldError('limit') !== undefined} aria-describedby={`${id}-limit-err`}
              onChange={(e) => edit({ limit: e.target.value })} onBlur={() => show('limit')} />
            <select aria-label="Storage unit" className={`${INPUT_SURFACE} w-[4.5rem] shrink-0 font-sans`} value={draft.unit} disabled={locked}
              onChange={(e) => edit({ unit: e.target.value as SourceDraft['unit'] })}>
              <option value="GiB">GiB</option>
              <option value="MiB">MiB</option>
            </select>
          </div>
        </Field>
      </div>

      {firstStart && busy !== 'load' && (
        <Note tone="warn" icon={<ShieldAlert className="h-4 w-4" />}>
          <p>
            Windows will ask whether Inwire may receive on the network. Choose <strong>Allow</strong>. If you choose
            Cancel, Windows will not ask again, and nothing will arrive until an administrator removes the rule in
            Windows Defender Firewall.
          </p>
        </Note>
      )}

      <div className="flex flex-wrap items-center gap-2 pt-0.5">
        {running ? (
          <button type="submit" className={BUTTON_PRIMARY} disabled={busy !== null || listener === 'starting'}>
            <Square className="h-3.5 w-3.5" aria-hidden />
            {busy === 'stop' ? 'Stopping…' : 'Stop'}
          </button>
        ) : (
          <button type="submit" className={BUTTON_PRIMARY} disabled={busy !== null}>
            <Play className="h-3.5 w-3.5" aria-hidden />
            {busy === 'start' ? 'Starting…' : 'Start'}
          </button>
        )}
        {!running && (
          <button type="button" className={BUTTON_SECONDARY} disabled={busy !== null || !dirty}
            onClick={() => void save()}>
            {busy === 'save' ? 'Saving…' : 'Save'}
          </button>
        )}
        {running && (
          <span id={`${id}-locked`} className="text-[11px] text-muted-foreground">Stop to change the source.</span>
        )}
      </div>
      {message && (
        <p role={message.tone === 'bad' ? 'alert' : 'status'}
          className={`text-xs ${message.tone === 'bad' ? 'text-danger' : 'text-muted-foreground'}`}>
          {message.text}
        </p>
      )}
    </form>
  );
}

function Field({ id, label, hint, error, children }: {
  id: string; label: string; hint?: string; error?: string; children: React.ReactNode;
}) {
  return (
    <div className="min-w-0 space-y-1">
      <label htmlFor={id} className="block text-xs font-semibold text-foreground">{label}</label>
      {children}
      {hint && !error && <p id={`${id}-hint`} className="text-[11px] leading-snug text-muted-foreground">{hint}</p>}
      <p id={`${id}-err`} className="text-[11px] leading-snug text-danger" hidden={!error}>{error}</p>
    </div>
  );
}
