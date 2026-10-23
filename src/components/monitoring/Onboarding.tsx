import { useId, useState } from 'react';
import { AlertTriangle, Check, Copy } from 'lucide-react';
import { copyText } from '../ui/CopyButton';
import { ONBOARDING_SNIPPETS, SNIPPET_CAVEAT, UNVERIFIED_CAVEAT, fillSnippet, snippetLabel } from './onboardingSnippets';
import { BUTTON_SECONDARY, INPUT_SURFACE } from './parts';

/**
 * How to point an exporter at this PC, for the routers and firewalls the survey read
 * (`docs/monitoring-v5-measurements.md`, *Exporter survey*): pick one, and its lines come back with
 * the address and port Inwire listens on filled in. Every snippet is the vendor's own documentation,
 * cited beside it, and none has been tried on the reader's hardware - the sheet says so every time.
 */
export function Onboarding({ address, port }: { address: string | null; port: number }) {
  const [id, setId] = useState(ONBOARDING_SNIPPETS[0].id);
  const [copied, setCopied] = useState(false);
  const selectId = useId();
  const snippet = ONBOARDING_SNIPPETS.find((s) => s.id === id) ?? ONBOARDING_SNIPPETS[0];
  const text = fillSnippet(snippet, address ?? '<this PC’s address>', port);

  const onCopy = async () => {
    if (!(await copyText(text))) return;
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={selectId} className="text-xs text-muted-foreground">Exporter</label>
        <select id={selectId} value={snippet.id} onChange={(e) => { setId(e.target.value); setCopied(false); }}
          className={`${INPUT_SURFACE} max-w-full cursor-pointer font-sans`}>
          {ONBOARDING_SNIPPETS.map((s) => <option key={s.id} value={s.id}>{snippetLabel(s)}</option>)}
        </select>
        <button type="button" onClick={() => void onCopy()} disabled={snippet.lines.length === 0} className={BUTTON_SECONDARY}>
          {copied ? <Check className="h-3.5 w-3.5 text-success" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
          {copied ? 'Copied' : snippet.kind === 'cli' ? 'Copy commands' : 'Copy steps'}
        </button>
      </div>

      {snippet.lines.length > 0 && (
        <pre aria-label={`${snippetLabel(snippet)}: ${snippet.kind === 'cli' ? 'commands' : 'steps'}`}
          className="overflow-x-auto rounded-md border border-border bg-muted px-2.5 py-2 font-mono text-[11px] leading-relaxed text-foreground">
          {text}
        </pre>
      )}

      {snippet.notes && snippet.notes.length > 0 && (
        <ul className="max-w-[44rem] list-disc space-y-0.5 pl-4 text-xs leading-relaxed text-muted-foreground">
          {snippet.notes.map((n) => <li key={n}>{n}</li>)}
        </ul>
      )}

      <p className="flex max-w-[44rem] items-start gap-1.5 text-xs leading-relaxed text-foreground">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
        <span>{snippet.verified ? SNIPPET_CAVEAT : UNVERIFIED_CAVEAT}</span>
      </p>
      <div className="space-y-0.5 text-[11px] text-muted-foreground">
        {snippet.sources.map((s) => (
          <p key={s.url} className="break-all">
            {s.title}, {snippet.verified ? 'read' : 'could not be read on'} {snippet.readOn}: <span className="select-text font-mono text-foreground">{s.url}</span>
          </p>
        ))}
      </div>
    </div>
  );
}
