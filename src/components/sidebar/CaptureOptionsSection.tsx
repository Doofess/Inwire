import React, { useEffect, useState } from 'react';
import { Check, TriangleAlert } from 'lucide-react';
import {
  MAX_CAPTURE_FILTER_CHARS, MAX_SNAPLEN, MIN_SNAPLEN,
  type CaptureOptions, type FilterVerdict,
} from '../../services/captureOptions';

/**
 * The capture filter and the snaplen, under the adapter list they narrow.
 *
 * **Here and not in Settings**, because both belong to the next capture the
 * way the adapters do: chosen before Start, fixed until Stop, and read in the
 * same glance as the rows above (ADR 0050). Wireshark puts them in the same
 * place for the same reason - its Capture Options dialog is the adapter list
 * with these two beside it.
 *
 * **The verdict under the field is the agent's**, compiled by libpcap for the
 * link types of the adapters chosen, and quoted in libpcap's words when it
 * refuses. This side does not parse a capture filter at all: a second
 * grammar here would be a second opinion that could only ever disagree with
 * the one that decides.
 */
export interface CaptureOptionsSectionProps {
  options: CaptureOptions;
  onChange: (patch: Partial<CaptureOptions>) => void;
  verdict: FilterVerdict;
  /** A capture is running here or elsewhere: the options are fixed until it stops. */
  locked: boolean;
}

const LABEL = 'text-[10px] uppercase tracking-wider text-muted-foreground';
const FIELD =
  'h-6 w-full rounded-sm border border-border bg-background px-1.5 font-mono text-xs '
  + 'text-foreground outline-none focus:border-primary placeholder:text-muted-foreground/60 '
  + 'disabled:opacity-50 disabled:cursor-not-allowed';
const NOTE = 'text-[11px] leading-snug';

/**
 * A field's keys are its own. The panel's roving focus and the window's
 * shortcuts listen for arrows and Space; in a text field those are editing.
 */
const keepKeys = (e: React.KeyboardEvent) => {
  if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', ' '].includes(e.key)) {
    e.stopPropagation();
  }
};

export const CaptureOptionsSection: React.FC<CaptureOptionsSectionProps> = ({
  options, onChange, verdict, locked,
}) => {
  // The snaplen as typed. Committed only when it is a length the agent takes,
  // so a half-typed "1" on the way to "128" is never sent, and never saved.
  const [draft, setDraft] = useState(String(options.snaplen));
  useEffect(() => { setDraft(String(options.snaplen)); }, [options.snaplen]);
  const typed = Number(draft);
  const draftValid = /^\d+$/.test(draft) && typed >= MIN_SNAPLEN && typed <= MAX_SNAPLEN;

  return (
    <div className="px-3 py-2 border-t border-border space-y-2">
      <div className="space-y-1">
        <label htmlFor="capture-filter" className={LABEL}>Capture filter</label>
        <input
          id="capture-filter"
          type="text"
          spellCheck={false}
          autoComplete="off"
          maxLength={MAX_CAPTURE_FILTER_CHARS}
          placeholder="e.g. tcp port 443 or udp port 53"
          className={FIELD}
          value={options.filter}
          disabled={locked}
          aria-invalid={verdict.kind === 'error'}
          aria-describedby="capture-filter-verdict"
          onChange={(e) => onChange({ filter: e.target.value })}
          onKeyDown={keepKeys}
        />
        <div id="capture-filter-verdict" aria-live="polite">
          {verdict.kind === 'none' && (
            <p className={`${NOTE} text-muted-foreground`}>
              Every frame the adapters see is captured.
            </p>
          )}
          {verdict.kind === 'checking' && (
            <p className={`${NOTE} text-muted-foreground`}>Checking with the agent…</p>
          )}
          {verdict.kind === 'ok' && (
            <p className={`${NOTE} text-muted-foreground flex items-center gap-1`}>
              <Check className="w-3 h-3 shrink-0 text-primary" strokeWidth={3} />
              Frames it does not match are dropped by the driver, before they are
              copied anywhere.
            </p>
          )}
          {verdict.kind === 'error' && (
            <p className={`${NOTE} text-danger flex items-start gap-1`}>
              <TriangleAlert className="w-3 h-3 shrink-0 mt-0.5" />
              <span className="break-words min-w-0">{verdict.message}</span>
            </p>
          )}
        </div>
      </div>

      <div className="space-y-1">
        <label className={`flex items-center gap-2 text-xs ${locked ? 'opacity-50' : 'cursor-pointer'}`}>
          <input
            type="checkbox"
            className="accent-primary"
            checked={options.limitBytes}
            disabled={locked}
            onChange={(e) => onChange({ limitBytes: e.target.checked })}
            onKeyDown={keepKeys}
          />
          <span>Keep only the first</span>
          <input
            aria-label="Bytes kept of each packet"
            inputMode="numeric"
            className={`${FIELD} w-16 text-center`}
            value={draft}
            disabled={locked || !options.limitBytes}
            aria-invalid={!draftValid}
            onChange={(e) => {
              const digits = e.target.value.replace(/\D/g, '').slice(0, 5);
              setDraft(digits);
              const n = Number(digits);
              if (digits !== '' && n >= MIN_SNAPLEN && n <= MAX_SNAPLEN) onChange({ snaplen: n });
            }}
            onBlur={() => setDraft(String(options.snaplen))}
            onKeyDown={keepKeys}
          />
          <span>bytes</span>
        </label>
        <p className={`${NOTE} text-muted-foreground`}>
          {options.limitBytes
            ? draftValid
              ? 'Headers without their payloads: less to store, and less for a burst to overflow. '
                + 'Cut packets are marked, and their lengths on the wire are kept.'
              : `A length from ${MIN_SNAPLEN} to ${MAX_SNAPLEN.toLocaleString()} bytes.`
            : 'Every packet is captured whole.'}
        </p>
      </div>
    </div>
  );
};
