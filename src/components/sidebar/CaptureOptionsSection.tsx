import React, { useEffect, useState } from 'react';
import { Check, TriangleAlert } from 'lucide-react';
import {
  MAX_CAPTURE_FILTER_CHARS, MAX_LIMIT, MAX_RING_FILES, MAX_SNAPLEN, MIN_RING_KEEP, MIN_SNAPLEN,
  ringProblem, type CaptureOptions, type FilterVerdict,
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
  /** Why the last capture stopped itself, or null: said where its limits were set. */
  stopNote?: string | null;
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

/**
 * A count the capture is limited by, blank for none. Committed only when it
 * is one - a half-typed number is never sent, and never saved - and put back
 * to the committed value on blur.
 */
const Count: React.FC<{
  label: string;
  unit: string;
  value: number | null;
  least: number;
  most?: number;
  disabled: boolean;
  onChange: (value: number | null) => void;
}> = ({ label, unit, value, least, most = MAX_LIMIT, disabled, onChange }) => {
  const [draft, setDraft] = useState(value === null ? '' : String(value));
  useEffect(() => { setDraft(value === null ? '' : String(value)); }, [value]);
  const n = Number(draft);
  const valid = draft === '' || (/^\d+$/.test(draft) && n >= least && n <= most);
  return (
    <span className="inline-flex items-center gap-1">
      <input
        aria-label={label}
        inputMode="numeric"
        className={`${FIELD} w-14 text-center`}
        value={draft}
        placeholder="-"
        disabled={disabled}
        aria-invalid={!valid}
        onChange={(e) => {
          const digits = e.target.value.replace(/\D/g, '').slice(0, 10);
          setDraft(digits);
          const next = Number(digits);
          if (digits === '') onChange(null);
          else if (next >= least && next <= most) onChange(next);
        }}
        onBlur={() => setDraft(value === null ? '' : String(value))}
        onKeyDown={keepKeys}
      />
      <span className="text-muted-foreground">{unit}</span>
    </span>
  );
};

export const CaptureOptionsSection: React.FC<CaptureOptionsSectionProps> = ({
  options, onChange, verdict, locked, stopNote = null,
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
              <Check className="w-3 h-3 shrink-0 text-primary" />
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
        {/* Two lines on purpose: the checkbox and its phrase, then the number
            and its unit beneath, indented to the phrase. Side by side the
            label wrapped mid-phrase into three or four lines at the side bar's
            170px floor. Still one label, so the ids and the aria wiring are
            unchanged. */}
        <label className={`flex flex-col gap-1 text-xs ${locked ? 'opacity-50' : 'cursor-pointer'}`}>
          <span className="flex items-center gap-2">
            <input
              type="checkbox"
              className="accent-primary"
              checked={options.limitBytes}
              disabled={locked}
              onChange={(e) => onChange({ limitBytes: e.target.checked })}
              onKeyDown={keepKeys}
            />
            <span>Keep only the first</span>
          </span>
          <span className="flex items-center gap-2 pl-5">
            <input
              aria-label="Bytes kept of each packet"
              inputMode="numeric"
              className={`${FIELD} w-16 text-center`}
              value={draft}
              disabled={locked || !options.limitBytes}
              aria-invalid={!draftValid}
              onChange={(e) => {
                const digits = e.target.value.replace(/\D/g, '').slice(0, 6);
                setDraft(digits);
                const n = Number(digits);
                if (digits !== '' && n >= MIN_SNAPLEN && n <= MAX_SNAPLEN) onChange({ snaplen: n });
              }}
              onBlur={() => setDraft(String(options.snaplen))}
              onKeyDown={keepKeys}
            />
            <span>bytes</span>
          </span>
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

      <div className="space-y-1">
        <label className={`flex items-center gap-2 text-xs ${locked ? 'opacity-50' : 'cursor-pointer'}`}>
          <input
            type="checkbox"
            className="accent-primary"
            checked={options.ringOn}
            disabled={locked}
            onChange={(e) => onChange({ ringOn: e.target.checked })}
            onKeyDown={keepKeys}
          />
          <span>Multiple files</span>
        </label>
        {options.ringOn && (
          <div className="pl-5 space-y-1 text-xs">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span>New file every</span>
              <Count label="Megabytes a file" unit="MB" value={options.ringMegabytes} least={1}
                disabled={locked} onChange={(v) => onChange({ ringMegabytes: v })} />
              <Count label="Seconds a file" unit="s" value={options.ringSeconds} least={1}
                disabled={locked} onChange={(v) => onChange({ ringSeconds: v })} />
              <Count label="Packets a file" unit="packets" value={options.ringPackets} least={1}
                disabled={locked} onChange={(v) => onChange({ ringPackets: v })} />
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span>Keep the newest</span>
              <Count label="Files kept" unit="files" value={options.ringKeep} least={MIN_RING_KEEP}
                most={MAX_RING_FILES} disabled={locked} onChange={(v) => onChange({ ringKeep: v })} />
            </div>
            {/* The deletion said beside the setting that causes it: a ring is
                the one place this app deletes frames without being asked
                each time (ADR 0052). */}
            <p className={`${NOTE} text-muted-foreground`}>
              {options.ringKeep === null
                ? 'Every file is kept.'
                : 'Older files are deleted as new ones fill, and their packets leave the list.'}
            </p>
          </div>
        )}
      </div>

      <div className="space-y-1">
        <span className={LABEL}>Stop after</span>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
          <Count label="Stop after packets" unit="packets" value={options.stopPackets} least={1}
            disabled={locked} onChange={(v) => onChange({ stopPackets: v })} />
          <Count label="Stop after megabytes" unit="MB" value={options.stopMegabytes} least={1}
            disabled={locked} onChange={(v) => onChange({ stopMegabytes: v })} />
          <Count label="Stop after seconds" unit="s" value={options.stopSeconds} least={1}
            disabled={locked} onChange={(v) => onChange({ stopSeconds: v })} />
          {options.ringOn && (
            <Count label="Stop after files" unit="files" value={options.stopFiles} least={1}
              most={MAX_RING_FILES} disabled={locked} onChange={(v) => onChange({ stopFiles: v })} />
          )}
        </div>
      </div>

      {stopNote !== null && (
        <p className={`${NOTE} text-muted-foreground`} role="status">{stopNote}</p>
      )}

      {ringProblem(options) !== null && (
        <p className={`${NOTE} text-danger flex items-start gap-1`} role="alert">
          <TriangleAlert className="w-3 h-3 shrink-0 mt-0.5" />
          <span className="break-words min-w-0">{ringProblem(options)}</span>
        </p>
      )}
    </div>
  );
};
