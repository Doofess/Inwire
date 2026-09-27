import type { AgentCaptureFilterCheckMessage, AgentCommand } from './agentProtocol';
import { createPreferenceStore } from './preferenceStore';

/**
 * What a capture asks the driver to do before a frame is copied anywhere: a
 * libpcap capture filter, and a snaplen (ADR 0050).
 *
 * **Both are the agent's to apply, which is the whole reason they exist.** A
 * display filter decides what the list shows; every frame it hides still
 * filled the kernel ring, crossed the pipe, was dissected and was written to
 * disk. A capture filter refuses a frame in the driver, so traffic nobody
 * asked for costs nothing - the one lever that makes a burst of it harmless -
 * and a snaplen keeps the headers of a bulk transfer without its payloads.
 *
 * Fixed for the life of a capture, as the adapters are (ADR 0048): the panel
 * locks while one runs, and a running capture ignores the options of a second
 * `start_capture` because they were applied to handles that are still reading.
 *
 * Pure, so `scripts/session/capture-options.ts` can hold the rules without
 * React or an agent.
 */
export interface CaptureOptions {
  /** A libpcap capture filter, as typed. Blank captures everything. */
  filter: string;
  /** Whether to keep only the first `snaplen` bytes of each frame. */
  limitBytes: boolean;
  /** Kept while `limitBytes` is off, so turning it back on restores it. */
  snaplen: number;
}

/**
 * The least a snaplen may be, and the most. The agent's own bounds: libpcap
 * takes any positive length, and the wire record's captured length is a
 * `u16`, so 65535 is keeping everything.
 */
export const MIN_SNAPLEN = 1;
export const MAX_SNAPLEN = 65535;

/**
 * What the snaplen field offers first. Enough for an Ethernet, IPv6 and TCP
 * header with options (14 + 40 + 60 = 114) and the start of what they carry -
 * the "headers and a bit" Wireshark's performance advice reaches for.
 */
export const SUGGESTED_SNAPLEN = 128;

/** The agent's `MAX_CAPTURE_FILTER_CHARS`: a longer filter is refused there. */
export const MAX_CAPTURE_FILTER_CHARS = 4096;

export const DEFAULT_CAPTURE_OPTIONS: CaptureOptions = {
  filter: '',
  limitBytes: false,
  snaplen: SUGGESTED_SNAPLEN,
};

export function normalizeCaptureOptions(raw: unknown): CaptureOptions | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const snaplen = typeof o.snaplen === 'number' && Number.isInteger(o.snaplen)
    && o.snaplen >= MIN_SNAPLEN && o.snaplen <= MAX_SNAPLEN ? o.snaplen : SUGGESTED_SNAPLEN;
  return {
    filter: typeof o.filter === 'string' ? o.filter.slice(0, MAX_CAPTURE_FILTER_CHARS) : '',
    limitBytes: o.limitBytes === true,
    snaplen,
  };
}

/**
 * Remembered, as Wireshark remembers the last capture filter: a filter is
 * usually typed once for a network and used for every capture on it.
 */
export const captureOptionsStore = createPreferenceStore<CaptureOptions>(
  'inwire.captureOptions', normalizeCaptureOptions, DEFAULT_CAPTURE_OPTIONS,
);

/** The filter as it is sent: trimmed, and nothing when it is blank. */
export function effectiveFilter(options: CaptureOptions): string | null {
  const filter = options.filter.trim();
  return filter === '' ? null : filter;
}

/** The snaplen as it is sent, or null for every byte. */
export function effectiveSnaplen(options: CaptureOptions): number | null {
  return options.limitBytes && options.snaplen < MAX_SNAPLEN ? options.snaplen : null;
}

/**
 * The `start_capture` for these options. Each field is left out when it asks
 * for nothing, so a plain capture sends the same message it always did.
 */
export function startCaptureCommand(options: CaptureOptions): AgentCommand {
  const filter = effectiveFilter(options);
  const snaplen = effectiveSnaplen(options);
  return {
    type: 'start_capture',
    ...(filter !== null ? { filter } : {}),
    ...(snaplen !== null ? { snaplen } : {}),
  };
}

/**
 * What the panel says about the filter.
 *
 * - `none`: blank, so the capture takes everything the adapters see.
 * - `checking`: typed, and the agent's answer for exactly this text has not
 *   come back - or there is no agent to ask.
 * - `ok` / `error`: the agent compiled it for the selected adapters' link
 *   types, in libpcap's own words when it would not.
 *
 * **Only an answer about this exact text counts.** The check is asked on every
 * pause in typing, so answers arrive for text that has since changed; one
 * about `tcp port 44` must not say `tcp port 443` is fine. The agent echoes
 * the filter for that reason.
 */
export type FilterVerdict =
  | { kind: 'none' }
  | { kind: 'checking' }
  | { kind: 'ok' }
  | { kind: 'error'; message: string };

export function filterVerdict(
  options: CaptureOptions, check: AgentCaptureFilterCheckMessage | null,
): FilterVerdict {
  const filter = effectiveFilter(options);
  if (filter === null) return { kind: 'none' };
  if (filter.length > MAX_CAPTURE_FILTER_CHARS) {
    return { kind: 'error', message: `A capture filter is at most ${MAX_CAPTURE_FILTER_CHARS} characters long.` };
  }
  if (check === null || check.filter !== filter) return { kind: 'checking' };
  return check.error === null ? { kind: 'ok' } : { kind: 'error', message: check.error };
}

/**
 * Why Start must wait, or null. Only a filter the agent has refused blocks it:
 * one still being checked is sent as typed, and the agent refuses it per
 * adapter if it will not compile, so waiting on the check would only make a
 * slow answer a reason not to capture.
 */
export function filterBlocksStart(verdict: FilterVerdict): string | null {
  return verdict.kind === 'error' ? `The capture filter does not compile: ${verdict.message}` : null;
}

/**
 * The options as a capture's metadata records them - what an export says
 * about how the capture was taken. Null fields asked for nothing.
 */
export interface CaptureOptionsRecord {
  filter: string | null;
  snaplen: number | null;
}

export function recordOf(options: CaptureOptions): CaptureOptionsRecord {
  return { filter: effectiveFilter(options), snaplen: effectiveSnaplen(options) };
}
