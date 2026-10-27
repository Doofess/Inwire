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
  /**
   * Multiple files - Wireshark's ring buffer, written by the agent into the
   * capture's own folder (ADR 0052). A new file at whichever limit comes
   * first; each limit left null is not one. Kept while switched off, like the
   * snaplen.
   */
  ringOn: boolean;
  ringMegabytes: number | null;
  ringSeconds: number | null;
  ringPackets: number | null;
  /** The newest files kept; the older ones are deleted. Null keeps them all. */
  ringKeep: number | null;
  /** When the agent stops the capture itself. Each null is not a limit. */
  stopPackets: number | null;
  stopMegabytes: number | null;
  stopSeconds: number | null;
  /** Only with multiple files: one file never becomes two. */
  stopFiles: number | null;
}

/**
 * The least a snaplen may be, and the most. The agent's own bounds: libpcap
 * takes any positive length, and the most is dumpcap's default, 262,144 -
 * keeping everything. It was 65,535 while the wire record's lengths were 16
 * bits; they are 32 since version 4.
 */
export const MIN_SNAPLEN = 1;
export const MAX_SNAPLEN = 262144;

/**
 * What the snaplen field offers first. Enough for an Ethernet, IPv6 and TCP
 * header with options (14 + 40 + 60 = 114) and the start of what they carry -
 * the "headers and a bit" Wireshark's performance advice reaches for.
 */
export const SUGGESTED_SNAPLEN = 128;

/** The agent's `MAX_CAPTURE_FILTER_CHARS`: a longer filter is refused there. */
export const MAX_CAPTURE_FILTER_CHARS = 4096;

/** The agent's bounds on a ring (`protocol.rs`): a file of at least 64 KiB,
 * at least two kept, at most Wireshark's 100,000 files. The panel counts in
 * whole megabytes, so its least file is 1 MB. */
export const MIN_RING_KEEP = 2;
export const MAX_RING_FILES = 100_000;
/** The most any count here may be: past it is not a setting but a typo. */
export const MAX_LIMIT = 1_000_000_000;

export const DEFAULT_CAPTURE_OPTIONS: CaptureOptions = {
  filter: '',
  limitBytes: false,
  snaplen: SUGGESTED_SNAPLEN,
  ringOn: false,
  ringMegabytes: 100,
  ringSeconds: null,
  ringPackets: null,
  ringKeep: 10,
  stopPackets: null,
  stopMegabytes: null,
  stopSeconds: null,
  stopFiles: null,
};

/** A whole number from `least` to `most`, or null - never a guess between. */
function countOf(value: unknown, least: number, most = MAX_LIMIT): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= least && value <= most ? value : null;
}

export function normalizeCaptureOptions(raw: unknown): CaptureOptions | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const snaplen = typeof o.snaplen === 'number' && Number.isInteger(o.snaplen)
    && o.snaplen >= MIN_SNAPLEN && o.snaplen <= MAX_SNAPLEN ? o.snaplen : SUGGESTED_SNAPLEN;
  return {
    filter: typeof o.filter === 'string' ? o.filter.slice(0, MAX_CAPTURE_FILTER_CHARS) : '',
    limitBytes: o.limitBytes === true,
    snaplen,
    ringOn: o.ringOn === true,
    // An option stored before this build had none of these: the defaults,
    // not nulls, so the ring a person switches on first has a size.
    ringMegabytes: 'ringMegabytes' in o ? countOf(o.ringMegabytes, 1) : DEFAULT_CAPTURE_OPTIONS.ringMegabytes,
    ringSeconds: countOf(o.ringSeconds, 1),
    ringPackets: countOf(o.ringPackets, 1),
    ringKeep: 'ringKeep' in o ? countOf(o.ringKeep, MIN_RING_KEEP, MAX_RING_FILES) : DEFAULT_CAPTURE_OPTIONS.ringKeep,
    stopPackets: countOf(o.stopPackets, 1),
    stopMegabytes: countOf(o.stopMegabytes, 1),
    stopSeconds: countOf(o.stopSeconds, 1),
    stopFiles: countOf(o.stopFiles, 1, MAX_RING_FILES),
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

const MEGABYTE = 1024 * 1024;

/** Whether the ring is on and has a limit to start a new file at. */
export function ringRotates(options: CaptureOptions): boolean {
  return options.ringOn
    && (options.ringMegabytes !== null || options.ringSeconds !== null || options.ringPackets !== null);
}

/**
 * Why these ring and stop settings cannot start a capture, or null. The
 * agent refuses the same things in its own words; saying so here means Start
 * is blocked with a reason instead of answered with a refusal.
 */
export function ringProblem(options: CaptureOptions): string | null {
  if (options.ringOn && !ringRotates(options)) {
    return 'Multiple files needs a size, a duration or a packet count to start a new file at.';
  }
  if (options.stopFiles !== null && !options.ringOn) {
    return 'Stopping after a number of files needs multiple files: one file never becomes two.';
  }
  return null;
}

/**
 * The `start_capture` for these options, for the capture `captureId` names.
 *
 * Each field is left out when it asks for nothing. The capture id is what
 * makes the agent write the capture's own pcapng, into that capture's folder
 * (ADR 0052) - the renderer names a capture, never a path.
 */
export function startCaptureCommand(options: CaptureOptions, captureId: string | null = null): AgentCommand {
  const filter = effectiveFilter(options);
  const snaplen = effectiveSnaplen(options);
  const ring = ringRotates(options)
    ? {
      ...(options.ringMegabytes !== null ? { fileBytes: options.ringMegabytes * MEGABYTE } : {}),
      ...(options.ringSeconds !== null ? { fileSeconds: options.ringSeconds } : {}),
      ...(options.ringPackets !== null ? { filePackets: options.ringPackets } : {}),
      ...(options.ringKeep !== null ? { keep: options.ringKeep } : {}),
    }
    : null;
  const autostop = {
    ...(options.stopPackets !== null ? { packets: options.stopPackets } : {}),
    ...(options.stopMegabytes !== null ? { bytes: options.stopMegabytes * MEGABYTE } : {}),
    ...(options.stopSeconds !== null ? { seconds: options.stopSeconds } : {}),
    ...(options.stopFiles !== null && ring !== null ? { files: options.stopFiles } : {}),
  };
  // Ring and autostop are about the capture's files, so without a capture to
  // write they are not sent - the agent would refuse them, rightly.
  const writes = captureId !== null;
  return {
    type: 'start_capture',
    ...(filter !== null ? { filter } : {}),
    ...(snaplen !== null ? { snaplen } : {}),
    ...(writes ? { captureId } : {}),
    ...(writes && ring !== null ? { ring } : {}),
    ...(writes && Object.keys(autostop).length > 0 ? { autostop } : {}),
  };
}

/**
 * Starts a live capture: the Worker hears it is capturing, then the agent is
 * told to start.
 *
 * In that order, and both through the pipeline Worker's one port, which keeps
 * it. The Worker drops a batch that reaches it before it is capturing, and the
 * first frame it keeps begins the capture's numbering - so a frame dropped
 * ahead of it is no hole, is never read back from the agent's file, and is
 * missing from the store with nothing said. Telling it from React's effect on
 * `isCapturing`, after the start had gone, lost the capture's first frames.
 */
export function startLiveCapture(
  pipeline: { setCapturing(capturing: boolean): void; command(command: AgentCommand): void },
  start: AgentCommand,
): void {
  pipeline.setCapturing(true);
  pipeline.command(start);
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
  /** How the capture's files rotated, in words, or null for one file. */
  ring?: string | null;
  /** When the capture was set to stop itself, in words, or null. */
  autostop?: string | null;
}

/** "every 100 MB or 60 s, newest 10 kept" - the ring as a sentence. */
export function describeRing(options: CaptureOptions): string | null {
  if (!ringRotates(options)) return null;
  const at = [
    options.ringMegabytes !== null ? `${options.ringMegabytes.toLocaleString()} MB` : null,
    options.ringSeconds !== null ? `${options.ringSeconds.toLocaleString()} s` : null,
    options.ringPackets !== null ? `${options.ringPackets.toLocaleString()} packets` : null,
  ].filter((part): part is string => part !== null);
  const kept = options.ringKeep === null ? 'every file kept' : `newest ${options.ringKeep.toLocaleString()} kept`;
  return `a new file every ${at.join(' or ')}, ${kept}`;
}

/** "5,000 packets or 600 s" - the autostop as a phrase. */
export function describeAutostop(options: CaptureOptions): string | null {
  const at = [
    options.stopPackets !== null ? `${options.stopPackets.toLocaleString()} packets` : null,
    options.stopMegabytes !== null ? `${options.stopMegabytes.toLocaleString()} MB` : null,
    options.stopSeconds !== null ? `${options.stopSeconds.toLocaleString()} s` : null,
    options.stopFiles !== null && options.ringOn ? `${options.stopFiles.toLocaleString()} files` : null,
  ].filter((part): part is string => part !== null);
  return at.length === 0 ? null : at.join(' or ');
}

export function recordOf(options: CaptureOptions): CaptureOptionsRecord {
  return {
    filter: effectiveFilter(options),
    snaplen: effectiveSnaplen(options),
    ring: describeRing(options),
    autostop: describeAutostop(options),
  };
}
