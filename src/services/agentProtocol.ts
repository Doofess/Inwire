/**
 * The typed protocol spoken with the local capture agent - message parsing,
 * version comparison, and command encoding. Kept dependency-free and pure so
 * it is testable without a connection at all (see scripts/agent-protocol/).
 *
 * **Transport-agnostic, and that is what made the move to a named pipe cheap.**
 * This file described `ws://localhost:8999` for most of its life; not one
 * message in it changed when the socket went. What the WebSocket supplied
 * underneath - message boundaries, and a text/binary distinction - is now
 * `services/agentFraming.ts`, and who may connect is now the pipe's security
 * descriptor rather than a token named in this file.
 *
 * Wire format decisions are recorded in docs/decisions/0005-agent-wire-format.md.
 */

/**
 * One capturable adapter. `id` is its position in the list the agent sent
 * and is what a packet's `iface` refers to; it is optional only so a 3.0 agent
 * (which sends none) still parses, and callers fall back to the array index.
 */
export interface AgentInterface {
  id?: number;
  name: string;
  label: string;
  /**
   * The adapter's `LINKTYPE_*` value, when the agent could read it.
   *
   * **Absent means "not said", and the fallback is Ethernet** - which is what
   * every caller assumed before this field existed, correctly for every
   * adapter on a Windows machine except Npcap's loopback device. That one is
   * `LINKTYPE.NULL`: a 4-byte address family and then the IP header. Read as
   * Ethernet, bytes 12-13 land on the IP header's TTL and protocol, so a
   * loopback capture showed ethertypes `0x8006` and `0x8011` - 0x80 being the
   * Windows default TTL and 0x06/0x11 TCP and UDP - two fabricated MAC
   * addresses with vendors resolved from them, a direction decided from those
   * MACs, and no transport layer at all.
   *
   * Optional rather than defaulted in the agent, because an agent that has
   * looked and found Ethernet and an agent too old to look are different
   * facts, and only the second may be overridden by a later answer.
   */
  linkType?: number;
  /**
   * How many decimals of a second this adapter's timestamps carry: 9 when
   * its driver stamps in nanoseconds, 6 when in microseconds. The wire always
   * carries nanoseconds (`agentBinary.ts`); this says how many of them were
   * measured. Absent when the agent could not open the adapter to ask, which
   * reads as 6.
   */
  tsPrecision?: number;
}

export interface AgentHelloMessage {
  type: 'hello';
  version: string;
  state: 'idle' | 'sniffing';
  interfaces: AgentInterface[];
  /**
   * This connection's own id, so it can recognise itself in `state.owner`.
   * Optional because an agent before 3.3.0 sends none, and a client that does
   * not know its id simply never sees a capture as somebody else's - which is
   * exactly how those agents behaved.
   */
  clientId?: string;
  /** The connection that owns the running capture, or null when idle. */
  owner?: string | null;
  /**
   * The Npcap device object's DACL, as an SDDL string.
   *
   * Null where the agent looked and found nothing - no driver, no pywin32, not
   * Windows - and **absent** on an agent before 3.9.0, which is a different
   * thing and reads the same here only because both end in "not known".
   *
   * A string rather than a verdict: the agent runs as SYSTEM and is what can
   * read the descriptor, and the app is what decides whether it means the
   * capture devices are open to every local account. `services/npcapAccess.ts`
   * does the deciding; ADR 0033 says why the question is worth asking.
   */
  npcapAccess?: string | null;
}

export interface AgentStateMessage {
  type: 'state';
  state: 'idle' | 'sniffing';
  interfaces: AgentInterface[];
  /**
   * Which connection asked for the capture that is running, by the id that
   * connection was handed in `hello`; null when nothing is being captured.
   *
   * This is what lets a second window tell "capture is running" from "capture
   * is running and I am the one who can stop it". Without it, two tabs each
   * showed a Stop button and whichever was pressed stopped the other's
   * capture.
   */
  owner?: string | null;
}

/**
 * Why the agent rejected or could not carry out a command. A closed set the
 * app switches on; anything else is shown as its message only.
 */
export type AgentErrorCode =
  | 'empty_interfaces'
  | 'invalid_interfaces'
  | 'restart_unavailable'
  | 'capture_failed'
  | 'capture_busy'
  // `set_interfaces` while this client's own capture is running. The adapter
  // set is fixed for the life of a capture (ADR 0048); the app never sends
  // one then, so this answers some other client, or a bug.
  | 'capture_running'
  | 'unknown_command'
  // The Rust agent's. `no_interfaces`: a start with no adapter to capture on
  // at all - a machine without Npcap - which the Python agent answers by
  // reporting `sniffing` on nothing. (`frame_too_long` was its second, and went
  // with version 4's 32-bit lengths: no frame is too long to describe now.)
  | 'no_interfaces'
  // A `start_capture` or `check_capture_filter` whose filter or snaplen was
  // not one. Refused rather than started on defaults, which would be a capture
  // of everything its owner believes is narrowed.
  | 'invalid_capture_options';

export interface AgentErrorMessage {
  type: 'error';
  message: string;
  // Optional, so an agent that sends a bare message still parses.
  code?: AgentErrorCode | string;
  /**
   * For `capture_failed`: which interface (id) could not be opened or stopped
   * delivering. Absent when the selection named a device the interface list
   * does not have, rather than an id that belongs to a different adapter.
   */
  iface?: number;
}

/**
 * One line of the agent's own log. `time` and `level` are null for a
 * backlog line the agent could not parse - a traceback continuation line,
 * most often - which still arrives with its text intact in `message`
 * rather than being dropped.
 */
export interface AgentLogEntry {
  time: string | null;
  level: string | null;
  message: string;
}

/**
 * Carries both the backlog sent on subscribe (many entries) and each live
 * line after it (one entry), so the app needs a single handler rather than
 * two message types that differ only in how many entries they hold.
 */
export interface AgentLogMessage {
  type: 'log';
  lines: AgentLogEntry[];
}

/**
 * A captured frame. The 3.1 fields are optional at the type level because a
 * 3.0 agent omits them; the app treats their absence as "single interface,
 * arrival order, millisecond time" - which is exactly what 3.0 delivered.
 */
export interface AgentPacketMessage {
  type: 'packet';
  /** Per-capture sequence number, for ordering across interface threads. */
  seq?: number;
  /** Index into the hello/state interface list. */
  iface?: number;
  /** Capture time in epoch microseconds, from the driver. */
  tsUs?: number;
  /** Wire length; `raw` may be shorter under a snaplen. */
  origLen?: number;
  [key: string]: unknown;
}

/**
 * One sampling tick of per-adapter traffic rates, sent only while a client has
 * subscribed. `name` matches the `name` in the interface list, so the rows and
 * the rates join without a second lookup key.
 */
export interface AgentInterfaceRate {
  name: string;
  packetsPerSec: number;
  bytesPerSec: number;
}

export interface AgentInterfaceStatsMessage {
  type: 'interface_stats';
  /** The agent's sampling period, so the client can size its history window. */
  intervalMs: number;
  interfaces: AgentInterfaceRate[];
}

/**
 * What the capture driver and the agent each dropped, once a second while
 * sniffing. This is the message that makes loss visible: before it existed the
 * agent logged 260,000 dropped frames in one afternoon and the app showed a
 * clean, complete-looking list.
 *
 * `droppedKernel` is null - never 0 - when the driver's counters could not be
 * read, so "unknown" and "none" are never confused.
 */
export interface AgentCaptureInterfaceStats {
  iface: number;
  /** Frames this capture's callback saw on this interface. */
  received: number;
  /** The driver's own count of frames it delivered, when readable. */
  kernelReceived: number | null;
  /** Frames the driver dropped before the agent saw them, when readable. */
  droppedKernel: number | null;
}

export interface AgentCaptureStatsMessage {
  type: 'capture_stats';
  intervalMs: number;
  /** The next `seq` the agent will assign - one more than the highest sent. */
  seqHigh: number;
  /** Frames the agent dropped from its sniffer queue, waiting to be batched. */
  droppedAgent: number;
  /**
   * Frames shed from the outbound pipe queue because the client was not
   * reading fast enough - the third loss site, and the one that had no number
   * at all until it was found discarding frames with no counter and no log
   * line per drop.
   *
   * **Optional, and absent rather than 0 when nobody counted.** An agent
   * predating it omits the field, and the WebSocket transport has no
   * counterpart; `undefined` is "unknown" and `0` is "none lost here", which
   * is the distinction `droppedKernel` already draws with `null`.
   */
  droppedPipe?: number;
  /**
   * Frames the capture's own pcapng refused because the disk fell behind
   * (ADR 0052). Present only for a capture that writes a file; the list
   * still has them, the file does not.
   */
  droppedWriter?: number;
  interfaces: AgentCaptureInterfaceStats[];
}

/**
 * The numbers the UI shows, folded from one capture_stats message.
 * Kernel drops sum across interfaces; an unreadable counter on any one of
 * them makes the sum unknown rather than an undercount.
 */
export interface CaptureDropStats {
  received: number;
  droppedAgent: number;
  droppedKernel: number | null;
  /** `null` when the agent did not report it. Never folded to 0. */
  droppedPipe: number | null;
  seqHigh: number;
}

export function summarizeCaptureStats(message: AgentCaptureStatsMessage): CaptureDropStats {
  let received = 0;
  let droppedKernel: number | null = 0;
  for (const entry of message.interfaces) {
    received += entry.received;
    if (entry.droppedKernel === null) droppedKernel = null;
    else if (droppedKernel !== null) droppedKernel += entry.droppedKernel;
  }
  return {
    received,
    droppedAgent: message.droppedAgent,
    droppedKernel,
    // `?? null` rather than `?? 0`: an agent that does not send the field has
    // not told us the pipe lost nothing, it has told us nothing.
    droppedPipe: message.droppedPipe ?? null,
    seqHigh: message.seqHigh,
  };
}

/**
 * Which process owns which local socket, as a delta.
 *
 * The one fact a capture cannot contain. A frame records that 10.0.0.4:54321
 * talked to a server; only the machine that sent it knows 54321 belonged to
 * chrome.exe, and a passive observer anywhere else on the network never can.
 *
 * **Keyed by the local endpoint alone**, because Windows reports no remote
 * address for UDP sockets at all - so a five-tuple key would attribute no QUIC
 * and no DNS. See `local-agent/sockets.py`.
 *
 * **A delta, not a snapshot.** The full table is ~890 sockets and 52 KB of
 * JSON; it changes by one or two a second. `full` marks the snapshot a new
 * subscriber is given, and says to discard whatever was held rather than
 * merging into it.
 *
 * Tuples rather than objects because this is the shape that repeats: at one
 * message a second for the life of a capture, the key names would be most of
 * the bytes.
 */
export interface AgentSocketTableMessage {
  type: 'socket_table';
  /** True only for the snapshot that opens a subscription. */
  full: boolean;
  /**
   * The processes this message's additions refer to, by pid as a string.
   *
   * Re-sent whenever referenced rather than only when new, so each message can
   * be applied on its own. A pid that is absent is one the OS would not name -
   * a protected process, or one that exited between the two reads - and it
   * stays absent rather than being invented.
   */
  procs: Record<string, { name: string; exe: string }>;
  /** `[protocol, local address, local port, pid]`. A pid of 0 means unowned. */
  add: [string, string, number, number][];
  /** `[protocol, local address, local port]` for sockets that have closed. */
  gone: [string, string, number][];
}

/** One address the OS has configured, with what it knows about it. */
export interface AgentAdapterIpv4 {
  address: string;
  /** Null when the OS would not say - never a default that looks like one. */
  prefixLength: number | null;
  broadcast: string | null;
}

export interface AgentAdapterIpv6 {
  address: string;
  prefixLength: number | null;
  scope: 'global' | 'link-local' | 'ula' | 'loopback' | null;
  /**
   * An RFC 4941 privacy address, which rotates.
   *
   * Three states, and the third matters: `true` is "the OS said temporary",
   * `false` is "the OS said otherwise", and `null` is macOS, where nothing
   * cheap answers the question. A capture taken yesterday will not match a
   * temporary address held today, so the distinction is worth showing.
   */
  temporary: boolean | null;
}

/**
 * How one adapter is configured, as the operating system has it.
 *
 * The counterpart to `socket_table`: both are facts about the captured machine
 * that no frame carries, read on that machine and sent over the local socket
 * alone (`docs/decisions/0009-off-wire-enrichment.md`). What makes it worth
 * having is the comparison - the capture reveals the gateway, the resolvers
 * and the DHCP server independently, so configured and observed can be put
 * side by side and disagreements called out.
 *
 * **Every field is nullable and a null means "not known".** It never means
 * zero, absent, or disabled. A provider that cannot read a lease time reports
 * no lease time, and `source` says which provider answered for each group so a
 * value on screen can be traced to where it came from.
 */
export interface AgentAdapter {
  /**
   * The capture device name, which is what the interface list is keyed by -
   * `\Device\NPF_{GUID}` on Windows, `eth0` elsewhere. Built from the GUID
   * rather than matched on a display name, so the join with a capture
   * interface is exact rather than a longest-prefix guess.
   */
  id: string;
  name: string;
  description: string | null;
  mac: string | null;
  status: 'up' | 'down' | null;
  speedMbps: number | null;
  mtu: number | null;
  dhcpEnabled: boolean | null;
  dhcpServer: string | null;
  /** Epoch seconds. Formatting a time belongs to whoever knows the locale. */
  leaseObtained: number | null;
  leaseExpires: number | null;
  ipv4: AgentAdapterIpv4[];
  ipv6: AgentAdapterIpv6[];
  gatewayV4: string | null;
  gatewayV6: string | null;
  gatewayMac: string | null;
  dnsServers: string[];
  dnsSuffix: string | null;
  /** Which provider supplied each group: `registry`, `powershell`, `ip`, ... */
  source: Record<string, string | null>;
}

/**
 * A whole snapshot, not a delta - unlike `socket_table`, and deliberately.
 *
 * A machine has a handful of adapters and the message is a couple of
 * kilobytes, where the socket table is 890 entries and 52 KB. A delta protocol
 * for two kilobytes would cost more in complexity than it could save in bytes.
 * What the two do share is the silence: the agent sends nothing at all when
 * nothing has changed, which is almost every poll.
 */
export interface AgentAdapterConfigMessage {
  type: 'adapter_config';
  adapters: AgentAdapter[];
}

/**
 * Whether a capture filter compiles, answering `check_capture_filter`.
 *
 * `filter` is the text that was asked about, echoed so an answer that crossed
 * a newer question on the way can be recognised as stale - a filter box asks
 * on every pause in typing. `error` is libpcap's own sentence, or null when
 * the filter compiles for every link type among the adapters named.
 */
export interface AgentCaptureFilterCheckMessage {
  type: 'capture_filter_check';
  filter: string;
  error: string | null;
}

/**
 * One of the capture's pcapng files, as the agent opened, closed or deleted it
 * (ADR 0052). `firstSeq`/`lastSeq` are the sequence numbers of the frames it
 * holds - what the store evicts by when a ring deletes the file - and null
 * until it holds one. A name, never a path: the app knows where its captures
 * live.
 */
export interface AgentCaptureFileMessage {
  type: 'capture_file';
  index: number;
  name: string;
  state: 'open' | 'closed' | 'deleted';
  firstSeq: number | null;
  lastSeq: number | null;
  frames: number;
  bytes: number;
}

/**
 * Where a ring file begins: frames from `firstSeq` on are in file `index`
 * (ADR 0052). Sent before any frame in the file, so the pipeline Worker files
 * every frame by its sequence number - which is what the capture on disk
 * follows the ring by.
 */
export interface AgentCaptureBoundaryMessage {
  type: 'capture_boundary';
  index: number;
  firstSeq: number;
}

/** The agent stopped the capture itself: an autostop limit was met. */
export interface AgentCaptureStoppedMessage {
  type: 'capture_stopped';
  reason: 'packets' | 'bytes' | 'seconds' | 'files';
}

export type AgentMessage =
  | AgentCaptureBoundaryMessage
  | AgentCaptureFileMessage
  | AgentCaptureStoppedMessage
  | AgentCaptureFilterCheckMessage
  | AgentHelloMessage
  | AgentStateMessage
  | AgentErrorMessage
  | AgentLogMessage
  | AgentInterfaceStatsMessage
  | AgentCaptureStatsMessage
  | AgentSocketTableMessage
  | AgentAdapterConfigMessage
  | AgentPacketMessage;

/**
 * Checks only what the app would break without, and lets the rest be null.
 *
 * Every field but `id` is allowed to be missing, because a provider that could
 * not read something reports nothing - that is the contract, not a fault - and
 * a validator that rejected a partially-answerable adapter would throw away
 * the half the OS did know. `id` is the exception because it is the join key
 * to the capture interface, and an entry that cannot be attached to one is an
 * entry with nowhere to go.
 */
function isValidAdapterList(adapters: unknown): adapters is AgentAdapter[] {
  return Array.isArray(adapters) && adapters.every((a) => {
    if (!a || typeof a !== 'object') return false;
    const entry = a as Record<string, unknown>;
    return typeof entry.id === 'string' && entry.id.length > 0
      && Array.isArray(entry.ipv4) && Array.isArray(entry.ipv6)
      && Array.isArray(entry.dnsServers);
  });
}

function isValidState(state: unknown): state is 'idle' | 'sniffing' {
  return state === 'idle' || state === 'sniffing';
}

function isValidInterfaceList(interfaces: unknown): interfaces is AgentInterface[] {
  return Array.isArray(interfaces) && interfaces.every((i) => {
    if (!i || typeof i !== 'object') return false;
    const entry = i as Record<string, unknown>;
    if (typeof entry.name !== 'string' || typeof entry.label !== 'string') return false;
    // A link type that is not a non-negative integer is a malformed message
    // rather than a missing field: it selects a dissector, and a NaN or a
    // negative would fall through to Ethernet silently - which is the exact
    // wrong reading this field exists to stop.
    if (entry.linkType !== undefined
      && !(typeof entry.linkType === 'number' && Number.isInteger(entry.linkType)
        && entry.linkType >= 0)) return false;
    // Decimals of a second, so 0 to 9: a precision past nanoseconds is one
    // the wire cannot carry, and would print digits nobody measured.
    if (entry.tsPrecision !== undefined
      && !(typeof entry.tsPrecision === 'number' && Number.isInteger(entry.tsPrecision)
        && entry.tsPrecision >= 0 && entry.tsPrecision <= 9)) return false;
    return entry.id === undefined || (typeof entry.id === 'number' && Number.isInteger(entry.id));
  });
}

function isValidLogLines(lines: unknown): lines is AgentLogEntry[] {
  return Array.isArray(lines) && lines.every((l) => {
    if (!l || typeof l !== 'object') return false;
    const entry = l as Record<string, unknown>;
    if (typeof entry.message !== 'string') return false;
    if (entry.time !== null && typeof entry.time !== 'string') return false;
    if (entry.level !== null && typeof entry.level !== 'string') return false;
    return true;
  });
}

function isValidInterfaceRates(rates: unknown): rates is AgentInterfaceRate[] {
  return Array.isArray(rates) && rates.every((r) => {
    if (!r || typeof r !== 'object') return false;
    const rate = r as Record<string, unknown>;
    // Rates are drawn as a chart, so a NaN or an Infinity would silently
    // collapse the whole sparkline's scale rather than showing one bad point.
    return typeof rate.name === 'string'
      && typeof rate.packetsPerSec === 'number' && Number.isFinite(rate.packetsPerSec)
      && typeof rate.bytesPerSec === 'number' && Number.isFinite(rate.bytesPerSec);
  });
}

const isCount = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const isCountOrNull = (v: unknown) => v === null || isCount(v);

function isValidCaptureStats(entries: unknown): entries is AgentCaptureInterfaceStats[] {
  return Array.isArray(entries) && entries.every((e) => {
    if (!e || typeof e !== 'object') return false;
    const s = e as Record<string, unknown>;
    return isCount(s.iface) && isCount(s.received)
      && isCountOrNull(s.kernelReceived) && isCountOrNull(s.droppedKernel);
  });
}

/**
 * Every agent message carries a `type` now - a clean break from the old
 * untyped packet-only stream (see spec: "there's no need to keep supporting
 * untyped legacy messages"). Anything that doesn't parse as one of the known
 * shapes - including the old shape with no `type` at all - returns null
 * rather than throwing, so a single malformed message can't take down the
 * handler draining the link.
 */
export function parseAgentMessage(raw: string): AgentMessage | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!data || typeof data !== 'object') return null;
  const msg = data as Record<string, unknown>;

  switch (msg.type) {
    case 'hello':
      if (typeof msg.version !== 'string' || !isValidState(msg.state) || !isValidInterfaceList(msg.interfaces)) return null;
      return msg as unknown as AgentHelloMessage;
    case 'state':
      if (!isValidState(msg.state) || !isValidInterfaceList(msg.interfaces)) return null;
      return msg as unknown as AgentStateMessage;
    case 'error':
      if (typeof msg.message !== 'string') return null;
      return msg as unknown as AgentErrorMessage;
    case 'log':
      if (!isValidLogLines(msg.lines)) return null;
      return msg as unknown as AgentLogMessage;
    case 'interface_stats':
      if (typeof msg.intervalMs !== 'number' || !isValidInterfaceRates(msg.interfaces)) return null;
      return msg as unknown as AgentInterfaceStatsMessage;
    case 'capture_stats':
      if (!isCount(msg.intervalMs) || !isCount(msg.seqHigh) || !isCount(msg.droppedAgent)
        || !isValidCaptureStats(msg.interfaces)) return null;
      // `droppedPipe` is additive and optional, so absent is valid - but a
      // present one that is not a count is a malformed message, not a missing
      // field, and accepting it would put a negative or a NaN into a figure
      // the status bar adds up.
      if (msg.droppedPipe !== undefined && !isCount(msg.droppedPipe)) return null;
      return msg as unknown as AgentCaptureStatsMessage;
    case 'socket_table':
      if (typeof msg.full !== 'boolean' || !Array.isArray(msg.add) || !Array.isArray(msg.gone)
        || typeof msg.procs !== 'object' || msg.procs === null) return null;
      return msg as unknown as AgentSocketTableMessage;
    case 'adapter_config':
      if (!isValidAdapterList(msg.adapters)) return null;
      return msg as unknown as AgentAdapterConfigMessage;
    case 'packet':
      return msg as unknown as AgentPacketMessage;
    case 'capture_filter_check':
      if (typeof msg.filter !== 'string' || !(msg.error === null || typeof msg.error === 'string')) return null;
      return msg as unknown as AgentCaptureFilterCheckMessage;
    case 'capture_file': {
      const seqOrNull = (v: unknown) => v === null || (typeof v === 'number' && Number.isInteger(v) && v >= 0);
      if (typeof msg.index !== 'number' || typeof msg.name !== 'string'
        || !['open', 'closed', 'deleted'].includes(msg.state as string)
        || !seqOrNull(msg.firstSeq) || !seqOrNull(msg.lastSeq)
        || typeof msg.frames !== 'number' || typeof msg.bytes !== 'number') return null;
      return msg as unknown as AgentCaptureFileMessage;
    }
    case 'capture_boundary':
      if (!isCount(msg.index) || (msg.index as number) < 1 || !isCount(msg.firstSeq)) return null;
      return msg as unknown as AgentCaptureBoundaryMessage;
    case 'capture_stopped':
      if (!['packets', 'bytes', 'seconds', 'files'].includes(msg.reason as string)) return null;
      return msg as unknown as AgentCaptureStoppedMessage;
    default:
      return null;
  }
}

/**
 * The agent Inwire ships with, which is Inwire's own version (ADR 0035).
 *
 * Compared against whatever the connected agent reports in `hello`, to flag a
 * build left behind by an earlier install. It is a **literal** rather than an
 * import of `package.json` because this module is loaded by the renderer, by
 * the pipeline Worker and by a dozen scripts under plain `tsx`, and pulling a
 * JSON module into all three to read one string costs more than a line that
 * `scripts/agent/version.ts` holds to the product on every `npm run check`.
 *
 * **Compared for equality, not order** (ADR 0051). The installer puts the app
 * and the agent down together, so an agent reporting any other version is one
 * a different install left behind - older or newer, the app cannot trust its
 * wire format, and the fix is the same installer either way. An ordering is
 * what this used to be, and it made the number unable to go down: an agent from
 * a higher-numbered build read as newer than required, and passed.
 */
export const REQUIRED_AGENT_VERSION = '0.5.0';

/**
 * Is the running agent from a different build than this app?
 *
 * Segment by segment as numbers, so "0.4.1" and "0.4.01" are one version and a
 * missing segment is 0. No pre-release tags and no build metadata: the version
 * is MAJOR.MINOR.PATCH, which `sync-version.ts` refuses to stamp otherwise.
 */
export function isAgentMismatched(reportedVersion: string, requiredVersion: string): boolean {
  const parse = (v: string) => v.split('.').map((n) => parseInt(n, 10) || 0);
  const [rMajor = 0, rMinor = 0, rPatch = 0] = parse(reportedVersion);
  const [qMajor = 0, qMinor = 0, qPatch = 0] = parse(requiredVersion);
  return rMajor !== qMajor || rMinor !== qMinor || rPatch !== qPatch;
}

export type AgentCommand =
  /**
   * Starts a capture on the selected adapters.
   *
   * `filter` is a libpcap capture filter and `snaplen` the most bytes of each
   * frame to keep; the driver applies both before a frame is copied anywhere
   * (`services/captureOptions.ts`). Each is left out when it asks for nothing
   * - no filter, every byte - so a plain start is the same message it always
   * was.
   */
  | {
    type: 'start_capture'; filter?: string; snaplen?: number;
    /**
     * The capture's id, which makes the agent write its pcapng into that
     * capture's folder (ADR 0052) - under the root main told it with
     * `set_capture_root`, so this names a capture and never a path.
     */
    captureId?: string;
    /** Wireshark's ring buffer: a new file at any limit, the newest `keep` kept. */
    ring?: { fileBytes?: number; fileSeconds?: number; filePackets?: number; keep?: number };
    /** When the agent stops the capture itself. */
    autostop?: { packets?: number; bytes?: number; seconds?: number; files?: number };
  }
  /**
   * Would this filter compile for these adapters? Asks nothing of the
   * capture, and is answered with `capture_filter_check`.
   */
  | { type: 'check_capture_filter'; filter: string; interfaces: string[] }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] }
  | { type: 'subscribe_logs' }
  | { type: 'unsubscribe_logs' }
  | { type: 'subscribe_interface_stats' }
  | { type: 'unsubscribe_interface_stats' }
  /**
   * Asks for the process behind each local socket, as a snapshot then deltas.
   *
   * Subscribed rather than always-on for the same reason the log and the
   * interface rates are: a client that never turns process attribution on
   * should not cause the socket table to be read at all.
   */
  | { type: 'subscribe_sockets' }
  | { type: 'unsubscribe_sockets' }
  /**
   * Asks how this machine's adapters are configured, then again on any change.
   *
   * Subscribed rather than sent with `hello` for the same reason the socket
   * table is: reading it costs real work - the registry, and a PowerShell
   * spawn when the address list has moved - and a client that never opens the
   * Network panel should not cause any of it.
   */
  | { type: 'subscribe_adapters' }
  | { type: 'unsubscribe_adapters' }
  /**
   * Re-reads from the machine, discarding anything the agent had cached.
   *
   * What Refresh sends. Pressing it is a statement that something has just
   * been changed, so answering from a reading taken before the change is the
   * one answer that is certainly wrong - and the agent replies even when the
   * result is identical, because "nothing changed" is itself the answer the
   * user asked for.
   */
  | { type: 'refresh_adapters' };
  // `restart_agent` is not here. Both agents still understand it, and the app
  // stopped sending it on 2026-09-26, when Restart Driver was removed from
  // Capture Health at the owner's request.

export function encodeAgentCommand(command: AgentCommand): string {
  return JSON.stringify(command);
}

/**
 * `set_capture_root`: where this app's captures live, which the agent writes
 * a capture's pcapng under (ADR 0052).
 *
 * **Main's to send, and deliberately not an `AgentCommand`.** The renderer
 * sends every command in that union, and the renderer never names a path - a
 * page that could name the folder a LocalSystem service writes into is the
 * door ADR 0052's impersonation exists to shut twice. Main knows the folder
 * because it made it (`electron/store/host.ts`), and sends this once per pipe.
 */
export function encodeCaptureRootCommand(dir: string): string {
  return JSON.stringify({ type: 'set_capture_root', dir });
}
