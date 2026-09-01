/**
 * The typed WebSocket protocol spoken with the local capture agent
 * (ws://localhost:8999) - message parsing, version comparison, and command
 * encoding. Kept dependency-free and pure so it's testable without a real
 * WebSocket (see scripts/agent-protocol/).
 */

export interface AgentHelloMessage {
  type: 'hello';
  version: string;
  state: 'idle' | 'sniffing';
  interfaces: { name: string; label: string }[];
}

export interface AgentStateMessage {
  type: 'state';
  state: 'idle' | 'sniffing';
  interfaces: { name: string; label: string }[];
}

export interface AgentErrorMessage {
  type: 'error';
  message: string;
  // Discriminates why the agent rejected a command - currently only
  // 'empty_interfaces'. Optional, so an agent that sends a bare message
  // still parses.
  code?: string;
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

export interface AgentPacketMessage {
  type: 'packet';
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

export type AgentMessage =
  | AgentHelloMessage
  | AgentStateMessage
  | AgentErrorMessage
  | AgentLogMessage
  | AgentInterfaceStatsMessage
  | AgentPacketMessage;

function isValidState(state: unknown): state is 'idle' | 'sniffing' {
  return state === 'idle' || state === 'sniffing';
}

function isValidInterfaceList(interfaces: unknown): interfaces is { name: string; label: string }[] {
  return Array.isArray(interfaces) && interfaces.every(
    (i) => i && typeof i === 'object' && typeof (i as any).name === 'string' && typeof (i as any).label === 'string'
  );
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

/**
 * Every agent message carries a `type` now - a clean break from the old
 * untyped packet-only stream (see spec: "there's no need to keep supporting
 * untyped legacy messages"). Anything that doesn't parse as one of the five
 * known shapes - including the old shape with no `type` at all - returns
 * null rather than throwing, so a single malformed message can't take down
 * the WebSocket handler.
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
    case 'packet':
      return msg as unknown as AgentPacketMessage;
    default:
      return null;
  }
}

/**
 * Bumped alongside AGENT_VERSION in local-agent/agent.py. Compared against
 * whatever the connected agent reports in its hello message to flag a
 * stale build in the UI.
 */
export const REQUIRED_AGENT_VERSION = '2.6.0';

/**
 * Simple major.minor.patch comparison - good enough for this agent's
 * versioning (no pre-release tags, no build metadata). Plain string
 * inequality would get "1.9.9" vs "1.10.0" backwards, which is why this
 * parses each segment as a number instead.
 */
export function isAgentOutdated(reportedVersion: string, requiredVersion: string): boolean {
  const parse = (v: string) => v.split('.').map((n) => parseInt(n, 10) || 0);
  const [rMajor = 0, rMinor = 0, rPatch = 0] = parse(reportedVersion);
  const [qMajor = 0, qMinor = 0, qPatch = 0] = parse(requiredVersion);
  if (rMajor !== qMajor) return rMajor < qMajor;
  if (rMinor !== qMinor) return rMinor < qMinor;
  return rPatch < qPatch;
}

export type AgentCommand =
  | { type: 'start_capture' }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] }
  | { type: 'subscribe_logs' }
  | { type: 'unsubscribe_logs' }
  | { type: 'subscribe_interface_stats' }
  | { type: 'unsubscribe_interface_stats' }
  /**
   * Asks the agent to restart its own process.
   *
   * The agent refuses unless it can confirm it is the process the Windows
   * service manager runs AND that a restart-on-failure policy exists to bring
   * it back - so an agent run from source, or one on a machine whose policy
   * was cleared, answers with `error` and stays up rather than exiting into a
   * state nothing can recover from. See agent.py's restart_agent handling.
   */
  | { type: 'restart_agent' };

export function encodeAgentCommand(command: AgentCommand): string {
  return JSON.stringify(command);
}
