/**
 * The typed WebSocket protocol spoken with the local capture agent
 * (ws://localhost:8999) - message parsing, version comparison, and pairing
 * token storage. Kept dependency-free and pure so it's testable without a
 * real WebSocket (see scripts/agent-protocol/).
 */

export interface AgentHelloMessage {
  type: 'hello';
  version: string;
  state: 'idle' | 'sniffing';
  authRequired: boolean;
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
  // Discriminates why the agent rejected something - e.g. 'invalid_token'
  // (stale/wrong pairing code, the one case that should clear the stored
  // token) vs. 'not_authenticated' or 'empty_interfaces' (neither of which
  // means the stored token itself is bad). Optional since older agent
  // builds only ever sent `message`.
  code?: string;
}

export interface AgentPacketMessage {
  type: 'packet';
  [key: string]: unknown;
}

export type AgentMessage = AgentHelloMessage | AgentStateMessage | AgentErrorMessage | AgentPacketMessage;

function isValidState(state: unknown): state is 'idle' | 'sniffing' {
  return state === 'idle' || state === 'sniffing';
}

function isValidInterfaceList(interfaces: unknown): interfaces is { name: string; label: string }[] {
  return Array.isArray(interfaces) && interfaces.every(
    (i) => i && typeof i === 'object' && typeof (i as any).name === 'string' && typeof (i as any).label === 'string'
  );
}

/**
 * Every agent message carries a `type` now - a clean break from the old
 * untyped packet-only stream (see spec: "there's no need to keep supporting
 * untyped legacy messages"). Anything that doesn't parse as one of the four
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
      if (typeof msg.version !== 'string' || typeof msg.authRequired !== 'boolean' || !isValidState(msg.state) || !isValidInterfaceList(msg.interfaces)) return null;
      return msg as unknown as AgentHelloMessage;
    case 'state':
      if (!isValidState(msg.state) || !isValidInterfaceList(msg.interfaces)) return null;
      return msg as unknown as AgentStateMessage;
    case 'error':
      if (typeof msg.message !== 'string') return null;
      return msg as unknown as AgentErrorMessage;
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
export const REQUIRED_AGENT_VERSION = '1.1.0';

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
  | { type: 'auth'; token: string }
  | { type: 'start_capture' }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] };

export function encodeAgentCommand(command: AgentCommand): string {
  return JSON.stringify(command);
}

const PAIRING_TOKEN_STORAGE_KEY = 'netview.agentPairingToken';

export function getStoredPairingToken(): string | null {
  return localStorage.getItem(PAIRING_TOKEN_STORAGE_KEY);
}

export function storePairingToken(token: string): void {
  localStorage.setItem(PAIRING_TOKEN_STORAGE_KEY, token);
}

export function clearStoredPairingToken(): void {
  localStorage.removeItem(PAIRING_TOKEN_STORAGE_KEY);
}
