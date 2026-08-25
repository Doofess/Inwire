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
