/**
 * Why the agent is not answering, in a sentence somebody can act on.
 *
 * "Disconnected" is four different situations wearing one word, and they want
 * four different responses: reinstall, ask an administrator, start it, or look
 * at the log. The app has always shown the union of them, which is the failure
 * CLAUDE.md names for the WebSocket handshake and which survived the move to a
 * pipe unchanged - a pipe that refuses to open looks exactly like a pipe
 * nothing is listening on, because it is.
 *
 * Pure on purpose. Every input is a fact somebody else established - the
 * link's status, what the registry said, how the last few connections
 * behaved - so the whole decision table is drivable from
 * `scripts/electron/agent-health.ts` without a service, a pipe or a window.
 */
import type { AgentLinkStatus, AgentServiceFacts } from './agentLink';

export type { AgentServiceFacts };

export interface AgentHealthInput {
  status: AgentLinkStatus;
  /** Null until main has answered, which is not the same as "nothing known". */
  service: AgentServiceFacts | null;
  /**
   * Connections that opened and closed again almost immediately, recently.
   *
   * The one symptom only the client can see. A service that starts, throws and
   * is restarted by the SCM's failure actions presents to us as a pipe that
   * accepts and drops on a cadence - and the registry cannot show it, because
   * every value in it is exactly what it should be.
   */
  shortConnections: number;
}

/** What the reader is told, and what (if anything) they can do about it. */
export type AgentHealth =
  | { kind: 'connected' }
  | { kind: 'connecting' }
  /** Installed, enabled, and not answering. The ordinary "start it" case. */
  | { kind: 'stopped'; summary: string; detail: string; canStart: true }
  | { kind: 'disabled'; summary: string; detail: string; canStart: false }
  | { kind: 'missing'; summary: string; detail: string; canStart: false }
  | { kind: 'crashing'; summary: string; detail: string; canStart: false }
  /** Not answering, and we cannot say why - never dressed up as a diagnosis. */
  | { kind: 'unknown'; summary: string; detail: string; canStart: false };

/**
 * How many short-lived connections in the window before it is a loop.
 *
 * Three, because two is a service legitimately restarting once - an upgrade,
 * or `restart_agent`, which the app itself can cause - and calling that a
 * crash loop would accuse the agent of failing at the exact moment it did what
 * it was told.
 */
export const CRASH_LOOP_CONNECTIONS = 3;

export function diagnoseAgent(input: AgentHealthInput): AgentHealth {
  if (input.status === 'connected') return { kind: 'connected' };
  if (input.status === 'connecting') return { kind: 'connecting' };

  // Checked before the registry, because a crash loop has every registry value
  // exactly right and would otherwise read as "stopped, press Start" - which
  // is advice that has already been tried three times by the machine itself.
  if (input.shortConnections >= CRASH_LOOP_CONNECTIONS) {
    return {
      kind: 'crashing',
      summary: 'The capture agent keeps stopping',
      detail: 'It starts and exits again within a second or two. Its own log is '
        + 'the only place that says why; open it below, or read '
        + '%ProgramData%\\Inwire\\agent.log.',
      canStart: false,
    };
  }

  if (input.service === null) {
    return {
      kind: 'unknown',
      summary: 'The capture agent is not responding',
      detail: 'Still checking whether its service is installed.',
      canStart: false,
    };
  }

  if (!input.service.installed) {
    return {
      kind: 'missing',
      summary: 'The capture agent is not installed',
      detail: 'Inwire installs it alongside the app, so this usually means it was '
        + 'removed separately. Reinstalling Inwire puts it back.',
      canStart: false,
    };
  }

  if (input.service.startType === 'disabled') {
    return {
      kind: 'disabled',
      summary: 'The capture agent is disabled',
      detail: 'Its Windows service is set to Disabled, so nothing can start it - '
        + 'not this app and not a reboot. An administrator has to set it back to '
        + 'Automatic in Services.',
      canStart: false,
    };
  }

  // Installed, not disabled, not answering. `unknown` start type lands here
  // too, and correctly: not knowing how it starts does not stop it starting.
  return {
    kind: 'stopped',
    summary: 'The capture agent is not running',
    detail: 'Its service is installed and enabled but nothing is listening. '
      + 'Starting it needs administrator rights, so Windows will ask.',
    canStart: true,
  };
}
