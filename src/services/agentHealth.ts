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
 * or the SCM bringing it back after one failure - and calling that a crash
 * loop would accuse the agent of the one restart its policy exists to make.
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
        + 'Manual in Services.',
      canStart: false,
    };
  }

  // Installed, not disabled, not answering. `unknown` start type lands here
  // too, and correctly: not knowing how it starts does not stop it starting.
  return {
    kind: 'stopped',
    summary: 'The capture agent is not running',
    // The agent is demand-start (ADR 0035) and Inwire asks for it on launch
    // without a prompt, so reaching this state means those attempts failed.
    // The copy no longer promises a UAC prompt unconditionally - it is now the
    // fallback for one specific refusal rather than the only route there is.
    detail: 'Its service is installed and enabled but nothing is listening. '
      + 'Inwire starts it on launch; if that did not work, starting it here may '
      + 'need administrator rights.',
    canStart: true,
  };
}

/**
 * The headline for each way the agent can be silent.
 *
 * Short because it has to fit a tooltip and an accessible name, and distinct
 * because the whole point of `diagnoseAgent` is that these are four different
 * problems - "Install Drivers" covered all of them and was the wrong
 * instruction for three.
 *
 * Moved here out of `Header.tsx` when the adapter control became an icon in the
 * rail. It was a component-local map, which was fine while exactly one bar
 * rendered it; now the rail's tooltip, its accessible name, the filter row's
 * banner and the status bar's link item all have to say the same thing, and a
 * string table living in one of four consumers is how they stop agreeing. Pure,
 * so `scripts/electron/agent-health.ts` holds every branch to a label - which
 * it did not until the bug below, and which is why the bug below existed.
 */
const AGENT_STATUS_LABEL: Record<AgentHealth['kind'], string> = {
  connected: 'Agent connected',
  connecting: 'Connecting',
  missing: 'Agent missing',
  disabled: 'Agent disabled',
  crashing: 'Agent crashing',
  stopped: 'Agent not running',
  unknown: 'Agent not reachable',
};

/**
 * The headline for any state the agent can be in.
 *
 * **This was `agentSilentLabel`, a `Partial<Record<...>>` of the five silent
 * kinds with `?? 'Agent not reachable'` behind it, and that shipped a lie.**
 * Its two original callers - the rail's tooltip and the filter row's banner -
 * only ask while the agent IS silent, so the missing `connected` entry could
 * not be reached. The status bar's link item asks unconditionally, because its
 * whole job is to name the state whatever the state is - so a perfectly healthy
 * agent read **"Agent not reachable"** in the bar while capture ran fine, and
 * the tooltip beside it said "The capture agent is connected", because that one
 * was written as a conditional rather than looked up here.
 *
 * Two things let it through and both are fixed by the same edit. `Partial`
 * meant the type could not object to a missing key, and the `??` turned that
 * hole into a confident wrong answer rather than an absence anybody would
 * notice. The record is TOTAL now and there is no fallback: a new member of
 * `AgentHealth['kind']` fails to compile until it has a label.
 */
export function agentStatusLabel(health: AgentHealth): string {
  return AGENT_STATUS_LABEL[health.kind];
}

/**
 * Whether the adapter control should draw its warning badge.
 *
 * **Shape as well as colour, deliberately.** The control is an icon in the rail
 * with no room for the label it used to carry, and a tint alone is the one
 * thing a colour-blind user cannot read - so the badge is the signal and the
 * tint reinforces it, rather than the other way round. No pixel size is quoted
 * here on purpose: the rail's target has been 32, 36 and 44, and the argument
 * has never depended on which.
 *
 * `connecting` is false on purpose, and it is the only interesting case here.
 * While the link is still opening the interface list is legitimately empty, and
 * flashing a warning during every launch would cry wolf on the one state that
 * should mean something is actually wrong. `Header.tsx` called this
 * `adapterStateKnown`; it is the same judgement, named for what it decides.
 */
export function agentNeedsAttention(health: AgentHealth): boolean {
  return health.kind !== 'connected' && health.kind !== 'connecting';
}
