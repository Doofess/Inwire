/**
 * The Update Center as the renderer sees it.
 *
 * The pipeline lives in the main process, because it fetches, writes a file
 * and raises a UAC prompt. What arrives here is a snapshot over IPC, and this
 * module is what says how it is read, what each state is called, and how the
 * agent's row is added.
 *
 * ## Why the types are declared again rather than imported
 *
 * `electron/updateCenter/` is compiled by a different TypeScript program with
 * no DOM lib, and importing across that line would undo the split that makes a
 * `window` reference in the main process a build failure. It is the same rule
 * `src/types/desktop.d.ts` states for the bridge, and the same answer
 * `services/agentProtocol.ts` gives for the agent - whose types cannot be
 * shared either, because that sender is written in Python.
 *
 * So the bridge hands over `unknown` and the receiver says what it accepts.
 * The two definitions can drift; a malformed snapshot is refused here rather
 * than rendered as a row full of `undefined`.
 *
 * ## The agent's row is composed here, not sent
 *
 * The capture agent ships inside the Inwire installer, so it has no manifest
 * row and nothing to apply - but its version should be visible beside the
 * others. That version arrives in `hello`, which this side already holds, so
 * main would have to be told a number in order to tell it back. The row is
 * added by `withAgentRow` instead.
 */

export type UpdateComponentId = 'inwire' | 'agent' | 'npcap' | 'oui' | 'geoip';

export type UpdateComponentKind = 'inwire-installer' | 'vendor-installer' | 'database';

export interface UpdateAvailable {
  version: string;
  url: string;
  sha256: string;
  size: number;
  kind: UpdateComponentKind;
  minAppVersion: string;
}

export type UpdateComponentState =
  | { kind: 'checking' }
  | { kind: 'unknown' }
  | { kind: 'up-to-date' }
  | { kind: 'not-installed' }
  | { kind: 'update-available'; version: string }
  | { kind: 'needs-newer-app'; version: string; requires: string }
  | { kind: 'downloading'; received: number; total: number }
  | { kind: 'verifying' }
  | { kind: 'elevating' }
  | { kind: 'installing' }
  | { kind: 'reboot-required' }
  | { kind: 'failed'; reason: string }
  | { kind: 'planned' }
  /**
   * The agent has not said hello yet.
   *
   * Composed here and never sent - main has no such state, because main has no
   * agent row. It exists because `unknown` reads as "Not checked", and the
   * agent is not something we failed to check: it is something that has not
   * spoken. Told apart, one of them is a reason to press Check and the other
   * is not.
   */
  | { kind: 'not-connected' };

export interface UpdateComponent {
  id: UpdateComponentId;
  displayName: string;
  installed: string | null;
  available: UpdateAvailable | null;
  state: UpdateComponentState;
  /**
   * The Npcap row only: `AdminOnly` as the registry records it, `null` where
   * nothing readable does, and absent on every other row.
   *
   * Half an answer on its own - `services/npcapAccess.ts` combines it with the
   * DACL the agent reports, which outranks it. ADR 0033.
   */
  adminOnly?: boolean | null;
}

export interface UpdateSnapshot {
  checking: boolean;
  lastChecked: number | null;
  components: UpdateComponent[];
}

export const EMPTY_SNAPSHOT: UpdateSnapshot = {
  checking: false, lastChecked: null, components: [],
};

const STATE_KINDS: readonly string[] = [
  'checking', 'unknown', 'up-to-date', 'not-installed', 'update-available',
  'needs-newer-app', 'downloading', 'verifying', 'elevating', 'installing',
  'reboot-required', 'failed', 'planned', 'not-connected',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readComponent(raw: unknown): UpdateComponent | null {
  if (!isRecord(raw)) return null;
  const { id, displayName, installed, available, state } = raw;
  if (typeof id !== 'string' || typeof displayName !== 'string') return null;
  if (installed !== null && typeof installed !== 'string') return null;
  if (!isRecord(state) || typeof state.kind !== 'string' || !STATE_KINDS.includes(state.kind)) {
    return null;
  }
  const component: UpdateComponent = {
    id: id as UpdateComponentId,
    displayName,
    installed,
    available: isRecord(available) ? (available as unknown as UpdateAvailable) : null,
    state: state as unknown as UpdateComponentState,
  };
  // Three-valued and read as three values. Anything that is not a boolean or
  // an explicit null - including a missing key, which is what every other row
  // sends - leaves the field absent, and the panel shows "not known".
  const { adminOnly } = raw;
  if (typeof adminOnly === 'boolean' || adminOnly === null) component.adminOnly = adminOnly;
  return component;
}

/**
 * Reads a snapshot off the bridge.
 *
 * A row that does not parse is **dropped**, and a document that does not parse
 * is refused whole. A row rendered from half-understood data would show a
 * button next to a state nobody can name.
 */
export function normalizeSnapshot(raw: unknown): UpdateSnapshot | null {
  if (!isRecord(raw)) return null;
  if (typeof raw.checking !== 'boolean') return null;
  if (raw.lastChecked !== null && typeof raw.lastChecked !== 'number') return null;
  if (!Array.isArray(raw.components)) return null;

  const components: UpdateComponent[] = [];
  for (const entry of raw.components) {
    const component = readComponent(entry);
    if (component !== null) components.push(component);
  }
  return { checking: raw.checking, lastChecked: raw.lastChecked, components };
}

/**
 * Adds the capture agent's row, in the position it belongs.
 *
 * Immediately after Inwire, because the two ship together: the agent's version
 * only ever changes when the app's does, and putting it anywhere else would
 * invite somebody to look for a way to update it on its own.
 *
 * Its state is not a manifest question. `outdated` is `isAgentOutdated`'s
 * answer, which compares the running agent against the protocol version this
 * build requires - so "out of date" here means "the app cannot talk to it",
 * and the fix is the Inwire row above rather than anything on this one.
 */
export function withAgentRow(
  snapshot: UpdateSnapshot, version: string | null, outdated: boolean,
): UpdateSnapshot {
  const state: UpdateComponentState = version === null
    ? { kind: 'not-connected' }
    : outdated
      ? { kind: 'update-available', version: 'in the Inwire installer' }
      : { kind: 'up-to-date' };

  const agent: UpdateComponent = {
    id: 'agent',
    displayName: 'Capture agent',
    installed: version,
    available: null,
    state,
  };

  const rows = snapshot.components.filter((component) => component.id !== 'agent');
  const at = rows.findIndex((component) => component.id === 'inwire');
  const components = at === -1
    ? [agent, ...rows]
    : [...rows.slice(0, at + 1), agent, ...rows.slice(at + 1)];
  return { ...snapshot, components };
}

/**
 * What each state is called, in the row.
 *
 * Here rather than in the panel so the wording is one decision and can be
 * asserted. Every string is a plain statement of fact: none of them tells the
 * reader to do anything, because the button beside it already does that.
 */
export function stateLabel(state: UpdateComponentState): string {
  switch (state.kind) {
    case 'checking': return 'Checking';
    case 'unknown': return 'Not checked';
    case 'up-to-date': return 'Up to date';
    case 'not-installed': return 'Not installed';
    case 'update-available': return `${state.version} available`;
    case 'needs-newer-app': return `${state.version} needs Inwire ${state.requires}`;
    case 'downloading': return `Downloading ${percent(state.received, state.total)}`;
    case 'verifying': return 'Checking the download';
    case 'elevating': return 'Waiting for Windows';
    case 'installing': return 'Installing';
    case 'reboot-required': return 'Installed - restart Windows to finish';
    case 'failed': return state.reason;
    case 'planned': return 'Planned';
    case 'not-connected': return 'Not connected';
  }
}

function percent(received: number, total: number): string {
  if (total <= 0) return '';
  return `${Math.min(100, Math.floor((received / total) * 100))}%`;
}

/**
 * The left half of a row: what is on this machine.
 *
 * Not simply `installed === null ? 'Not installed'`, and the difference is a
 * bug this had until somebody looked at a screenshot: the capture agent
 * reports its version over the pipe, so before it connects there is no
 * version - and the row said **"Not installed"** about a service that was
 * installed and running. A row that states a falsehood confidently is worse
 * than one that admits it does not know.
 */
export function installedLabel(component: UpdateComponent): string {
  if (component.installed !== null) return `Version ${component.installed}`;
  const unknown = component.state.kind === 'unknown' || component.state.kind === 'not-connected';
  return unknown ? 'Version not known' : 'Not installed';
}

/** Whether the row's button does anything, mirroring main's own `canApply`. */
export function canApply(component: UpdateComponent): boolean {
  if (component.available === null) return false;
  return component.state.kind === 'update-available' || component.state.kind === 'not-installed';
}

/**
 * Whether the row can be run through the install path again without anything
 * being out of date.
 *
 * This exists for exactly one case: Npcap is current, and is installed with
 * its capture devices open to every local account. The only way to change that
 * is to run the wizard again and tick the box, so the row needs a control
 * `canApply` deliberately does not give it - a reinstall is not an update, and
 * offering "Update" against an up-to-date component would be the confident
 * wrong answer the rest of this module is built to avoid.
 *
 * `up-to-date` only. A row that is mid-download, elevating, failed or
 * not-installed already has the right control or no business having one, and a
 * reinstall offered beside "Not installed" is just an install under a worse
 * name.
 */
export function canReinstall(component: UpdateComponent): boolean {
  if (component.available === null) return false;
  return component.state.kind === 'up-to-date';
}

/** The word on the button, when there is one. */
export function actionLabel(component: UpdateComponent): string {
  return component.installed === null ? 'Install' : 'Update';
}

/** Whether anything is mid-flight, which is what disables "Check now". */
export function isBusy(snapshot: UpdateSnapshot): boolean {
  const moving: readonly string[] = ['downloading', 'verifying', 'elevating', 'installing'];
  return snapshot.checking || snapshot.components.some((c) => moving.includes(c.state.kind));
}
