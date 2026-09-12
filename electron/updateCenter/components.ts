/**
 * What is installed, what is offered, and whether those differ.
 *
 * Every row of the Update Center is one `Component`, and every question the
 * tab asks about a row is a pure function over this model. Nothing here reads
 * a registry, opens a socket or knows what Electron is - that lives in
 * `electron/updateCenter/host.ts`, which is the only file in the feature that
 * cannot be driven by `scripts/electron/update-center.ts`.
 *
 * ## Why the state is a union rather than a pair of booleans
 *
 * A row is not "up to date or not". It can be mid-download, waiting on a UAC
 * prompt the user has not answered, installed-but-needing-a-reboot, or a
 * database that is declared and has no consumer yet. Those want different
 * words and different controls, and a boolean pair would collapse the ones
 * that matter: "the user declined the prompt" and "the installer failed" look
 * identical as `!ok` and are not remotely the same event.
 *
 * That distinction is load-bearing. **A cancelled UAC prompt is a normal
 * outcome**, not an error - somebody thought better of it, which is the prompt
 * working. It returns the row to the state it had and shows nothing.
 */

/** How a component is applied once it has been downloaded. */
export type ComponentKind = 'inwire-installer' | 'vendor-installer' | 'database';

export type ComponentId = 'inwire' | 'agent' | 'npcap' | 'oui' | 'geoip';

export const COMPONENT_IDS: readonly ComponentId[] = ['inwire', 'agent', 'npcap', 'oui', 'geoip'];

/**
 * Whether a string names a component.
 *
 * Used on the one message that ends in a UAC prompt. The pipeline would refuse
 * an unknown id anyway - there would be no manifest row for it - but "refuses
 * by accident, two layers down" is not the same as "refuses", and this is the
 * boundary where a renderer's string stops being a renderer's string.
 */
export function isComponentId(value: unknown): value is ComponentId {
  return typeof value === 'string' && (COMPONENT_IDS as readonly string[]).includes(value);
}

/** One component's row in the manifest, after validation. */
export interface Available {
  version: string;
  url: string;
  sha256: string;
  size: number;
  kind: ComponentKind;
  /** The oldest Inwire that may apply this. Compared against `app.getVersion()`. */
  minAppVersion: string;
}

export type ComponentState =
  | { kind: 'checking' }
  /** Never checked, or the feed was unreachable. Not the same as "up to date". */
  | { kind: 'unknown' }
  | { kind: 'up-to-date' }
  /** Absent. Offerable when `available` is non-null, informational when it is not. */
  | { kind: 'not-installed' }
  | { kind: 'update-available'; version: string }
  /** An update exists and this build is too old to apply it. Update Inwire first. */
  | { kind: 'needs-newer-app'; version: string; requires: string }
  | { kind: 'downloading'; received: number; total: number }
  | { kind: 'verifying' }
  /** The UAC prompt is on screen and nothing else can happen until it is answered. */
  | { kind: 'elevating' }
  | { kind: 'installing' }
  | { kind: 'reboot-required' }
  | { kind: 'failed'; reason: string }
  /** Declared so the tab shows its whole shape, with no consumer yet. */
  | { kind: 'planned' };

export interface Component {
  id: ComponentId;
  displayName: string;
  /** Null means absent, or - for a row we cannot interrogate - not known. */
  installed: string | null;
  available: Available | null;
  state: ComponentState;
  /**
   * The Npcap row only: `AdminOnly` as the registry records it, null where
   * nothing readable does, and absent on every other row.
   *
   * Sent as the raw fact rather than as a verdict because it is only half of
   * one - the device object's DACL is the other half, it arrives over the
   * pipe, and it outranks this. The renderer holds both and decides; see
   * `src/services/npcapAccess.ts` and ADR 0033.
   */
  adminOnly?: boolean | null;
}

/**
 * The numeric groups of a version, leading `v` and any suffix ignored.
 *
 * Returns `[]` for anything with no leading number, which callers must treat
 * as "unparseable" rather than as zero: a version that sorts as 0.0.0 would
 * make every comparison say "update available".
 */
export function versionGroups(version: string): number[] {
  const match = /^\s*v?(\d+(?:\.\d+)*)/.exec(version);
  if (!match) return [];
  return match[1].split('.').map((part) => Number.parseInt(part, 10));
}

export function isVersion(version: string | null): boolean {
  return version !== null && versionGroups(version).length > 0;
}

/**
 * Returns <0, 0 or >0, comparing group by group with missing groups as zero.
 *
 * Written out rather than compared as strings for the reason
 * `installer/setup.iss:231` already gives about its own copy of this: `'1.10.0'`
 * sorts before `'1.9.0'`, and getting exactly that case right is the point.
 *
 * Unequal lengths compare correctly in both directions - `1.88` against
 * `1.10.6` is 88 vs 10 at the second group and never reaches the third. That
 * pair is not hypothetical: it is Npcap's version against the libpcap version
 * `wpcap.dll` reports, which is why nothing reads `wpcap.dll`.
 */
export function compareVersions(a: string, b: string): number {
  const left = versionGroups(a);
  const right = versionGroups(b);
  const groups = Math.max(left.length, right.length);
  for (let i = 0; i < groups; i++) {
    const difference = (left[i] ?? 0) - (right[i] ?? 0);
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * The resting state of a manifest-driven row: what to show when nothing is in
 * flight.
 *
 * Deliberately does NOT cover the agent row, whose availability is not a
 * manifest question - it ships inside the Inwire installer, so it is
 * informational and its state comes from `isAgentOutdated`.
 *
 * The order of the guards is the content. An unparseable installed version
 * answers `unknown` rather than falling through to a comparison, because
 * comparing garbage would confidently offer an update over a working install.
 */
export function decideState(
  installed: string | null,
  available: Available | null,
  appVersion: string,
): ComponentState {
  if (available === null) {
    return installed === null ? { kind: 'not-installed' } : { kind: 'unknown' };
  }
  if (installed !== null && !isVersion(installed)) return { kind: 'unknown' };

  // Checked before the comparison: an update this build cannot apply is not an
  // update available, and offering it would send somebody into a UAC prompt
  // for an installer that refuses them.
  if (compareVersions(available.minAppVersion, appVersion) > 0) {
    return { kind: 'needs-newer-app', version: available.version, requires: available.minAppVersion };
  }
  if (installed === null) return { kind: 'not-installed' };
  if (compareVersions(available.version, installed) > 0) {
    return { kind: 'update-available', version: available.version };
  }
  return { kind: 'up-to-date' };
}

/**
 * Whether a row's button does anything.
 *
 * `not-installed` counts only when there is something to install - the same
 * state means "absent, and the feed has no answer" when `available` is null.
 */
export function canApply(component: Component): boolean {
  if (component.available === null) return false;
  return component.state.kind === 'update-available' || component.state.kind === 'not-installed';
}
