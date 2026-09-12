/**
 * Whether the Npcap driver is open to every local user, or only to
 * administrators.
 *
 * Npcap's installer has a checkbox - *"Restrict Npcap driver's access to
 * Administrators only"* - and it is **not ticked by default**. Unticked, the
 * capture devices are open to Everyone: any local account can read this
 * machine's traffic and write raw frames onto the wire, with nothing on screen
 * to say so and everything working exactly as well either way.
 *
 * Inwire captures through a LocalSystem service, so the restriction costs its
 * users nothing and is the install this app recommends. A recommendation has
 * to know whether it has already been taken, which is what this module answers.
 * docs/decisions/0033.
 *
 * ## Two facts, and the one that wins
 *
 * `AdminOnly` under `HKLM\SOFTWARE\Npcap` is what the installer **recorded**;
 * the DACL on the device object is what the kernel **enforces**. They can
 * disagree - the value is edited, the driver is not restarted - and when they
 * do the DACL decides, because it is what actually admits a process. Saying
 * "administrators only" over a device whose descriptor grants `WD` would be a
 * confident wrong answer in the one direction that matters.
 *
 * So the registry is the fallback, not the primary, even though it is the
 * cheaper read and the one that works with no agent connected.
 *
 * ## Why the agent sends a string rather than an answer
 *
 * Reading a device object's descriptor wants the SYSTEM process, and the agent
 * is it. Deciding what the descriptor means does not, and putting the decision
 * there would be a second implementation of something the app must be able to
 * do from the registry alone. Same rule as `0010`: the agent states facts.
 *
 * Everything here is pure, and asserted in `scripts/electron/update-center.ts`
 * against real captured strings.
 */

/**
 * Three answers, and the third is not a rounding of the other two.
 *
 * `unknown` is what an unreadable descriptor, an absent registry value, a
 * non-Windows agent and a driver that is not installed all produce. The panel
 * says so rather than guessing, because both guesses are harmful: "all users"
 * nags somebody who already ticked the box, and "administrators only" tells
 * somebody their machine is safe when nothing checked.
 */
export type DriverAccess = 'admin-only' | 'all-users' | 'unknown';

/**
 * The trustees that still count as "administrators only".
 *
 * `SY` is LocalSystem - the agent's own identity, and the reason the
 * restriction is free here. `BA` is the built-in Administrators group. Both
 * aliases and both raw SIDs, because `ConvertSecurityDescriptorToString...`
 * emits the alias for well-known SIDs and the SID for everything else, and a
 * future Windows changing its mind about which is which must not turn an
 * admin-only driver into a warning.
 *
 * Everything else - `WD` (Everyone), `AU`, `IU`, `BU`, a named account - means
 * somebody who is not an administrator can open the capture devices, which is
 * exactly the state this is looking for.
 */
const ADMIN_TRUSTEES: ReadonlySet<string> = new Set([
  'SY', 'S-1-5-18',
  'BA', 'S-1-5-32-544',
]);

/**
 * The DACL's ACE list, as `(type;flags;rights;guid;guid;sid)` tuples.
 *
 * Written as a scan rather than a regex over the whole string because the
 * resource-attribute ACE form has a trailing field containing parentheses of
 * its own, and a greedy match across it would swallow the next ACE.
 */
function aceStrings(dacl: string): string[] {
  const aces: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < dacl.length; i++) {
    const ch = dacl[i];
    if (ch === '(') {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === ')') {
      depth--;
      if (depth === 0 && start !== -1) {
        aces.push(dacl.slice(start, i));
        start = -1;
      }
      if (depth < 0) return [];
    }
  }
  return depth === 0 ? aces : [];
}

/**
 * The `D:` section of an SDDL string, flags and all.
 *
 * The descriptors this reads carry nothing but a DACL, but the function is
 * written for the full `O:..G:..D:..S:..` form anyway: a `S:` inside an ACE's
 * fields would otherwise cut the DACL short, so the split only counts one at
 * paren depth zero.
 */
function daclSection(sddl: string): string | null {
  const at = sddl.indexOf('D:');
  if (at === -1) return null;
  let depth = 0;
  for (let i = at + 2; i < sddl.length - 1; i++) {
    if (sddl[i] === '(') depth++;
    else if (sddl[i] === ')') depth--;
    else if (depth === 0 && sddl[i] === 'S' && sddl[i + 1] === ':') return sddl.slice(at + 2, i);
  }
  return sddl.slice(at + 2);
}

/**
 * What a descriptor admits.
 *
 * The order of the guards is the content:
 *
 * - **`NO_ACCESS_CONTROL` is `all-users`, not `admin-only`.** It means a NULL
 *   DACL, which grants everyone everything - and it contains no ACEs at all,
 *   so a reader that only counted non-admin ACEs would call the most open
 *   descriptor Windows can express the most restrictive one.
 * - **Anything that is not a plain allow ACE answers `unknown`.** A deny ACE
 *   makes a descriptor more restrictive than its allow ACEs suggest, so
 *   reading past one could report `all-users` over a driver nobody but an
 *   administrator can open. Refusing to answer is the honest outcome.
 * - **An ACE granting no rights grants nothing** and is skipped, rather than
 *   counting as access for whoever it names.
 * - **No ACEs at all answers `unknown`.** An empty DACL denies everybody,
 *   which is a shape this has never seen on a working driver and should not
 *   be narrated as either verdict.
 */
export function accessFromSddl(sddl: string | null | undefined): DriverAccess {
  if (typeof sddl !== 'string' || sddl.trim() === '') return 'unknown';
  const dacl = daclSection(sddl);
  if (dacl === null) return 'unknown';
  if (dacl.includes('NO_ACCESS_CONTROL')) return 'all-users';

  const aces = aceStrings(dacl);
  if (aces.length === 0) return 'unknown';

  let granted = 0;
  for (const ace of aces) {
    const fields = ace.split(';');
    if (fields.length < 6) return 'unknown';
    const [type, , rights] = fields;
    if (type.trim().toUpperCase() !== 'A') return 'unknown';
    if (rights.trim() === '') continue;
    const trustee = fields[5].trim().toUpperCase();
    if (!ADMIN_TRUSTEES.has(trustee)) return 'all-users';
    granted++;
  }
  return granted === 0 ? 'unknown' : 'admin-only';
}

/**
 * The answer the row shows, from both sources.
 *
 * The DACL first - see the header. `registryAdminOnly` is `AdminOnly`'s value
 * where it could be read and `null` where it could not, which is the ordinary
 * case on a machine with no Npcap at all.
 */
export function decideDriverAccess(
  registryAdminOnly: boolean | null | undefined,
  sddl: string | null | undefined,
): DriverAccess {
  const enforced = accessFromSddl(sddl);
  if (enforced !== 'unknown') return enforced;
  if (typeof registryAdminOnly !== 'boolean') return 'unknown';
  return registryAdminOnly ? 'admin-only' : 'all-users';
}

/**
 * What the row says on its second line.
 *
 * A statement of fact and nothing else - the recommendation below it is a
 * separate sentence with a separate button, so a machine that is already
 * admin-only carries no advice at all.
 */
export function driverAccessLabel(access: DriverAccess): string {
  switch (access) {
    case 'admin-only': return 'Driver access: administrators only';
    case 'all-users': return 'Driver access: all users';
    case 'unknown': return 'Driver access: not known';
  }
}

/**
 * The recommendation, or null when there is nothing to recommend.
 *
 * Only `all-users` gets one. `unknown` deliberately does not: advising a
 * reinstall on the strength of having failed to read anything would send
 * people through a UAC prompt and a kernel-driver install to fix a state
 * nobody established.
 *
 * The wording states the security fact rather than an instruction, which is
 * the same rule `stateLabel` follows - the button beside it says what to do.
 */
export function driverAccessAdvice(access: DriverAccess): string | null {
  if (access !== 'all-users') return null;
  return 'Npcap is installed with its capture devices open to every local account, '
    + "so any user of this machine can capture its traffic and send raw frames. "
    + 'Inwire captures through its own service, so restricting the driver to '
    + 'administrators costs you nothing here.';
}
