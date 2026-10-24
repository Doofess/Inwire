import { APP_VIEWS } from '../services/viewPrefs';

/**
 * Every command the window offers, as data (ADR 0057).
 *
 * The palette lists these, `useKeyboardNavigation` dispatches their keys, and
 * every keyed tooltip reads its "(Ctrl+X)" from here - so a key is written
 * once. **There is no `run` in this file**, deliberately: the actions are
 * App's handlers, bound in `App.tsx` by id, and a callback in `App.tsx` is
 * unreachable from any script (`scripts/CLAUDE.md`). Everything worth asserting -
 * which keys exist, which commands are offered when, how a title reads - is
 * here, where `scripts/commands/registry.ts` can import it.
 *
 * **No command exists only here.** Each one duplicates a control that is on
 * screen - a rail button, the title row's toggle, the filter field - because a
 * feature reachable only by typing its name is a feature most people never
 * find (the rule `d3b4326` set when the menu went). The palette is a faster
 * route to the window, never a second window.
 */

export type CommandGroup = 'View' | 'Capture' | 'Filter' | 'Navigate' | 'Marks' | 'Window';

/** A key with Ctrl and maybe Shift. `key` is lower-case: `'k'`, `'/'`, `'1'`. */
export interface KeyChord {
  key: string;
  ctrl?: true;
  shift?: true;
}

/** What `when` may read. Plain values, so a predicate is a pure function. */
export interface CommandContext {
  capturing: boolean;
  /** An adapter is chosen, the buffer is empty and nothing blocks Start. */
  canStartCapture: boolean;
  packetCount: number;
  filterApplied: boolean;
  sideBarOpen: boolean;
  /** A packet is selected, which is what Mark acts on. */
  hasSelection: boolean;
  /** How many frames are marked in this capture, held or not. */
  markCount: number;
}

export interface CommandSpec {
  id: string;
  title: string;
  group: CommandGroup;
  keys?: KeyChord;
  /** Extra words the palette matches on, never shown. */
  keywords?: readonly string[];
  /** Offered only while this holds. Absent means always. */
  when?: (ctx: CommandContext) => boolean;
}

/**
 * The order is the palette's order for an empty query, so it is curated: the
 * views first because they are the window's structure, then what acts on the
 * capture, then the window itself.
 *
 * The view commands are **generated from `APP_VIEWS`**, whose order is the
 * Ctrl+digit numbering, so the palette and the rail cannot disagree about which
 * key opens which view.
 */
export const COMMANDS: readonly CommandSpec[] = [
  ...APP_VIEWS.map((view, i): CommandSpec => ({
    id: `view.${view.id}`,
    title: view.label,
    group: 'View',
    keys: { key: String(i + 1), ctrl: true },
    keywords: ['view', 'show'],
  })),
  {
    id: 'capture.start', title: 'Start capture', group: 'Capture',
    keys: { key: 'e', ctrl: true }, keywords: ['record', 'sniff'],
    when: (c) => !c.capturing && c.canStartCapture,
  },
  {
    id: 'capture.stop', title: 'Stop capture', group: 'Capture',
    keys: { key: 'e', ctrl: true }, keywords: ['pause', 'end'],
    when: (c) => c.capturing,
  },
  {
    id: 'packet.goto', title: 'Go to packet…', group: 'Navigate',
    keys: { key: 'g', ctrl: true }, keywords: ['frame', 'number', 'jump'],
    when: (c) => c.packetCount > 0,
  },
  {
    id: 'mark.toggle', title: 'Mark or unmark packet', group: 'Marks',
    keys: { key: 'm', ctrl: true }, keywords: ['flag', 'bookmark', 'pin'],
    when: (c) => c.hasSelection,
  },
  {
    id: 'mark.next', title: 'Next marked packet', group: 'Marks',
    keys: { key: 'n', ctrl: true, shift: true }, keywords: ['flag', 'bookmark', 'jump'],
    when: (c) => c.markCount > 0,
  },
  {
    id: 'mark.prev', title: 'Previous marked packet', group: 'Marks',
    keys: { key: 'b', ctrl: true, shift: true }, keywords: ['flag', 'bookmark', 'jump'],
    when: (c) => c.markCount > 0,
  },
  {
    id: 'mark.clearAll', title: 'Unmark all packets', group: 'Marks',
    keywords: ['flag', 'bookmark', 'clear', 'remove'],
    when: (c) => c.markCount > 0,
  },
  {
    id: 'filter.focus', title: 'Focus display filter', group: 'Filter',
    keys: { key: '/', ctrl: true }, keywords: ['search', 'expression'],
  },
  {
    id: 'filter.clear', title: 'Clear display filter', group: 'Filter',
    keywords: ['reset', 'remove'],
    when: (c) => c.filterApplied,
  },
  {
    id: 'sidebar.toggle', title: 'Toggle side bar', group: 'Window',
    keys: { key: 'b', ctrl: true }, keywords: ['panel', 'hide', 'show'],
  },
  { id: 'sidebar.interfaces', title: 'Show adapters', group: 'Window', keywords: ['interfaces', 'nic'] },
  { id: 'sidebar.schedule', title: 'Capture schedule', group: 'Window', keywords: ['timer', 'autostop'] },
  { id: 'sidebar.transfer', title: 'Export / Import PCAP', group: 'Window', keywords: ['save', 'open', 'csv', 'pdf'] },
  { id: 'sidebar.network', title: 'Network', group: 'Window', keywords: ['dns', 'public ip', 'speed'] },
  { id: 'monitoring.open', title: 'Open monitoring', group: 'Window', keywords: ['netflow', 'flow', 'exporter', 'collector'] },
  { id: 'settings.open', title: 'Open settings', group: 'Window', keywords: ['preferences', 'options', 'theme'] },
  { id: 'help.tour', title: 'Take the tour', group: 'Window', keywords: ['help', 'walkthrough', 'getting started'] },
  {
    id: 'palette.open', title: 'Open command palette', group: 'Window',
    keys: { key: 'k', ctrl: true },
  },
  {
    id: 'palette.commands', title: 'Show all commands', group: 'Window',
    keys: { key: 'p', ctrl: true, shift: true },
  },
];

const BY_ID = new Map(COMMANDS.map((c) => [c.id, c]));

export function commandById(id: string): CommandSpec | undefined {
  return BY_ID.get(id);
}

/** `Ctrl+Shift+P`, the form every tooltip and the palette print. */
export function formatChord(chord: KeyChord): string {
  const parts: string[] = [];
  if (chord.ctrl) parts.push('Ctrl');
  if (chord.shift) parts.push('Shift');
  parts.push(chord.key.length === 1 ? chord.key.toUpperCase() : chord.key);
  return parts.join('+');
}

/**
 * A command's chord as the menus print it (`Ctrl+M`), or '' for one with none.
 * For a shortcut hint that sits beside a label rather than inside a tooltip,
 * which is where `titleWithKeys` goes.
 */
export function chordText(id: string): string {
  const keys = BY_ID.get(id)?.keys;
  return keys ? formatChord(keys) : '';
}

/**
 * `Packets (Ctrl+1)` - the house tooltip form, which the rail and the title row
 * already used. `title` overrides the registry's for a control whose label
 * depends on state ("Hide side bar" / "Show side bar").
 */
export function titleWithKeys(id: string, title?: string): string {
  const command = BY_ID.get(id);
  const label = title ?? command?.title ?? id;
  return command?.keys ? `${label} (${formatChord(command.keys)})` : label;
}

/**
 * The command a keydown names, or undefined. Meta counts as Ctrl; Alt never
 * matches, because AltGr arrives as Ctrl+Alt on Windows, and a chord that
 * matched it would fire whenever a European layout typed `@`, `{` or `€`.
 * Shift must match exactly, so Ctrl+Shift+K is not Ctrl+K.
 *
 * A key is read as the layout typed it. Only when that is not a printable
 * ASCII character - Hebrew, Cyrillic, Greek - does the physical key decide, so
 * Ctrl+K still opens the palette with a Hebrew layout active.
 */
export function matchChord(e: {
  key: string; code?: string; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean; altKey: boolean;
}): CommandSpec | undefined {
  if (e.altKey || !(e.ctrlKey || e.metaKey)) return undefined;
  const key = chordKey(e.key, e.code);
  if (key === undefined) return undefined;
  return COMMANDS.find((c) => c.keys?.ctrl && c.keys.key === key && Boolean(c.keys.shift) === e.shiftKey);
}

function chordKey(key: string, code: string | undefined): string | undefined {
  if (key.length !== 1 || /[\x20-\x7e]/.test(key)) return key.toLowerCase();
  const m = code === undefined ? null : /^(?:Key([A-Z])|Digit([0-9]))$/.exec(code);
  return m ? (m[1] ?? m[2]).toLowerCase() : undefined;
}

export function availableCommands(ctx: CommandContext): CommandSpec[] {
  return COMMANDS.filter((c) => c.when?.(ctx) ?? true);
}
