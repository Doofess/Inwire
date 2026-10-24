/**
 * What the Settings search knows about: one entry per setting, with the section
 * it lives in, the words it can be found by, and the preference it writes.
 *
 * A hand-kept index rather than one derived from the panels, because the panels
 * are JSX and a search cannot read JSX. `scripts/settings/settings-index.ts`
 * is what stops the two drifting: it reads every `<SettingRow label=...>` out of
 * the panels' source and fails on a row with no entry here, a row filed under
 * the wrong section, or a description that has changed on one side only.
 *
 * Pure: no React, no Electron, no `node:*`. The stores are imported for their
 * `defaults`, which is what "modified" is measured against.
 */
import type { PreferenceStore } from '../services/preferenceStore';
import {
  layoutStore,
  minimapStore,
  motionStore,
  nameResolutionStore,
  packetListStore,
  performanceStore,
} from '../services/interfacePrefs';
import { accentColorStore, packetColorSetStore } from '../services/themePrefs';
import { arcProtocolColorStore, mapSkinStore } from '../services/mapPrefs';
import { updateStore } from '../services/updatePrefs';

export type SettingsSection =
  | 'appearance'
  | 'interface'
  | 'accessibility'
  | 'filters'
  | 'decryption'
  | 'driver'
  | 'updates';

/**
 * The store a row's control writes, and the field of it when the store holds
 * several settings. No `field` means the store's whole value is the setting.
 */
export interface SettingPref<T = unknown> {
  store: PreferenceStore<T>;
  field?: keyof T & string;
}

export interface SettingEntry {
  section: SettingsSection;
  label: string;
  description?: string;
  /** Words the label and description do not contain, such as the panel's own section heading. */
  keywords?: readonly string[];
  /** Absent for a row whose control is an action, or whose value no single store holds. */
  pref?: SettingPref;
}

/** Types the pairing, so a field that is not in the store does not compile. */
function pref<T>(store: PreferenceStore<T>, field?: keyof T & string): SettingPref {
  return { store, field } as SettingPref;
}

/**
 * In the order the panels show them. The descriptions are the panels' own text,
 * and a row whose description is built at render time carries its fixed part.
 */
export const SETTINGS_INDEX: readonly SettingEntry[] = [
  // --- Appearance --------------------------------------------------------------------
  {
    section: 'appearance',
    label: 'App theme',
    description: "Light, Dark, Dim or High Contrast, or System to follow Windows.",
    keywords: ['theme', 'light', 'dark', 'dim', 'high contrast', 'system'],
  },
  {
    section: 'appearance',
    label: 'Accent colour',
    description: "The colour of the selected row, focus rings and the active rail button.",
    keywords: ['theme', 'color', 'swatch'],
    pref: pref(accentColorStore),
  },
  {
    section: 'appearance',
    label: 'Colour set',
    description: "How strongly packet rows are coloured, including a colourblind-safe set.",
    keywords: ['packet colours', 'color', 'colorblind'],
    pref: pref(packetColorSetStore),
  },
  {
    section: 'appearance',
    label: 'Colour arcs by protocol',
    description: "Colour each map arc by its main protocol, as the protocol chart does.",
    keywords: ['map', 'color'],
    pref: pref(arcProtocolColorStore),
  },
  {
    section: 'appearance',
    label: 'Basemap skin',
    description: "A fixed colourful globe, or a map drawn in the current theme's colours.",
    keywords: ['map', 'globe'],
    pref: pref(mapSkinStore),
  },

  // --- Interface ---------------------------------------------------------------------
  {
    section: 'interface',
    label: 'Pane arrangement',
    description: "The protocol tree and the bytes side by side, or one above the other.",
    keywords: ['layout', 'stacked', 'side by side'],
    pref: pref(layoutStore, 'arrangement'),
  },
  {
    section: 'interface',
    label: 'Follow live capture',
    description: "Keep the newest packet in view while capturing.",
    keywords: ['packet list', 'autoscroll', 'scroll'],
    pref: pref(packetListStore, 'follow'),
  },
  {
    section: 'interface',
    label: 'Packet list density',
    description: "Row height and text size in the packet list.",
    keywords: ['packet list', 'compact', 'comfortable'],
    pref: pref(packetListStore, 'density'),
  },
  {
    section: 'interface',
    label: 'Minimap',
    description: "An overview strip beside the scrollbar, the biggest CPU cost while capturing.",
    keywords: ['packet list'],
    pref: pref(minimapStore),
  },
  {
    section: 'interface',
    label: 'Dashboard refresh',
    description: "How often the Routing Map updates during a capture, or pause it.",
    keywords: ['performance'],
    pref: pref(performanceStore, 'dashboardRefreshMs'),
  },
  {
    section: 'interface',
    label: 'Buffer size',
    description: "Memory kept for recent frames, with older ones read from disk as needed.",
    keywords: ['performance', 'memory', 'ram'],
    pref: pref(performanceStore, 'packetBufferBytes'),
  },
  {
    section: 'interface',
    label: 'Multi Threaded Capture',
    description: "How many CPU threads decode TCP in a live capture, from the next Start.",
    keywords: ['performance', 'cores', 'workers'],
    pref: pref(performanceStore, 'dissectionThreads'),
  },
  {
    section: 'interface',
    label: 'Resolve network addresses',
    description: "Show host names the capture itself carried, from DNS, mDNS or NetBIOS, instead of IPs.",
    keywords: ['name resolution', 'hostname'],
    pref: pref(nameResolutionStore, 'network'),
  },
  {
    section: 'interface',
    label: 'Resolve transport ports',
    description: "Show service names beside port numbers in statistics, such as 443 as https.",
    keywords: ['name resolution', 'service'],
    pref: pref(nameResolutionStore, 'transport'),
  },
  {
    section: 'interface',
    label: 'Locate addresses',
    description: "Sends public addresses to get.geojs.io for the map, and this connection to ipapi.co.",
    keywords: ['privacy', 'geoip', 'location', 'map'],
    pref: pref(nameResolutionStore, 'geoIp'),
  },
  {
    section: 'interface',
    label: 'Reverse DNS',
    description: "Sends public IPv4 addresses to cloudflare-dns.com to look up their host names.",
    keywords: ['privacy', 'ptr', 'hostname'],
    pref: pref(nameResolutionStore, 'reverseDns'),
  },

  // --- Accessibility -----------------------------------------------------------------
  {
    section: 'accessibility',
    label: 'Animations',
    description: "Pulsing markers, map camera moves and panel transitions.",
    keywords: ['motion', 'reduce motion'],
    pref: pref(motionStore),
  },
  {
    // An action, not a value: the button replays a walkthrough, so there is
    // nothing to be modified from or reset to.
    section: 'accessibility',
    label: 'Tutorial',
    description: "The walkthrough from installing the driver to reading your first packet.",
    keywords: ['getting started', 'tour', 'walkthrough'],
  },

  // --- Tabs with no row of their own, so that they can be found ----------------------
  {
    section: 'filters',
    label: 'Display Filters',
    description: "Saved display filters, in groups.",
    keywords: ['presets', 'bookmarks', 'wireshark'],
  },
  {
    section: 'decryption',
    label: 'Decryption',
    description: "Decrypt TLS traffic using a key log file.",
    keywords: ['tls', 'key log', 'sslkeylogfile'],
  },
  {
    section: 'driver',
    label: 'Diagnostics',
    description: "The agent's status, the frames a capture lost, and the agent's log.",
    // The section's old name stays findable: it was "Capture Health" until the
    // UX audit's copy pass, and somebody who learned it should still land here.
    keywords: ['drops', 'dropped', 'driver', 'npcap', 'agent', 'buffer', 'log', 'capture health'],
  },

  // --- Updates -----------------------------------------------------------------------
  {
    section: 'updates',
    label: 'Check automatically on launch',
    description: "Checks for updates once after Inwire starts, which is a request out of this machine.",
    keywords: ['checking', 'update center'],
    pref: pref(updateStore, 'automatic'),
  },
];

const BY_LABEL = new Map(SETTINGS_INDEX.map((e) => [e.label, e]));

export function settingByLabel(label: string): SettingEntry | undefined {
  return BY_LABEL.get(label);
}

/** The words of a string, lower-cased: runs of letters and digits, so "get.geojs.io" is three. */
function wordsOf(text: string): string[] {
  return text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
}

/**
 * How a query token finds an entry, lower is better; null is not at all.
 * 0 starts the label, 1 starts any other word of it, 2 starts a keyword,
 * 3 starts the section's name, 4 starts a word of the description.
 */
function tokenTier(token: string, e: SettingEntry): number | null {
  const label = wordsOf(e.label);
  if (label[0]?.startsWith(token)) return 0;
  if (label.some((w) => w.startsWith(token))) return 1;
  if ((e.keywords ?? []).some((k) => wordsOf(k).some((w) => w.startsWith(token)))) return 2;
  if (e.section.startsWith(token)) return 3;
  if (wordsOf(e.description ?? '').some((w) => w.startsWith(token))) return 4;
  return null;
}

/**
 * The entries a query finds, best first.
 *
 * Every word of the query must START a word of the entry - of its label, its
 * keywords, its section's name or its description - so "dns" finds Reverse DNS
 * and not Packet list d-e-nsity, and "ram" finds the buffer (a keyword) and not
 * Pane a-rra-ngement. The palette's subsequence matcher is right for a command
 * typed from memory and wrong here: the rows are few, a person types a word
 * they recognise, and letters scattered across one is a false hit that reads as
 * the search being broken. Ranked by the worst way any word was found, then the
 * sum, then the index's own order: a label hit outranks a keyword hit outranks
 * a section hit outranks a description hit.
 * An empty query finds nothing - the search box shows the tabs then, not a list.
 */
export function searchSettings(
  query: string,
  index: readonly SettingEntry[] = SETTINGS_INDEX,
): SettingEntry[] {
  const tokens = wordsOf(query);
  if (tokens.length === 0) return [];
  const scored: { entry: SettingEntry; worst: number; sum: number; at: number }[] = [];
  index.forEach((entry, at) => {
    let worst = 0;
    let sum = 0;
    for (const token of tokens) {
      const tier = tokenTier(token, entry);
      if (tier === null) return;
      worst = Math.max(worst, tier);
      sum += tier;
    }
    scored.push({ entry, worst, sum, at });
  });
  scored.sort((x, y) => x.worst - y.worst || x.sum - y.sum || x.at - y.at);
  return scored.map((r) => r.entry);
}

function currentOf(p: SettingPref): unknown {
  const value = p.store.get();
  return p.field === undefined ? value : (value as Record<string, unknown>)[p.field];
}

function defaultOf(p: SettingPref): unknown {
  const value = p.store.defaults;
  return p.field === undefined ? value : (value as Record<string, unknown>)[p.field];
}

/** True when the setting's value differs from its default. An entry with no pref never is. */
export function isModified(entry: SettingEntry): boolean {
  if (!entry.pref) return false;
  return JSON.stringify(currentOf(entry.pref)) !== JSON.stringify(defaultOf(entry.pref));
}

/**
 * Puts one setting back to its default and leaves its siblings alone: three
 * rows share `performanceStore`, and resetting one must not undo another.
 */
export function resetSetting(entry: SettingEntry): void {
  const p = entry.pref;
  if (!p) return;
  if (p.field === undefined) {
    p.store.set(p.store.defaults);
    return;
  }
  p.store.set({ ...(p.store.get() as object), [p.field]: defaultOf(p) });
}

/**
 * The id of a row's element, for the search to scroll to.
 *
 * Not `setting-<slug>` bare: the switches already own ids of that shape
 * (`setting-minimap`), a label's `htmlFor` finds the FIRST element with its id,
 * and a row wrapper comes before the control inside it - so the shared prefix
 * would quietly stop the label from toggling its switch.
 */
export function settingAnchorId(label: string): string {
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return `setting-row-${slug}`;
}

/**
 * Whether a section's tab looks selected. Not while search results show: they
 * span every section, so a lit tab would claim the results are that tab's, and
 * it would be the tab the person left rather than one the answer is in. Each
 * hit names its own tab, and choosing one switches to it.
 */
export function settingsTabSelected(open: SettingsSection, tab: SettingsSection, searching: boolean): boolean {
  return !searching && open === tab;
}
