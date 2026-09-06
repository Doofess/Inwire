import { FilterPreset, FilterPresetGroup, FilterPresetLibrary } from '../types/packet';
import { loadPreference, savePreference } from './preferences';

/**
 * The display-filter preset library: the defaults, the localStorage round
 * trip, and the pure edits the Settings panel makes.
 *
 * Every mutation here returns a new library rather than editing in place, so
 * React state updates stay honest and the caller can persist whatever comes
 * back without wondering whether it changed.
 *
 * Groups are data, not a fixed enum. The four seeded below are only what the
 * app shipped with as `FilterPreset.category`; the user is free to rename or
 * delete every one of them.
 */

export const FILTER_PRESETS_STORAGE_KEY = 'inwire.filterPresets';

/** Seeds a first run, and what "Restore defaults" restores. */
export const DEFAULT_FILTER_PRESET_LIBRARY: FilterPresetLibrary = {
  groups: [
    {
      id: 'group-general',
      name: 'General',
      presets: [
        {
          id: 'all',
          name: 'All Traffic',
          filter: '',
          description: 'Show all captured network packets without filtering',
        },
      ],
    },
    {
      id: 'group-security',
      name: 'Security',
      presets: [
        {
          id: 'threats-anomalies',
          name: 'Security Anomalies & Alerts',
          filter: 'inwire.expert.category == "Broken" || inwire.expert.category == "Reset" || inwire.expert.category == "Security"',
          description: 'SYN floods, port scans, DNS tunneling, and IDS triggers',
        },
      ],
    },
    {
      id: 'group-web',
      name: 'Web',
      presets: [
        {
          id: 'web-traffic',
          name: 'Web (HTTP/HTTPS/TLS)',
          filter: 'http || tls || tcp.port == 443 || tcp.port == 80',
          description: 'Hypertext and Transport Layer Security web traffic',
        },
        {
          id: 'dns-queries',
          name: 'DNS Resolution',
          filter: 'dns || udp.port == 53',
          description: 'Domain Name System queries, responses, and records',
        },
        {
          id: 'mqtt-telemetry',
          name: 'IoT MQTT Traffic',
          filter: 'mqtt || tcp.port == 1883',
          description: 'Message Queuing Telemetry Transport broker streams',
        },
      ],
    },
    {
      id: 'group-troubleshooting',
      name: 'Troubleshooting',
      presets: [
        {
          id: 'syn-handshakes',
          name: 'TCP Handshakes (SYN/FIN)',
          filter: 'info contains "SYN" || info contains "FIN"',
          description: 'Connection initiation and termination frames',
        },
        {
          id: 'high-bandwidth',
          name: 'Large Payloads (> 1000B)',
          filter: 'len > 1000',
          description: 'Jumbo frames and high-throughput data segments',
        },
      ],
    },
    {
      id: 'group-custom',
      name: 'Custom',
      presets: [
        {
          id: 'custom-dissector',
          name: 'Custom Plugins (IoT / Fast)',
          filter: 'proto_iot || finfast || port == 18833',
          description: 'Frames processed by custom dissector engine',
        },
      ],
    },
  ],
};

/** Where a saved filter lands when the user has not said otherwise. */
export const FALLBACK_GROUP_NAME = 'Custom';

let idCounter = 0;
/**
 * Ids only have to be unique within one library, and are never sent anywhere,
 * so a timestamp plus a counter is enough. The counter matters: two groups
 * created in the same millisecond would otherwise collide, and React keys and
 * drag targets both key off this.
 */
function makeId(prefix: string): string {
  idCounter += 1;
  return `${prefix}-${Date.now().toString(36)}-${idCounter.toString(36)}`;
}

// --- Persistence ------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePreset(raw: unknown, seenIds: Set<string>): FilterPreset | null {
  if (!isRecord(raw)) return null;
  if (typeof raw.name !== 'string' || typeof raw.filter !== 'string') return null;
  // A stored id that collides with one already read is regenerated rather than
  // dropping the preset: a duplicate key would break rendering, but the
  // filter itself is still perfectly good.
  const id = typeof raw.id === 'string' && raw.id && !seenIds.has(raw.id) ? raw.id : makeId('preset');
  seenIds.add(id);
  return {
    id,
    name: raw.name,
    filter: raw.filter,
    description: typeof raw.description === 'string' ? raw.description : '',
  };
}

/**
 * Turns whatever was in localStorage into a library we can render, or returns
 * null if it is too far gone to salvage.
 *
 * Deliberately lenient about individual entries and strict about the shape:
 * this parses data a previous version of the app wrote, and losing one
 * malformed preset beats throwing away a user's whole library. Anything that
 * is not an object with a `groups` array, though, is not our data at all.
 */
export function normalizeLibrary(raw: unknown): FilterPresetLibrary | null {
  if (!isRecord(raw) || !Array.isArray(raw.groups)) return null;

  const seenGroupIds = new Set<string>();
  const seenPresetIds = new Set<string>();
  const groups: FilterPresetGroup[] = [];

  for (const rawGroup of raw.groups) {
    if (!isRecord(rawGroup) || typeof rawGroup.name !== 'string') continue;
    const id =
      typeof rawGroup.id === 'string' && rawGroup.id && !seenGroupIds.has(rawGroup.id)
        ? rawGroup.id
        : makeId('group');
    seenGroupIds.add(id);

    const presets: FilterPreset[] = [];
    if (Array.isArray(rawGroup.presets)) {
      for (const rawPreset of rawGroup.presets) {
        const preset = normalizePreset(rawPreset, seenPresetIds);
        if (preset) presets.push(preset);
      }
    }
    groups.push({ id, name: rawGroup.name, presets });
  }

  // An empty library is indistinguishable from a broken one to the user - both
  // show nothing - so treat it as absent and let the defaults seed instead.
  if (groups.length === 0) return null;
  return { groups };
}

/**
 * Reads the stored library, falling back to the defaults.
 *
 * The guarding, and the "validate before trusting" rule, live in
 * services/preferences.ts now - shared with the packet list's column widths
 * and the minimap's width. `normalizeLibrary` above is this preference's half
 * of that contract.
 *
 * Not debounced, unlike the drag-driven width preferences: this is written
 * once per deliberate user action (add a filter, drop a group, reorder), so
 * there is no burst to collapse and a delayed write would only widen the
 * window in which a crash loses an edit.
 */
export function loadFilterPresetLibrary(): FilterPresetLibrary {
  return loadPreference(FILTER_PRESETS_STORAGE_KEY, normalizeLibrary, DEFAULT_FILTER_PRESET_LIBRARY);
}

export function saveFilterPresetLibrary(library: FilterPresetLibrary): void {
  savePreference(FILTER_PRESETS_STORAGE_KEY, library);
}

// --- Lookups ----------------------------------------------------------------

/** Every preset across every group, in display order. */
export function allPresets(library: FilterPresetLibrary): FilterPreset[] {
  return library.groups.flatMap((g) => g.presets);
}

export function findPreset(library: FilterPresetLibrary, presetId: string): FilterPreset | null {
  for (const group of library.groups) {
    const hit = group.presets.find((p) => p.id === presetId);
    if (hit) return hit;
  }
  return null;
}

// --- Group edits ------------------------------------------------------------

export function addGroup(library: FilterPresetLibrary, name: string): FilterPresetLibrary {
  return { groups: [...library.groups, { id: makeId('group'), name, presets: [] }] };
}

export function renameGroup(
  library: FilterPresetLibrary,
  groupId: string,
  name: string,
): FilterPresetLibrary {
  return {
    groups: library.groups.map((g) => (g.id === groupId ? { ...g, name } : g)),
  };
}

/**
 * Deletes a group and every preset in it.
 *
 * The presets go with it rather than being rehomed: the panel shows them
 * nested under the group being deleted, so silently relocating them would
 * contradict what the user is looking at. The caller confirms first.
 */
export function deleteGroup(library: FilterPresetLibrary, groupId: string): FilterPresetLibrary {
  return { groups: library.groups.filter((g) => g.id !== groupId) };
}

/** Moves a group to an absolute index in the group order. */
export function moveGroup(
  library: FilterPresetLibrary,
  groupId: string,
  toIndex: number,
): FilterPresetLibrary {
  const from = library.groups.findIndex((g) => g.id === groupId);
  if (from === -1) return library;
  const groups = [...library.groups];
  const [moved] = groups.splice(from, 1);
  groups.splice(clampIndex(toIndex, groups.length), 0, moved);
  return { groups };
}

// --- Preset edits -----------------------------------------------------------

export function addPreset(
  library: FilterPresetLibrary,
  groupId: string,
  preset: Omit<FilterPreset, 'id'>,
): FilterPresetLibrary {
  const withId: FilterPreset = { ...preset, id: makeId('preset') };
  // A group id that no longer exists lands in the last group rather than
  // vanishing - the save button in the filter bar can outlive the group it
  // was pointed at.
  const targetId = library.groups.some((g) => g.id === groupId)
    ? groupId
    : library.groups[library.groups.length - 1]?.id;
  if (!targetId) return { groups: [{ id: makeId('group'), name: FALLBACK_GROUP_NAME, presets: [withId] }] };
  return {
    groups: library.groups.map((g) =>
      g.id === targetId ? { ...g, presets: [...g.presets, withId] } : g,
    ),
  };
}

export function updatePreset(
  library: FilterPresetLibrary,
  presetId: string,
  changes: Partial<Omit<FilterPreset, 'id'>>,
): FilterPresetLibrary {
  return {
    groups: library.groups.map((g) => ({
      ...g,
      presets: g.presets.map((p) => (p.id === presetId ? { ...p, ...changes } : p)),
    })),
  };
}

export function deletePreset(library: FilterPresetLibrary, presetId: string): FilterPresetLibrary {
  return {
    groups: library.groups.map((g) => ({
      ...g,
      presets: g.presets.filter((p) => p.id !== presetId),
    })),
  };
}

/**
 * Moves a preset to `toIndex` within `toGroupId` - the one operation a drag
 * performs, whether it stays in its group or crosses into another.
 *
 * `toIndex` is read against the destination list *after* the preset has been
 * lifted out, which is what makes dropping onto a slot below its current one
 * inside the same group land where the drop indicator was drawn.
 */
export function movePreset(
  library: FilterPresetLibrary,
  presetId: string,
  toGroupId: string,
  toIndex: number,
): FilterPresetLibrary {
  const preset = findPreset(library, presetId);
  if (!preset || !library.groups.some((g) => g.id === toGroupId)) return library;

  const lifted = library.groups.map((g) => ({
    ...g,
    presets: g.presets.filter((p) => p.id !== presetId),
  }));

  return {
    groups: lifted.map((g) => {
      if (g.id !== toGroupId) return g;
      const presets = [...g.presets];
      presets.splice(clampIndex(toIndex, presets.length), 0, preset);
      return { ...g, presets };
    }),
  };
}

/** Permits `length` itself: appending past the last item is a valid drop. */
function clampIndex(index: number, length: number): number {
  if (!Number.isFinite(index)) return length;
  return Math.max(0, Math.min(Math.floor(index), length));
}
