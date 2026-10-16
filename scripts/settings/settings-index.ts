/**
 * The Settings search index (Plan D item 4, Task 7).
 *
 *   npx tsx scripts/settings/settings-index.ts
 *
 * Three things go wrong here without a sound:
 *
 *   1. A row is added to a panel and not to the index, so the search box says
 *      "No settings match" for a setting that is on screen. The first half reads
 *      the panels' own source - every `<SettingRow label=...>` - and fails on a
 *      row with no entry, a wrong section, or a description that has drifted.
 *   2. A reset on a store shared by several rows resets the lot. Three of the
 *      Interface rows share `performanceStore` and two share `packetListStore`;
 *      the reset has to touch only its own field.
 *   3. A row's anchor id collides with the id of the control inside it. The
 *      Minimap switch is `#setting-minimap`; a row anchor of the same name would
 *      come first in the document and take the label's `htmlFor` away from the
 *      switch, so clicking the label would stop toggling it.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPreferenceStore } from '../../src/services/preferenceStore';
import { cancelPendingPreferenceWrites, resetPreferenceCache } from '../../src/services/preferences';
import {
  SETTINGS_INDEX,
  isModified,
  resetSetting,
  searchSettings,
  settingAnchorId,
  settingByLabel,
  type SettingEntry,
  type SettingPref,
  type SettingsSection,
} from '../../src/lib/settingsIndex';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const SECTIONS: SettingsSection[] = [
  'appearance', 'interface', 'accessibility', 'filters', 'decryption', 'driver', 'updates',
];

// --- The index against the panels -----------------------------------------------------

/** Which section a panel file belongs to; a panel with rows and no entry here is a failure. */
const PANEL_SECTION: Record<string, SettingsSection> = {
  'AppearanceSettingsPanel.tsx': 'appearance',
  'InterfaceSettingsPanel.tsx': 'interface',
  'AccessibilitySettingsPanel.tsx': 'accessibility',
  'UpdateCenterPanel.tsx': 'updates',
};

const panelDir = join(root, 'src', 'components', 'common');
const panelFiles = readdirSync(panelDir).filter((f) => /Panel\.tsx$/.test(f));
const rows: { file: string; label: string; description?: string }[] = [];
const controlIds = new Set<string>();
for (const file of panelFiles) {
  const src = readFileSync(join(panelDir, file), 'utf8');
  for (const m of src.matchAll(/<SettingRow\s+label="([^"]+)"(?:\s+description="([^"]*)")?/g)) {
    rows.push({ file, label: m[1], description: m[2] });
  }
  for (const m of src.matchAll(/\bid="(setting-[^"]+)"/g)) controlIds.add(m[1]);
}

check('the walk found the panels\' rows', rows.length >= 17, true);
check(
  'every panel with rows is mapped to a section',
  [...new Set(rows.map((r) => r.file))].filter((f) => !(f in PANEL_SECTION)),
  [],
);

for (const row of rows) {
  const entry = settingByLabel(row.label);
  check(`"${row.label}" has an entry`, entry !== undefined, true);
  if (!entry) continue;
  check(`"${row.label}" is filed under ${PANEL_SECTION[row.file]}`, entry.section, PANEL_SECTION[row.file]);
  if (row.description !== undefined) {
    check(`"${row.label}" carries the description the panel shows`, entry.description, row.description);
  }
}

check('every entry\'s section is one of the seven', SETTINGS_INDEX.filter((e) => !SECTIONS.includes(e.section)), []);
const labels = SETTINGS_INDEX.map((e) => e.label);
check('labels are unique', labels.length, new Set(labels).size);
check(
  'the non-row entries are there: theme, accent and the three tabs',
  ['App theme', 'Accent colour', 'Display Filters', 'Decryption', 'Capture Health']
    .filter((l) => settingByLabel(l) === undefined),
  [],
);
check(
  'anchor ids are unique',
  SETTINGS_INDEX.length,
  new Set(SETTINGS_INDEX.map((e) => settingAnchorId(e.label))).size,
);
check(
  'no anchor id is the id of a control inside a panel',
  SETTINGS_INDEX.map((e) => settingAnchorId(e.label)).filter((id) => controlIds.has(id)),
  [],
);
check('an anchor id is a slug', settingAnchorId('Packet list density').startsWith('setting-'), true);
check(
  'every field a pref names exists in its store\'s defaults',
  SETTINGS_INDEX.filter((e) => e.pref?.field !== undefined
    && !(e.pref.field in (e.pref.store.defaults as object))).map((e) => e.label),
  [],
);
check(
  'a fresh profile has nothing modified',
  SETTINGS_INDEX.filter((e) => isModified(e)).map((e) => e.label),
  [],
);
check(
  'rows that run an action carry no pref',
  settingByLabel('Tutorial')?.pref === undefined && settingByLabel('Tutorial') !== undefined,
  true,
);

// --- Search ----------------------------------------------------------------------------

const first = (q: string) => searchSettings(q)[0]?.label;
check('"dns" finds Reverse DNS first', first('dns'), 'Reverse DNS');
check('"minimp" finds Minimap first', first('minimp'), 'Minimap');
check(
  '"ipapi" finds Locate addresses through its description',
  searchSettings('ipapi').map((e) => e.label).includes('Locate addresses'),
  true,
);
check(
  'a section\'s heading finds its rows: "privacy" finds Reverse DNS',
  searchSettings('privacy').map((e) => e.label).includes('Reverse DNS'),
  true,
);
check('a query nothing matches is []', searchSettings('qqqq'), []);
check('an empty query is []', searchSettings(''), []);
check('a blank query is []', searchSettings('   '), []);
{
  const hits = searchSettings('dns').map((e) => e.label);
  check('a hit is listed once however it matched', hits.length, new Set(hits).size);
}
{
  const fake: SettingEntry[] = [
    { section: 'interface', label: 'Alpha', description: 'mentions beta and gamma' },
    { section: 'interface', label: 'Beta' },
  ];
  check(
    'a label match outranks a description match, over an injected index',
    searchSettings('beta', fake).map((e) => e.label),
    ['Beta', 'Alpha'],
  );
  check(
    'a description match needs every word, in any order',
    searchSettings('gamma beta', fake).map((e) => e.label).includes('Alpha'),
    true,
  );
  check('...and one missing word is no match', searchSettings('gamma zeta', fake), []);
}

// --- Modified and reset, on a store with two fields -----------------------------------

{
  // No browser here: the store reads localStorage at creation, guarded, and
  // starts at its defaults. Writes are queued on a timer, which is dropped.
  resetPreferenceCache();
  cancelPendingPreferenceWrites();
  const store = createPreferenceStore<{ a: number; b: number }>(
    'test.two',
    (n) => n as { a: number; b: number },
    { a: 1, b: 2 },
  );
  const a: SettingEntry = { section: 'interface', label: 'A', pref: { store, field: 'a' } as unknown as SettingPref };
  const b: SettingEntry = { section: 'interface', label: 'B', pref: { store, field: 'b' } as unknown as SettingPref };

  check('a field at its default is not modified', isModified(a), false);
  store.set({ a: 5, b: 9 });
  check('a changed field is modified', isModified(a), true);
  check('...and so is its sibling, on its own account', isModified(b), true);
  resetSetting(a);
  check('reset puts only its own field back', store.get(), { a: 1, b: 9 });
  check('...the field it reset is no longer modified', isModified(a), false);
  check('...and the sibling still is', isModified(b), true);

  let notified = 0;
  const off = store.subscribe(() => { notified++; });
  resetSetting(a);
  check('resetting what is already default notifies nobody', notified, 0);
  resetSetting(b);
  off();
  check('resetting the other field restores the defaults', store.get(), { a: 1, b: 2 });

  // A store whose whole value is the setting.
  const flag = createPreferenceStore<boolean>(
    'test.flag',
    (raw) => (typeof raw === 'boolean' ? raw : null),
    true,
  );
  const whole: SettingEntry = { section: 'interface', label: 'Flag', pref: { store: flag } };
  check('a whole-value setting at its default is not modified', isModified(whole), false);
  flag.set(false);
  check('...and is once it changes', isModified(whole), true);
  resetSetting(whole);
  check('...and reset restores it', flag.get(), true);

  // An entry with no pref has nothing to report or to reset.
  const bare: SettingEntry = { section: 'interface', label: 'Bare' };
  check('an entry with no pref is never modified', isModified(bare), false);
  resetSetting(bare);
  check('...and resetting it does nothing', isModified(bare), false);

  cancelPendingPreferenceWrites();
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All settings-index checks passed.');
process.exit(0);
