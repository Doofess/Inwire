/**
 * Assertion tests for the display-filter preset library.
 *
 *   npx tsx scripts/filter-presets/library.ts
 *
 * Covers the pure edits the Settings panel makes and the leniency rules
 * normalizeLibrary applies to whatever a previous version of the app left in
 * localStorage.
 */
import {
  DEFAULT_FILTER_PRESET_LIBRARY,
  addGroup,
  addPreset,
  allPresets,
  deleteGroup,
  deletePreset,
  findPreset,
  moveGroup,
  movePreset,
  normalizeLibrary,
  renameGroup,
  updatePreset,
} from '../../src/services/filterPresets';
import { FilterPresetLibrary } from '../../src/types/packet';

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

/** Group names in order, each with its preset names - the shape under test. */
function shape(lib: FilterPresetLibrary): [string, string[]][] {
  return lib.groups.map((g) => [g.name, g.presets.map((p) => p.name)]);
}

const lib: FilterPresetLibrary = {
  groups: [
    {
      id: 'g1',
      name: 'Alpha',
      presets: [
        { id: 'p1', name: 'One', filter: 'tcp', description: '' },
        { id: 'p2', name: 'Two', filter: 'udp', description: '' },
      ],
    },
    {
      id: 'g2',
      name: 'Beta',
      presets: [{ id: 'p3', name: 'Three', filter: 'icmp', description: '' }],
    },
  ],
};

// --- Defaults ---------------------------------------------------------------

check('defaults ship 5 groups', DEFAULT_FILTER_PRESET_LIBRARY.groups.length, 5);
check('defaults ship the original 8 presets', allPresets(DEFAULT_FILTER_PRESET_LIBRARY).length, 8);
check(
  'every default preset id is unique',
  new Set(allPresets(DEFAULT_FILTER_PRESET_LIBRARY).map((p) => p.id)).size,
  8,
);
check(
  'every default group id is unique',
  new Set(DEFAULT_FILTER_PRESET_LIBRARY.groups.map((g) => g.id)).size,
  5,
);

// --- Lookups ----------------------------------------------------------------

check('allPresets walks groups in order', allPresets(lib).map((p) => p.name), ['One', 'Two', 'Three']);
check('findPreset finds one in a later group', findPreset(lib, 'p3')?.name, 'Three');
check('findPreset returns null for an unknown id', findPreset(lib, 'nope'), null);

// --- Group edits ------------------------------------------------------------

check('addGroup appends', shape(addGroup(lib, 'Gamma')), [
  ['Alpha', ['One', 'Two']],
  ['Beta', ['Three']],
  ['Gamma', []],
]);
check('renameGroup renames in place', shape(renameGroup(lib, 'g1', 'Renamed')), [
  ['Renamed', ['One', 'Two']],
  ['Beta', ['Three']],
]);
check('deleteGroup takes its presets with it', shape(deleteGroup(lib, 'g1')), [['Beta', ['Three']]]);
check('deleteGroup on an unknown id is a no-op', shape(deleteGroup(lib, 'nope')), shape(lib));
check('moveGroup to the front', shape(moveGroup(lib, 'g2', 0)), [
  ['Beta', ['Three']],
  ['Alpha', ['One', 'Two']],
]);
check('moveGroup past the end clamps to last', shape(moveGroup(lib, 'g1', 99)), [
  ['Beta', ['Three']],
  ['Alpha', ['One', 'Two']],
]);
check('moveGroup on an unknown id is a no-op', shape(moveGroup(lib, 'nope', 0)), shape(lib));

// --- Preset edits -----------------------------------------------------------

const added = addPreset(lib, 'g2', { name: 'Four', filter: 'arp', description: 'd' });
check('addPreset appends to the named group', shape(added), [
  ['Alpha', ['One', 'Two']],
  ['Beta', ['Three', 'Four']],
]);
check(
  'addPreset assigns an id',
  allPresets(added).every((p) => typeof p.id === 'string' && p.id.length > 0),
  true,
);
check(
  'addPreset with an unknown group falls back to the last group',
  shape(addPreset(lib, 'gone', { name: 'Orphan', filter: 'x', description: '' })),
  [
    ['Alpha', ['One', 'Two']],
    ['Beta', ['Three', 'Orphan']],
  ],
);
check(
  'addPreset into an empty library creates a group',
  shape(addPreset({ groups: [] }, 'gone', { name: 'Solo', filter: 'x', description: '' })),
  [['Custom', ['Solo']]],
);

check(
  'updatePreset changes only the named fields',
  findPreset(updatePreset(lib, 'p2', { filter: 'dns' }), 'p2'),
  { id: 'p2', name: 'Two', filter: 'dns', description: '' },
);
check('deletePreset removes just that one', shape(deletePreset(lib, 'p2')), [
  ['Alpha', ['One']],
  ['Beta', ['Three']],
]);

// --- Drag: movePreset -------------------------------------------------------

check('movePreset across groups, to the front', shape(movePreset(lib, 'p1', 'g2', 0)), [
  ['Alpha', ['Two']],
  ['Beta', ['One', 'Three']],
]);
check('movePreset across groups, to the end', shape(movePreset(lib, 'p1', 'g2', 99)), [
  ['Alpha', ['Two']],
  ['Beta', ['Three', 'One']],
]);
// The index is read after the preset is lifted out, so moving One (index 0)
// to index 1 within its own group puts it after Two rather than back where it
// started - which is what the drop indicator between Two and the end showed.
check('movePreset within a group, downward', shape(movePreset(lib, 'p1', 'g1', 1)), [
  ['Alpha', ['Two', 'One']],
  ['Beta', ['Three']],
]);
check('movePreset within a group, upward', shape(movePreset(lib, 'p2', 'g1', 0)), [
  ['Alpha', ['Two', 'One']],
  ['Beta', ['Three']],
]);
check('movePreset to its own position is a no-op', shape(movePreset(lib, 'p1', 'g1', 0)), shape(lib));
// Built once: each addGroup call generates a fresh group id, so calling it
// twice would hand movePreset an id that is not in the library it was given.
const withGamma = addGroup(lib, 'Gamma');
check('movePreset into an empty group', shape(movePreset(withGamma, 'p3', withGamma.groups[2].id, 0)), [
  ['Alpha', ['One', 'Two']],
  ['Beta', []],
  ['Gamma', ['Three']],
]);
check('movePreset with an unknown preset is a no-op', shape(movePreset(lib, 'nope', 'g1', 0)), shape(lib));
check('movePreset into an unknown group is a no-op', shape(movePreset(lib, 'p1', 'nope', 0)), shape(lib));

// --- normalizeLibrary -------------------------------------------------------

check('null is rejected', normalizeLibrary(null), null);
check('a bare array is rejected', normalizeLibrary([]), null);
check('an object without groups is rejected', normalizeLibrary({ presets: [] }), null);
check('an empty groups array is rejected (falls back to defaults)', normalizeLibrary({ groups: [] }), null);
check(
  'a well-formed library round-trips unchanged',
  normalizeLibrary(JSON.parse(JSON.stringify(lib))),
  lib,
);
check(
  'a group without a name is dropped',
  shape(normalizeLibrary({ groups: [{ id: 'g1', name: 'Keep', presets: [] }, { id: 'g2' }] })!),
  [['Keep', []]],
);
check(
  'a preset missing filter is dropped, its siblings survive',
  shape(
    normalizeLibrary({
      groups: [{ id: 'g1', name: 'G', presets: [{ id: 'a', name: 'Good', filter: 'tcp' }, { id: 'b', name: 'Bad' }] }],
    })!,
  ),
  [['G', ['Good']]],
);
check(
  'a missing description defaults to empty',
  normalizeLibrary({ groups: [{ id: 'g1', name: 'G', presets: [{ id: 'a', name: 'A', filter: 'tcp' }] }] })!
    .groups[0].presets[0].description,
  '',
);
check(
  'a group with a non-array presets field keeps the group, empty',
  shape(normalizeLibrary({ groups: [{ id: 'g1', name: 'G', presets: 'oops' }] })!),
  [['G', []]],
);
const deduped = normalizeLibrary({
  groups: [
    { id: 'same', name: 'A', presets: [{ id: 'dup', name: 'X', filter: 'tcp' }] },
    { id: 'same', name: 'B', presets: [{ id: 'dup', name: 'Y', filter: 'udp' }] },
  ],
})!;
check('duplicate group ids are regenerated, both groups survive', shape(deduped), [
  ['A', ['X']],
  ['B', ['Y']],
]);
check('duplicate group ids end up distinct', deduped.groups[0].id !== deduped.groups[1].id, true);
check(
  'duplicate preset ids end up distinct',
  deduped.groups[0].presets[0].id !== deduped.groups[1].presets[0].id,
  true,
);
check(
  'the shipped defaults survive a normalize round trip',
  normalizeLibrary(JSON.parse(JSON.stringify(DEFAULT_FILTER_PRESET_LIBRARY))),
  DEFAULT_FILTER_PRESET_LIBRARY,
);

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
