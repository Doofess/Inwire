/**
 * Assertion tests for captureInterfaces.ts - the pure presentation rules for
 * the agent's adapter list.
 *
 *   npx tsx scripts/capture-interfaces/labels.ts
 */
import {
  LOOPBACK_DEVICE,
  filterCapturableInterfaces,
  selectionLabel,
  shortInterfaceLabel,
  toggleInterface,
} from '../../src/services/captureInterfaces';

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

// --- shortInterfaceLabel ---
check(
  'strips the driver description',
  shortInterfaceLabel('Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)'),
  'Ethernet 2',
);
check(
  'splits on the FIRST " (" so nested parens in the description do not leak',
  shortInterfaceLabel('Wi-Fi (Intel(R) Wi-Fi 6E AX211 160MHz)'),
  'Wi-Fi',
);
check(
  'handles a doubly-nested description',
  shortInterfaceLabel('Local Area Connection* 8 (WAN Miniport (Network Monitor))'),
  'Local Area Connection* 8',
);
check(
  'a label with no description is returned unchanged',
  shortInterfaceLabel('Software Loopback Interface 1'),
  'Software Loopback Interface 1',
);
check('an empty label stays empty', shortInterfaceLabel(''), '');
check(
  'a label that is only a description falls back to the full text rather than blank',
  shortInterfaceLabel(' (Some Adapter)'),
  '(Some Adapter)',
);
check('surrounding whitespace is trimmed', shortInterfaceLabel('  Wi-Fi  (Intel)'), 'Wi-Fi');
// Non-ASCII names must survive: this machine reports several adapters in Hebrew.
check(
  'a non-ASCII adapter name is preserved',
  shortInterfaceLabel('חיבור מקומי* 8 (WAN Miniport (IP))'),
  'חיבור מקומי* 8',
);

// --- filterCapturableInterfaces ---
const withLoopback = [
  { name: '\\Device\\NPF_{ABC}', label: 'Ethernet 2 (Intel)' },
  { name: LOOPBACK_DEVICE, label: 'Loopback Pseudo-Interface 1 (Software Loopback Interface 1)' },
  { name: '\\Device\\NPF_{DEF}', label: 'Wi-Fi (Intel)' },
];
check(
  'loopback is removed and the rest keep their order',
  filterCapturableInterfaces(withLoopback).map((i) => i.label),
  ['Ethernet 2 (Intel)', 'Wi-Fi (Intel)'],
);
check('a list with no loopback is unchanged', filterCapturableInterfaces([withLoopback[0]]).length, 1);
check('an empty list stays empty', filterCapturableInterfaces([]), []);
check(
  'matching is on the device path, not the label - a real adapter merely NAMED loopback survives',
  filterCapturableInterfaces([{ name: '\\Device\\NPF_{XYZ}', label: 'Loopback Pseudo-Interface 1' }]).length,
  1,
);

// --- several adapters at once -------------------------------------------------
//
// Capture takes several adapters again. The rail and the window title both read
// `selectedInterfaces[0]`, which would name one adapter of a two-adapter
// capture as if it were all of it; `selectionLabel` names the whole selection.
{
  const LIST = [
    { name: 'A', label: 'Ethernet (Intel(R) I225-V)' },
    { name: 'B', label: 'Wi-Fi (Intel(R) Wi-Fi 6E AX211)' },
    { name: 'C', label: 'Local Area Connection* 3 (WAN Miniport)' },
  ];
  check('no selection has no name', selectionLabel(LIST, []), null);
  check('one adapter is named as before', selectionLabel(LIST, ['B']), 'Wi-Fi');
  check('two are both named', selectionLabel(LIST, ['A', 'B']), 'Ethernet + Wi-Fi');
  check('...in the agent\'s order, not the order they were ticked', selectionLabel(LIST, ['B', 'A']), 'Ethernet + Wi-Fi');
  check('three or more are counted', selectionLabel(LIST, ['A', 'B', 'C']), '3 adapters');
  check('a remembered adapter the agent no longer lists is not named',
    selectionLabel(LIST, ['A', 'unplugged']), 'Ethernet');

  check('ticking an adapter adds it', toggleInterface(LIST, ['A'], 'C'), ['A', 'C']);
  check('...kept in the agent\'s order', toggleInterface(LIST, ['C'], 'A'), ['A', 'C']);
  check('ticking a chosen one takes it out', toggleInterface(LIST, ['A', 'C'], 'A'), ['C']);
  // Nothing forces one to stay: an empty selection is the "nothing chosen"
  // state, and Start stays blocked in it - which is the 2026-08-26 rule.
  check('the last one can be taken out', toggleInterface(LIST, ['A'], 'A'), []);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
