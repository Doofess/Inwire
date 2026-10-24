/**
 * The status bar's outbound-lookups item, and the Diagnostics rename.
 *
 *   npx tsx scripts/status/outbound-label.ts
 *
 * "no lookups" was three words that read as an error. The item now says what
 * the setting is - "Lookups off" - and, when something is on, which lookup, so
 * the person can tell which third party is learning an address.
 *
 * "Capture Health" became "Diagnostics" (the id stays `driver`, a stored key).
 * Search keeps the old name as a keyword, so somebody who learned it still
 * lands on the section.
 */
import { outboundLabel } from '../../src/components/status/outboundLabel';
import { SETTINGS_INDEX } from '../../src/lib/settingsIndex';

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

check('nothing on', outboundLabel(false, false), 'Lookups off');
check('geo-IP only', outboundLabel(true, false), 'Lookups: geo-IP');
check('reverse DNS only', outboundLabel(false, true), 'Lookups: rDNS');
check('both', outboundLabel(true, true), 'Lookups: geo-IP, rDNS');

const driver = SETTINGS_INDEX.find((e) => e.section === 'driver' && !e.pref);
check('the driver section is called Diagnostics', driver?.label, 'Diagnostics');
check(
  'searching the old name still finds it',
  driver?.keywords?.includes('capture health') ?? false,
  true,
);
check(
  'no index entry still says Capture Health',
  SETTINGS_INDEX.some((e) => e.label === 'Capture Health'),
  false,
);

if (failures > 0) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log('\nAll outbound-label checks passed.');
