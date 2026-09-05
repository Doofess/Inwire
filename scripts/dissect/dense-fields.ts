/**
 * Assertion tests for the declared dense-field set.
 *
 *   npx tsx scripts/dissect/dense-fields.ts
 *
 * Which fields get a column is **declared** rather than learned from the
 * capture (`src/services/dissect/denseFields.ts`). A learned set would have to
 * migrate a column mid-capture when it changed, and - the part that actually
 * forces the decision - a key written after dissection cannot live in a column
 * at all, so density has to be knowable before any frame arrives.
 *
 * A declaration that nothing checks is a guess with a comment, so this holds it
 * to three things: it may not overlap the keys written after dissection, every
 * key in it must be a real registered field, and it must not have missed a key
 * that is dense in the captures we do have.
 *
 * The fixture pass needs the fixtures (test/fixtures/README.md) and skips
 * cleanly without them; the rest always runs.
 */
import { existsSync, readFileSync } from 'node:fs';
import { DENSE_FIELDS, POST_DISSECTION_KEYS } from '../../src/services/dissect/denseFields';
import { FIELDS } from '../../src/services/dissect/fieldRegistry';
import { fieldEntries } from '../../src/services/dissect/fieldAccess';
import { PcapService } from '../../src/services/pcapParser';

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

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/netview_capture_1788426090876.pcap',
];

/** A key is worth a column when this much of a capture carries it. */
const DENSE_THRESHOLD = 0.2;

// --- The two halves may not overlap -------------------------------------------
//
// A key written after dissection cannot live in a column: the row is filled
// once, as the frame joins the buffer, and the column is shared with every
// other frame in the block. If this ever fails, the annotator's key must come
// OUT of DENSE_FIELDS - never the other way round.
{
  const dense = new Set(DENSE_FIELDS.map((k) => k.abbrev));
  const overlap = POST_DISSECTION_KEYS.filter((k) => dense.has(k));
  check('no field is both dense and written after dissection', overlap, []);
}

// --- Every declared key is a real registered field --------------------------------
//
// A typo would be invisible otherwise: the column would exist, nothing would
// ever write to it, and the field would keep costing a property slot.
{
  const registered = new Set(FIELDS.map((f) => f.abbrev));
  const unknown = DENSE_FIELDS.map((k) => k.abbrev).filter((a) => !registered.has(a));
  check('every dense key is in the field registry', unknown, []);

  const abbrevs = DENSE_FIELDS.map((k) => k.abbrev);
  const dupes = abbrevs.filter((a, i) => abbrevs.indexOf(a) !== i);
  check('no key is declared twice', dupes, []);
}

// --- And the declaration still matches the captures ---------------------------------
{
  if (FIXTURES.some((f) => !existsSync(f))) {
    console.log('SKIP  fixtures missing (test/fixtures/README.md)');
  } else {
    const counts = new Map<string, number>();
    let frames = 0;
    for (const path of FIXTURES) {
      const parsed = await PcapService.parseCaptureFile(
        new File([new Uint8Array(readFileSync(path))], 'fixture.pcap'), 1_000_000,
      );
      for (const packet of parsed.packets) {
        frames++;
        // Through the accessor, not off the bag: these frames came from
        // `parseCaptureFile`, which has already moved the dense keys into
        // columns - so counting the bag would find none of them, report every
        // declared key as sparse, and pass vacuously for ever after. It did
        // exactly that for one commit, and reported 0.0% coverage while
        // passing.
        for (const [key] of fieldEntries(packet)) {
          counts.set(key, (counts.get(key) ?? 0) + 1);
        }
      }
    }

    const declared = new Set(DENSE_FIELDS.map((k) => k.abbrev));

    // The expensive mistake, and so the failure: a key on a fifth of every
    // capture, still paying a property slot on every frame that carries it.
    const missed = [...counts.entries()]
      .filter(([key, n]) => n / frames >= DENSE_THRESHOLD && !declared.has(key))
      .map(([key]) => key)
      .sort();
    check('no key is dense in the fixtures but undeclared', missed, []);

    // The cheap one, and so a report: a key sparse in these two captures may be
    // dense in someone else's, and every IPv4 field here is exactly that case.
    const idle = DENSE_FIELDS
      .map((k) => k.abbrev)
      .filter((a) => (counts.get(a) ?? 0) / frames < DENSE_THRESHOLD);
    console.log('      declared but sparse in these two captures: '
      + (idle.length === 0 ? 'none' : idle.join(', ')));
    console.log('      (not a failure - both fixtures are IPv6-heavy)');

    const covered = DENSE_FIELDS.reduce((a, k) => a + (counts.get(k.abbrev) ?? 0), 0);
    const total = [...counts.values()].reduce((a, n) => a + n, 0);
    console.log('      the declared set covers ' + ((covered / total) * 100).toFixed(1)
      + '% of all ' + total.toLocaleString() + ' entries');
  }
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All dense-field checks passed.');
process.exit(0);
