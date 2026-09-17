/**
 * The packet counter's test hook, and the four drivers that depend on it.
 *
 *   npx tsx scripts/session/packet-counts.ts
 *
 * ## Why this exists
 *
 * Because the thing it guards broke, shipped, and could not be seen.
 *
 * `PacketCountsReadout` rendered the label `PACKETS:` while it was a dock
 * widget. All four Electron drivers found the counter by matching that string
 * in `document.body.innerText`. The widget became the title row's readout,
 * where the row's whole argument is that it does not spend its width on words -
 * so the label went, and with it every locator that depended on it.
 *
 * **The failure was worse than a failure.** `smoke.ts` runs inside
 * `npm run check`. Its locator returned nothing, `rows()` fell to its `?? '0'`
 * default, and the assertion that failed was *"frames arrive and are counted"* -
 * which accuses the pipe, `MessagePort`, the Worker and the dissector of losing
 * frames that were on screen the whole time. A broken locator that reports
 * itself as a broken data path costs more than no test at all.
 *
 * It also went unseen for another reason worth recording: on a development
 * machine running the real agent service, `smoke.ts` SKIPS - the pipe is
 * already served - so a green `npm run check` says nothing about it. This
 * script runs under plain `tsx` with no Electron and no pipe, so it is green or
 * red on every machine.
 *
 * ## What it holds
 *
 * That the component publishes the hook, that every driver uses it, and that
 * nobody has gone back to matching a label. The first two are the tie; the
 * third is what stops a new driver being written on the old pattern.
 */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

/**
 * Comments stripped, the same way `scripts/session/view.ts` and
 * `scripts/electron/shell.ts` do it.
 *
 * Not optional here. Every file this reads explains at length what it is doing,
 * and the drivers' comments now NAME the `PACKETS:` locator in order to record
 * why it was wrong - so a scan that cannot tell prose from code flags the
 * explanation as the defect. That happened on the first run of this very
 * script, which is the third time this repository has hit it.
 */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean): void => check(name, condition, true);

const HOOK = 'data-packet-counts';
const READOUT = 'src/components/common/PacketCountsReadout.tsx';
const DRIVERS = 'scripts/electron';

console.log('--- the component publishes the hook ---\n');

const readout = readFileSync(READOUT, 'utf8');
checkTrue(`${path.basename(READOUT)} carries \`${HOOK}\``, readout.includes(HOOK));

// On the span holding the two numbers, not on the row around it. The row also
// carries the scan badge, and its `textContent` runs the percentage straight on
// to the total with no separator - "44 / 178,200" "0.0%" reads back as 178,2000,
// which is a wrong number rather than a missing one.
checkTrue('...on the span that holds only the counts, not the row with the badge',
  /data-packet-counts[^>]*className="[^"]*items-baseline/.test(readout));

check('...exactly once', readout.split(HOOK).length - 1, 2); // attribute + its comment

console.log('\n--- every driver that reads the counter uses it ---\n');

/**
 * Read from disk rather than listed here. A fifth driver added next year has to
 * appear in this check without anybody remembering to add it - which is the
 * whole failure this file exists to prevent, one level up.
 */
const drivers = readdirSync(DRIVERS)
  .filter((f) => f.endsWith('.ts'))
  .map((f) => ({ name: f, source: code(readFileSync(path.join(DRIVERS, f), 'utf8')) }));

checkTrue('there are drivers to check', drivers.length > 0);

// A driver "reads the counter" if it mentions the counts at all. Anything that
// does must go through the hook.
const readsCounter = drivers.filter((d) =>
  /\bcounts\s*\(\)|\brows\s*\(\)|data-packet-counts|PACKETS:/.test(d.source));

check('every driver that reads the counter queries the hook',
  readsCounter.filter((d) => !d.source.includes(`[${HOOK}]`)).map((d) => d.name), []);

// The old shape, forbidden outright. It is not enough that today's drivers were
// fixed: the pattern has to stop being available to the next one.
const byLabel = drivers.filter((d) =>
  /innerText[\s\S]{0,80}PACKETS:|textContent === 'PACKETS:'/.test(d.source));
check('no driver finds the counter by matching a rendered label',
  byLabel.map((d) => d.name), []);

console.log(`\n        ${readsCounter.length} of ${drivers.length} scripts in `
  + `${DRIVERS}/ read the counter\n`);

console.log(failures === 0
  ? 'All packet-counter hook checks passed.'
  : `${failures} packet-counter hook check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
