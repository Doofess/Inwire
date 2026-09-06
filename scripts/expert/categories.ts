/**
 * What the expert categories actually paint, over the two parity fixtures.
 *
 *   npx tsx scripts/expert/categories.ts
 *
 * The eight bands ship **enabled**, which the band they replaced did not. That
 * decision rests on one measurement and this script is it: how much of a real
 * capture each category paints, and in particular that the checksum noise which
 * kept the old band switched off is gone.
 *
 * Before this change, `error/Checksum` was the largest finding bucket in both
 * fixtures - 1,998 and 3,459 - and **every single one of them was on a frame
 * the capturing machine had sent**, where the NIC fills the checksum in after
 * the sniffer has already seen the bytes. A band painting those paints an
 * artefact of where the capture was taken, which is why "Expert Warnings"
 * shipped disabled and the whole expert system reached the packet list through
 * nothing at all.
 *
 * Two things it asserts rather than merely reports, because both are the kind
 * of regression that would be invisible in the UI until someone wondered why a
 * fifth of the list was red:
 *
 *   - **No frame this machine sent carries a Broken checksum finding.** This is
 *     the property the whole redesign turns on. It is checked per frame against
 *     `frame.direction` rather than against a total, so one leaked frame fails
 *     it.
 *   - **No single category paints more than half the capture.** A band that
 *     paints most of the list is not triage, it is a background colour.
 *
 * The per-category counts are printed, not held to floors. They are a property
 * of these two captures - one browsing session and one idle machine - and
 * pinning them would be pinning the captures, not the code.
 *
 * A measurement with two assertions, so it needs the fixtures: `check.ts` skips
 * it by name, and it skips itself cleanly if they are not there.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { CATEGORY_ORDER, buildExpertLog, expertItemsFor } from '../../src/services/expertInfo';
import { Direction, directionOf } from '../../src/services/direction';
import type { ExpertCategory, Packet } from '../../src/types/packet';

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/netview_capture_1788426090876.pcap',
];

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

function pad(s: string, n: number) { return s.padEnd(n); }
function padStart(s: string, n: number) { return s.padStart(n); }

async function load(path: string): Promise<Packet[]> {
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(readFileSync(path))], 'fixture.pcap'),
    1_000_000,
  );
  return parsed.packets;
}

async function main() {
  const missing = FIXTURES.filter((f) => !existsSync(f));
  if (missing.length > 0) {
    console.log(`SKIP  fixture missing: ${missing[0]} (see test/fixtures/README.md)`);
    process.exit(0);
  }

  for (const path of FIXTURES) {
    const name = path.split('/').pop()!.split('_')[0];
    const packets = await load(path);
    const log = buildExpertLog(packets);

    // Frames PAINTED per category, not findings raised: the chain is
    // first-match-wins, so a frame carrying three findings is painted once, and
    // "how much of the list is this colour" is the question the enabled/disabled
    // decision was about.
    const painted = new Map<ExpertCategory, number>(CATEGORY_ORDER.map((c) => [c, 0]));
    let withAny = 0;
    for (const p of packets) {
      const category = log.categoryOf(p.id);
      if (category === undefined) continue;
      withAny++;
      painted.set(category, painted.get(category)! + 1);
    }

    console.log();
    console.log(`${name}  ${packets.length.toLocaleString()} frames`);
    console.log(`  ${pad('category', 14)}${padStart('frames', 8)}${padStart('% of list', 11)}`);
    for (const category of CATEGORY_ORDER) {
      const n = painted.get(category)!;
      console.log(`  ${pad(category, 14)}${padStart(n.toLocaleString(), 8)}`
        + `${padStart(`${((n / packets.length) * 100).toFixed(1)} %`, 11)}`);
    }
    console.log(`  ${pad('-- any --', 14)}${padStart(withAny.toLocaleString(), 8)}`
      + `${padStart(`${((withAny / packets.length) * 100).toFixed(1)} %`, 11)}`);
    console.log(`  ${log.groups().length} distinct finding(s), ${log.size.toLocaleString()} raised`);

    // --- the property the redesign turns on ---------------------------------
    //
    // Not "the Broken count went down": a frame at a time, so a single leak
    // fails it. A frame whose direction could not be decided is `Unknown` and
    // is left out rather than assumed either way - the claim is about the
    // frames we know this machine sent, and stretching it to cover the ones we
    // are unsure of would make it unfalsifiable rather than stronger.
    const leaked: number[] = [];
    for (const p of packets) {
      const direction = directionOf(p.direction);
      if (direction !== Direction.Out) continue;
      if (expertItemsFor(p).some((i) => i.summary.startsWith('Bad checksum'))) leaked.push(p.id);
    }
    check(`${name}: no frame this machine sent has a bad checksum`, leaked.slice(0, 5), []);

    const worst = CATEGORY_ORDER
      .map((c) => ({ c, share: painted.get(c)! / packets.length }))
      .sort((a, b) => b.share - a.share)[0];
    check(`${name}: no category paints more than half the list `
      + `(worst: ${worst.c} at ${(worst.share * 100).toFixed(1)} %)`,
      worst.share <= 0.5, true);
  }

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All expert category checks passed.');
  process.exit(0);
}

main();
