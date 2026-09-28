/**
 * The RAM window follows the agent's ring, as the list does (ADR 0052).
 *
 *   npx tsx scripts/session/ring-window.ts
 *
 * When the ring deletes a file the store says every frame id below
 * `floorId` has gone, and `dropBelowFloor` lets the buffer's copies go too. It
 * is a React state updater, so it must be safe to run twice with the same
 * `prev` - `StrictMode` always does - and the check that cannot be satisfied by
 * copying the code is `ingest.ts`'s: resident bytes equal the sum recomputed
 * over the frames actually left. Over the real `inwire` capture; skips without
 * it.
 */
import { adoptAccounting, dropBelowFloor, freshAccounting } from '../../src/services/packetBuffer';
import { estimateSummaryBytes } from '../../src/services/bufferBudget';
import { loadRealCaptures } from '../export/realCaptures';
import type { Packet } from '../../src/types/packet';

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

const bytesOf = (packets: readonly Packet[]) => packets.reduce((sum, p) => sum + estimateSummaryBytes(p), 0);

async function main(): Promise<void> {
  const inwire = (await loadRealCaptures()).find((c) => c.name === 'inwire');
  if (inwire === undefined) {
    console.log('SKIP  the inwire fixture is not present (test/fixtures/README.md)');
    process.exit(0);
  }
  const window = inwire.packets;
  const accounting = freshAccounting();
  adoptAccounting(accounting, window, null);

  const floorId = window[3_000].id;
  const once = dropBelowFloor(window, floorId, accounting);
  const twice = dropBelowFloor(window, floorId, accounting);
  check('the frames below the floor leave the window, and the rest stay in order',
    [once.length, once[0]?.id, once[once.length - 1]?.id],
    [window.length - 3_000, floorId, window[window.length - 1].id]);
  check('run twice on the same buffer, it answers the same', twice.map((p) => p.id), once.map((p) => p.id));
  check('...and the bytes it freed are counted once', accounting.residentBytes, bytesOf(once));

  check('a floor below the window changes nothing',
    dropBelowFloor(once, window[10].id, accounting) === once, true);

  const later = dropBelowFloor(once, window[6_000].id, accounting);
  check('a later floor drops the next run', [later.length, later[0]?.id], [window.length - 6_000, window[6_000].id]);
  check('...still counted once', accounting.residentBytes, bytesOf(later));

  const all = dropBelowFloor(later, window[window.length - 1].id + 1, accounting);
  dropBelowFloor(later, window[window.length - 1].id + 1, accounting);
  check('a floor past the window empties it, and counts it once', [all.length, accounting.residentBytes], [0, 0]);
  check('the frames that left were the ring\'s, not the budget\'s', accounting.droppedTotal, 0);

  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All ring window checks passed.');
  process.exit(0);
}

void main();
