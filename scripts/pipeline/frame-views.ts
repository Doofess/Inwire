/**
 * A live frame is a view into the agent's batch, not a buffer of its own (#17):
 * nothing copies it between the pipe and the dissector.
 *
 *   npx tsx scripts/pipeline/frame-views.ts
 *
 * Every frame of every real fixture is dissected twice, as `arrival.ts` does
 * it: once from a buffer of its own, once from a view at an odd offset inside
 * 0xA5 junk. The tree and the row must be the same. A dissector that reads
 * `bytes.buffer` without `byteOffset` reads the junk, and differs.
 *
 * Records are not compared: two arrivals in one process already differ in
 * the same frames' records (some numbering carries over from the first), so
 * a difference there says nothing about the view.
 *
 * Real captures only (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync } from 'node:fs';
import { FIXTURES, arrive, firstDifference, render } from './arrival';
import type { Packet } from '../../src/types/packet';

let failures = 0;

function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : `: ${detail}`}`);
  if (!ok) failures++;
}

/** A row's columns and fields, without the tree and the bytes compared beside it. */
function row(packet: Packet): string {
  const { layers: _layers, rawBytes: _bytes, ...rest } = packet;
  return JSON.stringify(rest, (_key, value) => (typeof value === 'bigint' ? `${value}n` : value));
}

async function main(): Promise<void> {
  let ran = 0;
  for (const fixture of FIXTURES) {
    if (!existsSync(fixture.path)) {
      console.log(`SKIP  ${fixture.name}: no fixture`);
      continue;
    }
    ran++;
    const own = await arrive(fixture.path);
    const view = await arrive(fixture.path, { view: true });
    check(`${fixture.name}: the same frames`, own.arrived.length === view.arrived.length);
    let trees = 0, rows = 0;
    let firstTree = '', firstRow = '';
    for (let i = 0; i < Math.min(own.arrived.length, view.arrived.length); i++) {
      const a = own.arrived[i], b = view.arrived[i];
      const want = render(a.packet.layers), got = render(b.packet.layers);
      if (want !== got) {
        trees++;
        if (firstTree === '') firstTree = `frame ${i + 1} ${firstDifference(want, got)}`;
      }
      if (row(a.packet) !== row(b.packet)) {
        rows++;
        if (firstRow === '') firstRow = `frame ${i + 1}`;
      }
    }
    check(`${fixture.name}: every tree is the same from a view (${own.arrived.length} frames)`, trees === 0,
      `${trees} differ, first ${firstTree}`);
    check(`${fixture.name}: every row is the same from a view`, rows === 0, `${rows} differ, first ${firstRow}`);
  }
  if (ran === 0) console.log('\nAll frame-views checks passed (skipped).');
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All frame-views checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
