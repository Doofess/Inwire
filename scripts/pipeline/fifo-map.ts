/**
 * The tree caches' container keeps exactly the newest entries, as the Map it
 * replaced did (`src/services/pipeline/fifoMap.ts`), and `IdRing` answers only
 * the ids it still holds.
 *
 *   npx tsx scripts/pipeline/fifo-map.ts
 */
import { FifoMap } from '../../src/services/pipeline/fifoMap';
import { IdRing } from '../../src/services/pipeline/coordinator';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

// Against the Map-evicted-from-its-front it replaced, over a stream with repeats.
const fifo = new FifoMap<number>(100);
const model = new Map<number, number>();
let agree = true;
for (let i = 1; i <= 5000; i++) {
  const id = i % 7 === 0 ? i - 3 : i; // a re-set of a recent id keeps its place
  fifo.set(id, i);
  model.set(id, i);
  while (model.size > 100) model.delete(model.keys().next().value!);
  if (fifo.size !== model.size) { agree = false; break; }
}
for (const [id, value] of model) if (fifo.get(id) !== value) agree = false;
check('keeps the newest 100 of 5,000, as the Map did', agree);
fifo.clear();
check('...and clears', fifo.size === 0 && !fifo.has(4999));

const ring = new IdRing(8);
for (let id = 1; id <= 20; id++) ring.set(id, id % 3);
check('a ring answers the ids it still holds', ring.get(20) === 2 && ring.get(13) === 1);
check('...and nothing for one it has overwritten', ring.get(12) === undefined && ring.get(1) === undefined);

console.log(failures === 0 ? '\nAll fifo-map checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
