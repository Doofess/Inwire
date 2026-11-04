/**
 * The burst drives send what the agent sends: batches cut at its bounds, and
 * capture times that only rise across a tick's batches, as one adapter's do.
 *
 *   npx tsx scripts/perf/agent-batches.ts
 *
 * The ordering window sorts by capture time, then number. A drive that
 * restarted each batch's stamps at the tick's start had the Worker dissect
 * `1, 244, 487, ..., 2, 245, ...`: every connection's segments out of order,
 * which no agent sends, under every ceiling measured with it.
 */
import { agentBatchBounds, cutTick } from './agentBatches';

let failed = 0;
function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : ` - ${detail}`}`);
  if (!ok) failed++;
}

const bounds = agentBatchBounds();
check('the agent\'s bounds are read from session.rs', bounds.records === 512 && bounds.bytes === 256 * 1024,
  `${bounds.records} records, ${bounds.bytes} bytes`);

// A 120,000-a-second tick: 1,200 frames of the burst's ~1,080 bytes.
const frame = new Uint8Array(1080);
const base = 1_700_000_000_000n * 1_000_000n;
const batches = cutTick(1200, base, 501, () => frame, bounds);
const all = batches.flat();

check('a tick at 120,000 a second is several agent batches', batches.length >= 3, `${batches.length}`);
check('no batch holds more records than the agent sends', batches.every((b) => b.length <= bounds.records));
check('a batch stops once past the byte bound, overrunning it by its last record at most',
  batches.every((b) => b.slice(0, -1).reduce((sum, f) => sum + f.bytes.length, 0) < bounds.bytes));
check('every frame of the tick is sent once, numbered on', all.length === 1200 && all.every((f, i) => f.seq === 501 + i));

let backwards = 0;
for (let i = 1; i < all.length; i++) if (all[i].tsNs <= all[i - 1].tsNs) backwards++;
check('capture times rise across the whole tick, so the ordering window keeps the order sent', backwards === 0,
  `${backwards} frames stamped at or before the frame sent ahead of them`);
check('the tick starts at its base, a microsecond a frame', all[0].tsNs === base && all[1199].tsNs === base + 1_199_000n);

if (failed > 0) {
  console.log(`\n${failed} check(s) failed`);
  process.exit(1);
}
console.log('\nall agent-batch checks passed');
