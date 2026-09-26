/**
 * The memory-only store of decrypted answers (ADR 0049), on real ones.
 *
 *   npx tsx scripts/pipeline/derived-store.ts
 *
 * A frame record never holds plaintext, so what a decrypted frame's revisit
 * needs lives in `DerivedStore`, in the pipeline Worker, bounded by bytes.
 * This holds the bound and the order it evicts in, using the decrypted
 * answers the real key-log capture actually produces - and holds the one
 * property that is the reason the store exists apart from the record: those
 * answers are never handed to the capture store, which writes to disk.
 *
 * Real capture only: the `keyLog` fixture and its key log
 * (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { keyLog } from '../../src/services/tls/keyLog';
import { DerivedStore } from '../../src/services/pipeline/derivedStore';
import { FIXTURES, arrive } from './arrival';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

async function main() {
  // Source-level, because `CaptureClient` needs the preload's bridge: whatever
  // an import's entry carries, the store is sent the id and the record alone.
  const client = readFileSync('src/services/capture/captureClient.ts', 'utf8');
  checkTrue('the store is sent each record and its id, and nothing else an entry carries',
    /frames: records\.map\(\(\{ id, record \}\) => \(\{ id, record \}\)\)/.test(client));

  const fixture = FIXTURES.find((f) => f.name === 'keyLog')!;
  const keysPath = fixture.path.replace(/\.pcapng$/, '.keys');
  if (!existsSync(fixture.path) || !existsSync(keysPath)) {
    console.log(`SKIP  ${fixture.path} or its key log is not present - see test/fixtures/README.md`);
    return;
  }
  keyLog.clear();
  keyLog.add(readFileSync(keysPath, 'utf8'));
  const { arrived } = await arrive(fixture.path);
  keyLog.clear();
  const real = arrived.flatMap((a) => (a.derived === null ? [] : [[a.packet.id, a.derived] as const]));
  const total = real.reduce((s, [, d]) => s + d.length, 0);
  console.log(`      ${real.length.toLocaleString()} of ${arrived.length.toLocaleString()} frames carried decrypted `
    + `answers: ${(total / 1024 / 1024).toFixed(1)} MB, ${(total / arrived.length).toFixed(0)} B a frame of the capture\n`);
  checkTrue('the capture has decrypted answers to hold', real.length > 100);

  // Unbounded, it holds exactly what arrival produced.
  const all = new DerivedStore(Number.MAX_SAFE_INTEGER);
  for (const [id, d] of real) all.set(id, d);
  check('every answer is held', all.size, real.length);
  check('...and counted to the byte', all.bytes, total);
  checkTrue('...and given back as it was', real.every(([id, d]) => all.get(id) === d));

  // Bounded to the newest half's worth: the oldest go, the newest stay.
  const half = Math.floor(real.length / 2);
  const newest = real.slice(half);
  const budget = newest.reduce((s, [, d]) => s + d.length, 0);
  const bounded = new DerivedStore(budget);
  for (const [id, d] of real) bounded.set(id, d);
  checkTrue('a bounded store never holds more than its budget', bounded.bytes <= budget);
  checkTrue('...keeps the newest frames', newest.every(([id]) => bounded.get(id) !== null));
  checkTrue('...and lets the oldest go first', real.slice(0, half).every(([id]) => bounded.get(id) === null));
  check('...in arrival order', bounded.entries().map(([id]) => id), newest.map(([id]) => id));

  // One frame bigger than the whole budget is refused, not allowed to empty it.
  const [bigId, big] = real.reduce((a, b) => (b[1].length > a[1].length ? b : a));
  const small = new DerivedStore(big.length - 1);
  const [otherId, other] = real.find(([id, d]) => id !== bigId && d.length < big.length)!;
  small.set(otherId, other);
  small.set(bigId, big);
  check('an answer larger than the budget is not kept', small.get(bigId), null);
  checkTrue('...and does not push out what is', small.get(otherId) === other);

  // Replacing a frame's answers counts the new size, not both.
  small.set(otherId, other);
  check('setting a frame twice counts it once', small.bytes, other.length);

  all.clear();
  check('clear holds nothing', [all.size, all.bytes], [0, 0]);
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All derived-store checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
