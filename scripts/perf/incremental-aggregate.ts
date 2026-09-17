/**
 * Assertion tests for the incremental packet fold.
 *
 *   npx tsx scripts/perf/incremental-aggregate.ts
 *
 * Every number the Statistics pane and the Routing Map draw comes out of this
 * fold - it was "every analytics widget", and the widgets went with the dock -
 * so the property that matters is not that it is fast; it is that it is **the
 * same answer**.
 * A fold that drifts from a full recompute produces statistics that are wrong
 * in a way nobody notices, which is worse than the stutter it was built to fix.
 *
 * So every case below is written the same way: do it incrementally, do it from
 * scratch, and require the two to be identical. The interesting cases are the
 * ones where the buffer does something other than grow - a trim, a wholesale
 * replacement by a pcap import, a value the fold closed over changing - because
 * those are exactly the ones where reusing the accumulator would be wrong.
 */
import { foldIncrementally, depsEqual, type AggregateCache } from '../../src/services/incrementalAggregate';
import type { Packet } from '../../src/types/packet';

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

let nextId = 1;
function pkt(protocol: string, length: number): Packet {
  return { id: nextId++, protocol, length } as unknown as Packet;
}

/** A representative fold: a count and a byte total per protocol. */
type Totals = Map<string, { count: number; bytes: number }>;
const create = (): Totals => new Map();
const add = (acc: Totals, p: Packet) => {
  const entry = acc.get(p.protocol) ?? { count: 0, bytes: 0 };
  entry.count += 1;
  entry.bytes += p.length;
  acc.set(p.protocol, entry);
};
/** Sorted, so a comparison is about the numbers rather than insertion order. */
const readable = (acc: Totals) =>
  [...acc.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => [k, v.count, v.bytes]);
const fromScratch = (packets: Packet[]) => readable(foldIncrementally(packets, create, add, [], null).acc);

const A = pkt('TCP', 100);
const B = pkt('UDP', 200);
const C = pkt('TCP', 300);
const D = pkt('DNS', 400);
const E = pkt('TCP', 500);

// --- The whole point ---------------------------------------------------------
{
  const buffer = [A, B, C, D, E];
  let cache: AggregateCache<Totals> | null = null;
  // Delivered the way a live capture delivers it: a growing array, one flush
  // at a time, never the same array twice.
  for (let n = 1; n <= buffer.length; n++) {
    cache = foldIncrementally(buffer.slice(0, n), create, add, [], cache);
  }
  check('folding a buffer one flush at a time equals folding it whole',
    readable(cache!.acc), fromScratch(buffer));
}

// --- Idempotence: the property the ref-during-render pattern rests on --------
{
  const buffer = [A, B, C];
  const once = foldIncrementally(buffer, create, add, [], null);
  // The SAME array again, with the cache that array produced. A React render
  // that is discarded and replayed does exactly this, and it must not count
  // anything twice.
  const twice = foldIncrementally(buffer, create, add, [], once);
  check('re-folding the same array with its own cache changes nothing',
    readable(twice.acc), fromScratch(buffer));
  check('and it does so without allocating a new accumulator', twice.acc === once.acc, true);
}

// --- A trim: the head moves, so nothing folded so far can be trusted ---------
{
  const before = [A, B, C, D];
  const cache = foldIncrementally(before, create, add, [], null);
  // What App.tsx's trim produces: the oldest packets dropped off the front.
  const after = [C, D, E];
  const trimmed = foldIncrementally(after, create, add, [], cache);
  check('a trim rebuilds rather than carrying the dropped packets forward',
    readable(trimmed.acc), fromScratch(after));
}

// --- A wholesale replacement, which is what a pcap import is -----------------
{
  const live = [A, B, C, D];
  const cache = foldIncrementally(live, create, add, [], null);
  // Same length, entirely different packets - the case a length comparison
  // alone would miss.
  const imported = [pkt('ARP', 60), pkt('ARP', 60), pkt('ICMP', 98), pkt('ICMP', 98)];
  const replaced = foldIncrementally(imported, create, add, [], cache);
  check('a replaced buffer of the same length rebuilds',
    readable(replaced.acc), fromScratch(imported));
}

// --- A shorter buffer that is still a prefix ---------------------------------
{
  const long = [A, B, C, D, E];
  const cache = foldIncrementally(long, create, add, [], null);
  const short = [A, B];
  const back = foldIncrementally(short, create, add, [], cache);
  check('a buffer that got shorter rebuilds', readable(back.acc), fromScratch(short));
}

// --- Deps: a value the fold closed over changing -----------------------------
{
  const buffer = [A, B, C];
  const cache = foldIncrementally(buffer, create, add, ['v1'], null);
  const same = foldIncrementally(buffer, create, add, ['v1'], cache);
  check('unchanged deps reuse the accumulator', same.acc === cache.acc, true);
  const changed = foldIncrementally(buffer, create, add, ['v2'], cache);
  check('changed deps rebuild', changed.acc === cache.acc, false);
  check('and the rebuild is correct', readable(changed.acc), fromScratch(buffer));
}

// --- The empty buffer --------------------------------------------------------
{
  const empty = foldIncrementally([], create, add, [], null);
  check('an empty buffer folds to an empty accumulator', readable(empty.acc), []);
  const grown = foldIncrementally([A], create, add, [], empty);
  check('and growing from empty is correct', readable(grown.acc), fromScratch([A]));
}

// --- The trap the reuse sets for callers ------------------------------------
//
// Reusing the accumulator is the whole point, and it is also the sharp edge:
// the value a `finalize` of `(acc) => acc` hands back keeps ONE identity for
// the life of the capture. Anything downstream keyed on that identity - a
// useMemo, an effect's dependency list - then never runs again.
//
// This is not hypothetical. GeoMap did exactly that, and its arcs froze: once
// every address had resolved, nothing in the routes memo's dependency list
// ever changed again, so new traffic between two already-located hosts drew
// nothing for the rest of the capture. Every other call site returns a freshly
// allocated value, and this check is here to say why that is required rather
// than incidental.
{
  const first = foldIncrementally([A], create, add, [], null);
  const second = foldIncrementally([A, B], create, add, [], first);
  check('an extended fold hands back the SAME accumulator object',
    second.acc === first.acc, true);
  check('...so a finalize of (acc) => acc is identity-stable, and a memo keyed '
    + 'on it never re-runs', ((acc) => acc)(second.acc) === ((acc) => acc)(first.acc), true);
  check('...which is why finalize must allocate: a copy is a new identity',
    new Map(second.acc as Map<unknown, unknown>) === new Map(first.acc as Map<unknown, unknown>), false);
}

// --- depsEqual ---------------------------------------------------------------
{
  check('depsEqual: same values', depsEqual([1, 'a'], [1, 'a']), true);
  check('depsEqual: different length', depsEqual([1], [1, 2]), false);
  const map = new Map();
  check('depsEqual: identity, not deep equality', depsEqual([map], [new Map()]), false);
  check('depsEqual: NaN is equal to itself, as Object.is says', depsEqual([NaN], [NaN]), true);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All incremental-aggregate checks passed.');
process.exit(0);
