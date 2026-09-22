/**
 * Assertion tests for the incremental display filter.
 *
 *   npx tsx scripts/filter/incremental.ts
 *
 * The whole contract is "same answer, less work", so nearly every check here
 * compares the incremental result against a full FilterEngine pass over the
 * same buffer. The interesting cases are the ones where the fast path must
 * NOT be taken: a trimmed buffer, a cleared one, a wholesale replacement by
 * import, and a changed filter string. Getting any of those wrong would show
 * as packets silently missing from the list rather than as a crash.
 */
import { FilterEngine } from '../../src/services/filterEngine';
import { filterIncrementally, type FilterCache } from '../../src/services/incrementalFilter';
import type { Packet, ProtocolType } from '../../src/types/packet';

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

const PROTOS: ProtocolType[] = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP'];
let nextId = 1;
function makePacket(i: number): Packet {
  return {
    id: nextId++,
    tsUs: 1_700_000_000_000_000 + i * 1000,
    relativeTime: i / 100,
    timeDelta: 0.01,
    source: `10.0.0.${i % 7}`,
    destination: `10.0.1.${i % 5}`,
    protocol: PROTOS[i % PROTOS.length],
    length: 60 + (i % 200),
    info: `frame ${i}`,
    status: 'ok',
    layers: [],
    rawBytes: new Uint8Array(0),
    interfaceName: 'test',
  };
}

const ids = (ps: Packet[]) => ps.map(p => p.id);
const full = (ps: Packet[], f: string) => ids(FilterEngine.filterPackets(ps, f));

const FILTER = 'tcp';
const buffer = Array.from({ length: 200 }, (_, i) => makePacket(i));

// --- Append-only growth, the case this exists for --------------------------
{
  let cache: FilterCache | null = null;
  let packets: Packet[] = [];
  let allMatched = true;
  // Grow the way a capture does: repeated appends onto the same prefix.
  for (let n = 20; n <= 200; n += 20) {
    packets = buffer.slice(0, n);
    const out = filterIncrementally(packets, FILTER, cache);
    cache = out.cache;
    if (ids(out.result).join() !== full(packets, FILTER).join()) {
      allMatched = false;
      check(`growth to ${n} matches a full pass`, ids(out.result), full(packets, FILTER));
      break;
    }
  }
  check('append-only growth matches a full pass at every step', allMatched, true);
  check('...and actually matched something', full(packets, FILTER).length > 0, true);
}

// --- Idempotence: the property that makes the ref write safe in render -----
{
  const packets = buffer.slice(0, 120);
  const first = filterIncrementally(packets, FILTER, null);
  // Exactly what a StrictMode double-invoke does: run again with the cache the
  // first run just stored, and the same input array.
  const second = filterIncrementally(packets, FILTER, first.cache);
  check('re-running with the just-stored cache returns the same ids', ids(second.result), ids(first.result));
  check('...and literally the same array, so memos downstream do not rerun', second.result === first.result, true);
}

// --- A trim REUSES the decided prefix rather than re-deciding it -----------
//
// The trim case below already asserted the right answer, and it asserted it
// just as happily when a trim threw the cache away and re-filtered the whole
// buffer - which is what it did, and which at a 700,000-frame buffer is a
// multi-hundred-millisecond freeze inside a render.
//
// So this measures the WORK, not the answer, by counting what reaches
// `FilterEngine.filterPackets`. Put `prefixShift` back to returning null on a
// trim and the first of these fails with 140 instead of 40: the whole buffer
// re-decided rather than the forty frames that arrived after it.
{
  const realFilterPackets = FilterEngine.filterPackets;
  const sizes: number[] = [];
  FilterEngine.filterPackets = ((ps: Packet[], f: string) => {
    sizes.push(ps.length);
    return realFilterPackets.call(FilterEngine, ps, f);
  }) as typeof FilterEngine.filterPackets;

  try {
    const grown = buffer.slice(0, 150);
    const warm = filterIncrementally(grown, FILTER, null).cache;

    // 50 dropped from the head, 40 appended on the end.
    sizes.length = 0;
    const trimmed = buffer.slice(50, 190);
    const out = filterIncrementally(trimmed, FILTER, warm);

    check('a trim decides only the frames that arrived after it', sizes, [40]);
    check('...and still gives the full pass answer', ids(out.result), full(trimmed, FILTER));

    // A trim with nothing appended decides nothing at all.
    sizes.length = 0;
    const shrunk = buffer.slice(50, 150);
    const only = filterIncrementally(shrunk, FILTER, warm);
    check('a trim with no new frames runs the matcher over nothing', sizes, []);
    check('...and is still the full pass answer', ids(only.result), full(shrunk, FILTER));

    // The cache the trim returns must itself be reusable, or the saving lasts
    // exactly one flush and the next one pays for the whole buffer.
    sizes.length = 0;
    const after = buffer.slice(50, 200);
    const grownAfterTrim = filterIncrementally(after, FILTER, out.cache);
    // Snapshotted before `full()` below, which is itself a full pass and would
    // otherwise land in the counter - it did, and read as a cache miss.
    const growthWork = [...sizes];
    check('growth after a trim matches a full pass',
      ids(grownAfterTrim.result), full(after, FILTER));
    check('...and decided only the ten frames past the trimmed buffer', growthWork, [10]);

    // A wholesale replacement whose ids do not line up must still be refused,
    // now that a moved head is no longer by itself a refusal.
    sizes.length = 0;
    const imported = Array.from({ length: 140 }, (_, i) => makePacket(i + 5000));
    const afterImport = filterIncrementally(imported, FILTER, out.cache);
    const importWork = [...sizes];
    check('an import after a trim is not served a shifted result',
      ids(afterImport.result), full(imported, FILTER));
    check('...by re-deciding all of it', importWork, [140]);
  } finally {
    FilterEngine.filterPackets = realFilterPackets;
  }
}

// --- The fast path must be refused when the prefix moved -------------------
{
  const grown = buffer.slice(0, 150);
  const warm = filterIncrementally(grown, FILTER, null).cache;

  // A trim drops the oldest packets, so element 0 changes.
  const trimmed = buffer.slice(50, 190);
  check('a trimmed buffer still matches a full pass', ids(filterIncrementally(trimmed, FILTER, warm).result), full(trimmed, FILTER));

  // A clear empties it.
  check('a cleared buffer yields nothing', ids(filterIncrementally([], FILTER, warm).result), []);

  // An import replaces the array wholesale with different packets. Same length
  // as the cached source, so only the identity check at the old final index can
  // catch it - this is the check that would let stale results through.
  const imported = Array.from({ length: 150 }, (_, i) => makePacket(i + 1000));
  check('an import of the same length is not served the old result', ids(filterIncrementally(imported, FILTER, warm).result), full(imported, FILTER));

  // Growth on top of an imported buffer must re-establish, not compound.
  const importedGrown = imported.concat(Array.from({ length: 30 }, (_, i) => makePacket(i + 2000)));
  const afterImport = filterIncrementally(imported, FILTER, warm).cache;
  check('growth after an import matches a full pass', ids(filterIncrementally(importedGrown, FILTER, afterImport).result), full(importedGrown, FILTER));
}

// --- A changed filter invalidates ------------------------------------------
{
  const packets = buffer.slice(0, 150);
  const warm = filterIncrementally(packets, 'tcp', null).cache;
  const grown = buffer.slice(0, 180);
  check('a changed filter re-runs from scratch', ids(filterIncrementally(grown, 'udp', warm).result), full(grown, 'udp'));
  check('...and the previous filter is unaffected', ids(filterIncrementally(grown, 'tcp', warm).result), full(grown, 'tcp'));
  // Only whitespace differs, so the cache should still be considered valid.
  const padded = filterIncrementally(grown, '  tcp  ', filterIncrementally(packets, 'tcp', null).cache);
  check('surrounding whitespace does not invalidate the cache', ids(padded.result), full(grown, 'tcp'));
}

// --- An empty filter is the identity ---------------------------------------
{
  const packets = buffer.slice(0, 90);
  const out = filterIncrementally(packets, '', null);
  check('an empty filter returns the same array by reference', out.result === packets, true);
  check('...and drops the cache rather than holding the buffer alive', out.cache, null);
  const blank = filterIncrementally(packets, '   ', null);
  check('a whitespace-only filter is treated as empty', blank.result === packets, true);
}

// --- A filter matching nothing, and one matching everything ----------------
{
  const packets = buffer.slice(0, 100);
  const NONE = 'ip.addr == "203.0.113.99"';
  const none = filterIncrementally(packets, NONE, null);
  check('a filter that matches nothing yields nothing', ids(none.result), full(packets, NONE));
  const grown = buffer.slice(0, 140);
  check('...and stays empty as the buffer grows', ids(filterIncrementally(grown, NONE, none.cache).result), full(grown, NONE));

  const all = filterIncrementally(packets, 'len > 0', null);
  check('a filter that matches everything keeps every packet', ids(all.result), full(packets, 'len > 0'));
  check('...and grows correctly', ids(filterIncrementally(grown, 'len > 0', all.cache).result), full(grown, 'len > 0'));
}

// --- Growing from an empty buffer -------------------------------------------
{
  // The first flush of a capture: the cache's source is empty, which the
  // prefix test refuses (there is no element 0 to compare), so this must fall
  // back rather than read undefined.
  const empty = filterIncrementally([], FILTER, null);
  const firstPackets = buffer.slice(0, 10);
  check('growing from empty matches a full pass', ids(filterIncrementally(firstPackets, FILTER, empty.cache).result), full(firstPackets, FILTER));
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
