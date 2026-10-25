/**
 * Assertion tests for folds that survive a trim of the window's head.
 *
 *   npx tsx scripts/expert/trim.ts
 *
 * App's name map and expert log are folded over the RAM window, and a full
 * window trims its head about twice a second. They used to refold the whole
 * window each time (about 1.27M rows, ~180 ms); `foldIncrementally` now takes
 * a `drop` and `ExpertLog.remove` gives the expert log one.
 *
 * What matters is that it is **the same answer**: after any run of trims,
 * appends and last-frame patches, the log must equal a fresh fold over the
 * array it was last given - every group with its first 200 frames, the
 * counts, the total and `categoryOf` for every frame - and `add` must have
 * run only on rows it had not seen. The group that matters most is the one
 * with more than 200 occurrences whose first 200 were trimmed: its `frames`
 * must be the next 200, not nothing.
 */
import { foldIncrementally, type AggregateCache } from '../../src/services/incrementalAggregate';
import { ExpertLog, expertSnapshot } from '../../src/services/expertInfo';
import { withDuplicate } from '../../src/services/direction';
import type { ExpertCategory, Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected).slice(0, 400)}`);
    console.log(`        actual   ${JSON.stringify(actual).slice(0, 400)}`);
  }
}

/** A seeded generator, so a failure is the same failure next run. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const POOL: Array<[ExpertCategory, string]> = [
  ['Loss', '[TCP Retransmission]'],
  ['Loss', '[TCP Dup ACK 5#2]'],
  ['Broken', 'Bad checksum'],
  ['Note', 'Keep-alive'],
  ['Security', 'Certificate expired'],
  ['Reset', 'Connection reset'],
];
const LABELS = ['TCP', 'TLS', 'UDP', 'DNS'];

let nextId = 1;
/**
 * A frame carrying 0 to 3 findings, some of them the same one twice, with a
 * protocol label that varies - a group's row reads its protocol off its first
 * remaining occurrence, so the labels must differ along a group.
 */
function packet(r: () => number, hot = 0.5): Packet {
  const expert: Array<{ category: ExpertCategory; message: string }> = [];
  if (r() < hot) expert.push({ category: 'Loss', message: '[TCP Retransmission]' });
  const extra = Math.floor(r() * 3);
  for (let i = 0; i < extra; i++) {
    const [category, message] = POOL[Math.floor(r() * POOL.length)];
    expert.push({ category, message });
  }
  return {
    id: nextId++,
    tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP', protocolLabel: LABELS[Math.floor(r() * LABELS.length)],
    length: 100, info: '', status: 'ok',
    layers: [], rawBytes: new Uint8Array(0),
    expert: expert.length ? expert : undefined,
    direction: r() < 0.05 ? withDuplicate(0) : undefined,
    interfaceName: 'test',
  };
}

/** Everything a reader of the log can ask, for ids 1..maxId. */
function everything(log: ExpertLog, maxId: number) {
  const categories: Array<ExpertCategory | undefined> = [];
  for (let id = 1; id <= maxId; id++) categories.push(log.categoryOf(id));
  return { groups: log.groups(), counts: log.counts(), size: log.size, categories };
}

function fresh(packets: Packet[]): ExpertLog {
  const log = new ExpertLog();
  for (const p of packets) log.add(p);
  return log;
}

/** `foldIncrementally` over an ExpertLog, counting what it asks of `add` and `remove`. */
function folder(withDrop: boolean) {
  const calls = { add: 0, remove: 0, create: 0 };
  let cache: AggregateCache<ExpertLog> | null = null;
  return {
    calls,
    get cache() { return cache!; },
    fold(packets: Packet[], deps: readonly unknown[] = []) {
      calls.add = calls.remove = calls.create = 0;
      cache = foldIncrementally(
        packets,
        () => { calls.create++; return new ExpertLog(); },
        (log, p) => { calls.add++; log.add(p); },
        deps,
        cache,
        withDrop ? (log, p) => { calls.remove++; log.remove(p); } : undefined,
      );
      return cache.acc;
    },
  };
}

// --- A random run of trims, appends and patches ------------------------------
{
  const r = rng(7);
  let buffer: Packet[] = [];
  for (let i = 0; i < 2600; i++) buffer.push(packet(r, 0.6));
  const f = folder(true);
  f.fold(buffer);

  let mismatches = 0;
  let wrongWork = 0;
  let bigTrims = 0;
  const steps = 400;
  for (let step = 0; step < steps; step++) {
    const old = buffer;
    // Trim 0 to 60% of the window, append 0 to 400, patch the last frame
    // sometimes. All three in one tick is the case a busy capture makes.
    const k = r() < 0.3 ? 0 : Math.floor(r() * old.length * 0.6);
    const appended = Math.floor(r() * 400);
    const next = old.slice(k);
    if (r() < 0.5 && next.length > 0) {
      // A patch replaces a frame with a copy of the same id (`commitBatch`);
      // what it changes is the Info, never the findings.
      next[next.length - 1] = { ...next[next.length - 1], info: `patched ${step}` };
    }
    for (let i = 0; i < appended; i++) next.push(packet(r, 0.6));
    buffer = next;
    if (k >= 200) bigTrims++;

    const log = f.fold(buffer);
    if (f.calls.add !== appended || f.calls.remove !== k || f.calls.create !== 0) wrongWork++;
    const want = JSON.stringify(everything(fresh(buffer), nextId));
    if (JSON.stringify(everything(log, nextId)) !== want) mismatches++;
  }
  check(`${steps} random trim/append/patch ticks equal a fresh fold, groups with frames, counts, `
    + 'size and categoryOf for every frame', mismatches, 0);
  check('...with `add` run on new rows only and `remove` on trimmed rows only', wrongWork, 0);
  check('...across many trims of 200 frames or more', bigTrims > 100, true);
}

// --- The group whose first 200 frames are trimmed ----------------------------
{
  const r = rng(11);
  const buffer: Packet[] = [];
  for (let i = 0; i < 1500; i++) {
    buffer.push({ ...packet(r, 0), expert: [{ category: 'Loss', message: '[TCP Retransmission]' }] });
  }
  const f = folder(true);
  f.fold(buffer);
  const trimmed = buffer.slice(700);
  const log = f.fold(trimmed);
  const row = log.groups().find((g) => g.summary === '[TCP Retransmission]')!;
  check('a group trimmed past its first 200 occurrences still has its count', row.count, 800);
  check('...and its frames are the first 200 of the window, not none',
    row.frames, trimmed.slice(0, 200).map((p) => p.id));
  check('...as a rebuild would give', JSON.stringify(log.groups()), JSON.stringify(fresh(trimmed).groups()));
  check('a trimmed frame has no category any more', log.categoryOf(buffer[0].id), undefined);
}

// --- Trim to the tail, and trim everything -----------------------------------
{
  const r = rng(13);
  const buffer: Packet[] = [];
  for (let i = 0; i < 300; i++) buffer.push(packet(r));
  const f = folder(true);
  f.fold(buffer);
  const tail = buffer.slice(buffer.length - 1);
  const log = f.fold(tail);
  check('a trim of everything but the last frame carries on', f.calls.remove, 299);
  check('...adding nothing', f.calls.add, 0);
  check('...and equals a fresh fold',
    JSON.stringify(everything(log, nextId)), JSON.stringify(everything(fresh(tail), nextId)));

  const replaced: Packet[] = [];
  for (let i = 0; i < 50; i++) replaced.push(packet(r));
  const after = f.fold(replaced);
  check('a trim of everything with new frames after it rebuilds',
    [f.calls.create, f.calls.add, f.calls.remove], [1, 50, 0]);
  check('...to the same answer',
    JSON.stringify(everything(after, nextId)), JSON.stringify(everything(fresh(replaced), nextId)));
}

// --- What still rebuilds -----------------------------------------------------
{
  const r = rng(17);
  const buffer: Packet[] = [];
  for (let i = 0; i < 200; i++) buffer.push(packet(r));
  const trimmed = buffer.slice(80);

  const without = folder(false);
  const before = without.fold(buffer);
  const kept = without.fold(trimmed);
  check('a fold with no drop rebuilds on a trim',
    [kept === before, without.calls.create, without.calls.add], [false, 1, 120]);

  const withDropped = folder(true);
  const first = withDropped.fold(buffer, ['a']);
  const same = withDropped.fold(buffer.slice(), ['a']);
  check('an unchanged fold with drop keeps the accumulator', same === first, true);
  const changed = withDropped.fold(trimmed, ['b']);
  check('a deps change rebuilds even when the shift is provable',
    [changed === first, withDropped.calls.create, withDropped.calls.add, withDropped.calls.remove],
    [false, 1, 120, 0]);

  // Same length, other frames - a pcap import over a live window.
  const imported: Packet[] = [];
  for (let i = 0; i < trimmed.length; i++) imported.push(packet(r));
  const other = withDropped.fold(imported, ['b']);
  check('a replaced buffer rebuilds',
    [other === changed, withDropped.calls.create, withDropped.calls.remove], [false, 1, 0]);
  check('...to the right answer',
    JSON.stringify(everything(other, nextId)), JSON.stringify(everything(fresh(imported), nextId)));

  // An older array than the one the cache holds: a discarded render's cache
  // meeting the render that was not discarded.
  const newer = withDropped.fold(imported.concat([packet(r)]), ['b']);
  const older = withDropped.fold(imported, ['b']);
  check('an older, shorter array rebuilds rather than un-adding',
    [older === newer, withDropped.calls.create], [false, 1]);
  check('...to the right answer',
    JSON.stringify(everything(older, nextId)), JSON.stringify(everything(fresh(imported), nextId)));
}

// --- A generic fold with a drop ----------------------------------------------
{
  type Totals = Map<string, number>;
  const mk = (id: number, protocol: string) => ({ id, protocol, length: 1 }) as unknown as Packet;
  const all = [mk(1, 'A'), mk(2, 'B'), mk(3, 'A'), mk(4, 'C'), mk(5, 'A')];
  let adds = 0;
  const drops: number[] = [];
  const add = (t: Totals, p: Packet) => { adds++; t.set(p.protocol, (t.get(p.protocol) ?? 0) + 1); };
  const drop = (t: Totals, p: Packet) => {
    drops.push(p.id);
    const left = (t.get(p.protocol) ?? 0) - 1;
    if (left === 0) t.delete(p.protocol); else t.set(p.protocol, left);
  };
  const first = foldIncrementally(all.slice(0, 4), () => new Map() as Totals, add, [], null, drop);
  adds = 0;
  const second = foldIncrementally(all.slice(2), () => new Map() as Totals, add, [], first, drop);
  check('a generic fold drops the head it lost, in order', drops, [1, 2]);
  check('...adds only the new tail', adds, 1);
  check('...and keeps the accumulator', second.acc === first.acc, true);
  check('...with the same totals as a fresh fold', [...second.acc.entries()].sort(),
    [['A', 2], ['C', 1]]);
}

// --- Report mode keeps its first 200 and never removes -----------------------
{
  const r = rng(19);
  const log = new ExpertLog(false);
  const ids: number[] = [];
  let last: Packet | undefined;
  for (let i = 0; i < 500; i++) {
    last = { ...packet(r, 0), expert: [{ category: 'Loss', message: '[TCP Retransmission]' }] };
    ids.push(last.id);
    log.add(last);
  }
  const row = log.groups()[0];
  check('report mode: a group still holds its first 200 frames', row.frames, ids.slice(0, 200));
  check('...and counts them all', row.count, 500);
  check('...and keeps no per-frame category', log.categoryOf(ids[0]), undefined);
  let threw = false;
  try { log.remove(last!); } catch { threw = true; }
  check('...and remove throws', threw, true);
}

// --- Snapshots keep what they were handed ------------------------------------
{
  const r = rng(23);
  const buffer: Packet[] = [];
  for (let i = 0; i < 400; i++) buffer.push(packet(r, 0.6));
  const log = fresh(buffer);
  const snap = expertSnapshot(log);
  const groups = snap.groups();
  const frozen = JSON.stringify({ groups, counts: snap.counts(), size: snap.size });

  for (let i = 0; i < 100; i++) log.remove(buffer[i]);
  for (let i = 0; i < 100; i++) log.add(packet(r, 0.6));
  check('a snapshot already read does not change after the log moves on',
    JSON.stringify({ groups, counts: snap.counts(), size: snap.size }), frozen);
  check('...and asking again gives the same rows', JSON.stringify(snap.groups()), JSON.stringify(groups));

  const later = log.groups();
  groups[0].frames.length = 0;
  groups[0].count = -1;
  check('rows handed out are copies: writing to one does not reach the log',
    JSON.stringify(log.groups()), JSON.stringify(later));
}

// --- The queue gives its memory back -----------------------------------------
{
  const r = rng(29);
  const log = new ExpertLog();
  const buffer: Packet[] = [];
  for (let i = 0; i < 60000; i++) {
    buffer.push({ ...packet(r, 0), expert: [{ category: 'Loss', message: '[TCP Retransmission]' }] });
  }
  for (const p of buffer) log.add(p);
  const slots = () => {
    const rows = (log as unknown as { rows: Map<string, { occurrences: { data: Uint32Array } }> }).rows;
    return [...rows.values()][0].occurrences.data.length;
  };
  const full = slots();
  for (let i = 0; i < 59990; i++) log.remove(buffer[i]);
  check('a group trimmed down to ten findings keeps a few slots, not its old array',
    [log.size, slots() <= 160, full >= 120000],
    [10, true, true]);
  check('...and still lists them', log.groups()[0].frames, buffer.slice(59990).map((p) => p.id));
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All trim-fold checks passed.');
process.exit(0);
