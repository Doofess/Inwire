/**
 * Diffs Inwire's own dissection of the fixture captures against tshark's,
 * column by column, and holds each column to the floor recorded in
 * test/fixtures/acceptance.json. This is the acceptance gate for every phase of
 * docs/specs/inwire-network-decoding-spec-v3.md.
 *
 *   npx tsx scripts/parity/parity-check.ts                 # every fixture
 *   npx tsx scripts/parity/parity-check.ts inwire          # one, by name
 *   npx tsx scripts/parity/parity-check.ts --write-floors  # raise floors to today's numbers
 *
 * Ground truth comes from ./regen-ground-truth.sh (tshark, two-pass). Running
 * the real `PcapService.parseCaptureFile` here - rather than a reimplementation -
 * means this exercises the same code path the browser does.
 *
 * Mismatches are bucketed by tshark's Protocol so a phase can see which
 * dissector owns each gap, and the rows tshark marks as segments of a PDU
 * reassembled later get a bucket of their own: they are the one case with a
 * single cause (no record cursor across segments) and a single fix.
 *
 * The fixtures are personal captures and are not in git; a missing file is a
 * failure that says how to get it, not a silent skip (docs/decisions/0004).
 * Exit code is non-zero when any column is below its floor or any enforced
 * count is wrong, so the recurring gate can run it as a command.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import { ColorRulesEngine, WIRESHARK_DEFAULT_RULES } from '../../src/services/colorRules';
import type { Packet } from '../../src/types/packet';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', '..', 'test', 'fixtures');
const ACCEPTANCE = join(FIXTURES, 'acceptance.json');

// --- acceptance.json --------------------------------------------------------

export interface FixtureSpec {
  file: string;
  sha256: string;
  frames: number;
  /** Per-column minimum match percentage. Raised, never lowered, phase by phase. */
  floors: Record<string, number>;
  /** What tshark counts. Only the keys in `enforce` fail the run. */
  counts: Record<string, number>;
  enforce: string[];
}

export interface Acceptance {
  tshark: string;
  groundTruthFields: string[];
  fixtures: Record<string, FixtureSpec>;
}

// --- ground truth ------------------------------------------------------------

interface GroundTruthRow {
  number: number;
  timeRelative: string;
  source: string;
  destination: string;
  protocol: string;
  frameLen: string;
  reassembledIn: string;
  ja3: string;
  ja3s: string;
  ja4: string;
  info: string;
}

function loadGroundTruth(name: string): { rows: GroundTruthRow[]; colors: Map<number, string> } {
  const rows = readFileSync(join(FIXTURES, `${name}.psv`), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => {
      const [number, timeRelative, source, destination, protocol, frameLen, reassembledIn, ja3, ja3s, ja4, ...rest] = line.split('|');
      // Info legitimately contains '|' (display filters and some dissectors), so
      // everything after the 10th field is rejoined rather than treated as columns.
      return {
        number: Number(number), timeRelative, source, destination, protocol, frameLen,
        reassembledIn, ja3, ja3s, ja4, info: rest.join('|'),
      };
    });

  const colors = new Map<number, string>();
  for (const line of readFileSync(join(FIXTURES, `${name}-colors.psv`), 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const [number, rule] = line.split('|');
    colors.set(Number(number), rule ?? '');
  }
  return { rows, colors };
}

// --- columns -----------------------------------------------------------------

/** The Protocol column Inwire renders: the free-form label when a dissector
 *  set one, else the coarse ProtocolType. Mirrors what PacketList displays. */
function inwireProtocol(p: Packet): string {
  return p.protocolLabel ?? p.protocol;
}

interface ColumnSpec {
  name: string;
  ours: (p: Packet) => string;
  theirs: (r: GroundTruthRow) => string;
  /** Compare only rows where the reference has a value (fingerprints exist on hellos alone). */
  sparse?: boolean;
}

const field = (p: Packet, name: string) => String(p.fields?.[name] ?? '');

const COLUMNS: ColumnSpec[] = [
  { name: 'Protocol', ours: inwireProtocol, theirs: r => r.protocol },
  { name: 'Source', ours: p => p.source, theirs: r => r.source },
  { name: 'Destination', ours: p => p.destination, theirs: r => r.destination },
  {
    name: 'Time',
    // tshark always prints 9 decimals; compare numerically so a capture stored
    // at microsecond resolution isn't failed for printing 6.
    ours: p => Number(p.relativeTime).toFixed(9),
    theirs: r => Number(r.timeRelative).toFixed(9),
  },
  { name: 'Length', ours: p => String(p.length), theirs: r => r.frameLen },
  { name: 'Info', ours: p => p.info, theirs: r => r.info },
  { name: 'JA3', ours: p => field(p, 'tls.handshake.ja3'), theirs: r => r.ja3, sparse: true },
  { name: 'JA3S', ours: p => field(p, 'tls.handshake.ja3s'), theirs: r => r.ja3s, sparse: true },
  { name: 'JA4', ours: p => field(p, 'tls.handshake.ja4'), theirs: r => r.ja4, sparse: true },
];

// --- counts the app can compute ---------------------------------------------

const has = (p: Packet, flag: string) => (p.analysisFlags ?? []).includes(flag);

const COUNTERS: Record<string, (packets: Packet[]) => number> = {
  frames: ps => ps.length,
  quicRows: ps => ps.filter(p => inwireProtocol(p) === 'QUIC').length,
  tcpRst: ps => ps.filter(p => p.fields?.['tcp.flags.reset'] === 1).length,
  tcpClientHelloSni: ps => ps.filter(p => (p.frameProtocols ?? []).includes('tcp') && /Client Hello \(SNI=/.test(p.info)).length,
  // The field, not the Info line: tshark does not put a QUIC connection's
  // server name in the packet-list column, and neither do we.
  quicClientHelloSni: ps => ps.filter(p => inwireProtocol(p) === 'QUIC' && p.fields?.['tls.handshake.extensions_server_name'] !== undefined).length,
  // tshark's tcp.analysis.retransmission is set on the fast and spurious kinds too.
  retransmission: ps => ps.filter(p => has(p, 'retransmission') || has(p, 'fast_retransmission') || has(p, 'spurious_retransmission')).length,
  dupAck: ps => ps.filter(p => has(p, 'duplicate_ack')).length,
  outOfOrder: ps => ps.filter(p => has(p, 'out_of_order')).length,
  lostSegment: ps => ps.filter(p => has(p, 'lost_segment')).length,
};

// --- the run -----------------------------------------------------------------

interface ColumnResult { name: string; pct: number; mismatches: number; compared: number }

async function checkFixture(name: string, spec: FixtureSpec, maxDiffs: number): Promise<{
  columns: ColumnResult[];
  counts: Record<string, number>;
  failures: string[];
}> {
  const failures: string[] = [];
  const capturePath = join(FIXTURES, spec.file);
  if (!existsSync(capturePath)) {
    failures.push(`fixture file missing: ${capturePath} (see test/fixtures/README.md)`);
    return { columns: [], counts: {}, failures };
  }
  if (!existsSync(join(FIXTURES, `${name}.psv`))) {
    failures.push(`ground truth missing for ${name}: run ./scripts/parity/regen-ground-truth.sh ${name}`);
    return { columns: [], counts: {}, failures };
  }

  const { rows, colors } = loadGroundTruth(name);
  const bytes = readFileSync(capturePath);
  const file = new File([bytes], spec.file);
  const t0 = performance.now();
  const { packets, totalFrames } = await PcapService.parseCaptureFile(file);
  const ms = performance.now() - t0;

  console.log(`\n=== ${name}: ${spec.file}`);
  console.log(`reference ${rows.length} frames, inwire ${packets.length} of ${totalFrames} in ${ms.toFixed(0)} ms (${(packets.length / ms * 1000).toFixed(0)} pkt/s)`);

  if (packets.length !== rows.length) {
    failures.push(`${name}: frame count ${packets.length} != reference ${rows.length}; every other column is meaningless until this is fixed`);
    return { columns: [], counts: {}, failures };
  }

  const columns: ColumnResult[] = [];
  for (const column of COLUMNS) {
    const byBucket = new Map<string, number>();
    const samples = new Map<string, string[]>();
    let mismatches = 0;
    let compared = 0;
    for (let i = 0; i < rows.length; i++) {
      const theirs = column.theirs(rows[i]);
      if (column.sparse && theirs === '') continue;
      compared++;
      const ours = column.ours(packets[i]);
      if (ours === theirs) continue;
      mismatches++;
      const bucket = rows[i].reassembledIn ? 'TCP (segment of reassembled PDU)' : rows[i].protocol;
      byBucket.set(bucket, (byBucket.get(bucket) ?? 0) + 1);
      const s = samples.get(bucket) ?? [];
      if (s.length < maxDiffs) {
        s.push(`      #${rows[i].number}\n        reference: ${theirs}\n        inwire:    ${ours}`);
        samples.set(bucket, s);
      }
    }
    if (compared === 0) continue; // nothing in the reference to hold this column to
    const pct = ((compared - mismatches) / compared) * 100;
    columns.push({ name: column.name, pct, mismatches, compared });
    if (mismatches > 0) {
      console.log(`\n--- ${column.name}: ${mismatches} mismatch(es) of ${compared}, ${pct.toFixed(2)}% match ---`);
      for (const [bucket, n] of [...byBucket.entries()].sort((a, b) => b[1] - a[1])) {
        console.log(`  ${bucket.padEnd(34)} ${n}`);
        for (const sample of samples.get(bucket) ?? []) console.log(sample);
      }
    }
  }

  // Colouring: the packets back through the rule chain the UI uses, so a rule
  // reordering or a filter-engine regression shows up here, not only on screen.
  // Wireshark's own chain, not the one the app ships. The app adds three bands
  // Wireshark has no equivalent for (Expert Warnings, TLS Handshake, QUIC), and
  // this column measures whether our filter engine and dissectors reach
  // Wireshark's colouring DECISIONS - which needs Wireshark's rules on both
  // sides. See INWIRE_EXTRA_RULES.
  const engine = new ColorRulesEngine(WIRESHARK_DEFAULT_RULES);
  const colorBuckets = new Map<string, number>();
  let colorMismatches = 0;
  for (let i = 0; i < rows.length; i++) {
    const theirs = colors.get(rows[i].number) ?? '';
    const ours = engine.getMatchedRuleName(packets[i]) ?? '';
    if (ours === theirs) continue;
    colorMismatches++;
    const key = `${theirs || '(no rule)'} -> ${ours || '(no rule)'}`;
    colorBuckets.set(key, (colorBuckets.get(key) ?? 0) + 1);
  }
  const colorPct = ((rows.length - colorMismatches) / rows.length) * 100;
  columns.push({ name: 'Color rule', pct: colorPct, mismatches: colorMismatches, compared: rows.length });
  if (colorMismatches > 0) {
    console.log(`\n--- Color rule: ${colorMismatches} mismatch(es), ${colorPct.toFixed(2)}% match ---`);
    for (const [key, n] of [...colorBuckets.entries()].sort((a, b) => b[1] - a[1]).slice(0, maxDiffs)) {
      console.log(`  ${String(n).padStart(6)}  ${key}`);
    }
  }

  const counts: Record<string, number> = {};
  for (const [key, fn] of Object.entries(COUNTERS)) counts[key] = fn(packets);

  console.log('\n--- columns vs floors ---');
  for (const c of columns) {
    const floor = spec.floors[c.name] ?? 0;
    const ok = c.pct + 1e-9 >= floor;
    if (!ok) failures.push(`${name}: ${c.name} ${c.pct.toFixed(2)}% is below its floor ${floor}%`);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name.padEnd(12)} ${c.pct.toFixed(2).padStart(6)}%  (floor ${floor}%)  ${c.compared - c.mismatches}/${c.compared}`);
  }
  console.log('\n--- counts (tshark reference | inwire) ---');
  for (const [key, expected] of Object.entries(spec.counts)) {
    const actual = counts[key];
    const enforced = spec.enforce.includes(key);
    const ok = actual === expected;
    if (enforced && !ok) failures.push(`${name}: ${key} = ${actual}, tshark says ${expected}`);
    const mark = actual === undefined ? '  - ' : ok ? 'PASS' : enforced ? 'FAIL' : 'gap ';
    console.log(`${mark}  ${key.padEnd(20)} ${String(expected).padStart(6)} | ${String(actual ?? 'n/a').padStart(6)}${enforced ? '' : '   (not enforced yet)'}`);
  }

  return { columns, counts, failures };
}

async function main() {
  const args = process.argv.slice(2);
  const writeFloors = args.includes('--write-floors');
  const names = args.filter(a => !a.startsWith('--'));
  const maxDiffs = process.env.PARITY_MAX_DIFFS === undefined ? 3 : Number(process.env.PARITY_MAX_DIFFS);

  const acceptance = JSON.parse(readFileSync(ACCEPTANCE, 'utf8')) as Acceptance;
  const selected = Object.entries(acceptance.fixtures).filter(([n]) => names.length === 0 || names.includes(n));
  if (selected.length === 0) {
    console.error(`no fixture named ${names.join(', ')}; known: ${Object.keys(acceptance.fixtures).join(', ')}`);
    process.exit(1);
  }

  const allFailures: string[] = [];
  for (const [name, spec] of selected) {
    const result = await checkFixture(name, spec, maxDiffs);
    allFailures.push(...result.failures);
    if (writeFloors && result.columns.length > 0) {
      // Floors are recorded one decimal below the measured value, rounded
      // down, so a rerun on the same code is never a failure by float noise.
      for (const c of result.columns) spec.floors[c.name] = Math.floor(c.pct * 10) / 10;
    }
  }

  if (writeFloors) {
    writeFileSync(ACCEPTANCE, JSON.stringify(acceptance, null, 2) + '\n');
    console.log(`\nfloors written to ${ACCEPTANCE}`);
  }

  console.log('\n=== SUMMARY ===');
  if (allFailures.length === 0) {
    console.log('PASS  every column at or above its floor; every enforced count matches');
    process.exit(0);
  }
  for (const f of allFailures) console.log(`FAIL  ${f}`);
  process.exit(1);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
