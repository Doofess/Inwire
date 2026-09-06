/**
 * Where this build and tshark disagree about TCP PDU boundaries.
 *
 *   npx tsx scripts/tcp/reassembly.ts             # both fixtures
 *   npx tsx scripts/tcp/reassembly.ts netview     # one
 *   npx tsx scripts/tcp/reassembly.ts netview 4   # ...and show 4 connections
 *
 * `parity-check.ts` reports *that* 861 of 883 remaining Info mismatches are
 * reassembly. It cannot say *why*, because it compares frames independently and
 * a boundary error is not a property of one frame - it is a property of a
 * stream, and it propagates: one misplaced record boundary makes every
 * subsequent segment in that direction wrong until something resynchronises.
 * So the mismatch list is mostly echoes, and reading it frame by frame invites
 * exactly the mistake made once already here - fixing a symptom, measured at
 * 16 frames fixed and 29 broken.
 *
 * This finds the **first** divergence in each connection instead, which is the
 * only frame in it that carries information. Everything after is consequence.
 *
 * `tcp.reassembled_in` is already a ground-truth column (acceptance.json), so
 * tshark's view needs no new capture: a value means "this frame is a segment of
 * a PDU that completes in frame N". Ours is read back out of the Info column,
 * which is deliberate - it is the string a user reads, so a disagreement here
 * is a disagreement they would see.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', '..', 'test', 'fixtures');

interface Row { number: number; protocol: string; reassembledIn: string; info: string }

/**
 * Whether the frame's Info column agrees, which is a **different question**
 * from whether the two agree about reassembly - and keeping them apart is the
 * point of this script.
 *
 * tshark records `tcp.reassembled_in` on a frame whose Info it prints as a
 * plain `Application Data`, with no `[TCP PDU reassembled in N]` suffix at all.
 * So a frame can disagree about reassembly while its Info matches exactly.
 * Acting on those - which was one edit away from happening - would have moved
 * the field into agreement and broken the column a user actually reads.
 *
 * The actionable set is the intersection: reassembly disagrees AND Info
 * disagrees. Everything else is either invisible or somebody else's bug.
 */

function loadGroundTruth(name: string): Row[] {
  return readFileSync(join(FIXTURES, `${name}.psv`), 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => {
      const f = line.split('|');
      // Info legitimately contains '|', so everything past the 10th field is rejoined.
      return { number: Number(f[0]), protocol: f[4], reassembledIn: f[6], info: f.slice(10).join('|') };
    });
}

/** The frame this build says a segment's PDU completes in, or 0 for none. */
function oursCompletesIn(packet: Packet): number {
  const m = /\[TCP PDU reassembled in (\d+)\]/.exec(packet.info);
  return m ? Number(m[1]) : 0;
}

/** The frame tshark says it completes in, or 0. */
function theirsCompletesIn(row: Row): number {
  const n = Number(row.reassembledIn.trim());
  return Number.isInteger(n) && n > 0 ? n : 0;
}

type Verdict = 'agree-none' | 'agree-same' | 'agree-different' | 'ours-only' | 'theirs-only';

function verdictOf(ours: number, theirs: number): Verdict {
  if (ours === 0 && theirs === 0) return 'agree-none';
  if (ours === 0) return 'theirs-only';
  if (theirs === 0) return 'ours-only';
  return ours === theirs ? 'agree-same' : 'agree-different';
}

const IGNORED_UNKNOWN = 'Ignored Unknown Record';
const REASSEMBLY_TAG = / \[TCP PDU reassembled in \d+\]/;
const TCP_TAG = /\[TCP [^\]]+\]/g;

/**
 * Why one frame's Info differs, in terms of the decision that produced it.
 *
 * The counts this yields are the reason the work is shaped the way it is. It
 * was assumed - in ADR 0020 and in the plan this script came from - that the
 * remaining gap was one problem. It is close to one *area* and it is not one
 * problem: the dominant failure is **over-claiming**, emitting
 * `Ignored Unknown Record` on a stream where the reference analyzer declines to
 * claim TLS at all, which is the opposite direction from the one assumed.
 *
 * The last three categories are not reassembly and never were. They are here
 * because they were found by looking, and a classifier that quietly folded them
 * into the reassembly bucket would keep them hidden.
 */
function classify(theirs: string, ours: string): string {
  // Identical once the suffix is removed => only the boundary tag differs.
  if (theirs.replace(REASSEMBLY_TAG, '') === ours.replace(REASSEMBLY_TAG, '')) {
    return 'reassembly tag only';
  }
  const theirsLost = theirs.includes(IGNORED_UNKNOWN);
  const oursLost = ours.includes(IGNORED_UNKNOWN);
  if (theirsLost && oursLost) return 'both lost (differ inside a desynchronised region)';
  if (theirsLost !== oursLost) {
    return theirsLost ? 'tshark claims TLS, we show TCP' : 'we claim TLS, tshark shows TCP';
  }
  const theirTags = (theirs.match(TCP_TAG) ?? []).join(',');
  const ourTags = (ours.match(TCP_TAG) ?? []).join(',');
  if (theirTags !== ourTags) return 'TCP analysis tags differ';
  if (/no response found/.test(theirs) !== /no response found/.test(ours)) {
    return 'ICMP response pairing';
  }
  return 'other';
}

/** Trims an Info line to something that fits a terminal without losing the tail. */
function brief(text: string, width = 96): string {
  if (text.length <= width) return text;
  return `${text.slice(0, width - 14)} … ${text.slice(-11)}`;
}

async function report(name: string, showConnections: number): Promise<void> {
  const spec = JSON.parse(readFileSync(join(FIXTURES, 'acceptance.json'), 'utf8'))
    .fixtures[name] as { file: string } | undefined;
  if (!spec) { console.log(`unknown fixture "${name}"`); return; }
  const capture = join(FIXTURES, spec.file);
  if (!existsSync(capture) || !existsSync(join(FIXTURES, `${name}.psv`))) {
    console.log(`SKIP  ${name} - fixture or ground truth not present (test/fixtures/README.md)`);
    return;
  }

  const rows = loadGroundTruth(name);
  const { packets } = await PcapService.parseCaptureFile(
    new File([readFileSync(capture)], spec.file));

  console.log(`\n=== ${name}: ${packets.length} frames`);
  if (packets.length !== rows.length) {
    console.log(`  frame counts differ (${packets.length} vs ${rows.length}); comparing the overlap`);
  }

  const tally = new Map<Verdict, number>();
  const tallyVisible = new Map<Verdict, number>();
  // Keyed by this build's stream index, which is what makes "first divergence"
  // meaningful: a boundary error belongs to one direction of one conversation.
  const byStream = new Map<number, { frame: number; verdict: Verdict; ours: number; theirs: number }[]>();

  const n = Math.min(packets.length, rows.length);
  for (let i = 0; i < n; i++) {
    const packet = packets[i];
    const row = rows[i];
    const ours = oursCompletesIn(packet);
    const theirs = theirsCompletesIn(row);
    const verdict = verdictOf(ours, theirs);
    const infoAgrees = packet.info === row.info;
    tally.set(verdict, (tally.get(verdict) ?? 0) + 1);
    if (!infoAgrees) tallyVisible.set(verdict, (tallyVisible.get(verdict) ?? 0) + 1);
    // Only a frame whose Info ALSO disagrees is worth chasing - see the note on
    // `Row`. A reassembly difference nobody can see is not a defect to fix.
    if (infoAgrees) continue;
    const stream = packet.streamId ?? -1;
    const list = byStream.get(stream) ?? [];
    list.push({ frame: packet.id, verdict, ours, theirs });
    byStream.set(stream, list);
  }

  const ORDER: Verdict[] = ['agree-none', 'agree-same', 'agree-different', 'ours-only', 'theirs-only'];
  const LABEL: Record<Verdict, string> = {
    'agree-none': 'both say: not a mid-PDU segment',
    'agree-same': 'both say: mid-PDU, completing in the same frame',
    'agree-different': 'both say: mid-PDU - but DIFFERENT completing frames',
    'ours-only': 'we claim a PDU tshark does not',
    'theirs-only': 'tshark claims a PDU we do not',
  };
  console.log();
  console.log(`  ${''.padEnd(52)} ${'all'.padStart(6)}  ${'Info differs too'.padStart(16)}`);
  for (const v of ORDER) {
    const count = tally.get(v) ?? 0;
    const visible = tallyVisible.get(v) ?? 0;
    console.log(`  ${LABEL[v].padEnd(52)} ${String(count).padStart(6)}  ${String(visible).padStart(16)}`);
  }
  // What the divergence is actually made of. This is the number that should
  // decide what gets built.
  const causes = new Map<string, number>();
  let mismatches = 0;
  for (let i = 0; i < n; i++) {
    if (packets[i].info === rows[i].info) continue;
    mismatches++;
    const cause = classify(rows[i].info, packets[i].info);
    causes.set(cause, (causes.get(cause) ?? 0) + 1);
  }
  console.log(`
  All ${mismatches} Info mismatches, by the decision that produced them:`);
  for (const [cause, count] of [...causes.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`   ${String(count).padStart(5)}  ${(100 * count / mismatches).toFixed(1).padStart(5)}%  ${cause}`);
  }

  const visibleTotal = [...tallyVisible.values()].reduce((a, b) => a + b, 0);
  console.log(`
  Frames where reassembly AND Info both disagree: ${visibleTotal}`);
  console.log('  (that is the actionable set; the rest is invisible to a reader)');

  const divergent = [...byStream.entries()]
    .map(([stream, list]) => ({ stream, list, first: list[0].frame }))
    .sort((a, b) => b.list.length - a.list.length);
  console.log(`\n  ${divergent.length} connection(s) diverge; worst by frame count:\n`);

  const byId = new Map(packets.map(p => [p.id, p]));
  const rowById = new Map(rows.map(r => [r.number, r]));
  for (const { stream, list, first } of divergent.slice(0, showConnections)) {
    const seed = byId.get(first);
    console.log(`  --- stream ${stream}: ${list.length} divergent frames, first at #${first}`);
    console.log(`      ${seed?.source}:${seed?.sourcePort} <-> ${seed?.destination}:${seed?.destPort}`);
    // The frames leading up to the first divergence are what explain it: the
    // boundary was decided earlier, by whichever frame last agreed.
    const context = packets
      .filter(p => (p.streamId ?? -1) === stream && p.id <= first)
      .slice(-CONTEXT_FRAMES);
    for (const p of context) {
      const row = rowById.get(p.id);
      const ours = oursCompletesIn(p);
      const theirs = row ? theirsCompletesIn(row) : 0;
      const mark = p.id === first ? '>>' : '  ';
      console.log(`      ${mark} #${String(p.id).padStart(6)}  ${(row?.protocol ?? '?').padEnd(9)}`
        + ` ours=${ours || '-'} theirs=${theirs || '-'}`);
      console.log(`            tshark: ${brief(row?.info ?? '')}`);
      console.log(`            inwire: ${brief(p.info)}`);
    }
    console.log();
  }
}

/** How many frames of run-up to print before the first divergence. */
const CONTEXT_FRAMES = 6;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const named = args.filter(a => !/^\d+$/.test(a));
  const count = Number(args.find(a => /^\d+$/.test(a)) ?? 2);
  const names = named.length > 0 ? named : ['inwire', 'netview'];
  for (const name of names) await report(name, count);
  process.exit(0);
}

main();
