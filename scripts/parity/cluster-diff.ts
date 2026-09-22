/**
 * Diffs one abbrev cluster against the reference, by frame AND by value.
 *
 *   npx tsx scripts/parity/cluster-diff.ts <pcap> <abbrev-prefix>
 *
 * This exists because an abbrev count cannot tell a correct body from a wrongly
 * offset one: a cluster reaches 100% of the reference's vocabulary just as
 * happily reading every field at the wrong offset. What settles it is comparing
 * the *values*, per frame, against the reference's own.
 *
 * `tree-coverage.ts` reports how many abbrevs differ but caps its listing at
 * twenty entries whatever `--top` says - so reading that list for a cluster's
 * absence proves nothing, and two commit messages have been corrected after
 * somebody did. This answers the question directly for one prefix.
 *
 * Four things it gets right that a naive version does not:
 *
 * - **It compares PDML's `show`.** For an FT_BYTES field `show` is colon
 *   separated hex, `showname` is unseparated, and `-T fields` is the raw value.
 *   Reading the wrong one turned 1,785 matching `data.data` values into
 *   apparent mismatches once.
 * - **It compares (frame, value) as a set**, not a join on frame number. An
 *   abbrev that appears twice in one frame - `ip.host`, say - turns a join into
 *   a cross product and reports every row as both matching and differing.
 * - **It runs tshark two-pass**, like `tree-coverage.ts` and
 *   `regen-ground-truth.sh`. The GUI is two-pass and is what this build is
 *   matched against; single-pass answers differ for anything that depends on a
 *   later frame. `tls.segment.data` is on 102 frames single-pass and 67
 *   two-pass, and a diff run in the wrong mode reports 35 phantom misses.
 * - **It streams the PDML and takes no display filter.** A whole fixture's PDML
 *   is larger than Node's maximum string, which invites a `-Y` to cut it down -
 *   and a filter restricts the REFERENCE's frames while this build still
 *   dissects all of them, so every frame outside the filter lands in
 *   "only ours". That reads as mass over-emission when the cluster is fine, or
 *   hides real over-emission behind an excuse. It cost a wrong conclusion once:
 *   a `tls.segment.data` on 1,339 frames of `bulk` against the reference's 2
 *   was first read as a filter artifact. So the filter is gone and the reader
 *   is line by line.
 *
 * Not a test: it measures one cluster the caller names, and has no pass mark of
 * its own. `scripts/check.ts` lists it as skipped.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

const TSHARK_CANDIDATES = [
  'tshark',
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe',
  '/usr/bin/tshark',
  '/usr/local/bin/tshark',
  '/opt/homebrew/bin/tshark',
];

const [, , pcapPath, prefix] = process.argv;
if (pcapPath === undefined || prefix === undefined) {
  console.log('usage: npx tsx scripts/parity/cluster-diff.ts <pcap> <abbrev-prefix>');
  process.exit(2);
}

// Probed rather than tested for existence: the bare name is first so a PATH
// install wins, and only actually running it proves the name resolves.
const tshark = TSHARK_CANDIDATES.find((c) => spawnSync(c, ['-v'], { shell: false }).status === 0);
if (tshark === undefined) {
  console.log('tshark not found; set one of the paths in TSHARK_CANDIDATES.');
  process.exit(2);
}

/** One `abbrev -> set of "<frame>\0<value>"`, for both sides. */
type Seen = Map<string, Set<string>>;
const add = (into: Seen, abbrev: string, frame: number, value: string): void => {
  let set = into.get(abbrev);
  if (set === undefined) { set = new Set(); into.set(abbrev, set); }
  set.add(`${frame}\u0000${value}`);
};

// --- theirs, streamed ---------------------------------------------------------
const theirs: Seen = new Map();
await new Promise<void>((resolve, reject) => {
  const child = spawn(tshark, ['-2', '-T', 'pdml', '-r', pcapPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => { stderr += chunk; });

  let frame = 0;
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const num = /<field name="frame\.number" .*?show="(\d+)"/.exec(line);
    if (num) frame = Number(num[1]);
    const m = /<field name="([^"]*)"[^>]*?\sshow="([^"]*)"/.exec(line);
    if (m && m[1].startsWith(prefix)) add(theirs, m[1], frame, m[2]);
  });
  child.on('error', reject);
  child.on('close', (code) => {
    if (code !== 0) { reject(new Error(`tshark exited ${code}: ${stderr.trim()}`)); return; }
    lines.close();
    resolve();
  });
});

// --- ours ---------------------------------------------------------------------
const { packets } = await PcapService.parseCaptureFile(
  // The third argument builds the protocol tree. Without it `packet.layers` is
  // undefined - trees are dissected on demand by replay - and every abbrev
  // below reads as absent from our side.
  new File([readFileSync(pcapPath)], 'fixture.pcap'), undefined, true);

const ours: Seen = new Map();
const walk = (fields: readonly ProtocolField[], id: number): void => {
  for (const f of fields) {
    if (f.abbrev !== undefined && f.abbrev.startsWith(prefix)) add(ours, f.abbrev, id, String(f.value));
    if (f.children !== undefined) walk(f.children, id);
  }
};
for (const p of packets) for (const layer of p.layers ?? []) walk(layer.fields, p.id);

// --- the diff -----------------------------------------------------------------
const names = [...new Set([...theirs.keys(), ...ours.keys()])].sort();
const frameCount = (set: Set<string>): number =>
  new Set([...set].map((x) => x.slice(0, x.indexOf('\u0000')))).size;

let bad = 0;
console.log(`${'abbrev'.padEnd(58)} theirs  ours  only-theirs only-ours`);
for (const name of names) {
  const t = theirs.get(name) ?? new Set<string>();
  const o = ours.get(name) ?? new Set<string>();
  const onlyT = [...t].filter((x) => !o.has(x));
  const onlyO = [...o].filter((x) => !t.has(x));
  if (onlyT.length || onlyO.length) bad++;
  console.log(
    `${name.padEnd(58)} ${String(frameCount(t)).padStart(6)} ${String(frameCount(o)).padStart(5)} `
    + `${String(onlyT.length).padStart(11)} ${String(onlyO.length).padStart(9)}`);
  // Values can be kilobytes of hex; the frame number is what a reader chases.
  const sample = (label: string, rows: string[]): void => {
    for (const row of rows.slice(0, 3)) {
      const at = row.indexOf('\u0000');
      const value = row.slice(at + 1);
      console.log(`      ${label}: frame ${row.slice(0, at)} -> `
        + (value.length > 60 ? `${value.slice(0, 60)}... (${value.length} chars)` : value));
    }
    if (rows.length > 3) console.log(`      ${label}: ...and ${rows.length - 3} more`);
  };
  sample('only theirs', onlyT);
  sample('only ours  ', onlyO);
}
console.log(bad === 0
  ? `\nEXACT: every (frame, value) pair matches for ${names.length} abbrev(s).`
  : `\n${bad} abbrev(s) differ.`);
