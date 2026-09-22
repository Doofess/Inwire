/**
 * Diffs one abbrev cluster against the reference, by frame AND by value.
 *
 *   npx tsx scripts/parity/cluster-diff.ts <pcap> <abbrev-prefix> [display-filter]
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
 * Two things it gets right that a naive version does not:
 *
 * - **It compares PDML's `show`.** For an FT_BYTES field `show` is colon
 *   separated hex, `showname` is unseparated, and `-T fields` is the raw value.
 *   Reading the wrong one turned 1,785 matching `data.data` values into
 *   apparent mismatches once.
 * - **It compares (frame, value) as a set**, not a join on frame number. An
 *   abbrev that appears twice in one frame - `ip.host`, say - turns a join into
 *   a cross product and reports every row as both matching and differing.
 *
 * Not a test: it measures one cluster the caller names, and has no pass mark of
 * its own. `scripts/check.ts` lists it as skipped.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

const TSHARK = 'C:/Program Files/Wireshark/tshark.exe';
const [, , pcapPath, prefix, filter] = process.argv;
if (pcapPath === undefined || prefix === undefined) {
  console.log('usage: npx tsx scripts/parity/cluster-diff.ts <pcap> <abbrev-prefix> [display-filter]');
  process.exit(2);
}

// --- theirs, from PDML -------------------------------------------------------
// A whole fixture's PDML can exceed Node's maximum string length, so a
// display filter narrows it to the frames that carry the cluster. Frames
// with none of these fields contribute nothing on either side, so the
// comparison is unaffected.
const pdml = execFileSync(TSHARK,
  ['-r', pcapPath, '-T', 'pdml', ...(filter ? ['-Y', filter] : [])], {
  encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024,
});

const theirs = new Map<string, Set<string>>();
let frame = 0;
for (const line of pdml.split('\n')) {
  const num = /<field name="frame\.number" .*?show="(\d+)"/.exec(line);
  if (num) frame = Number(num[1]);
  const m = /<field name="([^"]*)"[^>]*?\sshow="([^"]*)"/.exec(line);
  if (!m) continue;
  const [, abbrev, show] = m;
  if (!abbrev.startsWith(prefix)) continue;
  if (!theirs.has(abbrev)) theirs.set(abbrev, new Set());
  theirs.get(abbrev)!.add(`${frame}\u0000${show}`);
}

// --- ours --------------------------------------------------------------------
const { packets } = await PcapService.parseCaptureFile(
  // The third argument builds the protocol tree. Without it `packet.layers` is
  // undefined - trees are dissected on demand by replay - and every abbrev
  // below reads as absent from our side.
  new File([readFileSync(pcapPath)], 'fixture.pcap'), undefined, true);

const ours = new Map<string, Set<string>>();
const walk = (fields: readonly ProtocolField[], id: number): void => {
  for (const f of fields) {
    if (f.abbrev !== undefined && f.abbrev.startsWith(prefix)) {
      if (!ours.has(f.abbrev)) ours.set(f.abbrev, new Set());
      ours.get(f.abbrev)!.add(`${id}\u0000${String(f.value)}`);
    }
    if (f.children !== undefined) walk(f.children, id);
  }
};
for (const p of packets) for (const layer of p.layers ?? []) walk(layer.fields, p.id);

// --- the diff ----------------------------------------------------------------
const names = [...new Set([...theirs.keys(), ...ours.keys()])].sort();
let bad = 0;
console.log(`${'abbrev'.padEnd(58)} theirs  ours  only-theirs only-ours`);
for (const name of names) {
  const t = theirs.get(name) ?? new Set<string>();
  const o = ours.get(name) ?? new Set<string>();
  const onlyT = [...t].filter((x) => !o.has(x));
  const onlyO = [...o].filter((x) => !t.has(x));
  if (onlyT.length || onlyO.length) bad++;
  console.log(
    `${name.padEnd(58)} ${String(t.size).padStart(6)} ${String(o.size).padStart(5)} `
    + `${String(onlyT.length).padStart(11)} ${String(onlyO.length).padStart(9)}`);
  for (const x of onlyT.slice(0, 3)) console.log(`      only theirs: frame ${x.replace('\u0000', ' -> ')}`);
  for (const x of onlyO.slice(0, 3)) console.log(`      only ours  : frame ${x.replace('\u0000', ' -> ')}`);
}
console.log(bad === 0
  ? `\nEXACT: every (frame, value) pair matches for ${names.length} abbrev(s).`
  : `\n${bad} abbrev(s) differ.`);
