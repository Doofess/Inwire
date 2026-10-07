/**
 * The Frame layer of the tree, row by row, against the reference.
 *
 *   npx tsx scripts/parity/frame-layer.ts
 *
 * Every other layer of the tree has been measured against tshark since ADR
 * 0039. The Frame layer had not: `tree-coverage.ts` exempted `frame.*`, its
 * rows carried no field names, and it could drift without a number moving.
 * Two things had:
 * - **Its arrival times dropped the nanoseconds** the capture measured (ADR
 *   0050), padding every stamp with `000` while the meta rail beside it showed
 *   the real digits.
 * - **`Protocols in frame` read `frame:eth:ip:tcp`** where Wireshark reads
 *   `eth:ethertype:ip:tcp`, and the `frame.protocols` filter matched the same
 *   wrong string.
 *
 * `tree-coverage.ts` now measures the layer's names on the two classic-pcap
 * fixtures, which are microsecond captures and so cannot see the first defect
 * at all. This runs on the key-log fixture instead: a pcapng the agent wrote,
 * stamped to the 100 ns. Every frame's time, length, protocol list and delta
 * is compared with tshark's own for the same frame - times as numbers and as
 * the text up to the zone name, because the zone is spelled by the operating
 * system's ICU data on one side and Wireshark's on the other.
 *
 * Skips cleanly without the fixture (`test/fixtures/README.md`) or tshark.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { PcapService } from '../../src/services/pcapParser';
import { findWiresharkTool, OPTIONAL_CAPTURES } from '../export/realCaptures';
import type { ProtocolField, ProtocolLayer } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}
function skip(reason: string): never {
  console.log(`SKIP  ${reason}`);
  process.exit(0);
}

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test', 'fixtures');
const keylog = Object.values(OPTIONAL_CAPTURES).map((f) => path.join(fixtures, f)).find((f) => /keylog.*\.pcapng$/.test(f));
if (keylog === undefined || !existsSync(keylog)) skip('the key-log fixture is not present (test/fixtures/README.md)');
const tshark = findWiresharkTool('tshark');
if (tshark === null) skip('tshark not found');

// --- the reference: every frame.* row, by name ---------------------------------

const pdml = spawnSync(tshark, ['-r', keylog, '-T', 'pdml', '-j', 'frame'], { encoding: 'utf8', maxBuffer: 1 << 30 });
const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
const theirs = pdml.stdout.split('<packet>').slice(1).map((packet) => {
  const rows = new Map<string, { show: string; shown: string }>();
  for (const m of packet.matchAll(/<field name="(frame\.[a-z_.]+)" showname="([^"]*)"[^>]*? show="([^"]*)"/g)) {
    if (!rows.has(m[1])) rows.set(m[1], { shown: unescape(m[2]).replace(/^[^:]*: /, ''), show: unescape(m[3]) });
  }
  return rows;
});

// --- this build ------------------------------------------------------------------

const { packets } = await PcapService.parseCaptureFile(
  new File([readFileSync(keylog)], path.basename(keylog)), Number.POSITIVE_INFINITY, true);
check(`every frame dissected, as many as the reference read (${packets.length})`, packets.length === theirs.length);

function frameRows(layers: readonly ProtocolLayer[]): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev !== undefined && !out.has(f.abbrev)) out.set(f.abbrev, String(f.value));
      if (f.children) walk(f.children);
    }
  };
  if (layers[0]?.name === 'Frame') walk(layers[0].fields);
  return out;
}

/** Up to the zone name: `Sep 26, 2026 23:42:10.736581400`. */
const beforeZone = (text: string) => /^\w{3} +\d+, \d{4} \d{2}:\d{2}:\d{2}\.\d{9}/.exec(text)?.[0] ?? text;
const seconds = (text: string) => Number(text.replace(/ seconds$/, ''));

interface Rule { abbrev: string; same: (ours: string, ref: { show: string; shown: string }) => boolean }
const RULES: Rule[] = [
  { abbrev: 'frame.number', same: (o, r) => o === r.show },
  { abbrev: 'frame.len', same: (o, r) => o === r.shown },
  { abbrev: 'frame.cap_len', same: (o, r) => o === r.shown },
  { abbrev: 'frame.encap_type', same: (o, r) => o === r.shown },
  { abbrev: 'frame.time_epoch', same: (o, r) => o === r.show },
  { abbrev: 'frame.time', same: (o, r) => beforeZone(o) === beforeZone(r.shown) },
  { abbrev: 'frame.time_utc', same: (o, r) => o === r.shown },
  // Compared as numbers: the reference prints 62.788400 milliseconds where
  // this build prints 0.062788400 seconds, and the value is what is at stake.
  { abbrev: 'frame.time_relative', same: (o, r) => Math.abs(seconds(o) - Number(r.show)) < 1e-9 },
  { abbrev: 'frame.time_delta', same: (o, r) => Math.abs(seconds(o) - Number(r.show)) < 1e-9 },
  { abbrev: 'frame.protocols', same: (o, r) => o === r.show },
];

for (const rule of RULES) {
  let compared = 0;
  let missing = 0;
  const differ: string[] = [];
  packets.forEach((packet, i) => {
    const ref = theirs[i]?.get(rule.abbrev);
    const ours = frameRows(packet.layers ?? []).get(rule.abbrev);
    if (ref === undefined) {
      if (ours !== undefined && differ.length < 3) differ.push(`frame ${i + 1}: this build has "${ours}", the reference no row`);
      if (ours !== undefined) missing++;
      return;
    }
    compared++;
    if (ours === undefined) { missing++; if (differ.length < 3) differ.push(`frame ${i + 1}: no row`); return; }
    if (!rule.same(ours, ref)) differ.push(`frame ${i + 1}: this build "${ours}", the reference "${ref.shown}" (${ref.show})`);
  });
  const wrong = differ.length;
  if (rule.abbrev === 'frame.protocols') {
    // The token list is the dissectors' own, and a few protocols name their
    // layers differently from the reference (`tls:tls` for two records in one
    // segment). Held to a share rather than to every frame.
    const agree = compared - wrong - missing;
    check(`${rule.abbrev}: ${agree} of ${compared} frames list their protocols as the reference does`,
      agree / Math.max(1, compared) >= 0.9, differ.slice(0, 3).join('\n        '));
  } else {
    check(`${rule.abbrev}: every row matches the reference (${compared} frames)`, wrong === 0 && missing === 0,
      differ.slice(0, 3).join('\n        '));
  }
}

const sub = packets.filter((p) => !String(frameRows(p.layers ?? []).get('frame.time_epoch')).endsWith('000')).length;
check(`the arrival times carry the capture's nanoseconds (${sub} of ${packets.length} have digits past the microsecond)`,
  sub > packets.length / 2);

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All Frame-layer checks passed.');
process.exit(0);
