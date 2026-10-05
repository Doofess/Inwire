/**
 * IPv4 options, row for row against the reference.
 *
 *   npx tsx scripts/parity/ipv4-options.ts
 *
 * Options were decoded and drawn under names of this build's own, with no
 * field names: nothing in them could be applied as a filter or a column, and
 * the reference's `ip.opt.*` vocabulary did not exist here. They follow
 * packet-ip.c now - an `IP Option - <name>` row per option that is its
 * `ip.options.*` field, the Type byte opened into copy, class and number, the
 * Length, and what the option carries, with a route's slots named by what the
 * pointer makes them (recorded, next, destination).
 *
 * The fixtures hold one kind - the Router Alert on every IGMP report - so the
 * rest are built here: each option the dissector reads, under the pointer
 * positions that change which row a slot is, padded as a sender pads them.
 * Every option row and every field under it is compared with tshark's PDML
 * for the same `.pcap`.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Bytes, ethernet, internetChecksum, pcapOf, udp } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

/** An IPv4 UDP frame whose header carries `options`, NOP-padded to a word. */
function withOptions(options: number[]): Uint8Array {
  const padded = [...options];
  while (padded.length % 4) padded.push(0);
  const payload = udp(40000, 40001, new Uint8Array([1, 2, 3, 4]));
  const header = new Bytes()
    .u8(0x40 | (5 + padded.length / 4), 0)
    .u16(20 + padded.length + payload.length)
    .u16(1).u16(0)
    .u8(64, 17).u16(0)
    .ipv4('192.0.2.1').ipv4('192.0.2.2')
    .raw(padded)
    .build();
  const sum = internetChecksum(header);
  header[10] = sum >> 8;
  header[11] = sum & 0xff;
  return ethernet(0x0800).raw(header).raw(payload).build();
}

const route = (type: number, pointer: number, slots: number[][]) =>
  [type, 3 + slots.length * 4, pointer, ...slots.flat()];
const A = [10, 0, 0, 1];
const B = [10, 0, 0, 254];
const C = [198, 51, 100, 7];
const ZERO = [0, 0, 0, 0];
const be32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

const CASES: { label: string; options: number[] }[] = [
  { label: 'Router Alert', options: [0x94, 4, 0, 0] },
  { label: 'Router Alert, a reserved value', options: [0x94, 4, 0, 1] },
  { label: 'Record Route, nothing recorded yet', options: [...route(0x07, 4, [ZERO, ZERO, ZERO]), 1] },
  { label: 'Record Route, two of three recorded', options: [...route(0x07, 12, [A, B, ZERO]), 0] },
  { label: 'Record Route, full', options: [...route(0x07, 16, [A, B, C]), 0] },
  { label: 'Record Route, pointer into the header', options: [...route(0x07, 2, [A, B, C]), 0] },
  { label: 'Loose Source Route, mid-way', options: [...route(0x83, 8, [A, B, C]), 0] },
  { label: 'Strict Source Route, done', options: [...route(0x89, 16, [A, B, C]), 0] },
  { label: 'Time Stamp, stamps only', options: [0x44, 12, 9, 0x00, ...be32(1000), ...be32(0)] },
  { label: 'Time Stamp, with addresses', options: [0x44, 20, 13, 0x21, ...A, ...be32(77), ...ZERO, ...be32(0)] },
  { label: 'Time Stamp, prespecified', options: [0x44, 12, 5, 0x03, ...B, ...be32(0)] },
  { label: 'Stream ID', options: [0x88, 4, 0x12, 0x34] },
  { label: 'MTU Probe and Reply', options: [0x0b, 4, 0x05, 0xdc, 0x0c, 4, 0x05, 0x78] },
  { label: 'NOPs, then an option nobody dissects', options: [1, 1, 0x1e, 6, 1, 2, 3, 4] },
];

/** Every option row and every `ip.opt*`, `ip.*_rt` and option `ip.dst` under the Options row. */
function ours(fields: readonly ProtocolField[]): string[] {
  const out: string[] = [];
  const options = fields.find((f) => f.name === 'Options');
  if (options === undefined) return out;
  out.push(`Options: ${options.value}`);
  const walk = (rows: readonly ProtocolField[]) => {
    for (const f of rows) {
      out.push(f.abbrev?.startsWith('ip.options.') || f.abbrev === undefined
        ? `${f.name}${f.value !== '' ? `: ${f.value}` : ''}`
        // A row with no value is a note, and reads as its label.
        : `${f.abbrev}=${f.value !== '' ? f.value : f.name.replace(/^\[|\]$/g, '')}`);
      if (f.children) walk(f.children);
    }
  };
  walk(options.children ?? []);
  return out;
}

const pcap = pcapOf(CASES.map((c) => withOptions(c.options)));
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'ipv4-options.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${CASES.length})`, packets.length === CASES.length);
check('every frame still reaches its UDP header past the options',
  packets.every((p) => (p.frameProtocols ?? []).includes('udp')));

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the options were read; whether as the reference reads them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-ipv4-options-'));
  try {
    const file = join(dir, 'options.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === CASES.length);
    const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
    CASES.forEach((c, i) => {
      const ip = /<proto name="ip"[\s\S]*?<\/proto>/.exec(pdml[i])?.[0] ?? '';
      const start = ip.indexOf('show="Options: ');
      const section = start < 0 ? '' : ip.slice(ip.lastIndexOf('<field', start));
      const theirs: string[] = [];
      for (const m of section.matchAll(/<field name="([^"]*)"(?: showname="([^"]*)")?[^>]*? show="([^"]*)"/g)) {
        const [, name, showname, show] = m;
        const shown = unescape(showname ?? show);
        if (name === '' || name.startsWith('ip.options.')) theirs.push(shown);
        else if (/^ip\.(opt\.|rec_rt$|src_rt$|empty_rt$|dst$)/.test(name)) {
          theirs.push(`${name}=${shown.includes(': ') ? shown.slice(shown.indexOf(': ') + 2) : shown}`);
        } else if (name.startsWith('ip.') && !name.includes('host') && name !== 'ip.addr') break;
      }
      const mine = ours(packets[i].layers?.find((l) => l.name === 'Internet Protocol Version 4')?.fields ?? []);
      // The route on a route option's collapsed row is this build's addition.
      const comparable = mine.map((row) => row.replace(/^(IP Option - (?:Record|Loose Source|Strict Source) Route \(\d+ bytes\)): .*$/, '$1'));
      const differ = comparable.length !== theirs.length || comparable.some((row, k) => row !== theirs[k]);
      check(`${c.label}: every row matches the reference`, !differ,
        `reference:\n          ${theirs.join('\n          ')}\n        this build:\n          ${comparable.join('\n          ')}`);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All IPv4 option checks passed.');
process.exit(0);
