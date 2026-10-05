/**
 * TCP options, row for row against the reference.
 *
 *   npx tsx scripts/parity/tcp-options.ts
 *
 * Options are where a handshake says what the connection may do - segment
 * size, window scaling, SACK, timestamps, Fast Open - and where a receiver
 * says which bytes it holds. Four things here drew differently from the
 * reference:
 * - **SACK edges were absolute**, ten-digit numbers beside a single-digit
 *   Ack=, where the reference makes them relative to the peer's base, and
 *   they sat in per-block rows of this build's own shape.
 * - **The Timestamps row claimed TSval's field name** for the option itself,
 *   so `tcp.options.timestamp` matched nothing and TSval had no row.
 * - **TCP Fast Open, User Timeout and the MD5 signature** fell through to
 *   "Unknown".
 * - **Kind was a bare number**, where the reference names it: "SACK (5)".
 *
 * The fixtures are Windows traffic - no timestamps, no Fast Open - so a
 * connection is built here: a handshake carrying every handshake option, a
 * hole in the data, plain SACKs, both forms of D-SACK, and the rarer kinds.
 * Every option row and field is compared with tshark's PDML of the same file.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Bytes, ethernet, ipv4, pcapOf } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const SYN = 0x02;
const ACK = 0x10;
const PSH = 0x08;

/** One segment of the conversation, client 192.0.2.1:50000 <-> server 192.0.2.2:40001. */
function segment(fromClient: boolean, seq: number, ack: number, flags: number, options: number[], payloadLength = 0): Uint8Array {
  if (options.length % 4) throw new Error(`options must fill whole words (${options.length})`);
  const tcp = new Bytes()
    .u16(fromClient ? 50000 : 40001, fromClient ? 40001 : 50000).u32(seq).u32(ack)
    .u8((5 + options.length / 4) << 4, flags)
    .u16(65535, 0, 0)
    .raw(options)
    .raw(new Uint8Array(payloadLength).fill(0x61))
    .build();
  const [src, dst] = fromClient ? ['192.0.2.1', '192.0.2.2'] : ['192.0.2.2', '192.0.2.1'];
  return ethernet(0x0800).raw(ipv4(6, tcp, src, dst)).build();
}

const be32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const MSS = [2, 4, 0x05, 0xb4];
const WS = [3, 3, 8];
const SACK_PERM = [4, 2];
const TS = (val: number, ecr: number) => [8, 10, ...be32(val), ...be32(ecr)];
const sack = (...blocks: [number, number][]) => [5, 2 + blocks.length * 8, ...blocks.flatMap(([l, r]) => [...be32(l), ...be32(r)])];
const C = 1000;   // client ISN
const S = 5000;   // server ISN

const FRAMES: { label: string; frame: Uint8Array }[] = [
  { label: 'SYN: MSS, WS, SACK_PERM, timestamps, a Fast Open cookie request',
    frame: segment(true, C, 0, SYN, [...MSS, 1, ...WS, ...SACK_PERM, ...TS(100, 0), 34, 2, 1, 1]) },
  { label: 'SYN-ACK: presenting a Fast Open cookie',
    frame: segment(false, S, C + 1, SYN | ACK, [...MSS, ...SACK_PERM, 1, 1, ...TS(900, 100), 34, 10, 1, 2, 3, 4, 5, 6, 7, 8]) },
  { label: 'ACK with timestamps', frame: segment(true, C + 1, S + 1, ACK, [1, 1, ...TS(101, 900)]) },
  { label: 'data', frame: segment(false, S + 1, C + 1, ACK | PSH, [], 100) },
  { label: 'data past a hole', frame: segment(false, S + 201, C + 1, ACK | PSH, [], 100) },
  { label: 'a SACK for the data past the hole', frame: segment(true, C + 1, S + 101, ACK, [1, 1, ...sack([S + 201, S + 301])]) },
  { label: 'a D-SACK below the cumulative ACK', frame: segment(true, C + 1, S + 101, ACK, [1, 1, ...sack([S + 1, S + 101], [S + 201, S + 301])]) },
  { label: 'a D-SACK inside the second block', frame: segment(true, C + 1, S + 101, ACK, [1, 1, ...sack([S + 250, S + 280], [S + 201, S + 301])]) },
  { label: 'User Timeout and an MD5 signature',
    frame: segment(true, C + 1, S + 101, ACK, [28, 4, 0x80, 5, 19, 18, ...Array.from({ length: 16 }, (_, i) => i), 1, 1]) },
  { label: 'a kind nobody names, then End of Option List', frame: segment(true, C + 1, S + 101, ACK, [99, 6, 1, 2, 3, 4, 0, 0]) },
];

/** `Options: ...`, every option row as its label, every field under it as `abbrev=value`. */
function ours(fields: readonly ProtocolField[]): string[] {
  const options = fields.find((f) => f.abbrev === 'tcp.options');
  if (options === undefined) return [];
  const out = [`Options: ${options.value}`];
  const walk = (rows: readonly ProtocolField[]) => {
    for (const f of rows) {
      if (f.name.startsWith('TCP Option - ')) out.push(`${f.name}${f.value !== '' ? `: ${f.value}` : ''}`);
      else if (f.abbrev?.startsWith('tcp.option')) {
        out.push(`${f.abbrev}=${f.value !== '' ? f.value : f.name.replace(/^\[|\]$/g, '')}`);
      }
      if (f.children) walk(f.children);
    }
  };
  walk(options.children ?? []);
  return out;
}

const pcap = pcapOf(FRAMES.map((f) => f.frame));
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'tcp-options.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${FRAMES.length})`, packets.length === FRAMES.length);

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the options were read; whether as the reference reads them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-tcp-options-'));
  try {
    const file = join(dir, 'tcp-options.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    const info = spawnSync(tshark, ['-n', '-r', file, '-T', 'fields', '-e', '_ws.col.info'], { encoding: 'utf8' })
      .stdout.trim().split(/\r?\n/);
    check('the reference read every frame', pdml.length === FRAMES.length);
    const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
      .replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
    FRAMES.forEach((f, i) => {
      const theirs: string[] = [];
      for (const m of pdml[i].matchAll(/<field name="(tcp\.option[a-z0-9_.]*)" showname="([^"]*)"/g)) {
        const shown = unescape(m[2]);
        if (m[1] === 'tcp.options') theirs.push(shown);
        else if (shown.startsWith('TCP Option - ')) theirs.push(shown);
        else {
          const value = shown.includes(': ') ? shown.slice(shown.indexOf(': ') + 2)
            : shown.includes(' = ') ? shown.slice(shown.indexOf(' = ') + 3) : shown;
          theirs.push(`${m[1]}=${value}`);
        }
      }
      const mine = ours(packets[i].layers?.find((l) => l.name === 'Transmission Control Protocol')?.fields ?? []);
      const differ = mine.length !== theirs.length || mine.some((row, k) => row !== theirs[k]);
      check(`${f.label}: every option row matches the reference`, !differ,
        `reference:\n          ${theirs.join('\n          ')}\n        this build:\n          ${mine.join('\n          ')}`);
      check(`${f.label}: ...and so does Info`, packets[i].info === info[i], `reference "${info[i]}", this build "${packets[i].info}"`);
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
console.log('All TCP option checks passed.');
process.exit(0);
