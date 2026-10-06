/**
 * ICMPv6's multicast-listener and neighbour-discovery bodies, row for row
 * against the reference.
 *
 *   npx tsx scripts/parity/icmpv6-messages.ts
 *
 * What a router says on an IPv6 link is in these: which multicast groups it
 * asks about and how often (MLD queries), and what it tells hosts beyond the
 * prefix - more specific routes, DNS search domains, a captive portal, the
 * NAT64 prefix. The tree drew MLD queries, v1 reports and dones as a type and
 * a code, and five Neighbor Discovery options as a type and a length:
 * - **MLD queries**, v1 and v2 (RFC 3810): the maximum response code and the
 *   query interval decoded from their exponential forms, as the reference
 *   shows them, the S flag and QRV, and the source list; v1 reports and
 *   dones carry their delay and group.
 * - **Route Information** (RFC 4191), **DNS Search List** (RFC 8106),
 *   **Captive-Portal** (RFC 8910), **PREF64** (RFC 8781) and the
 *   **Redirected Header**, with lifetimes read as the reference reads them -
 *   "3600 (1 hour)", "Infinity".
 *
 * The fixtures hold MLDv2 reports and plain RAs, so the rest are built here
 * and every `icmpv6.mld.*` and `icmpv6.opt*` row is compared with tshark's
 * PDML for the same `.pcap`.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ethernet, internetChecksum, pcapOf, udp } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const ROUTER = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xff, 0xfe, 0x00, 0x53, 0x01];
const ALL_NODES = [0xff, 0x02, ...Array(13).fill(0), 1];
const GROUP = [0xff, 0x02, ...Array(9).fill(0), 1, 0xff, 0, 0, 1];
const HOST = [0x20, 0x01, 0x0d, 0xb8, ...Array(11).fill(0), 0x42];
const be16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const be32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

/** An ICMPv6 message from the router, with a correct checksum. */
function icmpv6(type: number, code: number, body: number[], dst = ALL_NODES): Uint8Array {
  const message = [type, code, 0, 0, ...body];
  const pseudo = [...ROUTER, ...dst, ...be32(message.length), 0, 0, 0, 58, ...message];
  const sum = internetChecksum(Uint8Array.from(pseudo));
  message[2] = sum >> 8;
  message[3] = sum & 0xff;
  return ethernet(0x86dd).u32(0x60000000).u16(message.length).u8(58, 255).raw(ROUTER).raw(dst).raw(message).build();
}

const label = (name: string) => name.split('.').flatMap((l) => [l.length, ...Array.from(l, (c) => c.charCodeAt(0))]);
const dnssl = (...names: string[]) => {
  const encoded = names.flatMap((n) => [...label(n), 0]);
  const total = 8 + encoded.length;
  const units = Math.ceil(total / 8);
  return [31, units, 0, 0, ...be32(3600), ...encoded, ...Array(units * 8 - total).fill(0)];
};
const portal = (uri: string) => {
  const bytes = Array.from(uri, (c) => c.charCodeAt(0));
  const units = Math.ceil((2 + bytes.length) / 8);
  return [37, units, ...bytes, ...Array(units * 8 - 2 - bytes.length).fill(0)];
};
const RA = [64, 0x00, ...be16(1800), ...be32(0), ...be32(0)];

const CASES: { label: string; frame: Uint8Array }[] = [
  { label: 'an MLDv1 query', frame: icmpv6(130, 0, [...be16(10000), 0, 0, ...Array(16).fill(0)]) },
  { label: 'an MLDv2 general query', frame: icmpv6(130, 0, [...be16(10000), 0, 0, ...Array(16).fill(0), 0x02, 125, 0, 0]) },
  { label: 'an MLDv2 query with S set, exponential codes and two sources',
    frame: icmpv6(130, 0, [...be16(40000), 0, 0, ...GROUP, 0x0a, 200, 0, 2, ...HOST, ...ROUTER]) },
  { label: 'an MLDv1 report', frame: icmpv6(131, 0, [0, 0, 0, 0, ...GROUP], GROUP) },
  { label: 'an MLD done', frame: icmpv6(132, 0, [0, 0, 0, 0, ...GROUP]) },
  { label: 'an RA with Route Information of each length',
    frame: icmpv6(134, 0, [...RA,
      24, 1, 0, 0x08, ...be32(0xffffffff),
      24, 2, 48, 0x18, ...be32(3600), 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0,
      24, 3, 64, 0x00, ...be32(90061), ...HOST]) },
  { label: 'an RA with DNS Search List, Captive-Portal and PREF64',
    frame: icmpv6(134, 0, [...RA,
      ...dnssl('example.com', 'corp.example'),
      ...portal('https://portal.example/'),
      38, 2, ...be16((600 << 3) | 1), 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0,
      25, 3, 0, 0, ...be32(3600), ...HOST]) },
  { label: 'a Redirect carrying a Redirected Header',
    frame: icmpv6(137, 0, [0, 0, 0, 0, ...ROUTER, ...HOST,
      4, 7, 0, 0, 0, 0, 0, 0, 0x60, 0, 0, 0, 0, 8, 17, 64, ...HOST, ...GROUP, ...udp(1000, 2000, new Uint8Array(0))]) },
];

const ROWS = /^icmpv6\.(mld\.|opt($|\.))/;

function ours(fields: readonly ProtocolField[], out: string[] = []): string[] {
  for (const f of fields) {
    if (f.abbrev !== undefined && ROWS.test(f.abbrev)) {
      const value = typeof f.value === 'boolean' ? (f.value ? 'True' : 'False') : String(f.value);
      out.push(f.abbrev === 'icmpv6.opt' ? `${f.name} ${value}` : `${f.abbrev}=${value === '' ? f.name : value}`);
    }
    if (f.children) ours(f.children, out);
  }
  return out;
}

const pcap = pcapOf(CASES.map((c) => c.frame));
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'icmpv6.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${CASES.length})`, packets.length === CASES.length);

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the bodies were read; whether as the reference reads them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-icmpv6-'));
  try {
    const file = join(dir, 'icmpv6.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === CASES.length);
    const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
      .replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
    CASES.forEach((c, i) => {
      const theirs: string[] = [];
      for (const m of pdml[i].matchAll(/<field name="(icmpv6\.[a-z0-9_.]+)" showname="([^"]*)"/g)) {
        if (!ROWS.test(m[1])) continue;
        const shown = unescape(m[2]);
        if (m[1] === 'icmpv6.opt') { theirs.push(shown); continue; }
        theirs.push(`${m[1]}=${shown.includes(': ') ? shown.slice(shown.indexOf(': ') + 2) : shown}`);
      }
      const icmp = packets[i].layers.find((l) => l.name === 'Internet Control Message Protocol v6');
      const mine = ours(icmp?.fields ?? []);
      const differ = mine.length !== theirs.length || mine.some((row, k) => row !== theirs[k]);
      check(`${c.label}: every row matches the reference (${theirs.length})`, !differ,
        `reference:\n          ${theirs.join('\n          ')}\n        this build:\n          ${mine.join('\n          ')}`);
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
console.log('All ICMPv6 message checks passed.');
process.exit(0);
