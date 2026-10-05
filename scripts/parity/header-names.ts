/**
 * What a header's numbers are called in the tree, against the reference.
 *
 *   npx tsx scripts/parity/header-names.ts
 *
 * ICMP's Type and Code, IPv4's Protocol and IPv6's Next Header are the rows a
 * network engineer reads first, and three of the four were bare numbers or
 * named only TCP and UDP. They are named from tables now
 * (`dissectors/icmpNames.ts`, `dissect/ipProtocolNames.ts`), and a table is
 * only as good as the last time somebody compared it - so this compares all of
 * it, every run:
 *
 * - every ICMPv4 type 0-43 and 200 under codes 0-20, which takes in the
 *   unassigned types, the types with a code table and the codes past each
 *   table's end;
 * - every ICMPv6 type the reference names, plus unassigned ones, under codes
 *   0-15;
 * - every IP protocol number 0-255, carried by IPv4 and by IPv6.
 *
 * Synthetic frames, built here rather than found in a capture: no capture
 * holds 256 protocols. The oracle is tshark's own `showname` for the same
 * `.pcap`, so the frames being made up does not make the answer made up.
 * Without tshark the comparison skips and the script still checks that every
 * row is named at all.
 */
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Bytes, ethernet, internetChecksum, ipv4, pcapOf, udp } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField, ProtocolLayer } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

// --- the frames ----------------------------------------------------------------

const address6 = (text: string) => text.split(':').flatMap((group) => {
  const value = parseInt(group, 16);
  return [(value >> 8) & 0xff, value & 0xff];
});
const HOST_A = address6('2001:0db8:0000:0000:0000:0000:0000:0001');
const HOST_B = address6('2001:0db8:0000:0000:0000:0000:0000:0002');

function ipv6(nextHeader: number, payload: Uint8Array): Uint8Array {
  const header = new Bytes().u32(0x60000000).u16(payload.length).u8(nextHeader, 64).raw(HOST_B).raw(HOST_A).build();
  return Uint8Array.from([...ethernet(0x86dd).build(), ...header, ...payload]);
}

/** An error quotes a datagram; giving every message one keeps each frame long enough for any type. */
const QUOTED4 = ipv4(17, udp(1234, 53, new Uint8Array(0)), '192.0.2.1', '198.51.100.7');
const QUOTED6 = new Bytes().u32(0x60000000).u16(8).u8(17, 64).raw(HOST_A).raw(HOST_B)
  .raw(udp(1234, 53, new Uint8Array(0))).build();

function icmp4(type: number, code: number): Uint8Array {
  const body = new Bytes().u8(type, code).u16(0).u32(0).raw(QUOTED4).build();
  const sum = internetChecksum(body);
  body[2] = sum >> 8;
  body[3] = sum & 0xff;
  return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(1, body, '192.0.2.9', '192.0.2.1')]);
}

function icmp6(type: number, code: number): Uint8Array {
  return ipv6(58, new Bytes().u8(type, code).u16(0).u32(0).raw(QUOTED6).build());
}

interface Case { frame: Uint8Array; abbrevs: string[]; label: string }
const cases: Case[] = [];
const v4Types = [...Array.from({ length: 44 }, (_, i) => i), 200];
for (const type of v4Types) {
  for (let code = 0; code <= 20; code++) {
    cases.push({ frame: icmp4(type, code), abbrevs: ['icmp.type', 'icmp.code'], label: `ICMP ${type}/${code}` });
  }
}
const v6Types = [1, 2, 3, 4, 5, 100, 101, 127, ...Array.from({ length: 35 }, (_, i) => 128 + i), 200, 201, 255];
for (const type of v6Types) {
  for (let code = 0; code <= 15; code++) {
    cases.push({ frame: icmp6(type, code), abbrevs: ['icmpv6.type', 'icmpv6.code'], label: `ICMPv6 ${type}/${code}` });
  }
}
for (let protocol = 0; protocol < 256; protocol++) {
  // Eight bytes of zeros: enough that nothing reads past the end, and nothing
  // any protocol's dissector will make much of - only the header row is compared.
  const payload = new Uint8Array(8);
  cases.push({
    frame: Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(protocol, payload)]),
    abbrevs: ['ip.proto'], label: `IPv4 protocol ${protocol}`,
  });
  cases.push({ frame: ipv6(protocol, payload), abbrevs: ['ipv6.nxt'], label: `IPv6 next header ${protocol}` });
}

// --- this build's answer ---------------------------------------------------------

function firstValue(layers: readonly ProtocolLayer[], abbrev: string): string | undefined {
  const walk = (fields: readonly ProtocolField[]): string | undefined => {
    for (const field of fields) {
      if (field.abbrev === abbrev) return String(field.value);
      const inner = field.children ? walk(field.children) : undefined;
      if (inner !== undefined) return inner;
    }
    return undefined;
  };
  for (const layer of layers) {
    const found = walk(layer.fields);
    if (found !== undefined) return found;
  }
  return undefined;
}

const pcap = pcapOf(cases.map((c) => c.frame));
const { packets } = await PcapService.parseCaptureFile(
  new File([pcap], 'header-names.pcap'), Number.POSITIVE_INFINITY, true); // keep the trees
check(`every frame dissected (${cases.length})`, packets.length === cases.length, `${packets.length} packets`);
const ours = packets.map((packet, i) => cases[i].abbrevs.map((abbrev) => firstValue(packet.layers ?? [], abbrev)));

check('every ICMP type row is named, never a bare number',
  cases.every((c, i) => !c.abbrevs[0].startsWith('icmp') || /\(\d+\)$/.test(ours[i][0] ?? '')));
check('every IP protocol row is named, never a bare number',
  cases.every((c, i) => c.abbrevs[0].startsWith('icmp') || /\(\d+\)$/.test(ours[i][0] ?? '')));

// --- the reference's answer -------------------------------------------------------

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the rows are named; whether as the reference names them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-header-names-'));
  try {
    const file = join(dir, 'frames.pcap');
    writeFileSync(file, pcap);
    const run = spawnSync(tshark, ['-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024 });
    const frames = run.stdout.split('<packet>').slice(1);
    check('the reference read every frame', frames.length === cases.length, `${frames.length} frames`);
    const differ: string[] = [];
    frames.forEach((pdml, i) => {
      cases[i].abbrevs.forEach((abbrev, k) => {
        // The FIRST occurrence: the outer header, not the datagram an error quotes.
        const shown = new RegExp(`name="${abbrev.replace('.', '\\.')}" showname="[^:"]*: ([^"]*)"`).exec(pdml)?.[1]
          ?.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'");
        if (shown !== undefined && shown !== ours[i][k]) {
          differ.push(`${cases[i].label} ${abbrev}: reference "${shown}", this build "${ours[i][k]}"`);
        }
      });
    });
    check(`every row reads as the reference draws it (${cases.length} frames)`, differ.length === 0,
      `${differ.length} differ, e.g.\n        ${differ.slice(0, 12).join('\n        ')}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All header-name checks passed.');
process.exit(0);
