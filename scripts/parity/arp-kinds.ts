/**
 * The kinds of ARP a host claims an address with, against the reference.
 *
 *   npx tsx scripts/parity/arp-kinds.ts
 *
 * RFC 5227's address conflict detection is three shapes of ARP, and they are
 * what a network engineer looks for when two machines fight over an address:
 * - a **probe** - a request from 0.0.0.0 asking whether anyone holds the address;
 * - an **announcement** - the gratuitous request that follows, target MAC zero;
 * - a **gratuitous** request or reply - sender and target address equal, a host
 *   telling the segment what it holds (failover, a NIC coming up).
 *
 * The tree said none of it: the Info column named a gratuitous ARP and nothing
 * else, and `arp.isgratuitous`, `arp.isprobe` and `arp.isannouncement` did not
 * exist. Neither fixture holds one of these, so the frames are built here and
 * the oracle is tshark's reading of the same `.pcap`: the Info column, the
 * layer's summary, and each flag row, frame for frame. Without tshark the
 * comparison skips and the script still checks this build's own answers.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ethernet, pcapOf } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet, ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const HOST_MAC = '00:00:5e:00:53:01';
const ZERO_MAC = '00:00:00:00:00:00';
const FLAGS = ['arp.isgratuitous', 'arp.isprobe', 'arp.isannouncement'] as const;

function arp(opcode: number, senderMac: string, senderIp: string, targetMac: string, targetIp: string): Uint8Array {
  return ethernet(0x0806)
    .u16(1, 0x0800).u8(6, 4).u16(opcode)
    .mac(senderMac).ipv4(senderIp).mac(targetMac).ipv4(targetIp)
    .build();
}

interface Case { label: string; frame: Uint8Array; flags: (typeof FLAGS)[number][] }
const CASES: Case[] = [
  { label: 'an ordinary request', frame: arp(1, HOST_MAC, '192.0.2.1', ZERO_MAC, '192.0.2.2'), flags: [] },
  { label: 'an ordinary reply', frame: arp(2, '00:00:5e:00:53:02', '192.0.2.2', HOST_MAC, '192.0.2.1'), flags: [] },
  { label: 'a probe', frame: arp(1, HOST_MAC, '0.0.0.0', ZERO_MAC, '192.0.2.9'), flags: ['arp.isprobe'] },
  { label: 'an announcement', frame: arp(1, HOST_MAC, '192.0.2.9', ZERO_MAC, '192.0.2.9'), flags: ['arp.isgratuitous', 'arp.isannouncement'] },
  { label: 'a gratuitous request', frame: arp(1, HOST_MAC, '192.0.2.9', 'ff:ff:ff:ff:ff:ff', '192.0.2.9'), flags: ['arp.isgratuitous'] },
  { label: 'a gratuitous reply', frame: arp(2, HOST_MAC, '192.0.2.9', 'ff:ff:ff:ff:ff:ff', '192.0.2.9'), flags: ['arp.isgratuitous'] },
  { label: 'a probe whose target MAC is not zero', frame: arp(1, HOST_MAC, '0.0.0.0', 'ff:ff:ff:ff:ff:ff', '192.0.2.9'), flags: ['arp.isprobe'] },
];

function rows(packet: Packet): Map<string, ProtocolField> {
  const out = new Map<string, ProtocolField>();
  for (const f of packet.layers?.find((l) => l.name === 'Address Resolution Protocol')?.fields ?? []) {
    if (f.abbrev !== undefined) out.set(f.abbrev, f);
  }
  return out;
}
const summaryOf = (packet: Packet) =>
  packet.layers?.find((l) => l.name === 'Address Resolution Protocol')?.summary ?? '';

const pcap = pcapOf(CASES.map((c) => c.frame));
const { packets } = await PcapService.parseCaptureFile(
  new File([pcap], 'arp-kinds.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${CASES.length})`, packets.length === CASES.length, `${packets.length} packets`);

// --- this build's own answers ---------------------------------------------------

CASES.forEach((c, i) => {
  const mine = rows(packets[i]);
  const has = FLAGS.filter((f) => mine.has(f));
  check(`${c.label}: flagged ${c.flags.join(', ') || 'as nothing'}`, has.join() === c.flags.join(),
    `this build: ${has.join(', ') || 'nothing'}`);
  check(`${c.label}: ...and each flag is a filter`, c.flags.every((f) => packets[i].fields?.[f] === 1));
});

// --- the reference --------------------------------------------------------------

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the flags were checked; whether as the reference draws them was not');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-arp-kinds-'));
  try {
    const file = join(dir, 'arp.pcap');
    writeFileSync(file, pcap);
    const info = spawnSync(tshark, ['-n', '-r', file, '-T', 'fields', '-e', '_ws.col.info'], { encoding: 'utf8' })
      .stdout.trim().split(/\r?\n/);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === CASES.length && info.length === CASES.length);
    CASES.forEach((c, i) => {
      check(`${c.label}: Info reads as the reference's ("${info[i]}")`, packets[i].info === info[i],
        `this build: "${packets[i].info}"`);
      const summary = /<proto name="arp" showname="([^"]*)"/.exec(pdml[i])?.[1] ?? '';
      check(`${c.label}: ...and so does the layer ("${summary}")`, summaryOf(packets[i]) === summary,
        `this build: "${summaryOf(packets[i])}"`);
      const theirs = FLAGS.filter((f) => pdml[i].includes(`name="${f}"`));
      const drawn = FLAGS.filter((f) => rows(packets[i]).has(f))
        .map((f) => `${rows(packets[i]).get(f)!.name.replace(/^\[|\]$/g, '')}: ${rows(packets[i]).get(f)!.value}`);
      const shown = theirs.map((f) => new RegExp(`name="${f.replace('.', '\\.')}" showname="([^"]*)"`).exec(pdml[i])?.[1]);
      check(`${c.label}: ...and its flag rows (${shown.join(', ') || 'none'})`, drawn.join() === shown.join(),
        `this build: ${drawn.join(', ') || 'none'}`);
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
console.log('All ARP kind checks passed.');
process.exit(0);
