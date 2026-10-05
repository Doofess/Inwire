/**
 * VLAN tags, row for row against the reference.
 *
 *   npx tsx scripts/parity/vlan-tags.ts
 *
 * A trunk port's capture is read by its tags: which VLAN, at what priority,
 * whether the switch may drop it, and on a provider network which service
 * VLAN carries which customer one. The tree drew every tag as "802.1Q Virtual
 * LAN" with three unnamed numbers, including an 802.1ad service tag, which
 * the reference dissects separately and names differently.
 *
 * Neither fixture holds a tagged frame - a desktop NIC strips them - so the
 * frames are built here: every priority with DEI clear and set, one service
 * tag, the usual QinQ shape (802.1ad then 802.1Q), two 802.1ad tags in a row
 * (which the reference reads as one S-VID/C-VID pair), and two 802.1Q tags.
 * Each layer's summary, every tag row and the frame's protocol list are
 * compared with tshark's PDML for the same `.pcap`.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ethernet, ipv4, pcapOf, udp } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import { protocolsInFrame } from '../../src/services/dissect/protocolsInFrame';
import type { Packet, ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const PAYLOAD = ipv4(17, udp(40000, 40001, new Uint8Array([1, 2, 3, 4])));
const tci = (priority: number, dei: number, id: number) => (priority << 13) | (dei << 12) | id;

/** Tags outermost first, each `[tpid, tci]`, then IPv4. */
function tagged(...tags: [number, number][]): Uint8Array {
  const b = ethernet(tags[0][0]);
  tags.forEach(([, value], i) => b.u16(value).u16(i + 1 < tags.length ? tags[i + 1][0] : 0x0800));
  return b.raw(PAYLOAD).build();
}

interface Case { label: string; frame: Uint8Array }
const CASES: Case[] = [];
for (let priority = 0; priority < 8; priority++) {
  for (const dei of [0, 1]) {
    CASES.push({ label: `802.1Q PRI ${priority} DEI ${dei}`, frame: tagged([0x8100, tci(priority, dei, 100 + priority)]) });
  }
}
CASES.push(
  { label: 'one 802.1ad service tag', frame: tagged([0x88a8, tci(3, 1, 200)]) },
  { label: 'QinQ: 802.1ad then 802.1Q', frame: tagged([0x88a8, tci(5, 0, 300)], [0x8100, tci(2, 1, 42)]) },
  { label: 'two 802.1ad tags in a row', frame: tagged([0x88a8, tci(6, 1, 400)], [0x88a8, tci(1, 0, 4094)]) },
  { label: 'two 802.1Q tags', frame: tagged([0x8100, tci(0, 0, 10)], [0x8100, tci(7, 1, 20)]) },
);

const ROWS = /^(?:vlan\.(?:priority|dei|id)|ieee8021ad\.(?:priority|dei|id|svid|cvid))$/;
const TYPES = /^(?:vlan\.etype|ieee8021ah\.etype)$/;

function ours(packet: Packet): { summaries: string[]; rows: Map<string, string[]>; types: number[] } {
  const rows = new Map<string, string[]>();
  const types: number[] = [];
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev !== undefined && ROWS.test(f.abbrev)) rows.set(f.abbrev, [...(rows.get(f.abbrev) ?? []), String(f.value)]);
      if (f.abbrev !== undefined && TYPES.test(f.abbrev)) types.push(parseInt(String(f.value), 16));
      if (f.children) walk(f.children);
    }
  };
  const tags = (packet.layers ?? []).filter((l) => l.name === '802.1Q Virtual LAN' || l.name === 'IEEE 802.1ad');
  for (const layer of tags) walk(layer.fields);
  return { summaries: tags.map((l) => l.summary ?? l.name), rows, types };
}

const pcap = pcapOf(CASES.map((c) => c.frame));
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'vlan.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${CASES.length})`, packets.length === CASES.length);
check('every frame still reaches its UDP payload past the tags',
  packets.every((p) => (p.frameProtocols ?? []).includes('udp')));

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the tags were walked; whether as the reference draws them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-vlan-'));
  try {
    const file = join(dir, 'vlan.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === CASES.length);
    CASES.forEach((c, i) => {
      const mine = ours(packets[i]);
      const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      const summaries = [...pdml[i].matchAll(/<proto name="(?:vlan|ieee8021ad)" showname="([^"]*)"/g)].map((m) => unescape(m[1]));
      const rows = new Map<string, string[]>();
      const types: number[] = [];
      for (const m of pdml[i].matchAll(/<field name="([a-z0-9_.]+)" showname="([^"]*)"/g)) {
        const shown = unescape(m[2]);
        if (ROWS.test(m[1])) rows.set(m[1], [...(rows.get(m[1]) ?? []), shown.slice(shown.indexOf(': ') + 2)]);
        if (TYPES.test(m[1])) types.push(parseInt(/\(0x([0-9a-f]+)\)$/.exec(shown)?.[1] ?? 'NaN', 16));
      }
      check(`${c.label}: the layers read "${summaries.join(' / ')}"`, mine.summaries.join(' / ') === summaries.join(' / '),
        `this build: "${mine.summaries.join(' / ')}"`);
      const differ = [...new Set([...rows.keys(), ...mine.rows.keys()])]
        .filter((k) => (rows.get(k) ?? []).join() !== (mine.rows.get(k) ?? []).join())
        .map((k) => `${k}: reference ${JSON.stringify(rows.get(k))}, this build ${JSON.stringify(mine.rows.get(k))}`);
      check(`${c.label}: ...every tag row matches`, differ.length === 0, differ.join('\n        '));
      check(`${c.label}: ...and each tag's Type`, types.join() === mine.types.join(), `reference ${types}, this build ${mine.types}`);
      const listed = /<field name="frame\.protocols"[^>]* show="([^"]*)"/.exec(pdml[i])?.[1] ?? '';
      const own = protocolsInFrame(packets[i].frameProtocols ?? []);
      check(`${c.label}: ...and the frame's protocols ("${listed}")`, own === listed, `this build: "${own}"`);
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
console.log('All VLAN tag checks passed.');
process.exit(0);
