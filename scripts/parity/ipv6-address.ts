/**
 * What an IPv6 address says about itself, row for row against the reference.
 *
 *   npx tsx scripts/parity/ipv6-address.ts
 *
 * `dissectors/ipv6Address.ts` draws, under each address, its IANA address
 * space, a multicast address's flags and scope, the special-purpose block it
 * falls in with that block's five properties, and the MAC or IPv4 address a
 * SLAAC, 6to4, Teredo or ISATAP address carries - each with the either-end
 * twin (`ipv6.addr_space`, `ipv6.multicast_scope`, ...) the reference hides
 * and a filter reads.
 *
 * The fixtures hold link-local, global and multicast traffic and the SLAAC
 * addresses beside them, which `tree-coverage.ts` measures. They hold no
 * Teredo, no 6to4 and almost none of IANA's special blocks, and the blocks
 * OVERLAP - 2001::/23 contains TEREDO's 2001::/32 and three /128 anycasts - so
 * which block an address is filed under is decided by the order a binary
 * search visits them in. A table that is right entry by entry can still answer
 * differently from the reference. So this builds an address at every block's
 * base, at its edges, at random inside it and just past it, every multicast
 * scope and flag, and each tunnelled shape, and compares every detail row of
 * every frame with tshark's PDML for the same `.pcap`.
 *
 * Without tshark it skips the comparison and still checks every frame has its
 * address space drawn.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ethernet, pcapOf, udp } from './synthetic';
import { findWiresharkTool } from '../export/realCaptures';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

/** Sixteen bytes from a full or `::`-compressed address. */
function address(text: string): number[] {
  const [head, tail] = text.includes('::') ? text.split('::') : [text, undefined];
  const groups = (s: string | undefined) => (s ? s.split(':').map((g) => parseInt(g, 16)) : []);
  const h = groups(head);
  const t = groups(tail);
  const all = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill(0), ...t];
  return all.flatMap((g) => [(g >> 8) & 0xff, g & 0xff]);
}

// A small deterministic generator, so a failure names the same frame twice.
let seed = 0x1234567;
const random = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 8) & 0xff;

/** Every special-purpose block's prefix and length, as the reference lists them. */
const BLOCKS: [string, number][] = [
  ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['64:ff9b:1::', 48],
  ['100::', 64], ['100:0:0:1::', 64], ['2001::', 23], ['2001::', 32], ['2001:1::1', 128],
  ['2001:1::2', 128], ['2001:1::3', 128], ['2001:2::', 48], ['2001:3::', 32], ['2001:4:112::', 48],
  ['2001:20::', 28], ['2001:30::', 28], ['2001:db8::', 32], ['2002::', 16], ['2620:4f:8000::', 48],
  ['3fff::', 20], ['5f00::', 16], ['fc00::', 7], ['fe80::', 10],
];

const addresses: number[][] = [];
for (const [base, bits] of BLOCKS) {
  const b = address(base);
  addresses.push(b);
  // The last address in the block, and the first one past it.
  const last = b.map((byte, i) => (i * 8 >= bits ? 0xff : i * 8 + 8 > bits ? byte | (0xff >> (bits - i * 8)) : byte));
  addresses.push(last);
  const past = [...last];
  for (let i = 15; i >= 0; i--) { past[i] = (past[i] + 1) & 0xff; if (past[i] !== 0) break; }
  addresses.push(past);
  // Random addresses inside it.
  for (let n = 0; n < 6; n++) {
    addresses.push(b.map((byte, i) => {
      if (i * 8 >= bits) return random();
      if (i * 8 + 8 > bits) return byte | (random() & (0xff >> (bits - i * 8)));
      return byte;
    }));
  }
}
// Every multicast scope, and each flag bit on its own and together.
for (let scope = 0; scope < 16; scope++) addresses.push(address(`ff0${scope.toString(16)}::1`));
for (const flags of [1, 2, 4, 8, 0xf]) addresses.push(address(`ff${flags.toString(16)}2::1:ff00:1`));
// The tunnelled shapes, and a near miss of each.
addresses.push(
  address('2002:c000:201:7::1'),                       // 6to4, gateway 192.0.2.1, SLA 7
  address('2001:0:4136:e378:8000:63bf:3fff:fdd2'),     // Teredo, RFC 4380's own example
  address('2001:1:4136:e378:8000:63bf:3fff:fdd2'),     // ...one bit off the prefix
  address('fe80::200:5efe:c000:201'),                  // ISATAP, universal bit set
  address('fe80::5efe:c000:201'),                      // ISATAP, local
  address('fe80::100:5efe:c000:201'),                  // ...not ISATAP
  address('fe80::4615:24ff:fe5d:cc62'),                // SLAAC from a MAC
  address('fe80::4415:24ff:fe5d:cc62'),                // ...universal bit clear: not SLAAC
  address('2001:db8::200:5eff:fe00:5301'),             // SLAAC under a global prefix
);
// The space rule's own edges: the reference tests bits, not ranges.
for (const first of [0x00, 0x10, 0x1f, 0x20, 0x3f, 0x40, 0x60, 0x7f, 0xa0, 0xe0, 0xfb, 0xfc, 0xfd, 0xfe]) {
  addresses.push([first, ...Array(14).fill(0), 1]);
}
addresses.push(address('febf::1'), address('fec0::1'));

const frames = addresses.map((src, i) => {
  const dst = addresses[(i * 7 + 3) % addresses.length];
  const payload = udp(40000, 9, new Uint8Array(0));
  return ethernet(0x86dd).u32(0x60000000).u16(payload.length).u8(17, 64).raw(src).raw(dst).raw(payload).build();
});

const DETAIL = /^ipv6\.(?:(?:src|dst)_)?(?:addr_space|multicast_|special_purpose|addr_special_purpose|6to4_|ts_ipv4|tc_|slaac_mac|isatap_ipv4)/;

function ours(fields: readonly ProtocolField[], out = new Map<string, string[]>()): Map<string, string[]> {
  for (const f of fields) {
    if (f.abbrev !== undefined && DETAIL.test(f.abbrev)) {
      out.set(f.abbrev, [...(out.get(f.abbrev) ?? []), String(f.value)]);
    }
    if (f.children) ours(f.children, out);
  }
  return out;
}

const pcap = pcapOf(frames);
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'ipv6-address.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${frames.length})`, packets.length === frames.length);
const mine = packets.map((p) => ours(p.layers?.find((l) => l.name === 'Internet Protocol Version 6')?.fields ?? []));
check('every address has its space drawn, for its side and either end',
  mine.every((m) => m.get('ipv6.src_addr_space')?.length === 1 && m.get('ipv6.dst_addr_space')?.length === 1
    && m.get('ipv6.addr_space')?.length === 2));

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the rows are drawn; whether as the reference draws them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-ipv6-address-'));
  try {
    const file = join(dir, 'ipv6.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 30 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === frames.length, `${pdml.length} frames`);
    const differ: string[] = [];
    let compared = 0;
    pdml.forEach((text, i) => {
      const proto = /<proto name="ipv6"[\s\S]*?<\/proto>/.exec(text)?.[0] ?? '';
      const theirs = new Map<string, string[]>();
      for (const m of proto.matchAll(/<field name="(ipv6\.[a-z0-9_.]+)" showname="([^"]*)"/g)) {
        if (!DETAIL.test(m[1])) continue;
        const shown = m[2].replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
        theirs.set(m[1], [...(theirs.get(m[1]) ?? []), shown.slice(shown.indexOf(': ') + 2)]);
      }
      for (const abbrev of new Set([...theirs.keys(), ...mine[i].keys()])) {
        compared++;
        const a = (mine[i].get(abbrev) ?? []).join(' | ');
        const b = (theirs.get(abbrev) ?? []).join(' | ');
        if (a !== b) differ.push(`frame ${i + 1} ${abbrev}: reference "${b}", this build "${a}"`);
      }
    });
    check(`every detail row matches the reference (${compared} rows over ${frames.length} frames)`,
      differ.length === 0, `${differ.length} differ, e.g.\n        ${differ.slice(0, 12).join('\n        ')}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All IPv6 address checks passed.');
process.exit(0);
