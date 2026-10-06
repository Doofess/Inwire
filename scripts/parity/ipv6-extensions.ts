/**
 * IPv6 extension headers and their options, row for row against the reference.
 *
 *   npx tsx scripts/parity/ipv6-extensions.ts
 *
 * Every MLD report carries a Hop-by-Hop header with a Router Alert, and the
 * tree drew it as "IPv6 Option (Router Alert): MLD (0)" with no field name
 * on it or on the header's own Next Header and Length - and Pad1 read as
 * PadN. The headers follow packet-ipv6.c now: each header's `nxt`, `len` and
 * `len_oct`, a row per option (`ipv6.opt`) with its Type byte opened into the
 * action a node that does not know it must take and whether it may change en
 * route, and the option's own data - Router Alert, PadN, Pad1, Jumbo Payload,
 * Tunnel Encapsulation Limit, Home Address, or the reference's "Unknown
 * Option Payload". Routing and Fragment headers name their fields too.
 *
 * The fixtures hold five Hop-by-Hop headers, all alike, so the rest are built
 * here and every header and option row is compared with tshark's PDML of the
 * same `.pcap`. A routing header's type-specific body (SRH segments, RPL
 * addresses) is not drawn here and is not compared.
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

const SRC = [0x20, 0x01, 0x0d, 0xb8, ...Array(11).fill(0), 1];
const DST = [0x20, 0x01, 0x0d, 0xb8, ...Array(11).fill(0), 2];
const HOME = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

/** An IPv6 frame whose extension headers are `chain`, then UDP. `first` is the fixed header's Next Header. */
function frame(first: number, chain: number[]): Uint8Array {
  if (chain.length % 8) throw new Error(`a header chain fills whole 8-octet units (${chain.length})`);
  const payload = [...chain, ...udp(40000, 40001, new Uint8Array([1, 2, 3, 4]))];
  return ethernet(0x86dd).u32(0x60000000).u16(payload.length).u8(first, 64).raw(SRC).raw(DST).raw(payload).build();
}

const HBH = 0;
const DST_OPTS = 60;
const UDP = 17;

const CASES: { label: string; frame: Uint8Array }[] = [
  { label: 'Hop-by-Hop: Router Alert (MLD) and an empty PadN', frame: frame(HBH, [UDP, 0, 0x05, 2, 0, 0, 0x01, 0]) },
  { label: 'Hop-by-Hop: a Router Alert nobody names', frame: frame(HBH, [UDP, 0, 0x05, 2, 0, 5, 0x01, 0]) },
  { label: 'Hop-by-Hop: Pad1, Pad1, PadN with bytes', frame: frame(HBH, [UDP, 0, 0x00, 0x00, 0x01, 2, 0, 0]) },
  { label: 'Hop-by-Hop: Jumbo Payload', frame: frame(HBH, [UDP, 0, 0xc2, 4, 0, 1, 0x11, 0x70]) },
  { label: 'Destination Options: Tunnel Encapsulation Limit', frame: frame(DST_OPTS, [UDP, 0, 0x04, 1, 4, 0x01, 1, 0]) },
  { label: 'Destination Options: Home Address', frame: frame(DST_OPTS, [UDP, 2, 0xc9, 16, ...HOME, 0x01, 2, 0, 0]) },
  { label: 'Destination Options: an option nobody names', frame: frame(DST_OPTS, [UDP, 0, 0x3f, 4, 1, 2, 3, 4]) },
  { label: 'an atomic Fragment header', frame: frame(44, [UDP, 0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78]) },
  { label: 'a Segment Routing header', frame: frame(43, [UDP, 2, 4, 0, 0, 0, 0, 0, ...DST]) },
  { label: 'Hop-by-Hop, then Destination Options', frame: frame(HBH, [DST_OPTS, 0, 0x01, 4, 0, 0, 0, 0, UDP, 0, 0x04, 1, 9, 0x01, 1, 0]) },
];

const ROWS = /^ipv6\.((hopopts|dstopts|routing)\.(nxt|len|len_oct)|routing\.(type|segleft)|fraghdr\.(nxt|reserved_octet|offset|reserved_bits|more|ident)|opt(\.(type(\.(action|change|rest))?|length|padn|pad1|router_alert|jumbo|tel|mipv6\.home_address|unknown))?)$/;

function ours(fields: readonly ProtocolField[], out: string[] = []): string[] {
  for (const f of fields) {
    if (f.abbrev !== undefined && ROWS.test(f.abbrev)) {
      out.push(`${f.abbrev}=${f.value === '' ? f.name : String(f.value)}`);
    }
    if (f.children) ours(f.children, out);
  }
  return out;
}

const pcap = pcapOf(CASES.map((c) => c.frame));
const { packets } = await PcapService.parseCaptureFile(new File([pcap], 'ipv6-ext.pcap'), Number.POSITIVE_INFINITY, true);
check(`every frame dissected (${CASES.length})`, packets.length === CASES.length);
check('every frame reaches its UDP header past the chain', packets.every((p) => (p.frameProtocols ?? []).includes('udp')));

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found - the headers were walked; whether as the reference draws them was not checked');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-ipv6-ext-'));
  try {
    const file = join(dir, 'ext.pcap');
    writeFileSync(file, pcap);
    const pdml = spawnSync(tshark, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 })
      .stdout.split('<packet>').slice(1);
    check('the reference read every frame', pdml.length === CASES.length);
    const unescape = (v: string) => v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
    CASES.forEach((c, i) => {
      const theirs: string[] = [];
      for (const m of pdml[i].matchAll(/<field name="(ipv6\.[a-z0-9_.]+)" showname="([^"]*)"/g)) {
        if (!ROWS.test(m[1])) continue;
        const shown = unescape(m[2]);
        theirs.push(`${m[1]}=${shown.includes(': ') ? shown.slice(shown.indexOf(': ') + 2) : shown}`);
      }
      const mine = packets[i].layers.flatMap((l) => ours(l.fields));
      const differ = mine.length !== theirs.length || mine.some((row, k) => row !== theirs[k]);
      check(`${c.label}: every header and option row matches the reference`, !differ,
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
console.log('All IPv6 extension header checks passed.');
process.exit(0);
