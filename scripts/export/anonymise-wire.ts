/**
 * Anonymised frames, checked byte for byte against the real captures.
 *
 *   npx tsx scripts/export/anonymise-wire.ts
 *
 * `anonymise.ts` beside this checks the anonymiser's properties. This checks
 * the one claim a person sharing a file relies on - **no identifier from the
 * capture is anywhere in the anonymised bytes** - and it asks somebody other
 * than the anonymiser what the identifiers are. tshark lists every value of
 * every IPv4, IPv6 and Ethernet-address field of every protocol in the capture
 * (`tshark -G fields`, filtered by type): headers, ARP, Neighbor Discovery
 * targets and link-layer options, Router Advertisement prefixes and DNS
 * servers, MLD and IGMP sources, the packet an ICMP error quotes, spanning
 * tree bridge ids, LLDP, IEEE 1905, and every DNS answer. Each one the
 * anonymiser is meant to rewrite is then searched for, as a byte sequence, in
 * every anonymised frame. So is each global IPv6 address's /64, and each
 * name a link-layer discovery protocol carries.
 *
 * The rewrite used to stop at the transport header and return early for
 * anything that was not TCP or UDP, on the belief that "ICMP, IGMP and the
 * rest are header-only in practice". A Neighbor Advertisement carries the
 * machine's MAC in an option; that belief shipped it in every anonymised file.
 *
 * Then the file has to still be a network: tshark reads the anonymised pcapng
 * with every checksum check on, and it may raise no checksum or malformed
 * finding the original did not have; every ND, RA, MLD, ICMP and discovery
 * frame still dissects as what it was; and the addresses that name each other
 * still agree - a Neighbor Advertisement's target is its source, a Neighbor
 * Solicitation goes to its target's solicited-node group, and the packet an
 * ICMP error quotes came from the host the error is sent to.
 *
 * Real captures only (ADR 0004), including the optional `icmpErrors` one; each
 * is skipped cleanly when absent, and everything needs tshark.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Anonymiser, anonymiseCapture, parseIpv4, parseIpv6 } from '../../src/services/anonymise';
import { generatePcapNg } from '../../src/services/pcapngWriter';
import { PcapService } from '../../src/services/pcapParser';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { findWiresharkTool, loadRealCaptures, runTool } from './realCaptures';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 600));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 600));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** Every tshark run turns on the checks a default run leaves off. */
const CHECKSUMS = ['-o', 'ip.check_checksum:TRUE', '-o', 'tcp.check_checksum:TRUE', '-o', 'udp.check_checksum:TRUE'];

const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;

interface Identifier { kind: string; text: string; bytes: Uint8Array }

function hexBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * The address-typed fields of every protocol in `file`, and the text fields
 * of the link-layer discovery protocols - the reference's vocabulary, not
 * this build's.
 */
function referenceFields(tshark: string, file: string): { addresses: string[]; names: string[] } {
  const protocols = new Set(runTool(tshark, ['-n', '-r', file, '-T', 'fields', '-e', 'frame.protocols'])
    .split(/\r?\n/).flatMap((l) => l.trim().split(':')).filter((p) => p !== ''));
  const addresses: string[] = [];
  const names: string[] = [];
  for (const line of runTool(tshark, ['-G', 'fields']).split(/\r?\n/)) {
    const [kind, , abbrev, type, protocol] = line.split('\t');
    if (kind !== 'F' || !protocols.has(protocol)) continue;
    if (type === 'FT_IPv4' || type === 'FT_IPv6' || type === 'FT_ETHER') addresses.push(abbrev);
    else if ((type === 'FT_STRING' || type === 'FT_STRINGZ') && (protocol === 'lldp' || protocol === 'ieee1905')) names.push(abbrev);
  }
  // A locally assigned chassis id is bytes to tshark and a machine's name to a reader.
  if (protocols.has('lldp')) names.push('lldp.chassis.id');
  return { addresses, names };
}

/** Every value tshark gives for `fields`, over the whole file. */
function valuesOf(tshark: string, file: string, fields: readonly string[]): Set<string> {
  const values = new Set<string>();
  if (fields.length === 0) return values;
  const out = runTool(tshark, [
    '-n', '-r', file, '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=|', '-E', 'separator=|',
    ...fields.flatMap((f) => ['-e', f]),
  ]);
  for (const line of out.split(/\r?\n/)) {
    for (const value of line.split('|')) if (value.trim() !== '') values.add(value.trim());
  }
  return values;
}

/**
 * What the anonymiser must remove: every address it would rewrite (a probe
 * with its own key decides - multicast, broadcast and the unspecified address
 * are left alone on purpose), each global IPv6 address's /64, and the names.
 */
function identifiersOf(tshark: string, file: string): { identifiers: Identifier[]; addressFields: string[] } {
  const { addresses, names } = referenceFields(tshark, file);
  const probe = new Anonymiser();
  const found = new Map<string, Identifier>();
  const add = (kind: string, text: string, bytes: Uint8Array) => {
    const key = Buffer.from(bytes).toString('hex');
    if (!found.has(key)) found.set(key, { kind, text, bytes });
  };
  for (const value of valuesOf(tshark, file, addresses)) {
    const lower = value.toLowerCase();
    if (MAC.test(value)) {
      if (probe.mac(lower) !== lower) add('MAC', lower, hexBytes(lower));
    } else if (parseIpv4(value)) {
      if (probe.ipv4Address(value) !== value) add('IPv4', value, parseIpv4(value)!);
    } else if (value.includes(':')) {
      const raw = parseIpv6(lower);
      if (raw === null || probe.ipv6Address(lower) === lower) continue;
      add('IPv6', lower, raw);
      // A global unicast address's /64 is the household's allocation, and
      // survives in any prefix that was passed through.
      if ((raw[0] & 0xe0) === 0x20) add('IPv6 /64', `${lower} /64`, raw.slice(0, 8));
    }
  }
  for (const value of valuesOf(tshark, file, names)) {
    const bytes = /^[0-9a-f]+$/i.test(value) && value.length % 2 === 0 ? hexBytes(value) : new TextEncoder().encode(value);
    if (bytes.length >= 4) add('name', value, bytes);
  }
  return { identifiers: [...found.values()], addressFields: addresses };
}

interface Hit { id: Identifier; frame: number; offset: number }

/** Every place an identifier occurs in `frames`: the frame's position and the byte offset. */
function occurrences(frames: readonly Packet[], identifiers: readonly Identifier[]): Hit[] {
  // Indexed by the first four bytes, so a frame is walked once whatever the
  // number of identifiers. One whose first four bytes are zero would match
  // every run of zeroed payload; there are none among real addresses.
  const byPrefix = new Map<number, Identifier[]>();
  for (const id of identifiers) {
    const key = ((id.bytes[0] << 24) | (id.bytes[1] << 16) | (id.bytes[2] << 8) | id.bytes[3]) >>> 0;
    if (key === 0) continue;
    const list = byPrefix.get(key);
    if (list) list.push(id); else byPrefix.set(key, [id]);
  }
  const hits: Hit[] = [];
  frames.forEach((frame, index) => {
    const b = frame.rawBytes;
    for (let i = 0; i + 4 <= b.length; i++) {
      const key = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      if (key === 0) continue;
      const candidates = byPrefix.get(key);
      if (candidates === undefined) continue;
      for (const id of candidates) {
        if (i + id.bytes.length > b.length) continue;
        let same = true;
        for (let k = 4; k < id.bytes.length && same; k++) same = b[i + k] === id.bytes[k];
        if (same) hits.push({ id, frame: index, offset: i });
      }
    }
  });
  return hits;
}

/**
 * Whether a short hit is an address or bytes that happen to spell one.
 *
 * Six and sixteen bytes do not happen by accident; four do, and so does a
 * /64 like Cloudflare's 2606:4700::, which is four bytes and four zeros. Frame 916
 * of the `inwire` fixture is an ICMP echo whose IP identification ends in
 * 0x0a, whose flags are zero and whose TTL is 255 - `0a 00 00 ff`, which is
 * 10.0.0.255, a real address in that capture, in bytes this module
 * deliberately keeps. So an IPv4 hit counts as a leak only when tshark says
 * the ORIGINAL frame had an address field at exactly that offset: the bytes
 * were an address, and they still are the same address.
 */
function addressFieldAt(tshark: string, file: string, hits: readonly Hit[], frames: readonly Packet[],
  addressFields: ReadonlySet<string>): Set<Hit> {
  const confirmed = new Set<Hit>();
  const numbers = [...new Set(hits.map((h) => frames[h.frame].id))];
  const positions = new Map<number, Set<string>>();
  for (let i = 0; i < numbers.length; i += 200) {
    const pdml = runTool(tshark, ['-n', '-r', file, '-Y', `frame.number in {${numbers.slice(i, i + 200).join(', ')}}`, '-T', 'pdml']);
    let current = -1;
    for (const line of pdml.split(/\r?\n/)) {
      const frame = /<field name="num"[^>]*show="(\d+)"/.exec(line);
      if (frame) { current = Number(frame[1]); positions.set(current, new Set()); continue; }
      const field = /<field name="([^"]+)"[^>]*\bsize="(\d+)"[^>]*\bpos="(\d+)"/.exec(line);
      if (field && current >= 0 && addressFields.has(field[1])) positions.get(current)!.add(`${field[3]}+${field[2]}`);
    }
  }
  for (const hit of hits) {
    // A /64 is confirmed by an IPv6 field (sixteen bytes) starting where it does.
    const size = hit.id.kind === 'IPv6 /64' ? 16 : hit.id.bytes.length;
    if (positions.get(frames[hit.frame].id)?.has(`${hit.offset}+${size}`)) confirmed.add(hit);
  }
  return confirmed;
}

/**
 * Checksum and malformed findings by what they say, with the numbers taken
 * out - "Bad checksum [should be 0xc865]" is one finding whatever it should
 * have been.
 */
function damage(tshark: string, file: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of runTool(tshark, ['-n', '-r', file, '-q', ...CHECKSUMS, '-z', 'expert']).split(/\r?\n/)) {
    const m = /^\s*(\d+)\s+(Checksum|Malformed)\s+(\S+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const key = `${m[2]} ${m[3]}: ${m[4].replace(/\[[^\]]*\]/g, '').replace(/0x[0-9a-f]+/gi, '#').trim()}`;
    out.set(key, (out.get(key) ?? 0) + Number(m[1]));
  }
  return out;
}

/** How many frames of each kind tshark finds: protocols, and ICMP / ICMPv6 / IGMP message types. */
function kinds(tshark: string, file: string): Record<string, number> {
  const out: Record<string, number> = {};
  const lines = runTool(tshark, ['-n', '-r', file, '-T', 'fields', '-E', 'separator=|',
    '-e', 'frame.protocols', '-e', 'icmp.type', '-e', 'icmpv6.type', '-e', 'igmp.type']).split(/\r?\n/);
  for (const line of lines) {
    if (line.trim() === '') continue;
    const [protocols, icmp, icmpv6, igmp] = line.split('|');
    const stack = new Set(protocols.split(':'));
    for (const p of ['arp', 'icmp', 'icmpv6', 'igmp', 'stp', 'lldp', 'ieee1905', 'ipv6.hopopts']) {
      if (stack.has(p)) out[p] = (out[p] ?? 0) + 1;
    }
    if (icmp) out[`icmp type ${icmp}`] = (out[`icmp type ${icmp}`] ?? 0) + 1;
    if (icmpv6) out[`icmpv6 type ${icmpv6}`] = (out[`icmpv6 type ${icmpv6}`] ?? 0) + 1;
    if (igmp) out[`igmp type ${igmp}`] = (out[`igmp type ${igmp}`] ?? 0) + 1;
  }
  return out;
}

/** Rows of `fields` for the frames `filter` selects, each field's occurrences joined by `,`. */
function rows(tshark: string, file: string, filter: string, fields: readonly string[]): string[][] {
  return runTool(tshark, ['-n', '-r', file, '-Y', filter, '-T', 'fields', '-E', 'separator=|',
    ...fields.flatMap((f) => ['-e', f])])
    .split(/\r?\n/).filter((l) => l.trim() !== '').map((l) => l.split('|'));
}

/** The low 24 bits of an IPv6 address, as the last three groups of hex. */
function low24(address: string): string {
  const raw = parseIpv6(address);
  return raw ? Buffer.from(raw.subarray(13)).toString('hex') : '';
}

async function main() {
  const tshark = findWiresharkTool('tshark');
  if (tshark === null) {
    console.log('SKIP  tshark not found - it is the independent list of what the capture identifies');
    process.exit(0);
  }
  const captures = await loadRealCaptures(['icmpErrors']);
  if (captures.length === 0) {
    console.log('SKIP  no fixtures present');
    process.exit(0);
  }
  const scratch = mkdtempSync(join(tmpdir(), 'inwire-anonymise-wire-'));

  try {
    for (const { name, path, packets } of captures) {
      console.log(`\n--- ${name}: ${packets.length} frames ---\n`);
      const { identifiers, addressFields } = identifiersOf(tshark, path);
      const byKind = (list: Iterable<Identifier>) => {
        const out: Record<string, number> = {};
        for (const id of list) out[id.kind] = (out[id.kind] ?? 0) + 1;
        return out;
      };
      console.log(`      ${identifiers.length} identifiers from tshark: ${JSON.stringify(byKind(identifiers))}`);

      // The scan has to be able to see them before its silence means anything.
      const before = occurrences(packets, identifiers);
      checkTrue(`${name}: the original frames carry the identifiers the scan looks for`,
        ['MAC', 'IPv4', 'IPv6'].every((k) => !identifiers.some((i) => i.kind === k)
          || before.some((h) => h.id.kind === k)));

      const { packets: anonymised, summary } = anonymiseCapture(packets);
      const after = occurrences(anonymised, identifiers);
      // IPv4 addresses and /64s are confirmed against tshark's field offsets; see ddressFieldAt.
      const short = (h: Hit) => h.id.kind === 'IPv4' || h.id.kind === 'IPv6 /64';
      const fourByte = after.filter(short);
      const confirmed = addressFieldAt(tshark, path, fourByte, packets, new Set(addressFields));
      const leaks = after.filter((h) => !short(h) || confirmed.has(h));
      const leaked = [...new Set(leaks.map((h) => `${h.id.kind} ${h.id.text}`))].map((what) => {
        const where = leaks.filter((h) => `${h.id.kind} ${h.id.text}` === what);
        return `${what} in ${new Set(where.map((h) => h.frame)).size} frame(s), first #${packets[where[0].frame].id} at byte ${where[0].offset}`;
      });
      if (fourByte.length > confirmed.size) {
        console.log(`      ${fourByte.length - confirmed.size} short hit(s) where tshark has no address field - coincidences, not leaks`);
      }
      check(`${name}: no identifier from the capture is anywhere in any anonymised frame`, leaked, []);
      checkTrue(`${name}: ...and the anonymiser says it removed payload`, summary.payloadsStripped > 0);

      const file = join(scratch, `${name}.anonymised.pcapng`);
      writeFileSync(file, new Uint8Array(await generatePcapNg(anonymised).arrayBuffer()));

      // ---- still a network -------------------------------------------------
      const realDamage = damage(tshark, path);
      const newDamage = damage(tshark, file);
      const worse = [...newDamage.entries()]
        .filter(([key, count]) => count > (realDamage.get(key) ?? 0))
        .map(([key, count]) => `${key}: ${realDamage.get(key) ?? 0} -> ${count}`);
      check(`${name}: tshark finds no checksum or malformed finding the original did not have`, worse, []);

      const realKinds = kinds(tshark, path);
      check(`${name}: every ND, RA, MLD, ICMP, IGMP and discovery frame still dissects as what it was`,
        kinds(tshark, file), realKinds);

      // Re-read by the app's own parser, too - what a recipient opening the
      // file in Inwire would see.
      const back = (await PcapService.parseCaptureFile(
        new File([new Uint8Array(await generatePcapNg(anonymised).arrayBuffer())], 'a.pcapng'), Number.POSITIVE_INFINITY,
      )).packets;
      const icmpv6Types = (frames: readonly Packet[]) => frames
        .map((p) => fieldValue(p, 'icmpv6.type')).filter((t) => t !== undefined).map(Number).sort((a, b) => a - b);
      check(`${name}: ...and the app's own dissector reads the same ICMPv6 messages back`,
        icmpv6Types(back), icmpv6Types(packets));

      // ---- the addresses still name each other -----------------------------
      if (realKinds['icmpv6 type 136']) {
        const agree = (f: string) => rows(tshark, f, 'icmpv6.type == 136', ['ipv6.src', 'icmpv6.nd.na.target_address'])
          .filter(([src, target]) => src === target).length;
        const agreeing = agree(path);
        checkTrue(`${name}: the capture has Neighbor Advertisements whose target is their sender`, agreeing > 0);
        check(`${name}: ...and they still are, under their pseudonyms`, agree(file), agreeing);
      }
      if (realKinds['icmpv6 type 135']) {
        const toGroup = (f: string) => rows(tshark, f, 'icmpv6.type == 135 && ipv6.dst == ff02::1:ff00:0/104',
          ['ipv6.dst', 'icmpv6.nd.ns.target_address', 'eth.dst'])
          .filter(([dst, target, mac]) => low24(dst) === low24(target) && mac.endsWith(low24(target).replace(/(..)(..)(..)/, '$1:$2:$3')))
          .length;
        const multicast = toGroup(path);
        if (multicast === 0) console.log(`SKIP  ${name}: no Neighbor Solicitation here is sent to its target's solicited-node group`);
        else check(`${name}: ...and they still are, IPv6 and Ethernet both`, toGroup(file), multicast);
      }
      for (const [filter, outer, inner] of [
        ['icmp.type == 11', 'ip.dst', 'ip.src'],
        ['icmpv6.type == 3', 'ipv6.dst', 'ipv6.src'],
      ] as const) {
        const quoted = (f: string) => rows(tshark, f, filter, [outer, inner])
          // The first occurrence is the outer header, the second the quoted one.
          .filter(([dsts, srcs]) => srcs.split(',')[1] !== undefined && srcs.split(',')[1] === dsts.split(',')[0]).length;
        const real = quoted(path);
        if (real === 0) continue;
        check(`${name}: an ICMP error (${filter}) still quotes a packet from the host it is sent to`, quoted(file), real);
      }
      if (realKinds['icmpv6 type 134']) {
        // Crypto-PAn keeps prefixes, so an advertised /64 is the /64 its
        // hosts' pseudonyms are in. Every address in the file is searched: a
        // pseudonym can be anywhere in the space, 2000::/3 or not.
        const covered = (f: string) => {
          const prefixes = rows(tshark, f, 'icmpv6.type == 134', ['icmpv6.opt.prefix']).flat().join(',').split(',').filter(Boolean);
          const hosts = [...new Set(rows(tshark, f, 'ipv6', ['ipv6.addr']).flat().join(',').split(','))].filter(Boolean);
          return prefixes.filter((p) => hosts.some((h) => parseIpv6(h)!.subarray(0, 8).every((byte, i) => byte === parseIpv6(p)![i]))).length;
        };
        const real = covered(path);
        if (real === 0) console.log(`SKIP  ${name}: no host here is in the prefix its Router Advertisement names`);
        else check(`${name}: an advertised prefix is still the /64 of the hosts in it`, covered(file), real);
      }
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All anonymised-wire assertions passed.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  anonymise-wire threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
