/**
 * Ground truth for protocols the fixtures do not contain.
 *
 *   npx tsx scripts/parity/synthetic.ts
 *
 * The two parity fixtures are personal desktop captures: browser TLS/QUIC, a
 * game client, LAN housekeeping. Measured, they hold **18 distinct protocols
 * and every one is already dissected** - so `parity-check.ts` can say nothing
 * at all about a new dissector. A test whose expectations are the author's own
 * reading of an RFC is a test of the author, not of the code.
 *
 * So this builds each frame byte by byte from its RFC's own example, writes a
 * real `.pcap`, and asks **tshark** what is in it. Same oracle as the fixture
 * harness, same exact-string comparison of the Protocol and Info columns; only
 * the provenance of the bytes differs. A dissector that disagrees with
 * Wireshark on a frame Wireshark can read is wrong, whether or not that frame
 * ever crossed this machine.
 *
 * Frames use RFC 5737 (`192.0.2.0/24`) and RFC 3849 (`2001:db8::/32`)
 * documentation addresses, as `scripts/dns/records.ts` does, so nothing here
 * is real traffic and nothing needs to be kept out of git.
 *
 * Skips cleanly - it does not fail - when tshark is not installed, because it
 * is the one assertion script in the repo with an external dependency.
 */
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Where tshark is.
 *
 * Not on PATH in the environment this was written in, so the standard Windows
 * install location is tried too. `TSHARK` overrides both.
 */
const TSHARK_CANDIDATES = [
  process.env.TSHARK,
  'tshark',
  'C:\\Program Files\\Wireshark\\tshark.exe',
  '/usr/bin/tshark',
  '/usr/local/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  for (const candidate of TSHARK_CANDIDATES) {
    const probe = spawnSync(candidate, ['-v'], { encoding: 'utf8', shell: false });
    if (probe.status === 0) return candidate;
  }
  return null;
}

// --- building frames ---------------------------------------------------------

/**
 * A byte builder, the same shape `scripts/dns/records.ts` uses.
 *
 * Deliberately dumb: every field is written explicitly, so a test frame reads
 * as the RFC's packet diagram rather than as a call to a helper that might be
 * wrong in the same way the dissector is.
 */
export class Bytes {
  private out: number[] = [];

  u8(...values: number[]): this { this.out.push(...values.map((v) => v & 0xff)); return this; }
  u16(...values: number[]): this {
    for (const v of values) this.out.push((v >> 8) & 0xff, v & 0xff);
    return this;
  }
  u32(...values: number[]): this {
    for (const v of values) this.out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    return this;
  }
  raw(bytes: ArrayLike<number>): this { this.out.push(...Array.from(bytes)); return this; }
  ascii(text: string): this { for (const c of text) this.out.push(c.charCodeAt(0) & 0xff); return this; }
  /** Dotted quad. */
  ipv4(text: string): this { return this.u8(...text.split('.').map(Number)); }
  /** Colon-separated MAC. */
  mac(text: string): this { return this.u8(...text.split(':').map((h) => parseInt(h, 16))); }
  zeros(n: number): this { for (let i = 0; i < n; i++) this.out.push(0); return this; }

  get length(): number { return this.out.length; }
  at(index: number): number { return this.out[index]; }
  /** Patches a 16-bit big-endian value already written - for length and checksum fields. */
  patch16(index: number, value: number): this {
    this.out[index] = (value >> 8) & 0xff;
    this.out[index + 1] = value & 0xff;
    return this;
  }
  build(): Uint8Array { return Uint8Array.from(this.out); }
}

/** The standard Internet checksum (RFC 1071) over a byte range. */
export function internetChecksum(bytes: ArrayLike<number>, start = 0, end?: number): number {
  const stop = end ?? bytes.length;
  let sum = 0;
  for (let i = start; i + 1 < stop; i += 2) sum += (bytes[i] << 8) | bytes[i + 1];
  if ((stop - start) % 2 === 1) sum += bytes[stop - 1] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

const MAC_SRC = '00:00:5e:00:53:01';   // RFC 7042 documentation MACs
const MAC_DST = '00:00:5e:00:53:02';

/** An Ethernet II header. */
export function ethernet(etherType: number): Bytes {
  return new Bytes().mac(MAC_DST).mac(MAC_SRC).u16(etherType);
}

/**
 * An IPv4 header with a correct length and checksum, wrapping `payload`.
 *
 * The checksum is computed rather than zeroed because `checksumVerdict` reads
 * it, and a frame that fails its own header check would be testing the
 * checksum path instead of the dissector under test.
 */
export function ipv4(
  protocol: number,
  payload: Uint8Array,
  src = '192.0.2.1',
  dst = '192.0.2.2',
): Uint8Array {
  const header = new Bytes()
    .u8(0x45, 0x00)
    .u16(20 + payload.length)
    .u16(0x0001).u16(0x0000)
    .u8(64, protocol)
    .u16(0)                       // checksum, patched below
    .ipv4(src).ipv4(dst);
  const bytes = header.build();
  const sum = internetChecksum(bytes);
  bytes[10] = (sum >> 8) & 0xff;
  bytes[11] = sum & 0xff;
  return Uint8Array.from([...bytes, ...payload]);
}

/** A UDP header with a correct length; checksum zero, which is legal on IPv4. */
export function udp(srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const header = new Bytes().u16(srcPort, dstPort, 8 + payload.length, 0).build();
  return Uint8Array.from([...header, ...payload]);
}

/** A complete Ethernet/IPv4/UDP frame. */
export function udpFrame(srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...ipv4(17, udp(srcPort, dstPort, payload)),
  ]);
}

/** A complete Ethernet/IPv4/<protocol> frame. */
export function ipFrame(protocol: number, payload: Uint8Array): Uint8Array {
  return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(protocol, payload)]);
}

// --- asking tshark -----------------------------------------------------------

/** One frame's columns, as tshark reports them. */
export interface TsharkRow {
  protocol: string;
  info: string;
}

/**
 * Writes `frames` to a `.pcap` and returns tshark's Protocol and Info columns.
 *
 * `-o tcp.desegment_tcp_streams:FALSE` is deliberately NOT set: the point is to
 * compare against Wireshark's default behaviour, which is what a user sees.
 */
export function askTshark(tshark: string, frames: Uint8Array[]): TsharkRow[] {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-synthetic-'));
  const file = join(dir, 'frames.pcap');
  try {
    writeFileSync(file, pcapOf(frames));
    const run = spawnSync(tshark, [
      '-r', file, '-T', 'fields',
      '-e', '_ws.col.Protocol', '-e', '_ws.col.Info',
      '-E', 'separator=|',
    ], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    if (run.status !== 0) throw new Error(`tshark exited ${run.status}: ${run.error ?? ''} ${run.stderr ?? ''}`.slice(0, 400));
    return run.stdout.split('\n').filter((l) => l.length > 0).map((line) => {
      const parts = line.split('|');
      return { protocol: parts[0] ?? '', info: parts.slice(1).join('|').trimEnd() };
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * A classic libpcap file, written here rather than through
 * `PcapService.generatePcapBinary`.
 *
 * The writer under test must not be the writer that builds the oracle's input:
 * a shared bug would cancel out and the comparison would pass on both sides
 * being wrong. This is twenty lines and depends on nothing.
 */
export function pcapOf(frames: Uint8Array[], linktype = 1): Uint8Array {
  const total = 24 + frames.reduce((n, f) => n + 16 + f.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);   // magic, little-endian
  view.setUint16(4, 2, true);            // version 2.4
  view.setUint16(6, 4, true);
  view.setInt32(8, 0, true);             // thiszone
  view.setUint32(12, 0, true);           // sigfigs
  view.setUint32(16, 262144, true);      // snaplen
  view.setUint32(20, linktype, true);
  let at = 24;
  frames.forEach((frame, i) => {
    view.setUint32(at, 1700000000 + i, true);       // ts_sec
    view.setUint32(at + 4, 0, true);                // ts_usec
    view.setUint32(at + 8, frame.length, true);     // incl_len
    view.setUint32(at + 12, frame.length, true);    // orig_len
    out.set(frame, at + 16);
    at += 16 + frame.length;
  });
  return out;
}

// --- the harness -------------------------------------------------------------

export interface SyntheticCase {
  /** What this frame is, for the failure line. */
  name: string;
  frame: Uint8Array;
  /**
   * Set when Wireshark's own answer is not what this app should give.
   *
   * Every use needs a reason. It exists because a handful of Inwire's columns
   * deliberately differ - and a deliberate difference belongs in the test as a
   * stated exception, not as a silently loosened comparison.
   */
  expectProtocol?: string;
  expectInfo?: string;
}

let failures = 0;

export function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

export function failureCount(): number { return failures; }

/**
 * Runs every case through both this app and tshark and compares the columns.
 *
 * The app side goes through the real `decodeRawEthernetPacket`, not a
 * reimplementation, for the same reason the fixture harness does.
 */
export async function runCases(cases: SyntheticCase[]): Promise<void> {
  const tshark = findTshark();
  if (tshark === null) {
    console.log('SKIP  tshark not found - set TSHARK to its path to run these checks.');
    console.log('      (Tried: ' + TSHARK_CANDIDATES.join(', ') + ')');
    process.exit(0);
  }
  console.log(`Oracle: ${tshark}\n`);

  const { decodeRawEthernetPacket } = await import('../../src/services/pcapParser');
  const reference = askTshark(tshark, cases.map((c) => c.frame));
  if (reference.length !== cases.length) {
    console.log(`FAIL  tshark read ${reference.length} frames of ${cases.length}`);
    process.exit(1);
  }

  cases.forEach((testCase, i) => {
    const { packet } = decodeRawEthernetPacket(
      testCase.frame, i + 1, 1_700_000_000_000_000 + i * 1_000_000, i, i === 0 ? 0 : 1,
      testCase.frame.length,
    );
    const ours = { protocol: packet.protocolLabel ?? packet.protocol, info: packet.info };
    check(`${testCase.name}: Protocol`, ours.protocol,
      testCase.expectProtocol ?? reference[i].protocol);
    check(`${testCase.name}: Info`, ours.info,
      testCase.expectInfo ?? reference[i].info);
  });
}

/** Ends a synthetic suite. */
export function finish(label: string): never {
  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log(`All ${label} checks passed.`);
  process.exit(0);
}

// Running this file directly is a self-test of the harness: one frame the app
// has decoded since long before this existed, so a failure here is the harness
// and not a dissector.
if (process.argv[1]?.replace(/\\/g, '/').endsWith('scripts/parity/synthetic.ts')) {
  const dnsQuery = new Bytes()
    .u16(0x1234).u16(0x0100).u16(1, 0, 0, 0)
    .u8(7).ascii('example').u8(3).ascii('com').u8(0)
    .u16(1, 1)
    .build();
  runCases([
    { name: 'a DNS query over UDP', frame: udpFrame(50000, 53, dnsQuery) },
  ]).then(() => finish('synthetic harness self-test'));
}
