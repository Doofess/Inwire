/**
 * The measurements behind ADRs 0058-0060: what a NetFlow v5 collector costs
 * here, before any of it is built.
 *
 *   npx tsx scripts/monitoring/measurement.ts socket            (needs the agent)
 *   npx tsx scripts/monitoring/measurement.ts journal [--quick]
 *   npx tsx scripts/monitoring/measurement.ts rollup  [--quick]
 *   npx tsx scripts/monitoring/measurement.ts vector
 *   npx tsx scripts/monitoring/measurement.ts firewall --electron <electron.exe> [--port n] [--seconds n] [--shot png] [--nic regex] [--listen-only]
 *   npx tsx scripts/monitoring/measurement.ts bindpair --electron <electron.exe>
 *   npx tsx scripts/monitoring/measurement.ts softflowd --pcap <capture> [--port n]
 *
 * Not a test: every number is a property of the machine it ran on, and the
 * journal mode writes about 2.7 GB under the OS temp folder (and deletes it).
 * `--quick` shrinks the day and week to an hour each, for trying the script.
 * `firewall` needs the agent, WSL's Ubuntu with python3, and a person to
 * answer the prompt: it binds `firewall-probe.cjs` under the given Electron on
 * the WSL adapter's address, sends to it from WSL, and prints what was sent,
 * what reached the adapter and what reached the socket, second by second. A
 * fresh copy of Electron's dist folder per run is a program with no rule yet.
 * `--nic` binds another adapter (Ethernet, for a real exporter on the LAN) and
 * `--listen-only` sends nothing, counting what an exporter elsewhere sends.
 * `bindpair` binds the wildcard beside a specific address, under an Electron
 * whose rules already say Allow. `softflowd` replays a capture through
 * softflowd in WSL and holds `normalizeFlows` to tshark on what it exported.
 * In `check.ts`'s NOT_TESTS.
 *
 * The journal framing and the rollup codec here are prototypes of the ones
 * ADR 0059 pins; product code is written against that ADR under its own tests.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { connect } from 'node:net';
import { networkInterfaces, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { crc32 as zlibCrc32, deflateSync, constants as zlibConstants } from 'node:zlib';
import { FRAME_JSON, FrameReader, encodeFrame } from '../../src/services/agentFraming';
import { decodePacketBatch } from '../../src/services/agentBinary';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { MemoryTemplateStore, normalizeFlows } from '../../src/services/flow/flowExport';

const mode = process.argv[2] ?? 'help';
const quick = process.argv.includes('--quick');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const fmt = (n: number, d = 1) => n.toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d });
const MB = 1024 * 1024;

// --- CRC-32 (ISO-HDLC, the zlib/PNG/Ethernet one) ------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes: Uint8Array, seed = 0): number {
  let c = ~seed >>> 0;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

// --- Prototype journal framing (ADR 0059) -------------------------------------

const FILE_MAGIC = new TextEncoder().encode('INWIREMJ');
const FILE_HEADER_BYTES = 64;
const ENTRY_MAGIC = 0x454a5749; // "IWJE" read little-endian
const ENTRY_HEADER_BYTES = 24;
const DATAGRAM_META_BYTES = 24;
const KIND_DATAGRAM = 1;
const KIND_BOUNDARY = 2;
const MAX_DATAGRAM_PAYLOAD = 65_507; // IPv4's largest UDP payload

function fileHeader(generation: Uint8Array, createdMs: number, policyVersion = 1): Uint8Array {
  const b = new Uint8Array(FILE_HEADER_BYTES);
  const v = new DataView(b.buffer);
  b.set(FILE_MAGIC, 0);
  v.setUint16(8, 1, true); // format version
  v.setUint16(10, policyVersion, true);
  v.setUint32(12, FILE_HEADER_BYTES, true);
  b.set(generation, 16);
  v.setBigUint64(32, BigInt(createdMs), true);
  v.setUint32(60, crc32(b.subarray(0, 60)), true);
  return b;
}

/** One framed entry: header, then body; the CRC covers header[0,20) and the body. */
function entry(entryId: number, kind: number, body: Uint8Array, crc: (b: Uint8Array, seed?: number) => number = crc32): Uint8Array {
  const out = new Uint8Array(ENTRY_HEADER_BYTES + body.length);
  const v = new DataView(out.buffer);
  v.setUint32(0, ENTRY_MAGIC, true);
  v.setUint32(4, body.length, true);
  v.setBigUint64(8, BigInt(entryId), true);
  out[16] = kind;
  out.set(body, ENTRY_HEADER_BYTES);
  v.setUint32(20, crc(out.subarray(ENTRY_HEADER_BYTES), crc(out.subarray(0, 20))), true);
  return out;
}

const ipv4Bytes = (s: string) => s.split('.').map(Number);
function datagramBody(receivedMs: number, local: [string, number], remote: [string, number], payload: Uint8Array): Uint8Array {
  const b = new Uint8Array(DATAGRAM_META_BYTES + payload.length);
  const v = new DataView(b.buffer);
  v.setBigUint64(0, BigInt(receivedMs), true);
  b.set(ipv4Bytes(local[0]), 8);
  v.setUint16(12, local[1], true);
  b.set(ipv4Bytes(remote[0]), 14);
  v.setUint16(18, remote[1], true);
  // 20..24 reserved
  b.set(payload, DATAGRAM_META_BYTES);
  return b;
}

interface ScannedEntry { offset: number; entryId: number; kind: number; bodyLength: number }

/**
 * Reads every entry from `file`, verifying each CRC unless told not to, in
 * reads of `chunk` bytes. Calls `onEntry` with a view valid only for the call.
 */
function scanJournal(
  file: NodeBlockFile, verify: boolean, onEntry?: (e: ScannedEntry, body: Uint8Array) => void, chunk = 4 * MB,
): { entries: number; bad: number; tornTail: boolean } {
  const size = file.size();
  const buf = new Uint8Array(chunk + 70_000);
  let base = FILE_HEADER_BYTES;
  let have = 0;
  let pos = 0;
  let entries = 0;
  let bad = 0;
  for (;;) {
    if (have - pos < ENTRY_HEADER_BYTES + 65_600 && base + have < size) {
      buf.copyWithin(0, pos, have);
      base += pos;
      have -= pos;
      pos = 0;
      have += file.read(base + have, buf.subarray(have, Math.min(buf.length, have + chunk)));
    }
    if (pos === have) return { entries, bad, tornTail: false };
    if (have - pos < ENTRY_HEADER_BYTES) return { entries, bad, tornTail: true };
    const v = new DataView(buf.buffer, buf.byteOffset + pos);
    if (v.getUint32(0, true) !== ENTRY_MAGIC) return { entries, bad: bad + 1, tornTail: false };
    const bodyLength = v.getUint32(4, true);
    if (pos + ENTRY_HEADER_BYTES + bodyLength > have) return { entries, bad, tornTail: true };
    const body = buf.subarray(pos + ENTRY_HEADER_BYTES, pos + ENTRY_HEADER_BYTES + bodyLength);
    if (verify && crc32(body, crc32(buf.subarray(pos, pos + 20))) !== v.getUint32(20, true)) bad++;
    onEntry?.({ offset: base + pos, entryId: Number(v.getBigUint64(8, true)), kind: buf[pos + 16], bodyLength }, body);
    entries++;
    pos += ENTRY_HEADER_BYTES + bodyLength;
  }
}

// --- A traffic model ------------------------------------------------------------

/** A small deterministic PRNG, so a run is repeatable. */
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
  };
}

interface FlowRec {
  src: number; dst: number; sport: number; dport: number; proto: number;
  octets: number; packets: number; firstMs: number; lastMs: number;
}

/**
 * Twelve hosts behind one exporter. Flows arrive as a Poisson process; 70% are
 * short (DNS, a QUIC handshake), 25% last ~20 s, 5% ~10 minutes. Each export
 * is two unidirectional v5 records, sent at the flow's end plus every active
 * timeout (60 s) while it lasts. The arrival rate is set so that records reach
 * `datagramsPerSecond` full 30-record datagrams. `highCardinality` replaces
 * every record with a fresh random 5-tuple: a scan, or a flood.
 */
class TrafficModel {
  private readonly rand: () => number;
  private readonly due = new Map<number, FlowRec[]>();
  private readonly remotes: number[] = [];
  private readonly zipf: number[] = [];
  private readonly flowsPerSecond: number;
  readonly hosts = Array.from({ length: 12 }, (_, i) => (10 << 24) | (0 << 16) | (0 << 8) | (10 + i));
  private readonly router = (10 << 24) | 1;

  constructor(readonly datagramsPerSecond: number, readonly highCardinality: boolean, seed = 7) {
    this.rand = rng(seed);
    for (let i = 0; i < 2000; i++) this.remotes.push(((23 + (i % 180)) << 24) | ((this.rand() * 2 ** 24) >>> 0));
    let total = 0;
    for (let i = 0; i < this.remotes.length; i++) { total += 1 / (i + 1) ** 1.1; this.zipf.push(total); }
    for (let i = 0; i < this.zipf.length; i++) this.zipf[i] /= total;
    // Expected records per flow: two per export, exports = 1 + floor(duration / 60 s).
    const exportsPerFlow = 0.7 * 1 + 0.25 * (1 + 20 / 60 * 0.5) + 0.05 * (1 + 600 / 60);
    this.flowsPerSecond = (datagramsPerSecond * 30) / (2 * exportsPerFlow);
  }

  get arrivalRate(): number { return this.flowsPerSecond; }

  private remote(): number {
    const u = this.rand();
    let lo = 0;
    let hi = this.zipf.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (this.zipf[mid] < u) lo = mid + 1; else hi = mid; }
    return this.remotes[lo];
  }

  private poisson(lambda: number): number {
    if (lambda > 30) return Math.max(0, Math.round(lambda + Math.sqrt(lambda) * this.gauss()));
    const l = Math.exp(-lambda);
    let k = 0;
    for (let p = this.rand(); p > l; p *= this.rand()) k++;
    return k;
  }

  private gauss(): number {
    return Math.sqrt(-2 * Math.log(this.rand() || 1e-12)) * Math.cos(2 * Math.PI * this.rand());
  }

  private schedule(atSecond: number, rec: FlowRec): void {
    const list = this.due.get(atSecond);
    if (list === undefined) this.due.set(atSecond, [rec]);
    else list.push(rec);
  }

  /** The records an exporter emits during second `t` (epoch seconds). */
  second(t: number): FlowRec[] {
    if (this.highCardinality) {
      const n = this.poisson(this.datagramsPerSecond * 30);
      const out: FlowRec[] = [];
      for (let i = 0; i < n; i++) {
        out.push({
          src: (this.rand() * 2 ** 32) >>> 0, dst: this.hosts[(this.rand() * 12) | 0],
          sport: (this.rand() * 65536) | 0, dport: (this.rand() * 65536) | 0, proto: this.rand() < 0.5 ? 6 : 17,
          octets: 40 + ((this.rand() * 100) | 0), packets: 1, firstMs: t * 1000, lastMs: t * 1000,
        });
      }
      return out;
    }
    for (let n = this.poisson(this.flowsPerSecond); n > 0; n--) {
      const host = this.hosts[(this.rand() * 12) | 0];
      const kind = this.rand();
      const duration = kind < 0.7 ? this.rand() * 2 : kind < 0.95 ? -20 * Math.log(this.rand() || 1e-9) : -600 * Math.log(this.rand() || 1e-9);
      const service = this.rand();
      const [dst, dport, proto] = service < 0.2 ? [this.router, 53, 17]
        : service < 0.62 ? [this.remote(), 443, 6]
        : service < 0.8 ? [this.remote(), 443, 17]
        : service < 0.85 ? [this.remote(), 80, 6]
        : service < 0.86 ? [this.remote(), 123, 17]
        : [this.remote(), 1024 + ((this.rand() * 64000) | 0), this.rand() < 0.5 ? 6 : 17];
      const sport = 49152 + ((this.rand() * 16384) | 0);
      const bytes = Math.exp(Math.log(dport === 53 ? 120 : 20_000) + 1.6 * this.gauss());
      const startMs = t * 1000 + ((this.rand() * 1000) | 0);
      const endMs = startMs + duration * 1000;
      for (let at = startMs + 60_000; ; at += 60_000) {
        const last = at >= endMs;
        const sliceEnd = last ? endMs : at;
        const sliceStart = at - 60_000 < startMs ? startMs : at - 60_000;
        const share = (sliceEnd - sliceStart) / Math.max(1, endMs - startMs);
        const down = Math.max(1, Math.round(bytes * share * 0.9));
        const up = Math.max(1, Math.round(bytes * share * 0.1));
        // A flow is exported when it ends plus the 15 s inactive timeout, or at each active timeout.
        const exportSecond = Math.floor((last ? endMs + 15_000 : at) / 1000);
        this.schedule(exportSecond, { src: host, dst, sport, dport, proto, octets: Math.min(up, 0xffffffff), packets: Math.max(1, Math.round(up / 600)), firstMs: sliceStart, lastMs: sliceEnd });
        this.schedule(exportSecond, { src: dst, dst: host, sport: dport, dport: sport, proto, octets: Math.min(down, 0xffffffff), packets: Math.max(1, Math.round(down / 1200)), firstMs: sliceStart, lastMs: sliceEnd });
        if (last) break;
      }
    }
    const out = this.due.get(t) ?? [];
    this.due.delete(t);
    return out;
  }
}

const BOOT_MS = 1_700_000_000_000 - 86_400_000;

/** Records as v5 datagrams of at most 30, the way an exporter packs them. */
function v5Datagrams(recs: FlowRec[], exportMs: number, seq: { n: number }, engineId = 1): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < recs.length; i += 30) {
    const batch = recs.slice(i, i + 30);
    const b = new Uint8Array(24 + 48 * batch.length);
    const v = new DataView(b.buffer);
    const uptime = (exportMs - BOOT_MS) >>> 0;
    v.setUint16(0, 5); v.setUint16(2, batch.length); v.setUint32(4, uptime);
    v.setUint32(8, Math.floor(exportMs / 1000)); v.setUint32(12, (exportMs % 1000) * 1e6);
    v.setUint32(16, seq.n >>> 0); b[20] = 0; b[21] = engineId; v.setUint16(22, 0);
    batch.forEach((r, k) => {
      const p = 24 + 48 * k;
      v.setUint32(p, r.src >>> 0); v.setUint32(p + 4, r.dst >>> 0); v.setUint32(p + 8, 0);
      v.setUint16(p + 12, 1); v.setUint16(p + 14, 2); v.setUint32(p + 16, r.packets >>> 0); v.setUint32(p + 20, r.octets >>> 0);
      v.setUint32(p + 24, (r.firstMs - BOOT_MS) >>> 0); v.setUint32(p + 28, (r.lastMs - BOOT_MS) >>> 0);
      v.setUint16(p + 32, r.sport); v.setUint16(p + 34, r.dport); b[p + 37] = r.proto === 6 ? 0x1b : 0; b[p + 38] = r.proto;
      b[p + 44] = 24; b[p + 45] = 16;
    });
    seq.n += batch.length;
    out.push(b);
  }
  return out;
}

// --- Prototype minute rollup -----------------------------------------------------

type KeyStyle = 'fiveTuple' | 'servicePort' | 'addressPair';
const KEY_STYLES: KeyStyle[] = ['fiveTuple', 'servicePort', 'addressPair'];

/** The port a conversation is "about": the well-known end, or the lower one. */
function servicePort(sport: number, dport: number): number {
  if (dport < 1024 || sport < 1024) return dport < 1024 && (sport >= 1024 || dport <= sport) ? dport : sport;
  return Math.min(sport, dport);
}

interface Rollup {
  records: number; octets: bigint; packets: bigint;
  endpoints: Map<number, [bigint, bigint]>;
  conversations: Map<string, [bigint, bigint]>;
  complete: boolean;
}
const newRollup = (): Rollup => ({ records: 0, octets: 0n, packets: 0n, endpoints: new Map(), conversations: new Map(), complete: true });

function conversationKey(style: KeyStyle, src: number, dst: number, sport: number, dport: number, proto: number): string {
  if (style === 'fiveTuple') return `${src},${dst},${sport},${dport},${proto}`;
  if (style === 'servicePort') return `${src},${dst},${servicePort(sport, dport)},${proto}`;
  return `${src},${dst}`;
}

function addToRollup(r: Rollup, style: KeyStyle, keyBudget: number, src: number, dst: number, sport: number, dport: number, proto: number, octets: bigint, packets: bigint): void {
  r.records++;
  r.octets += octets;
  r.packets += packets;
  if (!r.complete) return;
  const s = r.endpoints.get(src);
  if (s === undefined) r.endpoints.set(src, [octets, 0n]); else s[0] += octets;
  const d = r.endpoints.get(dst);
  if (d === undefined) r.endpoints.set(dst, [0n, octets]); else d[1] += octets;
  const key = conversationKey(style, src, dst, sport, dport, proto);
  const c = r.conversations.get(key);
  if (c === undefined) r.conversations.set(key, [octets, packets]); else { c[0] += octets; c[1] += packets; }
  if (r.endpoints.size + r.conversations.size > keyBudget) {
    r.complete = false;
    r.endpoints.clear();
    r.conversations.clear();
  }
}

/** Fixed-width little-endian minute record: 48-byte head, 20 B an endpoint, 29 B a conversation. */
function encodeRollup(minuteMs: number, r: Rollup, style: KeyStyle): Uint8Array {
  const convWidth = style === 'fiveTuple' ? 29 : style === 'servicePort' ? 27 : 24;
  const out = new Uint8Array(48 + r.endpoints.size * 20 + r.conversations.size * convWidth);
  const v = new DataView(out.buffer);
  out[0] = 1; out[1] = r.complete ? 1 : 0;
  v.setBigUint64(8, BigInt(minuteMs), true);
  v.setUint32(16, r.records, true);
  v.setBigUint64(20, r.octets, true);
  v.setBigUint64(28, r.packets, true);
  v.setUint32(40, r.endpoints.size, true);
  v.setUint32(44, r.conversations.size, true);
  let p = 48;
  for (const [ip, [sent, recv]] of r.endpoints) {
    v.setUint32(p, ip >>> 0, true); v.setBigUint64(p + 4, sent, true); v.setBigUint64(p + 12, recv, true); p += 20;
  }
  for (const [key, [o, pk]] of r.conversations) {
    const parts = key.split(',').map(Number);
    v.setUint32(p, parts[0] >>> 0, true); v.setUint32(p + 4, parts[1] >>> 0, true);
    let q = p + 8;
    if (style === 'fiveTuple') { v.setUint16(q, parts[2], true); v.setUint16(q + 2, parts[3], true); out[q + 4] = parts[4]; q += 5; }
    else if (style === 'servicePort') { v.setUint16(q, parts[2], true); out[q + 2] = parts[3]; q += 3; }
    v.setBigUint64(q, o, true); v.setBigUint64(q + 8, pk, true);
    p += convWidth;
  }
  return out;
}

interface DecodedRollup { minuteMs: number; complete: boolean; records: number; octets: bigint; endpoints: [number, bigint, bigint][]; conversations: [string, bigint][] }
function decodeRollup(b: Uint8Array, style: KeyStyle): DecodedRollup {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const convWidth = style === 'fiveTuple' ? 29 : style === 'servicePort' ? 27 : 24;
  const ne = v.getUint32(40, true);
  const nc = v.getUint32(44, true);
  const endpoints: [number, bigint, bigint][] = [];
  const conversations: [string, bigint][] = [];
  let p = 48;
  for (let i = 0; i < ne; i++, p += 20) endpoints.push([v.getUint32(p, true), v.getBigUint64(p + 4, true), v.getBigUint64(p + 12, true)]);
  for (let i = 0; i < nc; i++, p += convWidth) {
    const q = p + convWidth - 16;
    conversations.push([`${v.getUint32(p, true)},${v.getUint32(p + 4, true)},${style === 'addressPair' ? '' : v.getUint16(p + 8, true)}`, v.getBigUint64(q, true)]);
  }
  return { minuteMs: Number(v.getBigUint64(8, true)), complete: b[1] === 1, records: v.getUint32(16, true), octets: v.getBigUint64(20, true), endpoints, conversations };
}

/** A history query over minute rollups: 120 buckets, top 20 of each, distinct keys bounded. */
function queryRollups(minutes: Uint8Array[], style: KeyStyle, keyBound: number) {
  const buckets = new Array<bigint>(120).fill(0n);
  const endpoints = new Map<number, bigint>();
  const conversations = new Map<string, bigint>();
  let incomplete = 0;
  let overBound = false;
  const first = decodeRollup(minutes[0], style).minuteMs;
  const span = minutes.length * 60_000;
  for (const blob of minutes) {
    const m = decodeRollup(blob, style);
    buckets[Math.min(119, Math.floor(((m.minuteMs - first) / span) * 120))] += m.octets;
    if (!m.complete) { incomplete++; continue; }
    if (overBound) continue;
    for (const [ip, sent, recv] of m.endpoints) endpoints.set(ip, (endpoints.get(ip) ?? 0n) + sent + recv);
    for (const [key, o] of m.conversations) conversations.set(key, (conversations.get(key) ?? 0n) + o);
    if (endpoints.size + conversations.size > keyBound) overBound = true;
  }
  const top = <K>(m: Map<K, bigint>) => [...m].sort((a, b) => (b[1] > a[1] ? 1 : b[1] < a[1] ? -1 : 0)).slice(0, 20);
  return { buckets, incomplete, overBound, distinct: endpoints.size + conversations.size, topEndpoints: top(endpoints), topConversations: top(conversations) };
}

// --- socket ----------------------------------------------------------------------

const AGENT_PIPE = String.raw`\\.\pipe\inwire-agent`;

interface Captured { udpTo: Map<number, number>; icmpUnreachable: Map<number, number>; frames: number }

/** Captures `filter` on the agent's adapter whose device name or label matches `device`. */
async function agentCapture(filter: string, device: RegExp = /NPF_Loopback/): Promise<{ stop: () => Promise<Captured>; live: Captured; version: string; label: string }> {
  const reader = new FrameReader();
  const heard: Record<string, unknown>[] = [];
  const captured: Captured = { udpTo: new Map(), icmpUnreachable: new Map(), frames: 0 };
  let loopback = true;
  const open = () => new Promise<ReturnType<typeof connect>>((resolve, reject) => {
    const s = connect(AGENT_PIPE);
    s.once('connect', () => resolve(s));
    s.once('error', reject);
  });
  let socket;
  try { socket = await open(); } catch {
    spawnSync('sc.exe', ['start', 'InwireAgent'], { stdio: 'ignore' });
    await sleep(2000);
    socket = await open();
  }
  socket.on('data', (chunk: Buffer) => {
    for (const f of reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))) {
      if (f.kind === FRAME_JSON) { heard.push(JSON.parse(Buffer.from(f.payload).toString('utf8'))); continue; }
      const copy = f.payload.slice();
      for (const frame of decodePacketBatch(copy.buffer)) {
        captured.frames++;
        const raw = frame.bytes;
        // Npcap's loopback adapter is DLT_NULL (a 4-byte address family, 2 = IPv4); the others are Ethernet.
        const ip = loopback ? 4 : 14;
        if (raw.length < ip + 20 || (loopback ? raw[0] !== 2 : raw[12] !== 0x08 || raw[13] !== 0x00)) continue;
        const ihl = (raw[ip] & 0x0f) * 4;
        const proto = raw[ip + 9];
        const l4 = ip + ihl;
        if (proto === 17) {
          const dport = (raw[l4 + 2] << 8) | raw[l4 + 3];
          captured.udpTo.set(dport, (captured.udpTo.get(dport) ?? 0) + 1);
        } else if (proto === 1 && raw[l4] === 3 && raw[l4 + 1] === 3) {
          // The quoted datagram's UDP header follows the quoted IP header.
          const qip = l4 + 8;
          const qport = (raw[qip + (raw[qip] & 0x0f) * 4 + 2] << 8) | raw[qip + (raw[qip] & 0x0f) * 4 + 3];
          captured.icmpUnreachable.set(qport, (captured.icmpUnreachable.get(qport) ?? 0) + 1);
        }
      }
    }
  });
  const send = (m: unknown) => socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode(JSON.stringify(m))));
  const waitFor = async (pred: (m: Record<string, unknown>) => boolean, ms: number) => {
    for (const end = Date.now() + ms; Date.now() < end; await sleep(50)) { const m = heard.find(pred); if (m) return m; }
    return undefined;
  };
  const hello = await waitFor((m) => m.type === 'hello', 5000);
  if (hello === undefined) throw new Error('no hello from the agent');
  if (hello.state !== 'idle') throw new Error('a capture is running - stop it in every Inwire window first');
  const adapters = (hello.interfaces ?? []) as { name: string; label?: string }[];
  const adapter = adapters.find((i) => device.test(i.name) || device.test(i.label ?? ''));
  if (adapter === undefined) throw new Error(`no agent adapter matches ${device}`);
  loopback = /NPF_Loopback/.test(adapter.name);
  send({ type: 'set_interfaces', interfaces: [adapter.name] });
  send({ type: 'start_capture', filter });
  const started = await waitFor((m) => m.type === 'state' && m.state === 'sniffing', 10_000);
  if (started === undefined) throw new Error(`capture did not start: ${JSON.stringify(heard.slice(-3))}`);
  return {
    version: String(hello.version),
    label: adapter.label ?? adapter.name,
    live: captured,
    stop: async () => {
      await sleep(1500); // let the agent's pump drain its last batch
      send({ type: 'stop_capture' });
      await waitFor((m) => m.type === 'state' && m.state === 'idle', 5000);
      socket.destroy();
      return captured;
    },
  };
}

function bindUdp(address: string, port: number, opts: { reuseAddr?: boolean } = {}): Promise<{ socket?: UdpSocket; error?: string }> {
  return new Promise((resolve) => {
    const s = createSocket({ type: 'udp4', reuseAddr: opts.reuseAddr ?? false });
    s.once('error', (e: NodeJS.ErrnoException) => { s.close(); resolve({ error: e.code ?? e.message }); });
    s.bind(port, address, () => { s.removeAllListeners('error'); resolve({ socket: s }); });
  });
}

async function sendMany(target: number, payload: Uint8Array, count: number, perTick: number, connected: boolean) {
  const s = createSocket('udp4');
  const errors = new Map<string, number>();
  s.on('error', (e: NodeJS.ErrnoException) => errors.set(e.code ?? e.message, (errors.get(e.code ?? e.message) ?? 0) + 1));
  await new Promise<void>((r) => s.bind(0, '127.0.0.1', () => r()));
  if (connected) await new Promise<void>((r) => s.connect(target, '127.0.0.1', () => r()));
  let callbackErrors = 0;
  for (let i = 0; i < count; i += perTick) {
    for (let k = 0; k < perTick && i + k < count; k++) {
      const cb = (e: Error | null) => { if (e) { callbackErrors++; const c = (e as NodeJS.ErrnoException).code ?? e.message; errors.set(c, (errors.get(c) ?? 0) + 1); } };
      if (connected) s.send(payload, cb); else s.send(payload, target, '127.0.0.1', cb);
    }
    await sleep(10);
  }
  await sleep(300);
  s.close();
  return { callbackErrors, errors: Object.fromEntries(errors) };
}

async function socketMode(): Promise<void> {
  if (process.platform !== 'win32') { console.log('SKIP  the socket experiment uses the Windows agent'); return; }
  const LISTEN = 47055;
  const UNBOUND = 47056;
  const BURST = 47057;
  const N = 1000;
  const payload = v5Datagrams(new TrafficModel(7, false).second(1_700_000_000).concat(...Array.from({ length: 30 }, () => [])), 1_700_000_000_000, { n: 0 })[0]
    ?? new Uint8Array(1464);
  const full = new Uint8Array(24 + 30 * 48);
  full.set(payload.subarray(0, Math.min(payload.length, full.length)));
  console.log(`node ${process.versions.node}, payload ${full.length} B (a full 30-record v5 datagram)\n`);

  console.log('Bind behaviour (loopback and unassigned addresses only, which raise no firewall prompt):');
  const a = await bindUdp('127.0.0.1', LISTEN);
  const again = await bindUdp('127.0.0.1', LISTEN);
  const againReuse = await bindUdp('127.0.0.1', LISTEN, { reuseAddr: true });
  const foreign = await bindUdp('192.0.2.1', LISTEN);
  const ephemeral = await bindUdp('127.0.0.1', 0);
  const lowPort = await bindUdp('127.0.0.1', 514);
  console.log(`  first bind 127.0.0.1:${LISTEN}: ${a.error ?? 'ok'}; rcvbuf ${a.socket?.getRecvBufferSize()} B`);
  console.log(`  second bind, same address and port: ${again.error ?? 'ok (!)'}`);
  console.log(`  second bind with reuseAddr: ${againReuse.error ?? 'ok (!)'}`);
  console.log(`  an address not on this machine (192.0.2.1): ${foreign.error ?? 'ok (!)'}`);
  console.log(`  port 0: ${ephemeral.error ?? `ok, got ${ephemeral.socket?.address().port}`}`);
  console.log(`  port 514, below 1024: ${lowPort.error ?? 'ok (no privilege needed)'}`);
  for (const r of [again, againReuse, ephemeral, lowPort]) r.socket?.close();

  const capture = await agentCapture(`udp port ${LISTEN} or udp port ${UNBOUND} or udp port ${BURST} or icmp`);
  console.log(`\nAgent ${capture.version} capturing on NPF_Loopback.`);
  let received = 0;
  a.socket!.on('message', () => { received++; });
  const toListener = await sendMany(LISTEN, full, N, 50, false);
  await sleep(300);
  const receivedDefault = received;
  a.socket!.setRecvBufferSize(8 * MB);
  const toListenerBig = await sendMany(LISTEN, full, N, 50, false);
  await sleep(300);
  const receivedBig = received - receivedDefault;
  const toNothing = await sendMany(UNBOUND, full, N, 50, false);
  const toNothingConnected = await sendMany(UNBOUND, full, N, 50, true);

  // A listener that stops reading for two seconds while 5,000 datagrams arrive:
  // what the kernel keeps for it, at the default buffer and at 8 MiB.
  const burstResults: string[] = [];
  for (const rcvbuf of [0, 8 * MB]) {
    const b = await bindUdp('127.0.0.1', BURST);
    if (rcvbuf) b.socket!.setRecvBufferSize(rcvbuf);
    let got = 0;
    b.socket!.on('message', () => { got++; });
    const child = spawn(process.execPath, ['-e', `
      const s = require('node:dgram').createSocket('udp4'); const p = Buffer.alloc(${full.length});
      let i = 0; const tick = () => { for (let k = 0; k < 250 && i < 5000; k++, i++) s.send(p, ${BURST}, '127.0.0.1');
        if (i < 5000) setTimeout(tick, 5); else setTimeout(() => s.close(), 300); }; tick();`]);
    const until = Date.now() + 2000;
    while (Date.now() < until) { /* the listener's event loop is blocked */ }
    await new Promise((r) => child.once('exit', r));
    await sleep(500);
    burstResults.push(`  rcvbuf ${rcvbuf ? '8 MiB' : `default (${b.socket!.getRecvBufferSize()} B)`}: ${got} of 5000 delivered after a 2 s stall`);
    b.socket!.close();
  }
  a.socket!.close();
  const seen = await capture.stop();

  console.log(`\nDelivery, ${N} datagrams each, 50 per 10 ms:`);
  console.log(`  to a bound listener (two runs): received ${receivedDefault} at the default rcvbuf, ${receivedBig} at 8 MiB; capture saw ${seen.udpTo.get(LISTEN) ?? 0}; ICMP unreachable ${seen.icmpUnreachable.get(LISTEN) ?? 0}; sender errors ${JSON.stringify({ ...toListener.errors, ...toListenerBig.errors })}`);
  console.log(`  to no listener (sendto):    capture saw ${seen.udpTo.get(UNBOUND) ?? 0} datagrams (both runs); ICMP port unreachable ${seen.icmpUnreachable.get(UNBOUND) ?? 0}; sender errors ${JSON.stringify(toNothing.errors)}`);
  console.log(`  to no listener (connected): sender errors ${JSON.stringify(toNothingConnected.errors)}`);
  console.log('\nKernel buffering while the listener is stalled:');
  for (const line of burstResults) console.log(line);
}

// --- journal ---------------------------------------------------------------------

function timeIt<T>(f: () => T): [T, number] {
  const t = performance.now();
  const r = f();
  return [r, performance.now() - t];
}

const ipNumber = (s: string) => s.split('.').reduce((a, b) => (a << 8) | Number(b), 0) >>> 0;

async function journalMode(): Promise<void> {
  const dir = join(tmpdir(), `inwire-monitoring-measure-${process.pid}`);
  mkdirSync(dir, { recursive: true });
  try {
    // CRC cost, JS table against node's zlib.crc32 (which the utility process could use).
    const big = new Uint8Array(64 * MB).map((_, i) => (i * 2654435761) >>> 24);
    const [jsCrc, jsMs] = timeIt(() => crc32(big));
    const [zCrc, zMs] = timeIt(() => zlibCrc32(big));
    console.log(`CRC-32 over 64 MiB: JS table ${fmt(64 / (jsMs / 1000))} MiB/s, zlib.crc32 ${fmt(64 / (zMs / 1000))} MiB/s, agree: ${jsCrc === zCrc}`);

    // Append cost per entry, realistic and maximum payloads, with and without fsync per append.
    const realistic = new Uint8Array(24 + 30 * 48).fill(7);
    const maximum = new Uint8Array(MAX_DATAGRAM_PAYLOAD).fill(9);
    for (const [label, payload, count] of [['realistic 1,464 B', realistic, 100_000], ['maximum 65,507 B', maximum, 4_000]] as const) {
      const path = join(dir, `append-${payload.length}.iwmj`);
      const f = NodeBlockFile.open(path);
      f.write(0, fileHeader(new Uint8Array(16).fill(1), Date.now()));
      let at = FILE_HEADER_BYTES;
      const [, ms] = timeIt(() => {
        for (let i = 0; i < count; i++) {
          const e = entry(i + 1, KIND_DATAGRAM, datagramBody(1_700_000_000_000 + i, ['192.0.2.10', 2055], ['192.0.2.1', 50000], payload));
          f.write(at, e);
          at += e.length;
        }
      });
      const [, flushMs] = timeIt(() => f.flush());
      const fsyncEach = Math.min(count, 300);
      const [, syncedMs] = timeIt(() => {
        for (let i = 0; i < fsyncEach; i++) {
          const e = entry(count + i + 1, KIND_DATAGRAM, datagramBody(1_700_000_000_000 + i, ['192.0.2.10', 2055], ['192.0.2.1', 50000], payload));
          f.write(at, e); at += e.length; f.flush();
        }
      });
      const size = f.size();
      f.close();
      console.log(`Append ${label}: ${fmt((ms * 1000) / count, 2)} µs an entry (${fmt(count / (ms / 1000), 0)}/s), `
        + `flush after ${fmt(size / MB)} MiB ${fmt(flushMs)} ms, fsync per append ${fmt((syncedMs * 1000) / fsyncEach, 0)} µs, `
        + `${ENTRY_HEADER_BYTES + DATAGRAM_META_BYTES} B framing an entry (${fmt(((ENTRY_HEADER_BYTES + DATAGRAM_META_BYTES) / (payload.length + 48)) * 100, 2)}%)`);
      rmSync(path);
    }

    // A day at 7 datagrams/s and a week at 2, from the traffic model, written as journals.
    const datasets = quick
      ? [{ name: 'hour@7', dps: 7, seconds: 3600 }, { name: 'hour@2', dps: 2, seconds: 3600 }]
      : [{ name: 'day@7', dps: 7, seconds: 86_400 }, { name: 'week@2', dps: 2, seconds: 7 * 86_400 }];
    for (const ds of datasets) {
      const path = join(dir, `${ds.name}.iwmj`);
      const f = NodeBlockFile.open(path);
      f.write(0, fileHeader(new Uint8Array(16).fill(2), BOOT_MS));
      const model = new TrafficModel(ds.dps, false);
      const seq = { n: 0 };
      let at = FILE_HEADER_BYTES;
      let id = 0;
      let lastFlush = 0;
      let flushMsTotal = 0;
      let flushes = 0;
      const t0 = 1_700_000_000;
      const [, writeMs] = timeIt(() => {
        for (let s = 0; s < ds.seconds; s++) {
          for (const d of v5Datagrams(model.second(t0 + s), (t0 + s) * 1000, seq)) {
            const e = entry(++id, KIND_DATAGRAM, datagramBody((t0 + s) * 1000, ['192.0.2.10', 2055], ['192.0.2.1', 50000], d));
            f.write(at, e);
            at += e.length;
          }
          if (s - lastFlush >= 1) { const t = performance.now(); f.flush(); flushMsTotal += performance.now() - t; flushes++; lastFlush = s; }
        }
      });
      f.close();
      const size = statSync(path).size;
      console.log(`\n${ds.name}: ${id.toLocaleString()} datagrams (${fmt(id / ds.seconds, 2)}/s), ${fmt(size / MB)} MiB, `
        + `${fmt(size / id, 0)} B a datagram, ${fmt(size / ds.seconds * 86_400 / MB / 1024, 2)} GiB a day; `
        + `1 GiB lasts ${fmt(1024 * MB / (size / ds.seconds) / 3600, 1)} h; generated+written in ${fmt(writeMs / 1000)} s; `
        + `one-second flush ${fmt(flushMsTotal / flushes, 2)} ms mean`);

      const r = NodeBlockFile.open(path);
      const [hdr, hdrMs] = timeIt(() => scanJournal(r, false));
      const [ver, verMs] = timeIt(() => scanJournal(r, true));
      console.log(`  open scan (headers only) ${fmt(hdrMs)} ms; with every CRC ${fmt(verMs)} ms; entries ${hdr.entries} / ${ver.entries}, bad ${ver.bad}`);

      // A bounded raw query: the last 100,000 datagrams, decoded and aggregated exactly.
      const offsets: number[] = [];
      scanJournal(r, false, (e) => offsets.push(e.offset));
      const from = offsets[Math.max(0, offsets.length - 100_000)];
      const templates = new MemoryTemplateStore();
      const agg = newRollup();
      let records = 0;
      const [, qMs] = timeIt(() => {
        const sub = { size: () => r.size() - from + FILE_HEADER_BYTES, read: (o: number, into: Uint8Array) => r.read(o - FILE_HEADER_BYTES + from, into) };
        scanJournal(sub as unknown as NodeBlockFile, true, (_e, body) => {
          const payload = body.subarray(DATAGRAM_META_BYTES);
          if (payload.length !== 24 + 48 * ((payload[2] << 8) | payload[3])) return;
          for (const fr of normalizeFlows(payload, 0, payload.length, '192.0.2.1', templates)) {
            records++;
            addToRollup(agg, 'fiveTuple', 50_000, ipNumber(fr.srcAddr!), ipNumber(fr.dstAddr!), fr.srcPort!, fr.dstPort!, fr.protocol!, BigInt(fr.octets!), BigInt(fr.packets!));
          }
        });
      });
      console.log(`  raw query over the last ${Math.min(100_000, offsets.length).toLocaleString()} datagrams (${records.toLocaleString()} records): ${fmt(qMs)} ms`
        + `, distinct 5-tuple keys ${agg.complete ? agg.endpoints.size + agg.conversations.size : '> 50,000 (refused)'}`);

      // A narrow drill-down: the last ten minutes, exact by 5-tuple.
      const tail = offsets[Math.max(0, offsets.length - Math.round(ds.dps * 600))];
      const narrow = newRollup();
      let narrowRecords = 0;
      const [, nMs] = timeIt(() => {
        const sub = { size: () => r.size() - tail + FILE_HEADER_BYTES, read: (o: number, into: Uint8Array) => r.read(o - FILE_HEADER_BYTES + tail, into) };
        scanJournal(sub as unknown as NodeBlockFile, true, (_e, body) => {
          for (const fr of normalizeFlows(body.subarray(DATAGRAM_META_BYTES), 0, body.length - DATAGRAM_META_BYTES, '192.0.2.1', templates)) {
            narrowRecords++;
            addToRollup(narrow, 'fiveTuple', 50_000, ipNumber(fr.srcAddr!), ipNumber(fr.dstAddr!), fr.srcPort!, fr.dstPort!, fr.protocol!, BigInt(fr.octets!), BigInt(fr.packets!));
          }
        });
      });
      console.log(`  raw drill-down over the last 10 minutes (${narrowRecords.toLocaleString()} records): ${fmt(nMs)} ms, distinct 5-tuple keys ${narrow.complete ? (narrow.endpoints.size + narrow.conversations.size).toLocaleString() : '> 50,000'}`);

      // Rebuild every minute rollup from the journal, streaming: a minute is encoded and
      // dropped as soon as the journal moves past it, so memory is one minute's keys.
      // (Holding every minute's map until the end ran a week at 2 dps out of a 4 GB heap.)
      let peakHeap = 0;
      const [rebuilt, rebuildMs] = timeIt(() => {
        let open: { minute: number; m: Rollup } | undefined;
        let minutes = 0;
        let bytes = 0;
        let incomplete = 0;
        const close = () => {
          if (open === undefined) return;
          bytes += encodeRollup(open.minute, open.m, 'addressPair').length;
          if (!open.m.complete) incomplete++;
          minutes++;
          peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
        };
        scanJournal(r, true, (_e, body) => {
          const receivedMs = Number(new DataView(body.buffer, body.byteOffset).getBigUint64(0, true));
          const minute = receivedMs - (receivedMs % 60_000);
          if (open === undefined || open.minute !== minute) { close(); open = { minute, m: newRollup() }; }
          for (const fr of normalizeFlows(body.subarray(DATAGRAM_META_BYTES), 0, body.length - DATAGRAM_META_BYTES, '192.0.2.1', templates)) {
            addToRollup(open.m, 'addressPair', 16_384, ipNumber(fr.srcAddr!), ipNumber(fr.dstAddr!), fr.srcPort!, fr.dstPort!, fr.protocol!, BigInt(fr.octets!), BigInt(fr.packets!));
          }
        });
        close();
        return { minutes, bytes, incomplete };
      });
      console.log(`  streaming rebuild of ${rebuilt.minutes.toLocaleString()} minute rollups (address-pair key, budget 16,384): ${fmt(rebuildMs / 1000, 2)} s, `
        + `sidecar ${fmt(rebuilt.bytes / MB, 2)} MiB, incomplete ${rebuilt.incomplete}, peak heap ${fmt(peakHeap / MB, 0)} MiB`);
      r.close();
      rmSync(path);
    }
  } finally {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
}

// --- rollup ----------------------------------------------------------------------

function rollupMode(): void {
  const rates = [2, 7, 50];
  const minutesSampled = quick ? 5 : 30;
  console.log(`Per-minute cardinality over ${minutesSampled} minutes after a 15-minute warm-up (no key budget):\n`);
  console.log('profile           records/min  endpoints  5-tuple  svc-port  addr-pair   bytes/min (5t / svc / pair, raw; svc deflated)');
  for (const high of [false, true]) {
    for (const dps of rates) {
      const model = new TrafficModel(dps, high, 11);
      const t0 = 1_700_000_000;
      for (let s = 0; s < 900; s++) model.second(t0 + s);
      const sums = { records: 0, endpoints: 0, five: 0, svc: 0, pair: 0, b5: 0, bs: 0, bp: 0, bsz: 0 };
      for (let m = 0; m < minutesSampled; m++) {
        const roll = Object.fromEntries(KEY_STYLES.map((k) => [k, newRollup()])) as Record<KeyStyle, Rollup>;
        for (let s = 0; s < 60; s++) {
          for (const r of model.second(t0 + 900 + m * 60 + s)) {
            for (const k of KEY_STYLES) addToRollup(roll[k], k, Infinity, r.src, r.dst, r.sport, r.dport, r.proto, BigInt(r.octets), BigInt(r.packets));
          }
        }
        const minuteMs = (t0 + 900 + m * 60) * 1000;
        sums.records += roll.fiveTuple.records;
        sums.endpoints += roll.fiveTuple.endpoints.size;
        sums.five += roll.fiveTuple.conversations.size;
        sums.svc += roll.servicePort.conversations.size;
        sums.pair += roll.addressPair.conversations.size;
        sums.b5 += encodeRollup(minuteMs, roll.fiveTuple, 'fiveTuple').length;
        const svc = encodeRollup(minuteMs, roll.servicePort, 'servicePort');
        sums.bs += svc.length;
        sums.bsz += deflateSync(svc, { level: 1, strategy: zlibConstants.Z_DEFAULT_STRATEGY }).length;
        sums.bp += encodeRollup(minuteMs, roll.addressPair, 'addressPair').length;
      }
      const avg = (n: number) => fmt(n / minutesSampled, 0).padStart(9);
      console.log(`${(high ? 'high-card' : 'realistic').padEnd(10)} ${String(dps).padStart(2)} dps ${avg(sums.records)}  ${avg(sums.endpoints)} ${avg(sums.five)} ${avg(sums.svc)} ${avg(sums.pair)}   `
        + `${avg(sums.b5)} /${avg(sums.bs)} /${avg(sums.bp)}; ${avg(sums.bsz)}   (flows/s ${fmt(model.arrivalRate, 0)})`);

    }
  }

  // Real generated days, not cycled samples: per-minute keys under each budget,
  // sidecar bytes, how many minutes fall back to raw, and what a range query costs.
  const days = quick ? 2 / 24 : 1;
  console.log(`
Generated ${quick ? '2 h' : '24 h'} per profile; a 7-day range at 2 dps is generated too, at 7 dps it repeats the day:`);
  for (const dps of [2, 7]) {
    for (const style of ['addressPair', 'servicePort'] as KeyStyle[]) {
      for (const budget of [5000, 16_384]) {
        const model = new TrafficModel(dps, false, 23);
        const t0 = 1_700_000_000;
        for (let s = 0; s < 900; s++) model.second(t0 + s);
        const weekly = dps === 2 && !quick && budget === 16_384;
        const minutes = Math.round((weekly ? 7 : days) * 1440);
        const blobs: Uint8Array[] = [];
        let peakKeys = 0;
        const [, genMs] = timeIt(() => {
          for (let m = 0; m < minutes; m++) {
            const roll = newRollup();
            for (let s = 0; s < 60; s++) {
              for (const r of model.second(t0 + 900 + m * 60 + s)) {
                addToRollup(roll, style, budget, r.src, r.dst, r.sport, r.dport, r.proto, BigInt(r.octets), BigInt(r.packets));
              }
            }
            peakKeys = Math.max(peakKeys, roll.complete ? roll.endpoints.size + roll.conversations.size : budget + 1);
            blobs.push(encodeRollup((t0 + 900 + m * 60) * 1000, roll, style));
          }
        });
        const incomplete = blobs.filter((b) => b[1] === 0).length;
        const bytes = blobs.reduce((n, b) => n + b.length, 0);
        const perDay = (bytes / minutes) * 1440;
        const zipped = blobs.slice(0, 60).reduce((n, b) => n + deflateSync(b, { level: 1 }).length, 0) / Math.min(60, blobs.length) * 1440;
        const day = blobs.slice(0, Math.min(1440, blobs.length));
        const [qd, msd] = timeIt(() => queryRollups(day, style, 50_000));
        const [qdu] = timeIt(() => queryRollups(day, style, Infinity));
        const week = weekly ? blobs : Array.from({ length: 7 }, () => day).flat();
        const [qw, msw] = timeIt(() => queryRollups(week, style, 50_000));
        console.log(`  ${dps} dps ${style.padEnd(11)} budget ${String(budget).padStart(6)}: peak keys/min ${peakKeys > budget ? `>${budget}` : peakKeys}, incomplete ${incomplete}/${minutes} min; `
          + `sidecar ${fmt(perDay / MB, 1)} MiB/day raw, ~${fmt(zipped / MB, 1)} deflated; `
          + `day distinct ${qdu.distinct.toLocaleString()}; 24 h query ${fmt(msd, 0)} ms${qd.overBound ? ' (over 50,000: range-too-large)' : ''}; `
          + `7 d query ${fmt(msw, 0)} ms${qw.overBound ? ' (over 50,000)' : ''}${weekly ? ' [generated week]' : ''}; generated in ${fmt(genMs / 1000, 0)} s`);
      }
    }
  }
}

// --- vector ----------------------------------------------------------------------

function vectorMode(): void {
  const hex = (b: Uint8Array) => Buffer.from(b).toString('hex').replace(/(.{2})/g, '$1 ').trim();
  console.log(`CRC-32("123456789") = 0x${crc32(new TextEncoder().encode('123456789')).toString(16)} (zlib: 0x${zlibCrc32('123456789').toString(16)})`);
  const header = fileHeader(Uint8Array.from({ length: 16 }, (_, i) => i), 1_700_000_000_000);
  console.log(`file header (generation 00..0f, created 1700000000000 ms, policy 1):\n  ${hex(header)}`);
  const body = datagramBody(1_700_000_000_123, ['192.0.2.10', 2055], ['192.0.2.1', 50000], Uint8Array.from([0, 5, 0, 0]));
  const e = entry(1, KIND_DATAGRAM, body);
  console.log(`entry 1, datagram received 1700000000123 ms at 192.0.2.10:2055 from 192.0.2.1:50000, payload 00 05 00 00:\n  ${hex(e)}`);
  const boundary = entry(2, KIND_BOUNDARY, new TextEncoder().encode('{"action":"start"}'));
  console.log(`entry 2, boundary {"action":"start"}:\n  ${hex(boundary)}`);
}

// --- firewall --------------------------------------------------------------------

const argValue = (name: string) => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1]; };

const WSL_SENDER = `
import socket, sys, time
host, port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
n, end, last = 0, time.time() + seconds, 0.0
while time.time() < end:
    s.sendto(n.to_bytes(4, 'big') + b'x' * 60, (host, port))
    n += 1
    time.sleep(0.2)
    if time.time() - last >= 1:
        print(n, flush=True)
        last = time.time()
print(n, flush=True)
`;

async function firewallMode(): Promise<void> {
  const electron = argValue('--electron');
  if (electron === undefined || !existsSync(electron)) throw new Error('--electron <path to an electron.exe> is required');
  const port = Number(argValue('--port') ?? 2055);
  const seconds = Number(argValue('--seconds') ?? 120);
  const shot = argValue('--shot');
  const nicPattern = new RegExp(argValue('--nic') ?? 'WSL');
  const listenOnly = process.argv.includes('--listen-only');
  const nic = Object.entries(networkInterfaces()).find(([name]) => nicPattern.test(name));
  const host = nic?.[1]?.find((a) => a.family === 'IPv4' && !a.internal)?.address;
  if (host === undefined) throw new Error(`no IPv4 address on an adapter matching ${nicPattern}`);
  const capture = await agentCapture(`udp port ${port} or icmp`, nicPattern);
  console.log(`agent ${capture.version} capturing on ${capture.label}; binding ${nic![0]} port ${port} under ${electron}`);

  let delivered = 0;
  let sent = 0;
  const t0 = Date.now();
  const at = () => `${((Date.now() - t0) / 1000).toFixed(1).padStart(6)} s`;
  const probe = spawn(electron, [join(dirname(fileURLToPath(import.meta.url)), 'firewall-probe.cjs'), '--bind', host, '--port', String(port), '--seconds', String(seconds)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let buffered = '';
  probe.stdout.on('data', (c: Buffer) => {
    buffered += c.toString('utf8');
    for (let nl = buffered.indexOf('\n'); nl >= 0; nl = buffered.indexOf('\n')) {
      const line = buffered.slice(0, nl).trim();
      buffered = buffered.slice(nl + 1);
      if (!line.startsWith('{')) continue;
      const m = JSON.parse(line);
      if (m.received !== undefined) delivered = m.received;
      else console.log(`${at()}  probe ${JSON.stringify(m)}`);
    }
  });
  probe.stderr.on('data', () => { /* Chromium's own logging */ });
  const exited = new Promise<void>((r) => probe.once('exit', () => r()));
  await sleep(2000);

  const sender = listenOnly ? null : spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'python3', '-', host, String(port), String(seconds - 10)], { stdio: ['pipe', 'pipe', 'inherit'] });
  sender?.stdin.end(WSL_SENDER);
  sender?.stdout.on('data', (c: Buffer) => { const last = c.toString('utf8').trim().split('\n').pop(); if (last) sent = Number(last); });
  if (shot !== undefined) {
    setTimeout(() => spawnSync('powershell.exe', ['-NoProfile', '-Command',
      `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; ` +
      `$i=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($i); ` +
      `$g.CopyFromScreen($b.Left,$b.Top,0,0,$i.Size); $i.Save('${shot}')`]), 6000);
  }
  let lastRow = '';
  const timer = setInterval(() => {
    const row = `sent ${sent}  on the adapter ${capture.live.udpTo.get(port) ?? 0}  delivered ${delivered}`;
    if (row !== lastRow) console.log(`${at()}  ${row}`);
    lastRow = row;
  }, 1000);
  await exited;
  clearInterval(timer);
  sender?.kill();
  const captured = await capture.stop();
  console.log(`${at()}  done: sent ${sent}, on the adapter ${captured.udpTo.get(port) ?? 0}, delivered ${delivered}, ICMP unreachable for port ${port}: ${captured.icmpUnreachable.get(port) ?? 0}`);
}

// --- bindpair ---------------------------------------------------------------------

// The wildcard beside a specific bind on one port: does the second bind fail,
// and if not, which socket does a datagram to the specific address reach? Run
// under an Electron whose firewall rules already say Allow, or the prompt
// decides the answer instead of the stack.
async function bindPairMode(): Promise<void> {
  const electron = argValue('--electron');
  if (electron === undefined || !existsSync(electron)) throw new Error('--electron <path to an electron.exe> is required');
  const nic = Object.entries(networkInterfaces()).find(([name]) => /WSL/.test(name));
  const host = nic?.[1]?.find((a) => a.family === 'IPv4' && !a.internal)?.address;
  if (host === undefined) throw new Error('no IPv4 address on a WSL adapter');
  type Sock = { id: string; addr: string; port: number; reuse: boolean };
  const w = (port: number, reuse = false): Sock => ({ id: 'wildcard', addr: '0.0.0.0', port, reuse });
  const s = (port: number, reuse = false): Sock => ({ id: 'specific', addr: host, port, reuse });
  const cases: { name: string; plan: Sock[][] }[] = [
    { name: 'one process, wildcard then specific', plan: [[w(2061), s(2061)]] },
    { name: 'one process, specific then wildcard', plan: [[s(2062), w(2062)]] },
    { name: 'two processes, wildcard then specific', plan: [[w(2063)], [s(2063)]] },
    { name: 'two processes, specific then wildcard', plan: [[s(2064)], [w(2064)]] },
    { name: 'two processes, wildcard then specific, both reuseAddr', plan: [[w(2065, true)], [s(2065, true)]] },
    { name: 'two processes, specific then wildcard, both reuseAddr', plan: [[s(2066, true)], [w(2066, true)]] },
    { name: 'two processes, wildcard (reuseAddr) then specific (none)', plan: [[w(2067, true)], [s(2067)]] },
    { name: 'two processes, specific (none) then wildcard (reuseAddr)', plan: [[s(2068)], [w(2068, true)]] },
    { name: 'two processes, specific twice', plan: [[s(2069)], [{ ...s(2069), id: 'second' }]] },
    { name: 'two processes, specific twice, both reuseAddr', plan: [[s(2070, true)], [{ ...s(2070, true), id: 'second' }]] },
    { name: 'two processes, specific (none) then specific (reuseAddr)', plan: [[s(2071)], [{ ...s(2071, true), id: 'second' }]] },
  ];
  console.log(`specific = ${nic![0]}; sending from WSL to the specific address under ${electron}`);
  for (const c of cases) {
    const port = c.plan[0][0].port;
    const binds: string[] = [];
    let counts: Record<string, number> = {};
    let sent = 0;
    const probe = spawn(electron, [join(dirname(fileURLToPath(import.meta.url)), 'bind-pair-probe.cjs'), '--plan', JSON.stringify(c.plan), '--seconds', '9'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let buffered = '';
    const all = new Promise<void>((ready) => probe.stdout.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('utf8');
      for (let nl = buffered.indexOf('\n'); nl >= 0; nl = buffered.indexOf('\n')) {
        const line = buffered.slice(0, nl).trim();
        buffered = buffered.slice(nl + 1);
        if (!line.startsWith('{')) continue;
        const m = JSON.parse(line);
        if (m.all) ready();
        else if (m.counts) counts = m.counts;
        else binds.push(`${m.id} ${m.error ?? 'bound'}`);
      }
    }));
    probe.stderr.on('data', () => { /* Chromium's own logging */ });
    const exited = new Promise<void>((r) => probe.once('exit', () => r()));
    await all;
    const sender = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'python3', '-', host, String(port), '4'], { stdio: ['pipe', 'pipe', 'inherit'] });
    sender.stdin.end(WSL_SENDER);
    sender.stdout.on('data', (chunk: Buffer) => { const last = chunk.toString('utf8').trim().split('\n').pop(); if (last) sent = Number(last); });
    await new Promise<void>((r) => sender.once('exit', () => r()));
    await exited;
    console.log(`${c.name} (port ${port})\n  binds: ${binds.join(', ')}\n  sent ${sent}; received ${Object.entries(counts).map(([id, n]) => `${id} ${n}`).join(', ') || 'none'}`);
  }
}

// --- softflowd --------------------------------------------------------------------

// A receiver inside WSL that keeps every datagram, as [u32 length][payload],
// and stops 3 s after the last one (or 60 s after starting with none).
const WSL_KEEPER = `
import socket, struct, sys, time
port, path = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.bind(('127.0.0.1', port))
s.settimeout(0.5)
print('ready', flush=True)
n, start, last = 0, time.time(), None
with open(path, 'wb') as f:
    while True:
        try:
            d, src = s.recvfrom(65535)
            f.write(struct.pack('<I', len(d)) + d)
            n, last = n + 1, time.time()
        except socket.timeout:
            pass
        if (last and time.time() - last > 3) or (not last and time.time() - start > 60):
            break
print(n, flush=True)
`;

const winToWsl = (p: string) => `/mnt/${p[0].toLowerCase()}${p.slice(2).replace(/\\/g, '/')}`;

/** A classic pcap of raw IPv4 (LINKTYPE_RAW), each datagram given a UDP/IPv4 header. */
function rawUdpPcap(datagrams: Uint8Array[], dstPort: number): Uint8Array {
  const parts: Uint8Array[] = [];
  const g = new DataView(new ArrayBuffer(24));
  g.setUint32(0, 0xa1b2c3d4, true); g.setUint16(4, 2, true); g.setUint16(6, 4, true);
  g.setUint32(16, 65535, true); g.setUint32(20, 101, true);
  parts.push(new Uint8Array(g.buffer));
  datagrams.forEach((d, i) => {
    const frame = new Uint8Array(28 + d.length);
    const v = new DataView(frame.buffer);
    frame.set([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 192, 0, 2, 1]);
    v.setUint16(2, frame.length);
    let sum = 0;
    for (let p = 0; p < 20; p += 2) sum += v.getUint16(p);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    v.setUint16(10, ~sum & 0xffff);
    v.setUint16(20, 50000); v.setUint16(22, dstPort); v.setUint16(24, 8 + d.length);
    frame.set(d, 28);
    const r = new DataView(new ArrayBuffer(16));
    r.setUint32(0, 1_700_000_000 + i, true); r.setUint32(8, frame.length, true); r.setUint32(12, frame.length, true);
    parts.push(new Uint8Array(r.buffer), frame);
  });
  return Buffer.concat(parts);
}

// softflowd reads a capture from file and exports NetFlow v5 to a keeper in
// WSL; every record is then decoded twice, by `normalizeFlows` and by tshark's
// cflow, and compared field by field. The flows' totals are set beside the
// capture's own, which are not expected to match exactly (softflowd counts
// IPv4 alone, and per its own flow table). Needs WSL's Ubuntu with softflowd
// and python3, and tshark on this side.
async function softflowdMode(): Promise<void> {
  const { readFileSync, writeFileSync, mkdtempSync, realpathSync } = await import('node:fs');
  const { findWiresharkTool } = await import('../export/realCaptures');
  const pcap = argValue('--pcap');
  if (pcap === undefined || !existsSync(pcap)) throw new Error('--pcap <a capture to replay> is required');
  const port = Number(argValue('--port') ?? 2055);
  const tshark = findWiresharkTool('tshark');
  if (tshark === null) throw new Error('tshark not found');
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'inwire-softflowd-')));
  const kept = join(dir, 'datagrams.bin');
  const version = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'sh', '-c', 'softflowd -h 2>&1 | sed -n 2p'], { encoding: 'utf8' }).stdout.trim();

  const keeper = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'python3', '-', String(port), winToWsl(kept)], { stdio: ['pipe', 'pipe', 'inherit'] });
  keeper.stdin.end(WSL_KEEPER);
  let keeperOut = '';
  await new Promise<void>((ready) => keeper.stdout.on('data', (c: Buffer) => { keeperOut += c.toString('utf8'); if (keeperOut.includes('ready')) ready(); }));
  const exported = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'softflowd', '-r', winToWsl(realpathSync.native(pcap)), '-n', `127.0.0.1:${port}`, '-v', '5', '-d'], { encoding: 'utf8' });
  await new Promise<void>((r) => keeper.once('exit', () => r()));
  console.log(`${version}; exit ${exported.status}${exported.stderr.trim() ? `; stderr: ${exported.stderr.trim().split('\n').slice(-3).join(' | ')}` : ''}`);

  const raw = readFileSync(kept);
  const datagrams: Uint8Array[] = [];
  for (let p = 0; p + 4 <= raw.length;) { const n = raw.readUInt32LE(p); datagrams.push(raw.subarray(p + 4, p + 4 + n)); p += 4 + n; }
  const outPcap = join(dir, 'export.pcap');
  writeFileSync(outPcap, rawUdpPcap(datagrams, port));

  const FIELDS = ['srcaddr', 'dstaddr', 'nexthop', 'inputint', 'outputint', 'packets', 'octets', 'srcport', 'dstport', 'tcpflags', 'protocol', 'tos', 'srcas', 'dstas'] as const;
  const theirs = spawnSync(tshark, ['-r', outPcap, '-d', `udp.port==${port},cflow`, '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=,',
    '-e', 'cflow.version', '-e', 'cflow.count', '-e', 'cflow.sequence', ...FIELDS.flatMap((f) => ['-e', `cflow.${f}`])], { encoding: 'utf8', maxBuffer: 1 << 28 });
  const rows = theirs.stdout.trimEnd().split(/\r?\n/).map((l) => l.split('\t'));

  const ours = (fr: ReturnType<typeof normalizeFlows>[number]): Record<(typeof FIELDS)[number], string> => ({
    srcaddr: fr.srcAddr!, dstaddr: fr.dstAddr!, nexthop: fr.nextHop!, inputint: String(fr.inputIf), outputint: String(fr.outputIf),
    packets: String(fr.packets), octets: String(fr.octets), srcport: String(fr.srcPort), dstport: String(fr.dstPort),
    tcpflags: `0x${fr.tcpFlags!.toString(16).padStart(2, '0')}`, protocol: String(fr.protocol), tos: `0x${fr.tos!.toString(16).padStart(2, '0')}`,
    srcas: String(fr.srcAs), dstas: String(fr.dstAs),
  });
  let records = 0;
  let mismatches = 0;
  let sequenceBreaks = 0;
  let expectedSequence: number | null = null;
  let maxCount = 0;
  let packets = 0;
  let octets = 0;
  const versions = new Set<string>();
  const shown: string[] = [];
  datagrams.forEach((d, i) => {
    const flows = normalizeFlows(d, 0, d.length, '192.0.2.10', new MemoryTemplateStore());
    const row = rows[i] ?? [];
    versions.add(row[0]);
    const count = Number(row[1]);
    maxCount = Math.max(maxCount, count);
    const sequence = Number(row[2]);
    if (expectedSequence !== null && sequence !== expectedSequence) sequenceBreaks++;
    expectedSequence = sequence + count;
    if (flows.length !== count) { mismatches++; shown.push(`datagram ${i + 1}: ${flows.length} records decoded, header says ${count}`); }
    flows.forEach((fr, k) => {
      records++;
      packets += fr.packets ?? 0;
      octets += fr.octets ?? 0;
      const mine = ours(fr);
      FIELDS.forEach((f, c) => {
        const theirsValue = (row[3 + c] ?? '').split(',')[k];
        if (mine[f] !== theirsValue) { mismatches++; if (shown.length < 10) shown.push(`datagram ${i + 1} record ${k + 1} ${f}: ours ${mine[f]}, tshark ${theirsValue}`); }
      });
    });
  });
  // softflowd counts every byte past the Ethernet header, so a short frame's
  // padding is in its octets; both sums are printed, and it should match the second.
  const capture = spawnSync(tshark, ['-r', pcap, '-Y', 'ip', '-T', 'fields', '-E', 'occurrence=f', '-e', 'ip.len', '-e', 'frame.len'], { encoding: 'utf8', maxBuffer: 1 << 28 });
  const ipRows = capture.stdout.trimEnd().split(/\r?\n/).map((l) => l.split('\t').map(Number)).filter(([ip]) => ip > 0);
  const ipOctets = ipRows.reduce((a, [ip]) => a + ip, 0);
  const pastEthernet = ipRows.reduce((a, [, frame]) => a + frame - 14, 0);
  console.log(`datagrams ${datagrams.length}, versions ${[...versions].join(',')}, records ${records}, most in one datagram ${maxCount}, sequence breaks ${sequenceBreaks}`);
  console.log(`field mismatches against tshark: ${mismatches} (fields compared: ${FIELDS.length} per record)`);
  for (const line of shown) console.log(`  ${line}`);
  console.log(`flows' totals: ${packets} packets, ${octets} octets; the capture's IPv4: ${ipRows.length} packets, ${ipOctets} octets by ip.len, ${pastEthernet} past the Ethernet header`);
  rmSync(dir, { recursive: true, force: true });
}

switch (mode) {
  case 'softflowd': await softflowdMode(); break;
  case 'bindpair': await bindPairMode(); break;
  case 'socket': await socketMode(); break;
  case 'journal': await journalMode(); break;
  case 'rollup': rollupMode(); break;
  case 'vector': vectorMode(); break;
  case 'firewall': await firewallMode(); break;
  default:
    console.log('usage: measurement.ts socket | journal [--quick] | rollup [--quick] | vector | firewall --electron <exe>');
    process.exitCode = 2;
}
