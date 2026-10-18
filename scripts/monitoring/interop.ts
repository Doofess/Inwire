/**
 * An independent exporter through the WHOLE monitoring path.
 *
 *   npx tsx scripts/monitoring/interop.ts [--pcap <capture>] [--seed <n>] [--try-direct]
 *                                         [--fixture-only <out.pcap>] [--keep]
 *
 * softflowd (in WSL, Ubuntu) reads a saved capture and writes fresh NetFlow v5
 * exports. Those datagrams reach the BUILT app's real UDP collector, and from
 * there the journal, the Worker and the rollup. The app's answers are then set
 * beside two references that are not the app:
 *
 *   - tshark's `cflow` decode of the very same datagrams, and
 *   - the source capture's own totals, read from the capture by tshark.
 *
 * The app's answers are read twice: from the Monitoring sheet's visible text
 * (record count, accepted datagrams, the two top tables), and - once the app is
 * closed - from the journal and the sidecar in the temporary profile, through
 * the repo's own codecs and query code, exactly (bigint), on the rollup path and
 * on the raw path.
 *
 * Delivery (a) is softflowd sending straight to the host's port. Under WSL2 NAT
 * the host is the default gateway as seen from WSL, so the app would have to
 * bind that address - and an Electron exe with no inbound firewall rule makes
 * Windows raise an administrator prompt there is nobody to answer. So (a) is
 * ATTEMPTED FOR THE APP only when an inbound Allow rule for the exe exists (or
 * with --try-direct); the WSL-to-host path itself is always probed with a plain
 * node receiver (node.exe has a rule) and the result is printed. Otherwise
 * delivery is (b): a keeper inside WSL records softflowd's datagrams and this
 * script replays exactly those bytes to the app's loopback port.
 *
 * Skips with `NOT RUN  interop: <what is missing>` (exit 0) when WSL, Ubuntu,
 * softflowd, python3, tshark, a build or Playwright is missing. That is a
 * recorded limitation, not a pass. Nothing is installed.
 *
 * Not a test: it is in `check.ts`'s NOT_TESTS.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from '../electron/stubAgent';
import { launchApp } from '../electron/launchApp';
import { formatBytes } from '../../src/lib/formatBytes';
import { MonitoringJournal } from '../../src/services/monitoring/journal';
import { LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { runHistoryQuery } from '../../src/services/monitoring/queries';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { decodeV5 } from '../../src/services/monitoring/v5';
import { DECODER_POLICY_VERSION, type DatagramEvidence, type HistoryResult } from '../../src/services/monitoring/types';
import { JOURNAL_FILE, ROLLUP_FILE, monitoringRoot, openMonitoringVolume } from '../../electron/monitoring/volume';
import { HostRig, deflate, inflate } from './queryRig';

const argv = process.argv.slice(2);
const argValue = (name: string): string | undefined => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const hasFlag = (name: string): boolean => argv.includes(name);

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}
const note = (line: string): void => console.log(`NOTE  ${line}`);
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// --- the synthetic capture ---------------------------------------------------------------------------

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const T0 = 1_760_000_000;
const ip4 = (a: string): number[] => a.split('.').map(Number);

function sum16(b: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i + 1 < b.length; i += 2) sum += (b[i] << 8) | b[i + 1];
  if (b.length % 2 === 1) sum += b[b.length - 1] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

interface Expected { packets: number; ipOctets: number; pastEthernet: number }
interface Fixture {
  bytes: Uint8Array;
  seed: number;
  frames: number;
  /** Per directional `src>dst`, from what this generator wrote. */
  expected: Map<string, Expected>;
  nonIpFrames: number;
  /** Distinct one-way 5-tuples, plus the splits the idle timeout must make. */
  expectedRecords: number;
  gapKey: string;
}

/** About 450 frames between six known hosts, written byte by byte from RFC 791/793/768/792. */
function syntheticCapture(seed: number): Fixture {
  const rnd = mulberry32(seed);
  const between = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));
  const frames: { tMs: number; order: number; bytes: Uint8Array }[] = [];
  const expected = new Map<string, Expected>();
  const tuples = new Set<string>();
  let order = 0;
  let ipId = 1;
  let nonIpFrames = 0;

  const mac = (host: string) => [0x02, 0x00, 0x00, 0x00, 0x00, Number(host.split('.')[3])];
  const ethernet = (dst: number[], src: number[], etherType: number, payload: Uint8Array): Uint8Array => {
    const out = new Uint8Array(Math.max(60, 14 + payload.length));
    out.set(dst, 0);
    out.set(src, 6);
    out[12] = etherType >> 8;
    out[13] = etherType & 0xff;
    out.set(payload, 14);
    return out;
  };
  const ipv4 = (src: string, dst: string, proto: number, l4: Uint8Array): Uint8Array => {
    const out = new Uint8Array(20 + l4.length);
    const v = new DataView(out.buffer);
    out[0] = 0x45;
    v.setUint16(2, out.length);
    v.setUint16(4, ipId++ & 0xffff);
    v.setUint16(6, 0x4000);
    out[8] = 64;
    out[9] = proto;
    out.set(ip4(src), 12);
    out.set(ip4(dst), 16);
    v.setUint16(10, sum16(out.subarray(0, 20)));
    out.set(l4, 20);
    return out;
  };
  const filler = (n: number) => Uint8Array.from({ length: n }, () => Math.floor(rnd() * 256));
  const emit = (tMs: number, src: string, dst: string, proto: number, l4: Uint8Array, tuple: string) => {
    const packet = ipv4(src, dst, proto, l4);
    const bytes = ethernet(mac(dst), mac(src), 0x0800, packet);
    frames.push({ tMs, order: order++, bytes });
    const key = `${src}>${dst}`;
    const e = expected.get(key) ?? { packets: 0, ipOctets: 0, pastEthernet: 0 };
    e.packets++;
    e.ipOctets += packet.length;
    e.pastEthernet += bytes.length - 14;
    expected.set(key, e);
    tuples.add(`${src}:${tuple}`);
  };
  const tcp = (sport: number, dport: number, flags: number, payload: number): Uint8Array => {
    const out = new Uint8Array(20 + payload);
    const v = new DataView(out.buffer);
    v.setUint16(0, sport);
    v.setUint16(2, dport);
    v.setUint32(4, between(0, 0x7fffffff));
    out[12] = 0x50;
    out[13] = flags;
    v.setUint16(14, 64240);
    out.set(filler(payload), 20);
    return out;
  };
  const udp = (sport: number, dport: number, payload: number): Uint8Array => {
    const out = new Uint8Array(8 + payload);
    const v = new DataView(out.buffer);
    v.setUint16(0, sport);
    v.setUint16(2, dport);
    v.setUint16(4, out.length);
    out.set(filler(payload), 8);
    return out;
  };
  const icmp = (type: number, seq: number): Uint8Array => {
    const out = new Uint8Array(8 + 32);
    out[0] = type;
    new DataView(out.buffer).setUint16(6, seq);
    out.set(filler(32), 8);
    return out;
  };

  const A = '10.1.0.11', B = '10.1.0.12', C = '10.1.0.13';
  const X = '10.2.0.21', Y = '10.2.0.22', D = '10.2.0.53';

  // 40 short TCP connections on distinct client ports.
  const pairs: [string, string][] = [[A, X], [A, X], [A, Y], [B, X], [B, Y], [C, Y], [A, X], [B, Y]];
  for (let i = 0; i < 40; i++) {
    const [c, s] = pairs[i % pairs.length];
    const sport = 40000 + i;
    const dport = s === X ? 443 : 8080;
    let t = i * 120;
    const step = () => (t += between(1, 4));
    emit(step(), c, s, 6, tcp(sport, dport, 0x02, 0), `${sport}>${s}:${dport}/6`);
    emit(step(), s, c, 6, tcp(dport, sport, 0x12, 0), `${dport}>${c}:${sport}/6`);
    emit(step(), c, s, 6, tcp(sport, dport, 0x10, 0), `${sport}>${s}:${dport}/6`);
    for (let k = 0; k < between(1, 3); k++) {
      emit(step(), c, s, 6, tcp(sport, dport, 0x18, between(40, 1400)), `${sport}>${s}:${dport}/6`);
      emit(step(), s, c, 6, tcp(dport, sport, 0x10, 0), `${dport}>${c}:${sport}/6`);
      emit(step(), s, c, 6, tcp(dport, sport, 0x18, between(100, 1460)), `${dport}>${c}:${sport}/6`);
      emit(step(), c, s, 6, tcp(sport, dport, 0x10, 0), `${sport}>${s}:${dport}/6`);
    }
    emit(step(), c, s, 6, tcp(sport, dport, 0x11, 0), `${sport}>${s}:${dport}/6`);
    emit(step(), s, c, 6, tcp(dport, sport, 0x11, 0), `${dport}>${c}:${sport}/6`);
    emit(step(), c, s, 6, tcp(sport, dport, 0x10, 0), `${sport}>${s}:${dport}/6`);
  }
  // DNS: three queries from each client.
  [A, B, C].forEach((c, ci) => {
    for (let q = 0; q < 3; q++) {
      const sport = 51000 + ci * 10 + q;
      const t = 500 + ci * 300 + q * 700;
      emit(t, c, D, 17, udp(sport, 53, between(28, 50)), `${sport}>${D}:53/17`);
      emit(t + 2, D, c, 17, udp(53, sport, between(60, 120)), `53>${c}:${sport}/17`);
    }
  });
  // Two pings from B to Y.
  for (let n = 0; n < 2; n++) {
    emit(1000 + n * 1000, B, Y, 1, icmp(8, n), `icmp8>${Y}`);
    emit(1001 + n * 1000, Y, B, 1, icmp(0, n), `icmp0>${B}`);
  }
  // One UDP flow that goes quiet for 400 s: the idle timeout (300 s) must split it.
  const gapKey = `${A}>${X}`;
  emit(0, A, X, 17, udp(50000, 5004, 100), `50000>${X}:5004/17`);
  emit(400_000, A, X, 17, udp(50000, 5004, 100), `50000>${X}:5004/17`);
  emit(410_000, A, X, 17, udp(50000, 5004, 100), `50000>${X}:5004/17`);
  const gapSplits = 1;

  // What softflowd cannot export in v5: IPv6 and ARP.
  const raw = (tMs: number, etherType: number, payload: Uint8Array, dst = [0x02, 0, 0, 0, 0, 0x99]) => {
    frames.push({ tMs, order: order++, bytes: ethernet(dst, mac(A), etherType, payload) });
    nonIpFrames++;
  };
  for (let n = 0; n < 4; n++) {
    const v6 = new Uint8Array(48 + 20);
    v6[0] = 0x60;
    new DataView(v6.buffer).setUint16(4, 28);
    v6[6] = 17;
    v6[7] = 64;
    v6.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8);
    v6.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 24);
    v6.set(udp(5000 + n, 53, 20).subarray(0, 8), 40);
    raw(300 + n * 50, 0x86dd, v6);
  }
  for (let n = 0; n < 3; n++) {
    const arp = new Uint8Array(28);
    arp.set([0, 1, 8, 0, 6, 4, 0, 1], 0);
    arp.set(mac(A), 8);
    arp.set(ip4(A), 14);
    arp.set(ip4(X), 24);
    raw(200 + n * 40, 0x0806, arp, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  }

  frames.sort((a, b) => a.tMs - b.tMs || a.order - b.order);
  const parts: Uint8Array[] = [];
  const g = new DataView(new ArrayBuffer(24));
  g.setUint32(0, 0xa1b2c3d4, true); g.setUint16(4, 2, true); g.setUint16(6, 4, true);
  g.setUint32(16, 65535, true); g.setUint32(20, 1, true);
  parts.push(new Uint8Array(g.buffer));
  for (const f of frames) {
    const r = new DataView(new ArrayBuffer(16));
    r.setUint32(0, T0 + Math.floor(f.tMs / 1000), true);
    r.setUint32(4, (f.tMs % 1000) * 1000, true);
    r.setUint32(8, f.bytes.length, true);
    r.setUint32(12, f.bytes.length, true);
    parts.push(new Uint8Array(r.buffer), f.bytes);
  }
  return {
    bytes: Buffer.concat(parts), seed, frames: frames.length, expected, nonIpFrames,
    expectedRecords: tuples.size + gapSplits, gapKey,
  };
}

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
    v.setUint16(10, sum16(frame.subarray(0, 20)));
    v.setUint16(20, 50000); v.setUint16(22, dstPort); v.setUint16(24, 8 + d.length);
    frame.set(d, 28);
    const r = new DataView(new ArrayBuffer(16));
    r.setUint32(0, 1_700_000_000 + i, true); r.setUint32(8, frame.length, true); r.setUint32(12, frame.length, true);
    parts.push(new Uint8Array(r.buffer), frame);
  });
  return Buffer.concat(parts);
}

if (argValue('--fixture-only') !== undefined) {
  const f = syntheticCapture(Number(argValue('--seed') ?? 0x1ee7));
  writeFileSync(argValue('--fixture-only')!, f.bytes);
  console.log(`fixture: ${f.frames} frames, ${f.expected.size} directional IPv4 pairs, ${f.nonIpFrames} non-IP, ${f.expectedRecords} expected records`);
  process.exit(0);
}

// --- prerequisites -----------------------------------------------------------------------------------

const wsl = (args: string[], input?: string) =>
  spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', ...args], { encoding: 'utf8', input, timeout: 120_000 });
const winToWsl = (p: string) => `/mnt/${p[0].toLowerCase()}${p.slice(2).replace(/\\/g, '/')}`;

function notRun(what: string): never {
  console.log(`NOT RUN  interop: ${what}`);
  process.exit(0);
}

if (process.platform !== 'win32') notRun('the desktop app and WSL are Windows-only');
{
  const probe = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'true'], { encoding: 'utf8', timeout: 60_000 });
  if (probe.error) notRun('wsl.exe is not available (WSL is not installed)');
  if (probe.status !== 0) notRun('the WSL distribution "Ubuntu" is not available');
  if (wsl(['sh', '-c', 'command -v softflowd']).status !== 0) notRun('softflowd is not installed in WSL Ubuntu');
  if (wsl(['sh', '-c', 'command -v python3']).status !== 0) notRun('python3 is not installed in WSL Ubuntu (the datagram keeper needs it)');
}
const { findWiresharkTool } = await import('../export/realCaptures');
const tshark = findWiresharkTool('tshark');
if (tshark === null) notRun('tshark is not installed (Wireshark)');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'monitoring', 'monitoring.cjs'))) {
  notRun('no build with monitoring to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  notRun('playwright is not installed');
}

// --- the fixture -------------------------------------------------------------------------------------

const work = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'inwire-interop-')));
const external = argValue('--pcap');
const seed = Number(argValue('--seed') ?? 0x1ee7);
let fixture: Fixture | null = null;
let pcapPath: string;
if (external !== undefined) {
  if (!existsSync(external)) notRun(`--pcap ${external} does not exist`);
  pcapPath = realpathSync.native(external);
  const sha = createHash('sha256').update(readFileSync(pcapPath)).digest('hex');
  console.log(`fixture: ${pcapPath}\n         sha256 ${sha}`);
} else {
  fixture = syntheticCapture(seed);
  pcapPath = path.join(work, 'source.pcap');
  writeFileSync(pcapPath, fixture.bytes);
  const sha = createHash('sha256').update(fixture.bytes).digest('hex');
  console.log(`fixture: generated by scripts/monitoring/interop.ts, seed ${seed} (0x${seed.toString(16)}), ${fixture.frames} frames`);
  console.log(`         sha256 ${sha}`);
}

// --- tool versions -----------------------------------------------------------------------------------

const firstLine = (s: string) => s.split(/\r?\n/).find((l) => l.trim() !== '')?.trim() ?? '';
const softflowdVersion = /softflowd version [\d.]+/.exec(wsl(['sh', '-c', 'softflowd -h 2>&1 | sed -n 2p']).stdout)?.[0] ?? 'unknown';
const tsharkVersion = firstLine(spawnSync(tshark!, ['--version'], { encoding: 'utf8' }).stdout);
const distro = [
  /PRETTY_NAME="?([^"\r\n]*)/.exec(wsl(['cat', '/etc/os-release']).stdout)?.[1] ?? 'unknown distro',
  `kernel ${firstLine(wsl(['uname', '-r']).stdout)}`,
  firstLine(wsl(['python3', '-V']).stdout),
].join(', ');
const reportedGateway = /via\s+(\d+\.\d+\.\d+\.\d+)/.exec(wsl(['sh', '-c', 'ip route show default']).stdout)?.[1] ?? null;
const wslAddress = /inet\s+(\d+\.\d+\.\d+\.\d+)/.exec(wsl(['sh', '-c', 'ip -4 -o addr show eth0']).stdout)?.[1] ?? null;
console.log(`softflowd: ${softflowdVersion}`);
console.log(`tshark:    ${tsharkVersion}`);
console.log(`WSL:       ${distro}; eth0 ${wslAddress ?? 'none'}, default gateway ${reportedGateway ?? 'none'}`);
console.log(`Node:      ${process.version}`);

// --- the capture's own totals, read by tshark -------------------------------------------------------

const tsharkFields = (file: string, filter: string | null, fields: string[], extra: string[] = []): string[][] => {
  const r = spawnSync(tshark!, ['-r', file, ...(filter ? ['-Y', filter] : []), ...extra, '-T', 'fields', ...fields.flatMap((f) => ['-e', f])],
    { encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error(`tshark failed: ${r.stderr.split('\n').slice(0, 3).join(' | ')}`);
  return r.stdout.split(/\r?\n/).filter((l) => l !== '').map((l) => l.split('\t'));
};
const allFrames = tsharkFields(pcapPath, null, ['frame.number']).length;
const ipRows = tsharkFields(pcapPath, 'ip', ['ip.src', 'ip.dst', 'ip.len', 'frame.len'], ['-E', 'occurrence=f']);
const capture = new Map<string, Expected>();
for (const [src, dst, ipLen, frameLen] of ipRows) {
  const e = capture.get(`${src}>${dst}`) ?? { packets: 0, ipOctets: 0, pastEthernet: 0 };
  e.packets++;
  e.ipOctets += Number(ipLen);
  e.pastEthernet += Number(frameLen) - 14;
  capture.set(`${src}>${dst}`, e);
}
const captureTotals = [...capture.values()].reduce(
  (a, e) => ({ packets: a.packets + e.packets, ip: a.ip + e.ipOctets, past: a.past + e.pastEthernet }),
  { packets: 0, ip: 0, past: 0 },
);
console.log(`capture (by tshark): ${allFrames} frames, ${ipRows.length} IPv4 with ${captureTotals.packets} packets, ${captureTotals.ip} octets by ip.len, ${captureTotals.past} past the Ethernet header, ${allFrames - ipRows.length} frames not IPv4`);
if (fixture) {
  const same = fixture.expected.size === capture.size
    && [...fixture.expected].every(([k, e]) => {
      const c = capture.get(k);
      return c && c.packets === e.packets && c.ipOctets === e.ipOctets && c.pastEthernet === e.pastEthernet;
    });
  check('the generator and tshark agree on every directional total of the capture', same);
  check('...and on how many frames are not IPv4', allFrames - ipRows.length === fixture.nonIpFrames);
}

// --- the keeper (WSL) and softflowd ------------------------------------------------------------------

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

async function freePort(address = '127.0.0.1'): Promise<number> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, address, resolve));
  const port = s.address().port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

/** A keeper in WSL on its own loopback; resolves with the file it will fill once softflowd is done. */
async function startKeeper(file: string, port: number): Promise<{ done: Promise<void> }> {
  const keeper = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'python3', '-', String(port), winToWsl(file)], { stdio: ['pipe', 'pipe', 'inherit'] });
  keeper.stdin.end(WSL_KEEPER);
  let out = '';
  await new Promise<void>((ready) => keeper.stdout.on('data', (c: Buffer) => { out += c.toString('utf8'); if (out.includes('ready')) ready(); }));
  return { done: new Promise<void>((r) => keeper.once('exit', () => r())) };
}

function readKept(file: string): Uint8Array[] {
  const raw = readFileSync(file);
  const out: Uint8Array[] = [];
  for (let p = 0; p + 4 <= raw.length;) { const n = raw.readUInt32LE(p); out.push(raw.subarray(p + 4, p + 4 + n)); p += 4 + n; }
  return out;
}

const runSoftflowd = (destinations: string[], extra: string[] = []) => spawnSync('wsl.exe', [
  // softflowd 1.1.1 takes several destinations as ONE comma-separated -n; a repeated -n keeps only the last.
  '-d', 'Ubuntu', '--', 'softflowd', '-r', winToWsl(pcapPath), '-n', destinations.join(','), ...extra, '-v', '5', '-d',
], { encoding: 'utf8', timeout: 120_000 });

// --- (a) the WSL-to-host path, probed with a node receiver -------------------------------------------

interface Probe { bind: string; outcome: string; datagrams: number; from: string | null }
async function probeHostPath(): Promise<Probe> {
  if (reportedGateway === null) return { bind: 'none', outcome: 'WSL reports no default gateway (mirrored networking?)', datagrams: 0, from: null };
  const receiver = createSocket('udp4');
  const sources = new Set<string>();
  let datagrams = 0;
  receiver.on('message', (_m, r) => { datagrams++; sources.add(r.address); });
  try {
    await new Promise<void>((resolve, reject) => { receiver.once('error', reject); receiver.bind(0, reportedGateway, resolve); });
  } catch (e) {
    return { bind: reportedGateway, outcome: `node could not bind the gateway address: ${(e as Error).message}`, datagrams: 0, from: null };
  }
  const port = receiver.address().port;
  const r = runSoftflowd([`${reportedGateway}:${port}`]);
  await sleep(1000);
  receiver.close();
  return {
    bind: `${reportedGateway}:${port}`,
    outcome: r.status === 0 ? `softflowd exited 0 and ${datagrams} datagram(s) arrived` : `softflowd exit ${r.status}: ${r.stderr.trim().split('\n').slice(-2).join(' | ')}`,
    datagrams,
    from: [...sources].join(',') || null,
  };
}

function inboundRuleFor(exe: string): string {
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-Command',
    `Get-NetFirewallApplicationFilter | Where-Object { $_.Program -eq '${exe.replace(/'/g, "''")}' } | ForEach-Object { $r = $_ | Get-NetFirewallRule; "$($r.Direction)|$($r.Action)|$($r.Enabled)|$($r.Profile)" }`],
  { encoding: 'utf8', timeout: 60_000 });
  const rules = ps.stdout.split(/\r?\n/).filter((l) => l !== '');
  return rules.length === 0 ? 'none' : rules.join('; ');
}

// --- the app -----------------------------------------------------------------------------------------

type App = Awaited<ReturnType<typeof launchApp>>;
const SHEET = '[data-testid="monitoring-sheet"]';
const PIPE = String.raw`\\.\pipe\inwire-interop-` + process.pid;
const digits = (s: string): number => Number(s.replace(/[^\d]/g, ''));

let agent: StubAgent | null = null;
let app: App | null = null;
let profile: string | null = null;
let chosenPath = '(b) keeper fallback';
let electronVersion = 'unknown';

try {
  const electronExe = path.resolve('node_modules', 'electron', 'dist', 'electron.exe');
  const rule = inboundRuleFor(electronExe);
  const probe = await probeHostPath();
  console.log(`\n(a) direct, WSL -> host: probe with a node receiver on ${probe.bind}: ${probe.outcome}${probe.from ? `; seen from ${probe.from}` : ''}`);
  console.log(`    inbound firewall rules for ${electronExe}: ${rule}`);
  const allowRule = rule.split('; ').some((r) => r.startsWith('Inbound|Allow|True'));
  const direct = (allowRule || hasFlag('--try-direct')) && probe.datagrams > 0 && probe.from !== null && reportedGateway !== null;
  if (!direct) {
    const why = probe.datagrams === 0 ? 'the host path did not carry datagrams' : !allowRule && !hasFlag('--try-direct')
      ? 'no inbound Allow rule for the Electron exe, so binding the gateway address would raise an administrator firewall prompt nobody can answer (pass --try-direct to accept that)'
      : 'unknown';
    console.log(`    -> not attempted for the app: ${why}`);
  }

  // Two passes: softflowd exactly as Task 1 ran it, then with -a (see the notes at the first pass).
  const passes = [
    { label: 'PASS 1: softflowd -r <capture> -v 5 -d (as Task 1 ran it)', flags: [] as string[], exact: false },
    { label: 'PASS 2: softflowd -r <capture> -a -v 5 -d (header clock follows the capture)', flags: ['-a'], exact: true },
  ];
  for (const [passIndex, pass] of passes.entries()) {
  console.log(`\n=== ${pass.label} ===`);
  const endPass = async (): Promise<void> => {
    await app?.close().catch(() => {});
    app = null;
    await agent?.close();
    agent = null;
    if (profile) {
      try { rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); } catch { /* reported by the caller's finally */ }
    }
    profile = null;
  };
  // 1. softflowd's datagrams, recorded in WSL.
  const kept = path.join(work, `datagrams-${passIndex}.bin`);
  const keeperPort = await freePort();
  const appPort = await freePort(direct ? reportedGateway! : '127.0.0.1');
  const keeper = await startKeeper(kept, keeperPort);
  const destinations = [`127.0.0.1:${keeperPort}`, ...(direct ? [`${reportedGateway}:${appPort}`] : [])];

  agent = await startStubAgent(PIPE, 5);
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-interop-profile-'));
  app = await launchApp({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE } });
  electronVersion = await app.evaluate(() => process.versions.electron).catch(() => 'unknown');
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  const until = async (cond: () => Promise<boolean>, ms: number) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (await cond()) return true; await sleep(250); }
    return false;
  };
  const sheetText = () => p.locator(SHEET).innerText().catch(() => '');

  await p.getByRole('button', { name: 'Statistics', exact: true }).click();
  await p.getByRole('button', { name: 'Network', exact: true }).click();
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await p.locator(SHEET).waitFor();
  await p.getByRole('textbox', { name: 'Exporter', exact: true }).fill(direct ? probe.from!.split(',')[0] : '127.0.0.1');
  await p.getByRole('textbox', { name: 'Listen on', exact: true }).fill(direct ? reportedGateway! : '127.0.0.1');
  await p.getByRole('textbox', { name: 'Port', exact: true }).fill(String(appPort));
  await p.getByRole('button', { name: 'Start', exact: true }).click();
  check('the app listens', await until(async () => /Listening, nothing received yet/.test(await sheetText()), 20_000));
  const sourceAddress = direct ? probe.from!.split(',')[0] : '127.0.0.1';

  const exported = runSoftflowd(destinations, pass.flags);
  await keeper.done;
  const datagrams = readKept(kept);
  console.log(`\nsoftflowd exit ${exported.status}${exported.stderr.trim() ? `; stderr: ${exported.stderr.trim().split('\n').slice(-3).join(' | ')}` : ''}; ${datagrams.length} datagrams kept (${datagrams.reduce((a, d) => a + d.length, 0)} bytes)`);
  check('softflowd exported datagrams', exported.status === 0 && datagrams.length > 0);

  if (direct) {
    chosenPath = '(a) direct: softflowd sent to the app on the gateway address, and to the keeper for the reference copy';
  } else {
    const sender = createSocket('udp4');
    await new Promise<void>((resolve) => sender.bind(0, '127.0.0.1', resolve));
    for (const d of datagrams) {
      await new Promise<void>((resolve, reject) => sender.send(d, appPort, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
      await sleep(40);
    }
    sender.close();
  }
  console.log(`\nPATH RUN: ${chosenPath}`);

  // 2. the tshark reference over those same datagrams.
  const exportPcap = path.join(work, 'export.pcap');
  writeFileSync(exportPcap, rawUdpPcap(datagrams, keeperPort));
  const FIELDS = ['srcaddr', 'dstaddr', 'packets', 'octets', 'srcport', 'dstport', 'protocol'] as const;
  const rows = tsharkFields(exportPcap, null,
    ['cflow.version', 'cflow.count', 'cflow.sequence', 'cflow.engine_type', 'cflow.engine_id', ...FIELDS.map((f) => `cflow.${f}`)],
    ['-d', `udp.port==${keeperPort},cflow`, '-E', 'occurrence=a', '-E', 'aggregator=,']);
  interface Ref { src: string; dst: string; packets: number; octets: number; proto: number; sport: number; dport: number }
  const refs: Ref[] = [];
  const engines = new Set<string>();
  rows.forEach((row) => {
    engines.add(`${row[3]}/${row[4]}`);
    const col = (i: number) => (row[5 + i] ?? '').split(',');
    col(0).forEach((src, k) => refs.push({
      src, dst: col(1)[k], packets: Number(col(2)[k]), octets: Number(col(3)[k]),
      sport: Number(col(4)[k]), dport: Number(col(5)[k]), proto: Number(col(6)[k]),
    }));
  });
  const refPackets = refs.reduce((a, r) => a + r.packets, 0);
  const refOctets = refs.reduce((a, r) => a + BigInt(r.octets), 0n);
  const refSent = new Map<string, bigint>();
  const refRecv = new Map<string, bigint>();
  const refConv = new Map<string, { octets: bigint; packets: bigint }>();
  for (const r of refs) {
    refSent.set(r.src, (refSent.get(r.src) ?? 0n) + BigInt(r.octets));
    refRecv.set(r.dst, (refRecv.get(r.dst) ?? 0n) + BigInt(r.octets));
    const c = refConv.get(`${r.src}>${r.dst}`) ?? { octets: 0n, packets: 0n };
    c.octets += BigInt(r.octets);
    c.packets += BigInt(r.packets);
    refConv.set(`${r.src}>${r.dst}`, c);
  }
  console.log(`tshark cflow: ${rows.length} datagrams (versions ${[...new Set(rows.map((r) => r[0]))].join(',')}), ${refs.length} records, ${refPackets} packets, ${refOctets} octets, engines ${[...engines].join(',')}, ${refConv.size} directional pairs`);
  check('tshark decodes every datagram as version 5', rows.length === datagrams.length && rows.every((r) => r[0] === '5'));
  check('...with the header count equal to the records it lists', rows.every((r) => Number(r[1]) === (r[5] ?? '').split(',').filter((x) => x !== '').length));

  if (!pass.exact) {
    // Recorded, not asserted against: replaying a capture with -r stamps the header with the wall clock and
    // an uptime counted from softflowd's own start, while every record's First and Last are capture-relative.
    const headerUptimes = [...new Set(datagrams.map((d) => new DataView(d.buffer, d.byteOffset).getUint32(4)))];
    const firstSecs = datagrams.map((d) => new DataView(d.buffer, d.byteOffset).getUint32(8));
    const decoded = datagrams.map((d, i) => decodeV5({ kind: 'datagram', bytes: d, receivedMs: Date.now(), receiveOrdinal: i } as unknown as DatagramEvidence, '127.0.0.1'));
    const reasons = [...new Set(decoded.map((r) => (r.kind === 'valid' ? 'valid' : `${r.kind}: ${r.reason}`)))];
    console.log(`RECORDED: header sys_uptime in the ${datagrams.length} datagrams: ${headerUptimes.join(', ')} ms; unix_secs ${firstSecs[0]} (${new Date(firstSecs[0] * 1000).toISOString()}), the clock of this run, not the capture's (${new Date(T0 * 1000).toISOString()})`);
    console.log(`RECORDED: the app's own decoder on exactly these datagrams: ${reasons.join(' | ')}`);
    await sleep(6000);
    const t = await sheetText();
    const acc = digits(/Accepted\s+([\d.,\s  ]+)/.exec(t)?.[1] ?? '-1');
    const recs = digits(/([\d.,\s  ]+) received traffic records/.exec(t)?.[1] ?? '0');
    console.log(`RECORDED: the sheet after 6 s: Accepted ${acc}, ${recs} received traffic records; history says: ${/No received traffic records yet[^.]*\.?/.exec(t)?.[0] ?? '(no empty-history note)'}`);
    await p.getByRole('button', { name: 'Stop', exact: true }).click();
    await until(async () => /Stopped/.test(await sheetText()), 15_000);
    await p.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } }).inwire?.setUnsavedCapture?.(false));
    await app.close().catch(() => {});
    app = null;
    const copy1 = path.join(work, 'copy1');
    mkdirSync(copy1, { recursive: true });
    for (const f of [JOURNAL_FILE, ROLLUP_FILE]) copyFileSync(path.join(monitoringRoot(profile!), f), path.join(copy1, f));
    const vol1 = openMonitoringVolume(copy1);
    try {
      const { journal } = MonitoringJournal.open(vol1.journal, { limitBytes: 1 << 30 });
      const snap = journal.snapshot();
      const opened = RollupStore.open(vol1.rollups,
        { generation: snap.generation, throughEntryId: snap.throughEntryId, policyVersion: DECODER_POLICY_VERSION }, { nowMs: () => Date.now() });
      const rt = new LocalRuntime(journal, opened.store, opened.reason === undefined ? { status: opened.status } : { status: opened.status, reason: opened.reason });
      await new HostRig(rt, { wallNow: () => Date.now() }).connect();
      const srcs = await rt.sources();
      const now = Date.now();
      const reply = srcs[0] === undefined ? null
        : await runHistoryQuery(rt, rt, { sourceKey: srcs[0], fromMs: now - 3_600_000, toMs: now + 60_000, bucketCount: 60 }, new AbortController().signal, { inflate, nowMs: now });
      const show = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));
      console.log(`RECORDED: journal holds ${snap.throughEntryId} entries; sources [${srcs.join(', ')}]; ${reply === null ? 'no query' : reply.ok ? `matchingRecords ${reply.value.matchingRecords}, malformed ${show(reply.value.malformed)}, unsupported ${show(reply.value.unsupported)}` : `history query for the exporter-level key refused: ${reply.code} (${reply.message})`}`);
      journal.close?.();
    } finally {
      vol1.close();
    }
    const validCount = decoded.filter((r) => r.kind === 'valid').length;
    check('pass 1: the sheet counts as accepted exactly the datagrams the decoder calls valid, and lists records only for those',
      acc === validCount && (validCount === 0) === (recs === 0), `sheet accepted ${acc}, decoder valid ${validCount} of ${datagrams.length}; sheet records ${recs}`);
    await endPass();
    continue;
  }

  // 3. the sheet.
  const wantRecords = refs.length;
  const reached = await until(async () => digits(/([\d.,\s  ]+) received traffic records/.exec(await sheetText())?.[1] ?? '0') === wantRecords, 40_000);
  const text = await sheetText();
  const sheetRecords = digits(/([\d.,\s  ]+) received traffic records/.exec(text)?.[1] ?? '0');
  check(`the sheet counts ${wantRecords} received traffic records, as tshark decodes`, reached,
    `sheet says ${sheetRecords}; sheet text: ${text.replace(/\s+/g, ' ').slice(0, 700)}`);
  const accepted = digits(/Accepted\s+([\d.,\s  ]+)/.exec(text)?.[1] ?? '-1');
  check(`...and ${datagrams.length} accepted datagrams`, accepted === datagrams.length, `sheet says ${accepted}`);

  const readTable = (title: string): Promise<string[][]> => p.evaluate((t) => {
    const h = [...document.querySelectorAll('h3')].find((e) => e.textContent?.trim() === t);
    const box = h?.parentElement;
    return box ? [...box.querySelectorAll('tbody tr')].map((tr) => [...tr.querySelectorAll('td')].map((td) => (td as HTMLElement).innerText.trim())) : [];
  }, title);
  const fmt = (n: bigint) => formatBytes(Number(n));

  const endpoints = await readTable('Top endpoints');
  const addresses = new Set([...refSent.keys(), ...refRecv.keys()]);
  const endpointOk = endpoints.length === addresses.size && endpoints.every(([a, sent, recv]) =>
    sent === fmt(refSent.get(a) ?? 0n) && recv === fmt(refRecv.get(a) ?? 0n));
  check(`the sheet's Top endpoints list all ${addresses.size} addresses with tshark's sent and received (as the sheet formats bytes)`, endpointOk,
    endpoints.slice(0, 4).map((r) => r.join(' / ')).join(' | '));
  const conversationsBytes = await readTable('Top conversations');
  const bytesOk = conversationsBytes.length === refConv.size && conversationsBytes.every(([s, d, b]) => b === fmt(refConv.get(`${s}>${d}`)?.octets ?? -1n));
  check(`the sheet's Top conversations list all ${refConv.size} directional pairs with tshark's bytes (as formatted)`, bytesOk,
    `${conversationsBytes.length} rows; ${conversationsBytes.slice(0, 3).map((r) => r.join(' / ')).join(' | ')}`);
  await p.getByRole('group', { name: 'Measure' }).getByRole('button', { name: 'Packets' }).click({ timeout: 5000 }).catch(() => {});
  await until(async () => (await readTable('Top conversations'))[0]?.[2] !== conversationsBytes[0]?.[2], 15_000);
  const conversationsPackets = await readTable('Top conversations');
  const packetsOk = conversationsPackets.length === refConv.size
    && conversationsPackets.every(([s, d, n]) => digits(n) === Number(refConv.get(`${s}>${d}`)?.packets ?? -1n));
  check('...and the same pairs with tshark\'s packet counts, exactly', packetsOk,
    `${conversationsPackets.length} rows; ${conversationsPackets.slice(0, 3).map((r) => r.join(' / ')).join(' | ')}`);

  await p.getByRole('button', { name: 'Stop', exact: true }).click();
  await until(async () => /Stopped/.test(await sheetText()), 15_000);
  await p.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } }).inwire?.setUnsavedCapture?.(false));
  await app.close().catch(() => {});
  app = null;

  // 4. the journal and the sidecar, read with the repo's own code, exactly.
  const copy = path.join(work, 'copy');
  mkdirSync(copy, { recursive: true });
  for (const f of [JOURNAL_FILE, ROLLUP_FILE]) copyFileSync(path.join(monitoringRoot(profile), f), path.join(copy, f));
  const volume = openMonitoringVolume(copy);
  try {
    const { journal } = MonitoringJournal.open(volume.journal, { limitBytes: 1 << 30 });
    const snap = journal.snapshot();
    const opened = RollupStore.open(volume.rollups,
      { generation: snap.generation, throughEntryId: snap.throughEntryId, policyVersion: DECODER_POLICY_VERSION }, { nowMs: () => Date.now() });
    const runtime = new LocalRuntime(journal, opened.store, opened.reason === undefined ? { status: opened.status } : { status: opened.status, reason: opened.reason });
    const rig = new HostRig(runtime, { wallNow: () => Date.now() });
    await rig.connect();
    const sources = await runtime.sources();
    console.log(`\njournal copy: ${snap.throughEntryId} entries; sidecar ${opened.status}; sources ${sources.join(', ')}; sender seen as ${sourceAddress}`);
    const key = sources.find((s) => s.startsWith(`${sourceAddress}/`));
    check('the journal holds one engine source for the exporter', key !== undefined && sources.filter((s) => /\/\d+\/\d+$/.test(s)).length === 1, sources.join(','));
    note(`source key ${key ?? '(none)'} (exporter/engine type/engine id, as tshark's ${[...engines].join(',')})`);
    if (key !== undefined) {
      const now = Date.now();
      const query = { sourceKey: key, fromMs: now - 3_600_000, toMs: now + 60_000, bucketCount: 60 };
      const ask = async (forceRaw: boolean): Promise<HistoryResult> => {
        const reply = await runHistoryQuery(runtime, runtime, query, new AbortController().signal, { inflate, nowMs: now, forceRaw });
        if (!reply.ok) throw new Error(`${reply.code}: ${reply.message}`);
        return reply.value;
      };
      void deflate;
      const [fast, raw] = [await ask(false), await ask(true)];
      for (const [label, result] of [['rollup', fast], ['raw', raw]] as const) {
        const octets = result.buckets.reduce((a, b) => a + (b.reportedOctets ?? 0n), 0n);
        const packets = result.buckets.reduce((a, b) => a + (b.reportedPackets ?? 0n), 0n);
        check(`${label} path: ${refs.length} records, ${refPackets} packets, ${refOctets} octets, as tshark decodes`,
          result.matchingRecords === refs.length && packets === BigInt(refPackets) && octets === refOctets,
          `records ${result.matchingRecords}, packets ${packets}, octets ${octets}`);
        const eps = result.endpoints.status === 'ok' ? result.endpoints.rows : [];
        check(`${label} path: every endpoint's sent and received equal tshark's, exactly`,
          eps.length === addresses.size && eps.every((e) => e.sentOctets === (refSent.get(e.address) ?? 0n) && e.receivedOctets === (refRecv.get(e.address) ?? 0n)));
        const convs = result.conversations.status === 'ok' ? result.conversations.rows : [];
        check(`${label} path: every directional pair's bytes and packets equal tshark's, exactly`,
          convs.length === refConv.size && convs.every((c) => {
            const want = refConv.get(`${c.srcAddr}>${c.dstAddr}`);
            return want !== undefined && c.reportedOctets === want.octets && BigInt(c.reportedPackets) === want.packets;
          }));
      }
      note(`rollup answered from ${fast.answeredFrom.rollupMinutes} summarised and ${fast.answeredFrom.rawMinutes} raw minutes; raw from ${raw.answeredFrom.rollupMinutes} and ${raw.answeredFrom.rawMinutes}`);
      check('the rollup path and the raw path agree on everything but provenance',
        JSON.stringify({ ...fast, answeredFrom: 0 }, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v))
        === JSON.stringify({ ...raw, answeredFrom: 0 }, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)));
    }
    journal.close?.();
  } finally {
    volume.close();
  }

  // 5. against the capture's own expectations.
  console.log('\n--- against the source capture (what softflowd did, not what the app did) ---');
  const refKeys = new Set(refConv.keys());
  const capKeys = new Set(capture.keys());
  check('directions: the exporter reported exactly the capture\'s directional IPv4 pairs, and no others',
    refKeys.size === capKeys.size && [...capKeys].every((k) => refKeys.has(k)),
    `exported ${[...refKeys].filter((k) => !capKeys.has(k)).join(',') || '-'} extra; missing ${[...capKeys].filter((k) => !refKeys.has(k)).join(',') || '-'}`);
  check('coverage: the exported packet total equals the capture\'s IPv4 packets (IPv6 and ARP are not exported by v5)',
    refPackets === captureTotals.packets, `exported ${refPackets}, capture IPv4 ${captureTotals.packets}`);
  const perPair = [...capKeys].every((k) => refConv.get(k)?.packets === BigInt(capture.get(k)!.packets));
  check('...and so does every pair, packet for packet', perPair);
  const pastOk = [...capKeys].every((k) => refConv.get(k)?.octets === BigInt(capture.get(k)!.pastEthernet));
  const ipOk = [...capKeys].every((k) => refConv.get(k)?.octets === BigInt(capture.get(k)!.ipOctets));
  console.log(`BYTE ACCOUNTING: exported octets ${refOctets}; capture ip.len ${captureTotals.ip}; capture past the Ethernet header ${captureTotals.past}.`);
  console.log(`  every pair equals the bytes past the Ethernet header (padding included): ${pastOk}; every pair equals ip.len: ${ipOk}`);
  check('byte accounting: softflowd counts the bytes past the Ethernet header, short-frame padding included', pastOk);
  if (!ipOk) note(`the exporter's octets exceed IP total length by ${Number(refOctets) - captureTotals.ip} - the padding of short frames`);
  if (fixture) {
    const gapRecords = refs.filter((r) => r.src === '10.1.0.11' && r.dst === '10.2.0.21' && r.sport === 50000 && r.dport === 5004);
    console.log(`FLOW-TIMEOUT SPLIT: the 3-packet UDP flow idle for 400 s (timeout 300 s) came as ${gapRecords.length} record(s) with packets [${gapRecords.map((r) => r.packets).join(',')}]`);
    // Observed, not asserted: whether softflowd 1.1.1 splits a replayed flow at its idle timeout is the
    // exporter's behaviour, and the app's answer is already compared exactly with tshark above either way.
    const split = gapRecords.length === 2 && gapRecords.map((r) => r.packets).sort().join() === '1,2';
    note(split ? 'softflowd split the idle UDP flow at its timeout, as the capture\'s timeline implies'
      : 'softflowd 1.1.1 did NOT split the idle UDP flow at its 300 s timeout when replaying the capture (-r -a); the exporter kept it as one record, which is its behaviour, not the app\'s');
    console.log(`RECORD COUNT: expected ${fixture.expectedRecords} (one per one-way 5-tuple plus the split); exported ${refs.length}`);
    if (refs.length !== fixture.expectedRecords) note('the record count differs from one-per-one-way-tuple; softflowd merges or splits flows by its own rules');
  }
  await endPass();
  }
  console.log(`\nElectron ${electronVersion}`);
} finally {
  await app?.evaluate(() => {}).catch(() => {});
  await app?.close().catch(() => {});
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    if (!hasFlag('--keep')) rmSync(work, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    else console.log(`kept: ${work}`);
  } catch {
    console.log(`      note: could not remove a temporary directory under ${work}`);
  }
}

console.log(failures === 0 ? '\nAll interop checks passed.' : `\n${failures} interop check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
