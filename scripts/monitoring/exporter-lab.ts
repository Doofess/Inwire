/**
 * What independent NetFlow v9 and IPFIX exporters actually send (Task 7 of the
 * monitoring 1.5 and 2 plan; ADR 0064).
 *
 *   npx tsx scripts/monitoring/exporter-lab.ts [--write-vectors] [--keep]
 *
 * softflowd and pmacct's nfprobe (both in WSL, Ubuntu) read the generated
 * capture that `interop.ts --fixture-only` writes - never a real one - and
 * export to a keeper in WSL that records each datagram with its receipt time
 * and source port. Each pass is then read three ways:
 *
 *   - by the tree decoder's readers (`flowExport.ts`), at the template-id and
 *     information-element level: templates, options data, refresh, sequence
 *     numbers, header clocks and the flow-time elements used;
 *   - by tshark's cflow decode of the same datagrams (on Windows);
 *   - by nfdump, after the same bytes are replayed into nfcapd in WSL.
 *
 * `--write-vectors` writes `exporter-vectors.json` beside this file: every
 * datagram as hex with its port and relative receipt time (the refresh passes
 * trimmed to their first datagrams), and each reference's totals over what
 * was kept, so a plain-tsx test can decode them without WSL.
 *
 * Prints `NOT RUN  exporter-lab: <what is missing>` and exits 0 when WSL,
 * Ubuntu, softflowd, python3 or tshark is missing; a pass whose exporter is
 * missing (pmacct, nfdump) is NOT RUN on its own line. That is a recorded
 * limitation, not a pass.
 *
 * Not a test: it is in `check.ts`'s NOT_TESTS.
 */
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  readDataRecords, readFlowHeader, readFlowSets, readTemplateSet, readUint, setKind,
  type FlowHeader, type FlowTemplate, type FlowTemplateField,
} from '../../src/services/flow/flowExport';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const hasFlag = (f: string) => argv.includes(f);

function notRun(what: string): never {
  console.log(`NOT RUN  exporter-lab: ${what}`);
  process.exit(0);
}

const wsl = (script: string, input?: string, timeout = 120_000) =>
  spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', '-c', script], { encoding: 'utf8', input, timeout });
const has = (tool: string) => wsl(`command -v ${tool}`).status === 0;
const winToWsl = (p: string) => `/mnt/${p[0].toLowerCase()}${p.slice(2).replace(/\\/g, '/')}`;

if (process.platform !== 'win32') notRun('WSL is Windows-only');
{
  const probe = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'true'], { encoding: 'utf8', timeout: 60_000 });
  if (probe.error || probe.status !== 0) notRun('WSL Ubuntu is not available');
  if (!has('softflowd')) notRun('softflowd is not installed in WSL Ubuntu');
  if (!has('python3')) notRun('python3 is not installed in WSL Ubuntu');
}
const { findWiresharkTool } = await import('../export/realCaptures');
const tshark = findWiresharkTool('tshark');
if (tshark === null) notRun('tshark is not installed');
const hasPmacct = has('pmacctd');
const hasNfdump = has('nfcapd') && has('nfdump');

const versionOf = (cmd: string) => wsl(`${cmd} 2>&1 | head -2`).stdout.replace(/\0/g, '').trim().split('\n').find((l) => /\d+\.\d+/.test(l))?.trim().replace(/\. Valid commandline options:$/, '') ?? 'unknown';
const versions = {
  softflowd: versionOf('softflowd -h'),
  pmacct: hasPmacct ? versionOf('pmacctd -V') : 'not installed',
  nfdump: hasNfdump ? versionOf('nfdump -V') : 'not installed',
  tshark: spawnSync(tshark!, ['--version'], { encoding: 'utf8' }).stdout.split('\n')[0].trim(),
};

const work = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'inwire-exporter-lab-')));
const fixture = path.join(work, 'fixture.pcap');
const made = spawnSync(process.execPath, ['--import', 'tsx', path.join(here, 'interop.ts'), '--fixture-only', fixture], { encoding: 'utf8' });
if (made.status !== 0) throw new Error(`fixture: ${made.stderr}`);
const fixtureLine = made.stdout.trim();

/**
 * The refresh capture: 4,000 one-packet UDP flows between generated addresses, a
 * millisecond apart, so an exporter sends well over 32 messages and its template
 * refresh shows. Classic pcap, Ethernet.
 */
function manyFlowCapture(flows: number): Uint8Array {
  const parts: Uint8Array[] = [];
  const g = new DataView(new ArrayBuffer(24));
  g.setUint32(0, 0xa1b2c3d4, true); g.setUint16(4, 2, true); g.setUint16(6, 4, true);
  g.setUint32(16, 65535, true); g.setUint32(20, 1, true);
  parts.push(new Uint8Array(g.buffer));
  for (let i = 0; i < flows; i++) {
    const frame = new Uint8Array(14 + 28 + 32);
    const v = new DataView(frame.buffer);
    frame.set([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
    frame.set([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, (i >> 8) & 0xff, i & 0xff, 10, 8, 0, 1], 14);
    v.setUint16(16, 60);
    let sum = 0;
    for (let p = 14; p < 34; p += 2) sum += v.getUint16(p);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    v.setUint16(24, ~sum & 0xffff);
    v.setUint16(34, 40_000 + (i % 1000)); v.setUint16(36, 53); v.setUint16(38, 40);
    const r = new DataView(new ArrayBuffer(16));
    r.setUint32(0, 1_700_000_000 + Math.floor(i / 1000), true); r.setUint32(4, (i % 1000) * 1000, true);
    r.setUint32(8, frame.length, true); r.setUint32(12, frame.length, true);
    parts.push(new Uint8Array(r.buffer), frame);
  }
  return Buffer.concat(parts);
}
const refreshCapture = path.join(work, 'refresh.pcap');
writeFileSync(refreshCapture, manyFlowCapture(4000));

// A keeper inside WSL: every datagram as [f64 receipt seconds][u16 source port][u32 length][payload],
// stopping 3 s after the last one (or 60 s with none). Replay with -r sends in a burst, so 3 s is enough.
const KEEPER = `
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
            f.write(struct.pack('<dHI', time.time(), src[1], len(d)) + d)
            n, last = n + 1, time.time()
        except socket.timeout:
            pass
        if (last and time.time() - last > 3) or (not last and time.time() - start > 60):
            break
print(n, flush=True)
`;

// Replays kept datagrams, byte for byte and in order, to nfcapd on WSL loopback.
const REPLAY = `
import socket, struct, sys, time
port, path = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
raw = open(path, 'rb').read()
p = 0
while p + 14 <= len(raw):
    t, sport, n = struct.unpack_from('<dHI', raw, p)
    s.sendto(raw[p + 14:p + 14 + n], ('127.0.0.1', port))
    time.sleep(0.02)
    p += 14 + n
`;

interface Kept { atMs: number; port: number; bytes: Uint8Array }
function readKept(file: string): Kept[] {
  const raw = readFileSync(file);
  const out: Kept[] = [];
  for (let p = 0; p + 14 <= raw.length;) {
    const n = raw.readUInt32LE(p + 10);
    out.push({ atMs: raw.readDoubleLE(p) * 1000, port: raw.readUInt16LE(p + 8), bytes: new Uint8Array(raw.subarray(p + 14, p + 14 + n)) });
    p += 14 + n;
  }
  return out;
}

let nextPort = 21_000 + Math.floor(Math.random() * 20_000);
async function record(exporterScript: string): Promise<{ datagrams: Kept[]; exit: number | null; stderr: string }> {
  const port = nextPort++;
  const file = path.join(work, `kept-${port}.bin`);
  const keeper = spawn('wsl.exe', ['-d', 'Ubuntu', '--', 'python3', '-', String(port), winToWsl(file)], { stdio: ['pipe', 'pipe', 'inherit'] });
  keeper.stdin.end(KEEPER);
  let out = '';
  await new Promise<void>((ready) => keeper.stdout.on('data', (c: Buffer) => { out += c.toString('utf8'); if (out.includes('ready')) ready(); }));
  const done = new Promise<void>((r) => keeper.once('exit', () => r()));
  const ran = wsl(exporterScript.replaceAll('$PORT', String(port)));
  await done;
  return { datagrams: readKept(file), exit: ran.status, stderr: ran.stderr.replace(/\0/g, '').trim() };
}

// --- the passes ---------------------------------------------------------------------------------

// softflowd names the -r file in its options data (interfaceName, IE 82), so the capture is read
// from a fixed WSL path: no local directory reaches the vectors.
const fx = '/tmp/inwire-exporter-lab/fixture.pcap';
const rx = '/tmp/inwire-exporter-lab/refresh.pcap';
wsl(`mkdir -p /tmp/inwire-exporter-lab && cp '${winToWsl(fixture)}' ${fx} && cp '${winToWsl(refreshCapture)}' ${rx}`);

/**
 * A refresh pass goes into the vectors trimmed to its first `trim` datagrams:
 * enough refreshes and sequence pairs to learn from (ADR 0064 needs eight
 * discriminating pairs), without the whole capture. Its references are
 * recomputed over the trimmed datagrams.
 */
interface Pass { name: string; exporter: 'softflowd' | 'pmacct'; flags: string; script: string; trim?: number }
const softflowd = (name: string, flags: string, capture = fx, trim?: number): Pass =>
  ({ name, exporter: 'softflowd', flags, script: `softflowd -r '${capture}' -n 127.0.0.1:$PORT ${flags} -d 2>&1 | tail -3`, ...(trim === undefined ? {} : { trim }) });
const pmacct = (name: string, version: 9 | 10, capture = fx, trim?: number): Pass => ({
  name, exporter: 'pmacct', flags: `nfprobe_version: ${version}`, ...(trim === undefined ? {} : { trim }),
  script: `printf 'daemonize: false\\npcap_savefile: ${capture}\\nplugins: nfprobe\\nnfprobe_receiver: 127.0.0.1:$PORT\\nnfprobe_version: ${version}\\n' > /tmp/inwire-exporter-lab/nfprobe.conf && timeout 60 pmacctd -f /tmp/inwire-exporter-lab/nfprobe.conf </dev/null 2>&1 | tail -3`,
});
const PASSES: Pass[] = [
  softflowd('softflowd-v9', '-v 9'),
  softflowd('softflowd-v9-s10', '-v 9 -s 10'),
  softflowd('softflowd-v10', '-v 10'),
  softflowd('softflowd-v10-b', '-v 10 -b'),
  softflowd('softflowd-v10-s10', '-v 10 -s 10'),
  softflowd('softflowd-v10-A-milli', '-v 10 -A milli'),
  pmacct('pmacct-v9', 9),
  pmacct('pmacct-v10', 10),
  softflowd('refresh-softflowd-v9', '-v 9', rx, 40),
  softflowd('refresh-softflowd-v10', '-v 10', rx, 80),
  pmacct('refresh-pmacct-v9', 9, rx, 40),
  pmacct('refresh-pmacct-v10', 10, rx, 80),
];

// --- reading a pass with the tree decoder's readers ---------------------------------------------------

const REVERSE_PEN = 29305;
const fieldName = (f: FlowTemplateField) => `${f.pen !== undefined ? `${f.pen}/` : ''}${f.type}:${f.length === 0xffff ? 'v' : f.length}`;
const TIME_IES = new Set([21, 22, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160]);

interface Totals { records: number; octets: bigint; packets: bigint; reverseOctets: bigint; reversePackets: bigint }
interface Reading {
  versions: number[];
  domains: number[];
  ports: number[];
  templates: { key: string; set: string; scopeCount: number; fields: string[]; seenAt: number[] }[];
  optionsData: { key: string; values: Record<string, string> }[];
  awaiting: { key: string; sets: number; bytes: number }[];
  timeIes: string[];
  sequence: { domain: number; deltas: string; perPacket: number; perDataRecord: number; perDataRecordWithOptions: number; perOwnDataRecord: number; other: number }[];
  clock: { firstUptimeMs: number | null; exportMinusReceiptMs: number[] };
  totals: Totals;
}

function read(datagrams: Kept[]): Reading {
  const templates = new Map<string, { t: FlowTemplate; set: string; seenAt: number[] }>();
  const optionsData: Reading['optionsData'] = [];
  const awaiting = new Map<string, { sets: number; bytes: number }>();
  const timeIes = new Set<string>();
  const totals: Totals = { records: 0, octets: 0n, packets: 0n, reverseOctets: 0n, reversePackets: 0n };
  const seq = new Map<number, { last: FlowHeader; lastData: number; lastDataWithOptions: number; deltas: number[]; perPacket: number; perDataRecord: number; perDataRecordWithOptions: number; perOwnDataRecord: number; other: number }>();
  const exportMinusReceipt: number[] = [];
  let firstUptime: number | null = null;
  const versions = new Set<number>(), domains = new Set<number>(), ports = new Set<number>();

  datagrams.forEach((d, i) => {
    const h = readFlowHeader(d.bytes, 0, d.bytes.length);
    if (h === null) throw new Error(`datagram ${i}: no header`);
    versions.add(h.version); domains.add(h.domain); ports.add(d.port);
    if (firstUptime === null && h.sysUptimeMs !== undefined) firstUptime = h.sysUptimeMs;
    exportMinusReceipt.push(h.unixSecs * 1000 + (h.unixNsecs ?? 0) / 1e6 - d.atMs);
    let dataRecords = 0, optionRecords = 0;
    for (const set of readFlowSets(d.bytes, h, d.bytes.length)) {
      const kind = setKind(h.version, set.id);
      if (kind === 'template' || kind === 'options') {
        for (const t of readTemplateSet(d.bytes, h.version, set).templates) {
          const key = `${h.domain}/${t.id}`;
          const known = templates.get(key);
          if (known === undefined) templates.set(key, { t, set: kind, seenAt: [i] });
          else { known.seenAt.push(i); if (JSON.stringify(known.t.fields) !== JSON.stringify(t.fields)) throw new Error(`template ${key} redefined with another layout at datagram ${i}`); }
          for (const f of t.fields) if (TIME_IES.has(f.type) && f.pen === undefined) timeIes.add(`${t.id}:${f.type}`);
        }
        continue;
      }
      if (kind !== 'data') continue;
      const key = `${h.domain}/${set.id}`;
      const known = templates.get(key);
      if (known === undefined) {
        const a = awaiting.get(key) ?? { sets: 0, bytes: 0 };
        a.sets++; a.bytes += set.length;
        awaiting.set(key, a);
        continue;
      }
      const { records } = readDataRecords(d.bytes, set, known.t);
      if (known.t.scopeCount > 0 || known.set === 'options') {
        optionRecords += records.length;
        for (const r of records) {
          const values: Record<string, string> = {};
          for (const v of r) {
            const name = fieldName(v.field);
            values[name] = v.field.type === 82 && v.field.pen === undefined
              ? new TextDecoder().decode(d.bytes.subarray(v.start, v.start + v.length)).replace(/\0+$/, '')
              : v.length <= 8 ? String(readUint(d.bytes, v.start, v.length)) : Buffer.from(d.bytes.subarray(v.start, v.start + v.length)).toString('hex');
          }
          optionsData.push({ key, values });
        }
        continue;
      }
      dataRecords += records.length;
      for (const r of records) {
        totals.records++;
        const value = (ie: number, pen?: number) => {
          const v = r.find((x) => x.field.type === ie && x.field.pen === pen);
          return v === undefined ? null : readUint(d.bytes, v.start, v.length);
        };
        totals.octets += value(1) ?? value(85) ?? 0n;
        totals.packets += value(2) ?? value(86) ?? 0n;
        totals.reverseOctets += value(1, REVERSE_PEN) ?? value(85, REVERSE_PEN) ?? 0n;
        totals.reversePackets += value(2, REVERSE_PEN) ?? value(86, REVERSE_PEN) ?? 0n;
      }
    }
    const s = seq.get(h.domain);
    if (s === undefined) {
      seq.set(h.domain, { last: h, lastData: dataRecords, lastDataWithOptions: dataRecords + optionRecords, deltas: [], perPacket: 0, perDataRecord: 0, perDataRecordWithOptions: 0, perOwnDataRecord: 0, other: 0 });
    } else {
      const delta = (h.sequence - s.last.sequence) >>> 0;
      s.deltas.push(delta);
      if (delta === 1) s.perPacket++;
      if (delta === s.lastData) s.perDataRecord++;
      if (delta === s.lastDataWithOptions) s.perDataRecordWithOptions++;
      // softflowd's IPFIX counts this message's records too (the value after adding them), against RFC 7011 §10.3.2.
      if (delta === dataRecords) s.perOwnDataRecord++;
      if (delta !== 1 && delta !== s.lastData && delta !== s.lastDataWithOptions && delta !== dataRecords) s.other++;
      s.last = h; s.lastData = dataRecords; s.lastDataWithOptions = dataRecords + optionRecords;
    }
  });
  return {
    versions: [...versions], domains: [...domains], ports: [...ports],
    templates: [...templates].map(([key, { t, set, seenAt }]) => ({ key, set, scopeCount: t.scopeCount, fields: t.fields.map(fieldName), seenAt })),
    optionsData,
    awaiting: [...awaiting].map(([key, a]) => ({ key, ...a })),
    timeIes: [...timeIes],
    sequence: [...seq].map(([domain, s]) => ({
      domain, deltas: compress(s.deltas), perPacket: s.perPacket, perDataRecord: s.perDataRecord, perDataRecordWithOptions: s.perDataRecordWithOptions, perOwnDataRecord: s.perOwnDataRecord, other: s.other,
    })),
    clock: { firstUptimeMs: firstUptime, exportMinusReceiptMs: exportMinusReceipt },
    totals,
  };
}

/** `[1,1,1,30,30]` as `1x3 30x2`. */
function compress(xs: number[]): string {
  const out: string[] = [];
  for (let i = 0; i < xs.length;) {
    let j = i;
    while (j < xs.length && xs[j] === xs[i]) j++;
    out.push(j - i > 1 ? `${xs[i]}x${j - i}` : String(xs[i]));
    i = j;
  }
  return out.join(' ');
}

// --- tshark ------------------------------------------------------------------------------------------

function rawUdpPcap(datagrams: Kept[], dstPort: number): Uint8Array {
  const parts: Uint8Array[] = [];
  const g = new DataView(new ArrayBuffer(24));
  g.setUint32(0, 0xa1b2c3d4, true); g.setUint16(4, 2, true); g.setUint16(6, 4, true);
  g.setUint32(16, 65535, true); g.setUint32(20, 101, true);
  parts.push(new Uint8Array(g.buffer));
  datagrams.forEach((d) => {
    const frame = new Uint8Array(28 + d.bytes.length);
    const v = new DataView(frame.buffer);
    frame.set([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]);
    v.setUint16(2, frame.length);
    let sum = 0;
    for (let p = 0; p < 20; p += 2) sum += v.getUint16(p);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    v.setUint16(10, ~sum & 0xffff);
    v.setUint16(20, d.port); v.setUint16(22, dstPort); v.setUint16(24, 8 + d.bytes.length);
    frame.set(d.bytes, 28);
    const r = new DataView(new ArrayBuffer(16));
    const ms = Math.floor(d.atMs);
    r.setUint32(0, Math.floor(ms / 1000), true); r.setUint32(4, (ms % 1000) * 1000, true);
    r.setUint32(8, frame.length, true); r.setUint32(12, frame.length, true);
    parts.push(new Uint8Array(r.buffer), frame);
  });
  return Buffer.concat(parts);
}

interface TsharkTotals { datagrams: number; records: number; octets: string; packets: string; reverseOctets: string; reversePackets: string; samplingInterval: string[] }
function tsharkTotals(datagrams: Kept[], name: string): TsharkTotals {
  const pcap = path.join(work, `${name}.pcap`);
  writeFileSync(pcap, rawUdpPcap(datagrams, 2055));
  // IE 1/2 are cflow.octets/packets, 85/86 cflow.permanent_octets/packets. tshark files a
  // PEN 29305 (reverse) count under the same field, so the reverse values are read from the
  // verbose tree - "Octets: 2759 (Reverse Type 1 BYTES)" - and taken out of the sums.
  const fields = ['cflow.version', 'cflow.octets', 'cflow.packets', 'cflow.permanent_octets', 'cflow.permanent_packets', 'cflow.sampling_interval'];
  const run = spawnSync(tshark!, ['-r', pcap, '-d', 'udp.port==2055,cflow', '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=,', ...fields.flatMap((f) => ['-e', f])],
    { encoding: 'utf8', maxBuffer: 1 << 28 });
  const rows = run.stdout.trimEnd().split(/\r?\n/).filter((l) => l !== '').map((l) => l.split('\t'));
  const nums = (c: number) => rows.flatMap((r) => (r[c] ?? '').split(',').filter((x) => x !== '')).map((x) => BigInt(x));
  const octets = [...nums(1), ...nums(3)];
  const packets = [...nums(2), ...nums(4)];
  const verbose = spawnSync(tshark!, ['-r', pcap, '-d', 'udp.port==2055,cflow', '-V'], { encoding: 'utf8', maxBuffer: 1 << 28 }).stdout;
  let reverseOctets = 0n, reversePackets = 0n, reverseRecords = 0;
  for (const line of verbose.split(/\r?\n/)) {
    const m = /^\s*(?:Permanent )?(Octets|Packets): (\d+) \(Reverse Type \d+ /.exec(line);
    if (m === null) continue;
    if (m[1] === 'Octets') { reverseOctets += BigInt(m[2]); reverseRecords++; } else reversePackets += BigInt(m[2]);
  }
  return {
    datagrams: rows.length, records: octets.length - reverseRecords,
    octets: String(octets.reduce((a, b) => a + b, 0n) - reverseOctets), packets: String(packets.reduce((a, b) => a + b, 0n) - reversePackets),
    reverseOctets: String(reverseOctets), reversePackets: String(reversePackets),
    samplingInterval: [...new Set(rows.flatMap((r) => (r[5] ?? '').split(',').filter((x) => x !== '')))],
  };
}

// --- nfdump -----------------------------------------------------------------------------------------

function nfdumpSummary(datagrams: Kept[], name: string): string {
  const kept = path.join(work, `${name}.replay`);
  writeFileSync(kept, Buffer.concat(datagrams.map((d) => {
    const head = Buffer.alloc(14);
    head.writeDoubleLE(d.atMs / 1000, 0); head.writeUInt16LE(d.port, 8); head.writeUInt32LE(d.bytes.length, 10);
    return Buffer.concat([head, d.bytes]);
  })));
  const port = nextPort++;
  const dir = `/tmp/inwire-exporter-lab/nfcapd-${port}`;
  const replay = path.join(work, 'replay.py');
  writeFileSync(replay, REPLAY);
  // Run from a file: a script handed to `bash -c` with the replayer on stdin left nfcapd's wait hanging.
  const script = path.join(work, `nfdump-${port}.sh`);
  writeFileSync(script, [
    `rm -rf ${dir}; mkdir -p ${dir}`,
    `nfcapd -b 127.0.0.1 -p ${port} -w ${dir} -t 3600 >${dir}.log 2>&1 </dev/null &`,
    'pid=$!',
    'sleep 1',
    `python3 '${winToWsl(replay)}' ${port} '${winToWsl(kept)}'`,
    'sleep 1; kill -TERM $pid; wait $pid',
    `for f in ${dir}/nfcapd.*; do nfdump -r "$f" -o 'fmt:%pr %sa %da %pkt %byt' -N 2>&1 | tail -4; done`,
    `ls ${dir}/nfcapd.* >/dev/null 2>&1 || { echo "no nfcapd file; its log:"; tail -5 ${dir}.log; }`,
    `rm -rf ${dir} ${dir}.log`,
    '',
  ].join('\n'));
  return spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', winToWsl(script)], { encoding: 'utf8', timeout: 120_000 }).stdout.replace(/\0/g, '').trim();
}

// --- run ----------------------------------------------------------------------------------------------

console.log(`exporter-lab: ${versions.softflowd}; pmacct ${versions.pmacct}; nfdump ${versions.nfdump}; ${versions.tshark}`);
console.log(`input: the generated capture (${fixtureLine})`);
const vectors: unknown[] = [];
try {
  for (const pass of PASSES) {
    console.log(`\n=== ${pass.name}: ${pass.exporter} ${pass.flags}`);
    if (pass.exporter === 'pmacct' && !hasPmacct) { console.log('NOT RUN  pmacct is not installed in WSL'); continue; }
    const { datagrams, exit, stderr } = await record(pass.script);
    console.log(`exit ${exit}; ${datagrams.length} datagrams, ${datagrams.reduce((a, d) => a + d.bytes.length, 0)} bytes${stderr ? `; stderr: ${stderr.split('\n').slice(-2).join(' | ')}` : ''}`);
    if (datagrams.length === 0) continue;
    const r = read(datagrams);
    console.log(`versions ${r.versions.join(',')}; source id / domain ${r.domains.join(',')}; source ports ${r.ports.join(',')}`);
    for (const t of r.templates) {
      console.log(`  template ${t.key} (${t.set}${t.scopeCount ? `, ${t.scopeCount} scope` : ''}): [${t.fields.join(' ')}]`);
      console.log(`    sent in datagrams ${compress(t.seenAt.map((x, k) => (k === 0 ? x : x - t.seenAt[k - 1])))} (first index, then gaps) of ${datagrams.length}`);
    }
    for (const o of r.optionsData.slice(0, 3)) console.log(`  options data ${o.key}: ${JSON.stringify(o.values)}`);
    if (r.optionsData.length > 3) console.log(`  ... ${r.optionsData.length} options records in all`);
    for (const a of r.awaiting) console.log(`  data before its template: ${a.key}, ${a.sets} sets, ${a.bytes} bytes`);
    console.log(`  flow-time elements (template:IE): ${r.timeIes.join(' ') || 'none'}`);
    for (const s of r.sequence) {
      console.log(`  sequence (domain ${s.domain}): deltas ${s.deltas}; equal to 1: ${s.perPacket}, to the previous message's data records: ${s.perDataRecord}, `
        + `with options records: ${s.perDataRecordWithOptions}, to this message's own data records: ${s.perOwnDataRecord}, none of these: ${s.other}`);
    }
    const skew = r.clock.exportMinusReceiptMs;
    console.log(`  clock: first uptime ${r.clock.firstUptimeMs ?? '-'} ms; export minus receipt ${Math.round(Math.min(...skew))}..${Math.round(Math.max(...skew))} ms`);
    console.log(`  ours (readers): ${r.totals.records} records, ${r.totals.packets} packets, ${r.totals.octets} octets; reverse ${r.totals.reversePackets} packets, ${r.totals.reverseOctets} octets`);
    const t = tsharkTotals(datagrams, pass.name);
    console.log(`  tshark: ${t.datagrams} datagrams, ${t.records} records, ${t.packets} packets, ${t.octets} octets; reverse ${t.reversePackets} packets, ${t.reverseOctets} octets; sampling interval ${t.samplingInterval.join(',') || '-'}`);
    const agree = t.records === r.totals.records && t.octets === String(r.totals.octets) && t.packets === String(r.totals.packets)
      && t.reverseOctets === String(r.totals.reverseOctets) && t.reversePackets === String(r.totals.reversePackets);
    console.log(`  readers and tshark ${agree ? 'AGREE' : 'DIFFER'}`);
    const nf = hasNfdump ? nfdumpSummary(datagrams, pass.name) : 'NOT RUN  nfdump is not installed in WSL';
    console.log(`  nfdump:\n${nf.split('\n').map((l) => `    ${l}`).join('\n')}`);
    const t0 = datagrams[0].atMs;
    const kept = pass.trim === undefined ? datagrams : datagrams.slice(0, pass.trim);
    const [rv, tv, nfv] = kept === datagrams ? [r, t, nf]
      : [read(kept), tsharkTotals(kept, `${pass.name}-trim`), hasNfdump ? nfdumpSummary(kept, `${pass.name}-trim`) : 'NOT RUN  nfdump is not installed in WSL'];
    if (kept !== datagrams) console.log(`  vector: the first ${kept.length} of ${datagrams.length} datagrams, ${rv.totals.records} records; tshark ${tv.records}`);
    vectors.push({
      name: pass.name, exporter: pass.exporter, version: pass.exporter === 'softflowd' ? versions.softflowd : versions.pmacct, flags: pass.flags,
      ...(kept === datagrams ? {} : { trimmed: `the first ${kept.length} of ${datagrams.length} datagrams` }),
      datagrams: kept.map((d) => ({ atMs: Math.round(d.atMs - t0), port: d.port, hex: Buffer.from(d.bytes).toString('hex') })),
      readers: { records: rv.totals.records, octets: String(rv.totals.octets), packets: String(rv.totals.packets), reverseOctets: String(rv.totals.reverseOctets), reversePackets: String(rv.totals.reversePackets) },
      tshark: tv, nfdump: nfv.split('\n').filter((l) => /^Summary|^Total/.test(l)),
    });
  }
  if (hasFlag('--write-vectors')) {
    const out = path.join(here, 'exporter-vectors.json');
    writeFileSync(out, `${JSON.stringify({
      note: 'Recorded by scripts/monitoring/exporter-lab.ts from the generated capture of interop.ts --fixture-only; no real traffic. Totals are the references the collector must equal (ADR 0064).',
      tools: versions, fixture: fixtureLine, passes: vectors,
    }, null, 1)}\n`);
    console.log(`\nwrote ${path.relative(process.cwd(), out)}`);
  }
} finally {
  if (hasFlag('--keep')) console.log(`kept: ${work}`);
  else rmSync(work, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
