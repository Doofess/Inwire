/**
 * Both agents capturing the same adapter at once, compared.
 *
 *   npx tsx scripts/agent/agent-compare.ts
 *
 * ## Why this exists
 *
 * The Rust port is checked against golden vectors, against the app's own
 * client, and against the SCM. None of that answers the question a person asks
 * after ten seconds of looking at a packet list: **does it show the same thing
 * the agent that ships shows?** The two implementations can agree on every byte
 * of the wire format and still disagree about what they put in it.
 *
 * So this runs them side by side - the Python agent on its service pipe, the
 * Rust agent on a private one via `INWIRE_AGENT_PIPE` - pointed at the same
 * adapter, at the same moment, and diffs what comes back.
 *
 * **They will not see identical frames and that is not the test.** Two capture
 * handles on one adapter have their own kernel buffers and start microseconds
 * apart, so counts differ. What must match is the SHAPE: the same EtherType
 * mix, the same protocols after dissection, the same relationship between
 * captured and wire length, timestamps in the same units and the same epoch.
 * A structural fault - an offset error, a unit error, a truncation - moves the
 * shape and nothing else does.
 *
 * ## Running it
 *
 * The Python agent is whichever one is registered as `InwireAgent`; use
 * `agent-rs/switch-agent.ps1 -Python`. Then, in another terminal:
 *
 * ```
 * $env:INWIRE_AGENT_PIPE = '\\.\pipe\inwire-rs-compare'
 * .\agent-rs\target\release\inwire-agent.exe debug
 * ```
 *
 * The adapter defaults to **loopback**, where this script generates the traffic
 * itself, because the alternative is a test that captures whoever is running
 * it. `INWIRE_COMPARE_ADAPTER` picks another by substring - a real adapter is a
 * deliberate act, and on one the traffic is ambient rather than generated.
 *
 * In `NOT_TESTS`: it needs two agents running and a capture device.
 */
import { connect, createServer, type Socket } from 'node:net';
import { FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame } from '../../src/services/agentFraming';
import { decodePacketBatch } from '../../src/services/agentBinary';
import { encodeAgentCommand, parseAgentMessage, type AgentCommand } from '../../src/services/agentProtocol';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';

const PY_PIPE = process.env.INWIRE_PY_PIPE ?? String.raw`\\.\pipe\inwire-agent`;
const RS_PIPE = process.env.INWIRE_RS_PIPE ?? String.raw`\\.\pipe\inwire-rs-compare`;
const ADAPTER = process.env.INWIRE_COMPARE_ADAPTER ?? 'loopback';
const SECONDS = Number(process.env.INWIRE_COMPARE_SECONDS ?? 6);

let failures = 0;
function check(name: string, condition: boolean, detail?: string): void {
  if (!condition) failures++;
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
  if (!condition && detail !== undefined) console.log(`        ${detail}`);
}

interface Record_ { seq: number; iface: number; tsUs: number; origLen: number; bytes: Uint8Array }

/** Everything about a side that can be compared without comparing frame to frame. */
interface Shape {
  frames: number;
  bytes: number;
  /** Frames whose captured length is under the wire length. A snaplen is set by
   *  neither agent, so any truncation at all is a difference. */
  truncated: number;
  tsMin: number;
  tsMax: number;
  /** Timestamps that went backwards. Both agents carry the driver's own. */
  regressions: number;
  ifaces: Set<number>;
  ethertypes: Map<number, number>;
  protocols: Map<string, number>;
  samples: string[];
}

function shapeOf(records: Record_[]): Shape {
  const s: Shape = {
    frames: records.length,
    bytes: records.reduce((n, r) => n + r.bytes.length, 0),
    truncated: records.filter((r) => r.bytes.length < r.origLen).length,
    tsMin: records.length ? Math.min(...records.map((r) => r.tsUs)) : 0,
    tsMax: records.length ? Math.max(...records.map((r) => r.tsUs)) : 0,
    regressions: 0,
    ifaces: new Set(records.map((r) => r.iface)),
    ethertypes: new Map(),
    protocols: new Map(),
    samples: [],
  };
  for (let i = 1; i < records.length; i++) {
    if (records[i].tsUs < records[i - 1].tsUs) s.regressions++;
  }
  for (const r of records) {
    // Bytes 12..13 of an Ethernet frame. Read raw rather than through the
    // dissector, because this is the check that catches the dissector being
    // fed from the wrong offset in the first place.
    if (r.bytes.length >= 14) {
      const et = (r.bytes[12] << 8) | r.bytes[13];
      s.ethertypes.set(et, (s.ethertypes.get(et) ?? 0) + 1);
    }
  }
  // Dissected with the app's own dissector, which is the only opinion that
  // matters - it is what draws the Protocol and Info columns.
  const base = records.length ? records[0].tsUs : 0;
  records.slice(0, 400).forEach((r, i) => {
    try {
      // `decodeRawEthernetPacket` answers with the row PLUS the cross-frame
      // facts a live pipeline would feed back; the row is `packet`.
      const { packet } = decodeRawEthernetPacket(
        r.bytes, i, r.tsUs, (r.tsUs - base) / 1e6, 0, r.origLen);
      const proto = String(packet.protocol ?? '?');
      s.protocols.set(proto, (s.protocols.get(proto) ?? 0) + 1);
      if (s.samples.length < 3 && packet.info) {
        s.samples.push(`${proto}  ${String(packet.info).slice(0, 78)}`);
      }
    } catch (error) {
      s.protocols.set('THREW', (s.protocols.get('THREW') ?? 0) + 1);
      if (s.samples.length < 3) s.samples.push(`THREW  ${(error as Error).message.slice(0, 70)}`);
    }
  });
  return s;
}

/** The top entries of a histogram, as proportions, so two sides compare. */
function top(hist: Map<string | number, number>, total: number, n = 5): [string, number][] {
  return [...hist.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => [typeof k === 'number' ? `0x${k.toString(16).padStart(4, '0')}` : k, v / (total || 1)]);
}

/** Traffic on loopback, made here, so a comparison captures nobody's but ours. */
function floodLoopback(): () => void {
  const sockets: Socket[] = [];
  const payload = Buffer.alloc(16 * 1024, 0x5a);
  let stopped = false;
  const server = createServer((c) => { sockets.push(c); c.on('error', () => {}); c.resume(); });
  server.on('error', () => {});
  server.listen(0, '127.0.0.1', () => {
    const port = (server.address() as { port: number }).port;
    for (let i = 0; i < 2; i++) {
      const client = connect(port, '127.0.0.1');
      sockets.push(client);
      client.on('error', () => {});
      const pump = () => {
        if (stopped || client.destroyed) return;
        if (client.write(payload)) setTimeout(pump, 1);
        else client.once('drain', pump);
      };
      client.on('connect', pump);
    }
  });
  return () => { stopped = true; for (const s of sockets) s.destroy(); server.close(); };
}

/** Drives one agent through a whole capture and returns what it delivered. */
function capture(pipe: string, label: string): Promise<Record_[]> {
  return new Promise((resolve, reject) => {
    const socket = connect(pipe);
    const reader = new FrameReader();
    const records: Record_[] = [];
    let started = false;
    let stopping = false;

    const send = (command: AgentCommand) =>
      socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode(encodeAgentCommand(command))));

    socket.on('error', (error) => reject(new Error(`${label}: ${error.message}`)));
    socket.on('close', () => resolve(records));

    socket.on('data', (chunk) => {
      for (const frame of reader.push(new Uint8Array(chunk))) {
        if (frame.kind === FRAME_BINARY) {
          // `decodePacketBatch` takes an ArrayBuffer, and a Uint8Array is not
          // one however willingly `tsc` accepts it here - TS 5.8 finds the two
          // structurally assignable, so the annotation is documentation rather
          // than a guard and `new DataView(...)` is what says no, at runtime,
          // on the first batch. The slice is `agent-interop.ts`'s, for the
          // reason `pipeline.worker.ts` states: a view into a larger buffer
          // would decode from the wrong offset in silence.
          const b = frame.payload;
          const batch = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
          for (const r of decodePacketBatch(batch)) {
            records.push({ seq: r.seq, iface: r.iface, tsUs: r.tsUs, origLen: r.origLen, bytes: r.bytes });
          }
          continue;
        }
        const parsed = parseAgentMessage(new TextDecoder().decode(frame.payload));
        if (parsed === null) continue;
        if (parsed.type === 'hello') {
          const interfaces = (parsed as unknown as {
            interfaces?: { name?: string; label?: string }[];
          }).interfaces ?? [];
          const wanted = interfaces.find((i) =>
            `${i.label ?? ''} ${i.name ?? ''}`.toLowerCase().includes(ADAPTER.toLowerCase()));
          if (wanted?.name === undefined) {
            reject(new Error(`${label}: no adapter matching "${ADAPTER}" - offered `
              + interfaces.map((i) => i.label ?? i.name).join(', ')));
            return;
          }
          console.log(`      ${label}: capturing on ${wanted.label ?? wanted.name}`);
          send({ type: 'set_interfaces', interfaces: [wanted.name] });
          send({ type: 'start_capture' });
          started = true;
          setTimeout(() => { stopping = true; send({ type: 'stop_capture' }); }, SECONDS * 1000);
        }
        // `state: idle` after a stop is the agent's last word - it follows the
        // final capture_stats, so the figures are complete by the time it lands.
        if (parsed.type === 'state' && (parsed as { state?: string }).state === 'idle'
            && started && stopping) {
          socket.end();
        }
        if (parsed.type === 'error') {
          reject(new Error(`${label}: ${(parsed as { code?: string }).code} `
            + `${(parsed as { message?: string }).message}`));
        }
      }
    });
  });
}

console.log('\n--- both agents, one adapter, at the same moment ---\n');
console.log(`      python: ${PY_PIPE}`);
console.log(`      rust:   ${RS_PIPE}`);
console.log(`      adapter: ${ADAPTER}    ${SECONDS}s\n`);

const onLoopback = ADAPTER.toLowerCase().includes('loopback');
if (!onLoopback) {
  console.log('      NOTE: not loopback, so the traffic is ambient and is yours.\n');
}
const stopFlood = onLoopback ? floodLoopback() : () => {};

let python: Record_[] = [];
let rust: Record_[] = [];
try {
  // Started together rather than in sequence: the comparison is only fair if
  // both handles are open across the same traffic.
  [python, rust] = await Promise.all([capture(PY_PIPE, 'python'), capture(RS_PIPE, 'rust')]);
} catch (error) {
  stopFlood();
  console.log(`\nFAIL  ${(error as Error).message}`);
  console.log('\nBoth agents have to be running. The Python one is the registered service');
  console.log('(`switch-agent.ps1 -Python`); the Rust one is:');
  console.log(`  $env:INWIRE_AGENT_PIPE = '${RS_PIPE}'`);
  console.log('  .\\agent-rs\\target\\release\\inwire-agent.exe debug');
  process.exit(1);
}
stopFlood();

const py = shapeOf(python);
const rs = shapeOf(rust);

const row = (name: string, a: string, b: string) =>
  console.log(`  ${name.padEnd(26)} ${a.padStart(18)}   ${b.padStart(18)}`);

console.log('\n                                       PYTHON                 RUST');
row('frames', py.frames.toLocaleString(), rs.frames.toLocaleString());
row('bytes', py.bytes.toLocaleString(), rs.bytes.toLocaleString());
row('mean frame', py.frames ? Math.round(py.bytes / py.frames).toString() : '-',
  rs.frames ? Math.round(rs.bytes / rs.frames).toString() : '-');
row('truncated (capLen<origLen)', String(py.truncated), String(rs.truncated));
row('timestamp regressions', String(py.regressions), String(rs.regressions));
row('iface values', [...py.ifaces].join(',') || '-', [...rs.ifaces].join(',') || '-');
row('span (s)', ((py.tsMax - py.tsMin) / 1e6).toFixed(2), ((rs.tsMax - rs.tsMin) / 1e6).toFixed(2));

console.log('\n  EtherType mix (share of frames)');
console.log(`    python: ${top(py.ethertypes, py.frames).map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`).join('  ')}`);
console.log(`    rust:   ${top(rs.ethertypes, rs.frames).map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`).join('  ')}`);

console.log('\n  Protocol after dissection (share of the first 400)');
console.log(`    python: ${top(py.protocols, Math.min(py.frames, 400)).map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`).join('  ')}`);
console.log(`    rust:   ${top(rs.protocols, Math.min(rs.frames, 400)).map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`).join('  ')}`);

console.log('\n  Info column, as the app would draw it');
for (const s of py.samples) console.log(`    python  ${s}`);
for (const s of rs.samples) console.log(`    rust    ${s}`);

console.log();
check('both agents delivered frames', py.frames > 0 && rs.frames > 0,
  `python ${py.frames}, rust ${rs.frames} - a side with none is the whole finding`);

if (py.frames > 0 && rs.frames > 0) {
  // Epoch sanity, checked per side rather than against each other: a unit or
  // epoch error puts a side decades away and nothing else does.
  const nowUs = Date.now() * 1000;
  const sane = (s: Shape) => Math.abs(s.tsMax - nowUs) < 60 * 60 * 1e6;
  check('timestamps are epoch microseconds on both', sane(py) && sane(rs),
    `python ${new Date(py.tsMax / 1000).toISOString()}, rust ${new Date(rs.tsMax / 1000).toISOString()}`);

  check('neither agent truncates', py.truncated === 0 && rs.truncated === 0,
    `python ${py.truncated}, rust ${rs.truncated} - neither sets a snaplen, so any truncation is a defect`);

  // The structural one. If a side reads frames from the wrong offset its
  // EtherTypes are noise, and no single value dominates the way a real mix does.
  const lead = (s: Shape) => top(s.ethertypes, s.frames, 1)[0];
  const [pyEt, pyShare] = lead(py) ?? ['-', 0];
  const [rsEt, rsShare] = lead(rs) ?? ['-', 0];
  check('the commonest EtherType is the same on both', pyEt === rsEt,
    `python ${pyEt} (${(pyShare * 100).toFixed(0)}%), rust ${rsEt} (${(rsShare * 100).toFixed(0)}%)`);

  const dissectFailures = (s: Shape) => (s.protocols.get('THREW') ?? 0);
  check('dissection throws on neither side',
    dissectFailures(py) === 0 && dissectFailures(rs) === 0,
    `python ${dissectFailures(py)}, rust ${dissectFailures(rs)}`);

  const pyProto = top(py.protocols, Math.min(py.frames, 400), 1)[0]?.[0] ?? '-';
  const rsProto = top(rs.protocols, Math.min(rs.frames, 400), 1)[0]?.[0] ?? '-';
  check('the commonest protocol is the same on both', pyProto === rsProto,
    `python ${pyProto}, rust ${rsProto}`);
}

console.log();
if (failures) {
  console.log(`${failures} difference(s) found`);
  process.exit(1);
}
console.log('The two agents agree on the shape of what they captured.');
process.exit(0);
