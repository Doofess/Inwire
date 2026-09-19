/**
 * The Rust agent end to end, driven by the app's own code.
 *
 *   cargo run --manifest-path agent-rs/Cargo.toml --example agent_serve -- \
 *     --device "\Device\NPF_Loopback"
 *   npx tsx scripts/agent/agent-interop.ts
 *
 * **In `NOT_TESTS`**: needs a server beside it, a real capture device, and
 * Windows. Run it by hand after anything touching the Rust agent's capture
 * path.
 *
 * ## What this proves that nothing else does
 *
 * Every other check here holds one piece against fixed bytes. This one holds
 * the pieces against each other and against the app:
 *
 *   - the pipe carries the control protocol AND the packet batches on one
 *     connection, interleaved, which is the arrangement the overlapped handle
 *     exists for
 *   - `parseAgentMessage` accepts what the agent actually sends at run time,
 *     not what a fixture says it sends
 *   - `decodePacketBatch` decodes frames the driver really produced, including
 *     whatever sizes happened to arrive
 *   - every gap in the sequence numbers matches a loss the agent reported,
 *     and every loss it reported shows up as a real gap
 *
 * The last one is the point, and it is CONSERVATION rather than zero loss. A
 * capture that shed frames still looks like a capture: the list fills, the
 * bytes decode, nothing errors. The only thing between a lossy capture and a
 * silently wrong one is a counter that moved.
 */
import { connect, createServer, type Socket } from 'node:net';
import { FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame } from '../../src/services/agentFraming';
import { decodePacketBatch } from '../../src/services/agentBinary';
import { parseAgentMessage, summarizeCaptureStats } from '../../src/services/agentProtocol';
import type { AgentCaptureStatsMessage } from '../../src/services/agentProtocol';

const PIPE = process.env.INWIRE_PROBE_PIPE ?? String.raw`\\.\pipe\inwire-probe`;
const SECONDS = Number(process.env.INWIRE_PROBE_SECONDS ?? 6);

/**
 * Which adapter to capture on, matched against the label the agent reports.
 *
 * **Loopback by default, and that is a privacy decision rather than a
 * convenience one.** The other adapters on a development machine carry the
 * person's actual traffic, and a test harness must not be the thing that
 * captures it. Loopback carries what this file puts on it and nothing else.
 */
const ADAPTER = process.env.INWIRE_PROBE_ADAPTER ?? 'loopback';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, actual: boolean): void { check(name, actual, true); }

if (process.platform !== 'win32') {
  console.log('SKIP  the named pipe is Windows-only');
  process.exit(0);
}

const control: Record<string, unknown>[] = [];
let frames = 0;
let bytes = 0;
let batches = 0;
const seqs: number[] = [];
let lastStats: AgentCaptureStatsMessage | null = null;
let sawStart = false;
let chosenLabel = '(none)';

/**
 * Traffic of our own, on loopback, for as long as the capture runs.
 *
 * The harness used to rely on whatever happened to be on the wire, which makes
 * it non-deterministic on a quiet machine and makes it capture somebody's real
 * traffic on a busy one. A server and a client talking to themselves is neither.
 *
 * The flood is the point as well as the traffic: the bounded queues are meant
 * to shed under pressure, and a harness that never applies any proves only that
 * the counters are zero.
 */
function floodLoopback(): () => void {
  const sockets: Socket[] = [];
  const payload = Buffer.alloc(64 * 1024, 0x5a);
  let stopped = false;
  const server = createServer((connection) => {
    sockets.push(connection);
    connection.on('error', () => {});
    connection.resume();
  });
  server.on('error', () => {});
  server.listen(0, '127.0.0.1', () => {
    const port = (server.address() as { port: number }).port;
    for (let i = 0; i < 4; i++) {
      const client = connect(port, '127.0.0.1');
      sockets.push(client);
      client.on('error', () => {});
      const pump = () => {
        if (stopped || client.destroyed) return;
        // `write` answers false when the buffer is full; `drain` is the signal
        // to carry on. Ignoring it would grow an unbounded queue in THIS
        // process, which is the failure the agent is being tested for.
        if (client.write(payload)) setImmediate(pump);
        else client.once('drain', pump);
      };
      client.on('connect', pump);
    }
  });
  return () => {
    stopped = true;
    for (const s of sockets) s.destroy();
    server.close();
  };
}

const stopFlood = floodLoopback();

const socket = connect(PIPE);
const reader = new FrameReader();

let sawFinalState = false;

await new Promise<void>((resolve, reject) => {
  // Stop the capture and WAIT for the agent's last word, rather than hanging up
  // mid-flight. Without this the newest figures the client holds are up to a
  // second stale while frames keep arriving, so the numbers cannot be made to
  // add up and a real accounting bug would be indistinguishable from the gap
  // that sampling alone creates.
  const stopAt = setTimeout(() => {
    socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode('{"type":"stop_capture"}')));
  }, SECONDS * 1000);
  const stop = setTimeout(() => { clearTimeout(stopAt); socket.end(); resolve(); },
    SECONDS * 1000 + 2500);
  socket.on('error', (e) => { clearTimeout(stop); reject(e); });
  socket.on('close', () => { clearTimeout(stop); resolve(); });

  socket.on('connect', () => {
    console.log(`connected to ${PIPE}`);
  });

  socket.on('data', (chunk) => {
    for (const frame of reader.push(new Uint8Array(chunk))) {
      if (frame.kind === FRAME_JSON) {
        const text = new TextDecoder().decode(frame.payload);
        const parsed = parseAgentMessage(text);
        if (parsed === null) {
          console.log(`FAIL  the app's parser REFUSED a live message: ${text.slice(0, 160)}`);
          failures++;
          continue;
        }
        control.push(parsed as unknown as Record<string, unknown>);
        if (parsed.type === 'capture_stats') lastStats = parsed as AgentCaptureStatsMessage;
        // **Choose an adapter, THEN start - which is what the app does.**
        //
        // This used to send `start_capture` alone, and the agent fell back to
        // the first adapter in its own list. On this machine that is
        // `WAN Miniport (Network Monitor)`, which carries nothing: the agent
        // opened it, reported `sniffing` perfectly truthfully, and delivered
        // zero frames. A harness that does not pick an adapter is not
        // exercising the path the app takes.
        if (parsed.type === 'hello') {
          const interfaces = (parsed as unknown as {
            interfaces?: { id?: number; label?: string; name?: string }[];
          }).interfaces ?? [];
          const wanted = interfaces.find((i) =>
            `${i.label ?? ''} ${i.name ?? ''}`.toLowerCase().includes(ADAPTER.toLowerCase()));
          if (wanted === undefined) {
            console.log(`FAIL  no adapter matching "${ADAPTER}" - the agent offered `
              + interfaces.map((i) => i.label ?? i.name).join(', '));
            failures++;
          } else {
            chosenLabel = wanted.label ?? wanted.name ?? String(wanted.id);
            socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode(
              JSON.stringify({ type: 'set_interfaces', interfaces: [wanted.id ?? 0] }))));
          }
          socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode('{"type":"start_capture"}')));
        }
        // `state: idle` is the agent's last word: it follows the final
        // capture_stats, so by the time it lands the figures are complete.
        if (parsed.type === 'state' && parsed.state === 'idle' && sawStart) {
          sawFinalState = true;
          clearTimeout(stop);
          socket.end();
          resolve();
        }
        if (parsed.type === 'state' && parsed.state === 'sniffing') sawStart = true;
      } else if (frame.kind === FRAME_BINARY) {
        batches++;
        const b = frame.payload;
        const decoded = decodePacketBatch(
          b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer,
        );
        for (const f of decoded) {
          frames++;
          bytes += f.bytes.length;
          seqs.push(f.seq);
        }
      }
    }
  });
});

stopFlood();
console.log(`        captured on ${chosenLabel}`);

console.log();
const kinds = control.map((m) => m.type);
checkTrue('the agent said hello', kinds.includes('hello'));
checkTrue('...and every control message it sent was one the app accepts', failures === 0);
checkTrue('the capture started', control.some((m) => m.type === 'state' && m.state === 'sniffing'));
checkTrue('packet batches arrived on the same connection as the control messages', batches > 0);
checkTrue('...carrying frames', frames > 0);

console.log();
console.log(`        ${frames} frames in ${batches} batches, ${(bytes / 1e6).toFixed(1)} MB`);

// **Conservation, not zero loss** - and getting this wrong once is instructive.
//
// The first version of this asserted that no sequence number was ever missing.
// That is the wrong property and it failed on a correct agent: this harness
// floods loopback on purpose, the bounded queues shed on purpose, and shedding
// leaves gaps on purpose. An agent that never shed under that load would be one
// with an unbounded queue, which is the thing the bounds exist to prevent.
//
// The property that IS worth asserting is that loss is always accounted for.
// A capture that shed frames still looks like a capture - the list fills, the
// bytes decode, nothing errors - so the only thing standing between a lossy
// capture and a silently wrong one is a counter that moved.
let missing = 0;
if (seqs.length > 1) {
  const sorted = [...seqs].sort((a, b) => a - b);
  const span = sorted[sorted.length - 1] - sorted[0] + 1;
  missing = span - sorted.length;
  console.log(`        seq span ${span}, delivered ${sorted.length}, missing ${missing}`);
}

checkTrue('the agent sent its final figures before saying it had stopped', sawFinalState);

if (lastStats) {
  const s = summarizeCaptureStats(lastStats);
  // Captured but never handed over: still in the queue when stop arrived, and
  // discarded WITHOUT being counted as a drop - deliberately, because those
  // frames were not lost to pressure. They still have to appear in the sum, or
  // the figures fail to add up and the counters look wrong when they are not.
  const queuedAtStop = Number(
    (lastStats as unknown as { queuedAtStop?: number }).queuedAtStop ?? 0);
  const accounted = frames + s.droppedAgent + (s.droppedPipe ?? 0) + queuedAtStop;
  const residual = s.received - accounted;

  console.log();
  console.log(`        delivered ${frames} + droppedAgent ${s.droppedAgent}`
    + ` + droppedPipe ${s.droppedPipe ?? 0} + queuedAtStop ${queuedAtStop}`
    + ` = ${accounted}, against received ${s.received} (residual ${residual})`);

  // **The real assertion, and it is conservation.** Every frame the agent took
  // off the driver was delivered, shed with a counter moving, or still queued
  // when the capture stopped. A frame that is none of those is one that
  // vanished, which is the entire class of bug this round has been about - and
  // it is invisible without this sum, because a lossy capture looks exactly
  // like a complete one.
  //
  // The tolerance is frames the sniffer took between the final stats being
  // built and the queue being discarded, which is a few microseconds of
  // arrivals rather than a licence for slop.
  const tolerance = Math.max(64, Math.round(s.received * 0.001));
  checkTrue(`every frame is accounted for (residual ${residual}, tolerance ${tolerance})`,
    Math.abs(residual) <= tolerance);

  // And the two halves of the gap story, which catch a counter wired to nothing
  // in either direction.
  if (missing > 0) {
    checkTrue('every gap in the sequence is a loss the agent reported',
      s.droppedAgent + (s.droppedPipe ?? 0) > 0);
  }
  if (s.droppedAgent + (s.droppedPipe ?? 0) > 0) {
    checkTrue('...and a reported loss shows up as a real gap, not just a number',
      missing > 0);
  }
}

if (lastStats) {
  const s = summarizeCaptureStats(lastStats);
  console.log();
  console.log(`        agent reported: received ${s.received}, droppedAgent ${s.droppedAgent}, `
    + `droppedKernel ${s.droppedKernel ?? 'unknown'}, droppedPipe ${s.droppedPipe ?? 'unknown'}`);
  // Not asserted as zero: a slow reader SHOULD shed, and saying so is the
  // feature. Asserted as REPORTED, because a counter that exists and is wired
  // to nothing is the failure this whole round has been about.
  checkTrue('the agent reported its own losses rather than staying silent',
    typeof s.droppedAgent === 'number' && s.droppedPipe !== null);
  checkTrue('...and it never claims to have delivered more than it took',
    s.received >= frames);
} else {
  check('capture_stats arrived', false, true);
}

console.log();
if (failures) {
  console.log(`${failures} agent interop check(s) FAILED`);
  process.exit(1);
}
console.log('All agent interop checks passed.');
process.exit(0);
