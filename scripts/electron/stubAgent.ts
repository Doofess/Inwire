/**
 * A capture agent that is not one, for driving the app in a test.
 *
 * The real agent needs Administrator, a driver and a machine with traffic on
 * it. None of that belongs in a check that runs on every commit, and all of it
 * is beside the point: what the smoke test needs to know is whether the app
 * can take frames off the pipe, dissect them and put them on screen. So this
 * serves the **real protocol** over the **real transport** with synthetic
 * frames.
 *
 * It speaks the production framing (`src/services/agentFraming.ts`) and the
 * production control messages, so a change to either breaks this too - which
 * is the point. What it does NOT reuse is the batch encoder, because there
 * isn't one in TypeScript: the app only ever decodes. The twenty lines below
 * are written against `agentBinary.ts`'s exported layout constants, and the
 * two are held together by `scripts/agent/binary.ts` and
 * `local-agent/test_protocol.py` asserting the same hand-written vectors.
 *
 * Frames are DNS queries built byte by byte, for the same reason
 * `scripts/parity/synthetic.ts` builds its frames that way: a dissected result
 * that can be predicted exactly is worth more than a realistic one that cannot.
 */
import { createServer, type Server, type Socket } from 'node:net';
import {
  BATCH_HEADER_BYTES, BATCH_RECORD_BYTES, BATCH_VERSION,
} from '../../src/services/agentBinary';
import {
  FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame, encodeJsonFrame, frameText,
} from '../../src/services/agentFraming';

/** The name the app dials. Must match `AGENT_PIPE_PATH`. */
export const STUB_PIPE = '\\\\.\\pipe\\inwire-agent';

/** What the app is told it can capture on. */
const INTERFACES = [
  { id: 0, name: '\\Device\\NPF_{STUB-0}', label: 'Ethernet (stub)' },
  { id: 1, name: '\\Device\\NPF_{STUB-1}', label: 'Wi-Fi (stub)' },
];

/**
 * One Ethernet/IPv4/UDP/DNS query, built by hand.
 *
 * `192.168.1.42 → 1.1.1.1`, an A query for `example.com`, which the dissector
 * renders as `Standard query 0x…… A example.com`. Predictable enough that the
 * smoke test can assert the Info column rather than merely counting rows.
 */
export function dnsQuery(txid: number): Uint8Array {
  const name = [7, ...[...'example'].map((c) => c.charCodeAt(0)),
    3, ...[...'com'].map((c) => c.charCodeAt(0)), 0];
  const dns = [
    (txid >> 8) & 0xff, txid & 0xff, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...name, 0x00, 0x01, 0x00, 0x01,
  ];
  const udpLen = 8 + dns.length;
  const srcPort = 0xc000 + (txid & 0x0fff);
  const udp = [
    (srcPort >> 8) & 0xff, srcPort & 0xff, 0x00, 0x35,
    (udpLen >> 8) & 0xff, udpLen & 0xff, 0x00, 0x00, ...dns,
  ];
  const total = 20 + udp.length;
  const ip = [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
    192, 168, 1, 42, 1, 1, 1, 1,
  ];
  const eth = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02, 0x08, 0x00];
  return new Uint8Array([...eth, ...ip, ...udp]);
}

/** The 18-byte record plus its bytes; see `agentBinary.ts` for the layout. */
function encodeBatch(frames: { seq: number; tsUs: number; bytes: Uint8Array }[]): Uint8Array {
  const body = frames.reduce((n, f) => n + BATCH_RECORD_BYTES + f.bytes.length, 0);
  const out = new Uint8Array(BATCH_HEADER_BYTES + body);
  const view = new DataView(out.buffer);
  out.set([0x49, 0x57, 0x50, 0x31], 0);          // 'IWP1'
  view.setUint8(4, BATCH_VERSION);
  view.setUint16(6, frames.length, true);

  let offset = BATCH_HEADER_BYTES;
  for (const frame of frames) {
    view.setUint32(offset, frame.seq, true);
    view.setUint16(offset + 4, 0, true);          // iface
    view.setUint16(offset + 6, frame.bytes.length, true);
    view.setUint16(offset + 8, 0, true);          // wire length excess: nothing truncated
    view.setFloat64(offset + 10, frame.tsUs, true);
    out.set(frame.bytes, offset + BATCH_RECORD_BYTES);
    offset += BATCH_RECORD_BYTES + frame.bytes.length;
  }
  return out;
}

export interface StubAgent {
  /** Everything the app has said, for assertions about the handshake. */
  readonly received: string[];
  /** Frames handed over so far. */
  readonly sent: () => number;
  close: () => Promise<void>;
}

/**
 * Serves the pipe until closed.
 *
 * Streams batches while a capture is running, at the agent's own cadence, so
 * the app's 100 ms flush and ordering window are exercised rather than
 * bypassed by one giant message.
 */
export async function startStubAgent(
  pipePath = STUB_PIPE,
  /**
   * Frames per 100 ms tick.
   *
   * 40 is a plausible trickle, which is what the smoke test wants: it
   * exercises the ordering window and the 100 ms flush rather than bypassing
   * them with one enormous message. Cranking it is how a capture is driven
   * past the RAM buffer's budget by hand, which needs ~180,000 frames and
   * would otherwise take seven minutes - see `serveStub.ts --burst`.
   */
  perTick = 40,
): Promise<StubAgent> {
  const received: string[] = [];
  let seq = 0;
  let pump: ReturnType<typeof setInterval> | null = null;
  const clients = new Set<Socket>();

  const stop = () => {
    if (pump) clearInterval(pump);
    pump = null;
  };

  const server: Server = createServer((socket) => {
    clients.add(socket);
    const reader = new FrameReader();

    const send = (payload: Uint8Array) => {
      if (!socket.destroyed) socket.write(payload);
    };
    const tell = (message: unknown) => send(encodeJsonFrame(message));

    tell({
      type: 'hello', version: '3.8.0', state: 'idle', interfaces: INTERFACES,
      clientId: 'stub-1', owner: null,
    });

    socket.on('data', (chunk: Buffer) => {
      // A view, never the Buffer: `Buffer.prototype.slice` is `subarray`, so a
      // FrameReader fed Buffers hands out windows into Node's read pool.
      const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      for (const frame of reader.push(bytes)) {
        if (frame.kind !== FRAME_JSON) continue;
        const text = frameText(frame);
        received.push(text);
        const message = JSON.parse(text) as { type?: string };

        if (message.type === 'start_capture') {
          stop();
          pump = setInterval(() => {
            const batch = [];
            for (let i = 0; i < perTick; i++) {
              seq++;
              batch.push({ seq, tsUs: Date.now() * 1000, bytes: dnsQuery(seq & 0xffff) });
            }
            send(encodeFrame(FRAME_BINARY, encodeBatch(batch)));
          }, 100);
        }
        if (message.type === 'stop_capture') stop();

        // Every state-changing command is answered with `state`, which is what
        // the app's reconnect resync and its Start button both read.
        if (['start_capture', 'stop_capture', 'set_interfaces'].includes(message.type ?? '')) {
          tell({
            type: 'state',
            state: pump ? 'sniffing' : 'idle',
            interfaces: INTERFACES,
            owner: pump ? 'stub-1' : null,
          });
        }
      }
    });

    socket.on('close', () => {
      clients.delete(socket);
      stop();
    });
    socket.on('error', () => { /* the app going away is not an error here */ });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(pipePath, () => resolve());
  });

  return {
    received,
    sent: () => seq,
    close: () => new Promise<void>((resolve) => {
      stop();
      for (const socket of clients) socket.destroy();
      server.close(() => resolve());
    }),
  };
}
