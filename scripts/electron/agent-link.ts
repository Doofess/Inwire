/**
 * The transport to the capture agent, driven against a real pipe.
 *
 *   npx tsx scripts/electron/agent-link.ts
 *
 * `scripts/agent/pipe-framing.ts` holds the byte format to hand-written
 * vectors. This holds the thing built on top of it to a **socket that actually
 * exists**: `node:net` serves one end, `PipeTransport` connects to the other,
 * and the bytes go through the operating system rather than through a call
 * from one function to the next. Everything interesting about this transport
 * is what a real stream does to it - a read boundary that is not a message
 * boundary, a server that goes away mid-conversation, a connect that fails
 * because nothing is listening yet.
 *
 * That is only possible because `pipeTransport.ts` imports no Electron. It is
 * the same split `local-agent/pipe_server.py` makes for the same reason: the
 * half with the decisions in it takes its outputs as callbacks, so it can be
 * driven on a machine with none of the surrounding machinery.
 *
 * **A named pipe on Windows and a Unix socket elsewhere.** `net.connect({
 * path })` is the same call for both, and this is testing the transport rather
 * than the operating system's naming, so CI on ubuntu exercises every line
 * below. What it cannot exercise is the security descriptor, which is the one
 * part of this that is Windows and the one part that has to be checked on a
 * machine with a second user account. `local-agent/test_protocol.py` pins the
 * SDDL's shape; only a real machine can pin its effect.
 */
import { createServer, type Socket } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame, encodeJsonFrame, frameText,
} from '../../src/services/agentFraming';
import type { AgentLinkStatus } from '../../src/services/agentLink';
import { PipeTransport } from '../../electron/pipeTransport';

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

/** A pipe name nothing else can collide with, on either platform. */
function testPipePath(name: string): string {
  return process.platform === 'win32'
    ? `\\\\.\\pipe\\inwire-test-${name}-${process.pid}`
    : path.join(mkdtempSync(path.join(tmpdir(), 'inwire-')), `${name}.sock`);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for a condition the transport reaches asynchronously, or gives up. */
async function until(condition: () => boolean, ms = 4000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await sleep(10);
  }
  return condition();
}

/** One collected run of the transport, so an assertion can read what happened. */
function recorder() {
  const statuses: AgentLinkStatus[] = [];
  const texts: string[] = [];
  const binaries: Uint8Array[] = [];
  return {
    statuses, texts, binaries,
    events: {
      status: (status: AgentLinkStatus) => { statuses.push(status); },
      text: (text: string) => { texts.push(text); },
      binary: (bytes: Uint8Array) => { binaries.push(bytes); },
    },
  };
}

/**
 * A stand-in agent: listens, and hands back each client that connects.
 *
 * Clients come back through `nth` rather than through a `let` the callback
 * assigns, for two reasons: TypeScript does not track an assignment made
 * inside a callback, so such a variable stays `Socket | null` at every use;
 * and a reconnect produces a NEW socket, so a test that held "the client"
 * would be writing to the dead one.
 */
async function serve(pipePath: string, onData?: (socket: Socket, read: FrameReader) => void) {
  const clients: Socket[] = [];
  const server = createServer((socket) => {
    onData?.(socket, new FrameReader());
    clients.push(socket);
  });
  await new Promise<void>((resolve) => server.listen(pipePath, () => resolve()));
  /** The nth client to connect - a reconnect is a NEW socket, not the old one. */
  const nth = async (index: number): Promise<Socket> => {
    await until(() => clients.length > index);
    return clients[index];
  };
  return { server, clients, nth };
}

async function main(): Promise<void> {
  console.log('--- a stream that arrives however it arrives ---\n');

  {
    const pipePath = testPipePath('stream');
    const { server, nth } = await serve(pipePath);

    const seen = recorder();
    const pipe = new PipeTransport(seen.events, pipePath, 50);
    pipe.open();
    const client = await nth(0);
    await until(() => seen.statuses.includes('connected'));
    check('connecting, then connected', seen.statuses, ['connecting', 'connected']);

    // The case a message transport never produced. A control message split
    // INSIDE its five-byte header, which is where an implementation that read
    // the length before checking it had four bytes would fall over.
    const hello = encodeJsonFrame({ type: 'hello', version: '3.8.0' });
    client.write(hello.subarray(0, 3));
    await sleep(30);
    check('half a header is not a message yet', seen.texts.length, 0);
    client.write(hello.subarray(3));
    await until(() => seen.texts.length === 1);
    check('the rest of it completes one', seen.texts, ['{"type":"hello","version":"3.8.0"}']);

    // And the opposite: several messages in one write, which is what a busy
    // agent produces and what the flush cadence makes likely rather than rare.
    const batch = encodeFrame(FRAME_BINARY, new Uint8Array([0x49, 0x57, 0x50, 0x31, 7]));
    client.write(new Uint8Array([
      ...encodeJsonFrame({ type: 'state' }), ...batch, ...encodeJsonFrame({ type: 'log' }),
    ]));
    await until(() => seen.texts.length === 3 && seen.binaries.length === 1);
    check('three frames in one write come back as three',
      [seen.texts.slice(1), [...(seen.binaries[0] ?? [])]],
      [['{"type":"state"}', '{"type":"log"}'], [0x49, 0x57, 0x50, 0x31, 7]]);

    // Why `consume` hands the reader a plain view and never the `Buffer`.
    // `Buffer.prototype.slice` is `subarray`, so a reader fed `Buffer`s
    // returns payloads that are WINDOWS into Node's 8 kB read pool - the
    // right bytes at the wrong offset, over a buffer 8 kB long. Nothing is
    // corrupted (the pool's cursor advances rather than wrapping), which is
    // exactly why this needs asserting rather than trusting: it fails silently
    // downstream, where `asArrayBuffer` in `pipeline.worker.ts` takes
    // `payload.buffer` on the strength of the view owning it exactly.
    const payload = seen.binaries[0];
    check('a payload owns its bytes exactly, so `payload.buffer` is the payload',
      [payload.byteOffset, payload.buffer.byteLength], [0, payload.byteLength]);

    pipe.close();
    server.close();
    client.destroy();
  }

  console.log('\n--- what it writes ---\n');

  {
    const pipePath = testPipePath('write');
    const received: string[] = [];
    const { server, nth } = await serve(pipePath, (socket, read) => {
      socket.on('data', (chunk: Buffer) => {
        const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        for (const frame of read.push(bytes)) {
          if (frame.kind === FRAME_JSON) received.push(frameText(frame));
        }
      });
    });

    const seen = recorder();
    const pipe = new PipeTransport(seen.events, pipePath, 50);

    // Before the link is up. A closed socket dropped a command; so does this,
    // rather than queueing one the agent's state has moved past by the time it
    // arrives.
    pipe.send('{"type":"start_capture"}');
    pipe.open();
    await until(() => seen.statuses.includes('connected'));
    pipe.send('{"type":"start_capture"}');
    pipe.send('{"type":"stop_capture"}');
    await until(() => received.length === 2);
    check('commands are framed and arrive in order',
      received, ['{"type":"start_capture"}', '{"type":"stop_capture"}']);
    check('...and one sent before the link was up was dropped, not queued',
      received.length, 2);

    pipe.close();
    server.close();
    (await nth(0)).destroy();
  }

  {
    // The greeting (ADR 0052): main says where its captures live first, on
    // every connection - a reconnect is a new client to the agent, which has
    // forgotten the last one's root - and before anything else can be sent.
    const pipePath = testPipePath('greet');
    const received: string[] = [];
    const { server, nth } = await serve(pipePath, (socket, read) => {
      socket.on('data', (chunk: Buffer) => {
        const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        for (const frame of read.push(bytes)) {
          if (frame.kind === FRAME_JSON) received.push(frameText(frame));
        }
      });
    });
    const greeting = '{"type":"set_capture_root","dir":"C:\\\\captures"}';
    const seen = recorder();
    const pipe = new PipeTransport(seen.events, pipePath, 50, greeting);
    pipe.open();
    await until(() => seen.statuses.includes('connected'));
    pipe.send('{"type":"start_capture"}');
    await until(() => received.length === 2);
    check('the greeting is the first thing the agent hears',
      received, [greeting, '{"type":"start_capture"}']);

    (await nth(0)).destroy();
    await until(() => received.length === 3);
    check('...and it is said again on the reconnect, to the new client',
      received[2], greeting);

    pipe.close();
    server.close();
    (await nth(1)).destroy();
  }

  console.log('\n--- when the agent is not there ---\n');

  {
    // Nothing is listening. This is the ordinary state on a machine where the
    // service has not started yet, so it must be a retry rather than a
    // failure the user has to act on.
    const pipePath = testPipePath('absent');
    const seen = recorder();
    const pipe = new PipeTransport(seen.events, pipePath, 50);
    pipe.open();
    await until(() => seen.statuses.filter((s) => s === 'connecting').length >= 3);
    check('a missing agent is retried rather than reported once',
      seen.statuses.filter((s) => s === 'connecting').length >= 3, true);
    check('...and each attempt says what happened',
      [seen.statuses.includes('error'), seen.statuses.includes('disconnected')], [true, true]);

    pipe.close();
    const after = seen.statuses.length;
    await sleep(200);
    // The property that matters more than the retry: closing must actually
    // stop it. The Worker's old `closeSocket` cleared its listeners first for
    // exactly this reason - a teardown that reads as the agent going away
    // re-arms the retry that closing exists to stop.
    check('closing stops the retry', seen.statuses.length, after);
  }

  {
    // The agent restarting under a live app - a service upgrade, or a crash.
    const pipePath = testPipePath('restart');
    const { server, nth } = await serve(pipePath);

    const seen = recorder();
    const pipe = new PipeTransport(seen.events, pipePath, 50);
    pipe.open();
    const client = await nth(0);
    await until(() => seen.statuses.includes('connected'));

    // Half a frame, and then the agent vanishes. The next connection must not
    // inherit it: a reader still holding those bytes would read the new
    // stream's first frame as the tail of a message that no longer exists.
    client.write(encodeJsonFrame({ type: 'state' }).subarray(0, 4));
    await sleep(30);
    client.destroy();
    await until(() => seen.statuses.filter((s) => s === 'connected').length === 2, 5000);
    check('a dropped agent is reconnected to',
      seen.statuses.filter((s) => s === 'connected').length, 2);

    // The SECOND socket: a reconnect is a new client, and writing to the dead
    // one is how this test would pass by not testing anything.
    (await nth(1)).write(encodeJsonFrame({ type: 'hello' }));
    await until(() => seen.texts.length === 1);
    check('...and the half-frame from the dead stream is not prepended to the new one',
      seen.texts, ['{"type":"hello"}']);

    pipe.close();
    server.close();
    client.destroy();
  }

  console.log(failures === 0
    ? '\nAll agent link checks passed.'
    : `\n${failures} agent link check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
