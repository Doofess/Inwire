/**
 * Two clients of the installed agent, one capture (docs/verification.md,
 * "Two clients").
 *
 *   npx tsx scripts/agent/two-client-drive.ts
 *
 * A capture belongs to the connection that started it (`control.rs`). Two
 * Inwire windows - or two people over Fast User Switching - are two
 * connections to one agent, and the second must never take the first's
 * capture, stop it or re-point it, and leaving must not end it. Checked here
 * over two real connections to `\\.\pipe\inwire-agent`, capturing on a real
 * adapter with real traffic:
 *
 *   - A starts; B is told whose capture it is in its `hello`
 *   - B's start, stop and set_interfaces are each answered `capture_busy`,
 *     and A's capture carries on
 *   - B leaving does not end A's capture: frames keep reaching A
 *   - A leaving does end it, and the agent is free: every client is told
 *     `idle`, and another can start its own
 *
 * Both clients are this account. Ownership is per connection and never per
 * account, so that is the logic Fast User Switching reaches; that a second
 * account's client reaches the pipe at all is `second-account-check.ps1`.
 *
 * No files: without a `captureId` the agent writes none. Needs the Inwire
 * service, Npcap and a connected adapter, and no capture running in any
 * Inwire window. About half a minute. In `check.ts`'s NOT_TESTS.
 */
import { spawnSync } from 'node:child_process';
import { connect, type Socket } from 'node:net';
import { FRAME_JSON, FrameReader, encodeFrame } from '../../src/services/agentFraming';

const AGENT_PIPE = '\\\\.\\pipe\\inwire-agent';

let failures = 0;
function checkTrue(name: string, ok: boolean, detail?: unknown): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${JSON.stringify(detail)}`.slice(0, 400));
}
function skip(reason: string): never {
  console.log(`SKIP  ${reason}`);
  process.exit(0);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Message = Record<string, unknown>;

/** One connection to the agent, speaking the app's framing. */
class Client {
  readonly heard: Message[] = [];
  /** Batches of frames: a capture is reaching this client. */
  batches = 0;
  closed = false;
  private readonly reader = new FrameReader();

  private constructor(readonly name: string, private readonly socket: Socket) {
    socket.on('data', (chunk: Buffer) => {
      for (const frame of this.reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))) {
        if (frame.kind === FRAME_JSON) this.heard.push(JSON.parse(Buffer.from(frame.payload).toString('utf8')));
        else this.batches++;
      }
    });
    socket.on('close', () => { this.closed = true; });
    socket.on('error', () => { this.closed = true; });
  }

  static async open(name: string): Promise<Client> {
    const socket = connect(AGENT_PIPE);
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const client = new Client(name, socket);
    await client.waitFor((m) => m.type === 'hello', 5000);
    return client;
  }

  send(command: Message): void {
    this.socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode(JSON.stringify(command))));
  }

  /** The first message from `from` on that matches, waiting up to `ms`. */
  async waitFor(match: (m: Message) => boolean, ms: number, from = 0): Promise<Message | undefined> {
    const deadline = Date.now() + ms;
    for (;;) {
      const found = this.heard.slice(from).find(match);
      if (found !== undefined || Date.now() > deadline) return found;
      await sleep(50);
    }
  }

  get hello(): Message {
    return this.heard.find((m) => m.type === 'hello')!;
  }

  close(): void {
    this.socket.destroy();
  }
}

/** Real traffic while a capture runs, so there is something to deliver. */
async function traffic(ms: number): Promise<void> {
  const sites = ['https://www.wikipedia.org/', 'https://www.cloudflare.com/', 'https://github.com/', 'https://example.com/'];
  const deadline = Date.now() + ms;
  for (let i = 0; Date.now() < deadline; i++) {
    await fetch(sites[i % sites.length], { signal: AbortSignal.timeout(5000) }).then((r) => r.arrayBuffer()).catch(() => {});
    await sleep(200);
  }
}

const isState = (state: string, owner?: string) => (m: Message) =>
  m.type === 'state' && m.state === state && (owner === undefined || m.owner === owner);
const isBusy = (m: Message) => m.type === 'error' && m.code === 'capture_busy';

if (process.platform !== 'win32') skip('the agent\'s pipe is Windows-only');

/**
 * The first connection. The service is demand start and stops itself once
 * nobody is connected (ADR 0035), so it is asked to start first, as the app
 * asks at launch - an interactive user may (`RP` in the IU ACE).
 */
async function first(): Promise<Client> {
  try {
    return await Client.open('A');
  } catch {
    spawnSync('sc.exe', ['start', 'InwireAgent'], { stdio: 'ignore' });
  }
  for (const deadline = Date.now() + 10_000; ;) {
    try {
      return await Client.open('A');
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await sleep(250);
    }
  }
}

let a: Client;
try {
  a = await first();
} catch {
  skip('the Inwire agent is not reachable at \\\\.\\pipe\\inwire-agent - is the service installed?');
}
const clients: Client[] = [a];
try {
  if (a.hello.state !== 'idle') skip('a capture is running - stop it in every Inwire window first');
  const interfaces = (a.hello.interfaces as { name: string; label: string }[]) ?? [];
  // A wired adapter first: it is what the other live drives capture on, and a
  // machine's Wi-Fi can be up with nothing on it. A label is the connection's
  // name and then the device's: "Ethernet (Intel(R) Ethernet Controller ...)".
  const adapter = interfaces.find((i) => /^Ethernet\b/.test(i.label))
    ?? interfaces.find((i) => /^Wi-?Fi\b/i.test(i.label));
  if (adapter === undefined) skip('no Ethernet or Wi-Fi adapter to capture on');
  const aId = String(a.hello.clientId);
  console.log(`      capturing on ${adapter.label}; A is ${aId}\n`);

  // --- A starts ----------------------------------------------------------------
  a.send({ type: 'set_interfaces', interfaces: [adapter.name] });
  a.send({ type: 'start_capture' });
  checkTrue('A\'s capture starts, and is A\'s', (await a.waitFor(isState('sniffing', aId), 10_000)) !== undefined);
  // What A hears from here on is about the running capture: `set_interfaces`
  // is answered with an idle state of its own, before the start.
  const running = a.heard.findIndex(isState('sniffing', aId)) + 1;
  const sinceStart = () => a.heard.slice(running);
  await traffic(3000);
  checkTrue('frames reach A', a.batches > 0, { batches: a.batches });

  // --- B joins -------------------------------------------------------------------
  const b = await Client.open('B');
  clients.push(b);
  checkTrue('B\'s hello says a capture is running, and whose',
    b.hello.state === 'sniffing' && b.hello.owner === aId, { state: b.hello.state, owner: b.hello.owner });

  for (const command of [
    { type: 'start_capture' },
    { type: 'stop_capture' },
    { type: 'set_interfaces', interfaces: [adapter.name] },
  ]) {
    const from = b.heard.length;
    b.send(command);
    checkTrue(`B's ${command.type} is answered capture_busy`, (await b.waitFor(isBusy, 3000, from)) !== undefined,
      b.heard.slice(from).map((m) => m.type === 'error' ? `${m.type}:${m.code}` : m.type));
  }
  checkTrue('...and none of them stopped A\'s capture',
    !sinceStart().some((m) => m.type === 'state' && (m.state !== 'sniffing' || m.owner !== aId)),
    sinceStart().filter((m) => m.type === 'state'));

  // --- B leaves ------------------------------------------------------------------
  b.close();
  await sleep(1000);
  const before = a.batches;
  await traffic(4000);
  checkTrue('B leaving does not end A\'s capture: frames keep reaching A',
    a.batches > before && !sinceStart().some(isState('idle')), { before, after: a.batches });

  // --- A leaves ------------------------------------------------------------------
  const c = await Client.open('C');
  clients.push(c);
  const cId = String(c.hello.clientId);
  checkTrue('a third client is told the capture is still A\'s', c.hello.owner === aId, { owner: c.hello.owner });
  const leaving = c.heard.length;
  a.close();
  checkTrue('A leaving ends its capture: C is told idle', (await c.waitFor(isState('idle'), 10_000, leaving)) !== undefined,
    c.heard.map((m) => m.type === 'state' ? `state:${m.state}` : m.type));

  // --- and the agent is free -----------------------------------------------------
  c.send({ type: 'set_interfaces', interfaces: [adapter.name] });
  c.send({ type: 'start_capture' });
  checkTrue('C can then start a capture of its own', (await c.waitFor(isState('sniffing', cId), 10_000, leaving)) !== undefined);
  const started = c.heard.findIndex((m, i) => i >= leaving && isState('sniffing', cId)(m)) + 1;
  c.send({ type: 'stop_capture' });
  checkTrue('...and stop it', (await c.waitFor(isState('idle'), 10_000, started)) !== undefined);
} finally {
  for (const client of clients) client.close();
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All two-client checks passed.');
process.exit(0);
