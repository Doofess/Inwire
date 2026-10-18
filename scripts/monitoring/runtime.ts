/**
 * The monitoring utility's intake, journal ownership and live feed, and the
 * runtime port's live-ack and busy rules (ADRs 0058, 0059; Task 5 rulings).
 *
 *   npx tsx scripts/monitoring/runtime.ts
 *
 * Everything runs under plain `tsx`: the collector takes its socket, volume,
 * clock, timers, next tick and randomness as arguments, so here the socket is
 * a fake that emits what a case says, the clock is moved by hand, and the two
 * files are `MemoryBlockFile`s. `udp.ts` (the `dgram` adapter) and `entry.ts`
 * (the process) hold no rule and are not driven here; the drives that launch
 * the real app are Task 6's.
 *
 * Each case that guards a rule was checked by breaking the rule, seeing the
 * case fail by name, and putting it back.
 */
import assert from 'node:assert/strict';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { Collector, STATUS_COALESCE_MS, type CollectorVolume, type UdpSocket } from '../../electron/monitoring/collector';
import { readIntakeStatus, type IntakeStatus } from '../../src/services/monitoring/control';
import { MonitoringJournal } from '../../src/services/monitoring/journal';
import { MAX_APPEND_BYTES, MAX_APPEND_MINUTES } from '../../src/services/monitoring/rollupStore';
import { RuntimeUnavailableError, type HostRuntime } from '../../src/services/monitoring/runtime';
import { createRuntimeClient, serveRuntime, type RpcPort } from '../../src/services/monitoring/runtimeRpc';
import { DECODER_POLICY_VERSION, LIMITS, type BoundaryEvidence, type DatagramEvidence, type Evidence, type SourceConfig } from '../../src/services/monitoring/types';
import { FILE_HEADER_BYTES } from '../../src/services/monitoring/journalCodec';

const MiB = 1024 * 1024;
const CFG: SourceConfig = { exporterIPv4: '10.0.0.1', bindIPv4: '192.168.1.5', port: 2055, storageLimitBytes: 16 * MiB };
const ROOT = 'C:/fake/monitoring';

// --- the harness ------------------------------------------------------------------------------------------------

let failures = 0;
let passes = 0;
async function test(name: string, fn: () => Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // A case that waits on a promise nothing will settle would otherwise end the process silently with status 0.
    await Promise.race([
      fn(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('timed out: a promise never settled')), 5000); }),
    ]);
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 7).join('\n        ')}`.slice(0, 1200));
  } finally {
    clearTimeout(timer);
  }
}

/** Lets every promise a step started finish; the fakes never wait on anything real. */
async function settle(): Promise<void> {
  for (let i = 0; i < 6; i++) await new Promise<void>((r) => setImmediate(r));
}

class FakeClock {
  t = 1_700_000_000_000;
  private seq = 0;
  private timers: { at: number; seq: number; fn: () => void }[] = [];
  setTimer = (fn: () => void, ms: number): (() => void) => {
    const timer = { at: this.t + ms, seq: this.seq++, fn };
    this.timers.push(timer);
    return () => { const i = this.timers.indexOf(timer); if (i >= 0) this.timers.splice(i, 1); };
  };
  now = (): number => this.t;
  get pending(): number { return this.timers.length; }
  advance(ms: number): void {
    const target = this.t + ms;
    for (;;) {
      const due = this.timers.filter((x) => x.at <= target).sort((a, b) => a.at - b.at || a.seq - b.seq)[0];
      if (due === undefined) break;
      this.timers.splice(this.timers.indexOf(due), 1);
      this.t = Math.max(this.t, due.at);
      due.fn();
    }
    this.t = target;
  }
}

type BindMode = 'ok' | 'hang' | { code?: string; message: string };

class FakeSocket implements UdpSocket {
  closed = false;
  binds: [string, number][] = [];
  private msg: ((data: Uint8Array, from: { address: string; port: number }) => void) | null = null;
  private err: ((e: { code?: string; message: string }) => void) | null = null;
  private gate: (() => void) | null = null;
  constructor(readonly mode: BindMode) {}
  onMessage(h: (data: Uint8Array, from: { address: string; port: number }) => void): void { this.msg = h; }
  onError(h: (e: { code?: string; message: string }) => void): void { this.err = h; }
  bind(address: string, port: number): Promise<void> {
    this.binds.push([address, port]);
    if (this.mode === 'ok') return Promise.resolve();
    if (this.mode === 'hang') return new Promise<void>((resolve) => { this.gate = resolve; });
    return Promise.reject(Object.assign(new Error(this.mode.message), this.mode.code === undefined ? {} : { code: this.mode.code }));
  }
  close(): void { this.closed = true; }
  release(): void { this.gate?.(); }
  /** Delivered even when closed: a real socket can have events in flight. */
  emit(data: Uint8Array, address = CFG.exporterIPv4, port = 2055): void { this.msg?.(data, { address, port }); }
  fail(code: string, message: string): void { this.err?.({ code, message }); }
}

class TestFile extends MemoryBlockFile {
  failWrites = false;
  failFlush = false;
  /** Reads served, so a case can tell a rescan of the journal from none. */
  reads = 0;
  override read(offset: number, into: Uint8Array): number {
    this.reads++;
    return super.read(offset, into);
  }
  override write(offset: number, from: Uint8Array): void {
    if (this.failWrites) throw new Error('disk full');
    super.write(offset, from);
  }
  override flush(): void {
    if (this.failFlush) throw new Error('flush refused');
    super.flush();
  }
}

class FakePort implements RpcPort {
  posted: any[] = [];
  closed = false;
  autoAck = false;
  private h: ((m: unknown) => void) | null = null;
  private closeH: (() => void) | null = null;
  postMessage(m: unknown): void {
    if (this.closed) throw new Error('port closed');
    this.posted.push(m);
    if (this.autoAck && (m as { type?: string }).type === 'live') queueMicrotask(() => this.h?.({ type: 'live-ack' }));
  }
  onMessage(h: (m: unknown) => void): void { this.h = h; }
  onClose(h: () => void): void { this.closeH = h; }
  close(): void { this.closed = true; }
  deliver(m: unknown): void { this.h?.(m); }
  fireClose(): void { this.closeH?.(); }
  ack(n = 1): void { for (let i = 0; i < n; i++) this.deliver({ type: 'live-ack' }); }
  get pushes(): Evidence[][] { return this.posted.filter((m) => m.type === 'live').map((m) => m.entries as Evidence[]); }
  get pushed(): Evidence[] { return this.pushes.flat(); }
}

interface TestVolume { journal: TestFile; rollups: MemoryBlockFile; opens: number; closes: number }

class Rig {
  clock = new FakeClock();
  sockets: FakeSocket[] = [];
  nextBinds: BindMode[] = [];
  deferred: (() => void)[] = [];
  statuses: IntakeStatus[] = [];
  badStatuses: unknown[] = [];
  volumes = new Map<string, TestVolume>();
  openError: Error | null = null;
  /** Failures for the next opens, one each, in order; after them the opener works again. */
  openErrors: Error[] = [];
  logs: string[] = [];
  private rand = 0;
  readonly collector: Collector;

  constructor() {
    this.collector = new Collector({
      openVolume: (root): CollectorVolume => {
        if (this.openError !== null) throw this.openError;
        const once = this.openErrors.shift();
        if (once !== undefined) throw once;
        let v = this.volumes.get(root);
        if (v === undefined) { v = { journal: new TestFile(), rollups: new MemoryBlockFile(), opens: 0, closes: 0 }; this.volumes.set(root, v); }
        v.opens++;
        const volume = v;
        return { journal: volume.journal, rollups: volume.rollups, close: () => { volume.closes++; } };
      },
      createSocket: () => {
        const s = new FakeSocket(this.nextBinds.shift() ?? 'ok');
        this.sockets.push(s);
        return s;
      },
      now: this.clock.now,
      randomBytes: (n) => { this.rand++; const b = new Uint8Array(n).fill(0xa0); b[0] = this.rand; return b; },
      setTimer: this.clock.setTimer,
      defer: (fn) => { this.deferred.push(fn); },
      postStatus: (status) => {
        const read = readIntakeStatus(JSON.parse(JSON.stringify(status)));
        if (read === null) this.badStatuses.push(status);
        this.statuses.push(status);
      },
      log: (line) => { this.logs.push(line); },
    });
  }

  get volume(): TestVolume { return this.volumes.get(ROOT)!; }
  get socket(): FakeSocket { return this.sockets[this.sockets.length - 1]; }
  get last(): IntakeStatus { return this.statuses[this.statuses.length - 1]; }
  /** The next-tick work the collector asked for, run now. */
  drain(): void { const q = this.deferred.splice(0); for (const f of q) f(); }

  /** Opens the dataset, attaches a Worker and starts; returns the port. */
  async listen(config: SourceConfig = CFG, port: FakePort = new FakePort()): Promise<FakePort> {
    assert.deepEqual(await this.collector.open(ROOT, config.storageLimitBytes), { ok: true });
    this.collector.attach(port);
    const started = await this.collector.start(config);
    assert.deepEqual(started, { ok: true });
    return port;
  }

  /** Every entry the journal holds, read through the served runtime. */
  async entries(): Promise<Evidence[]> {
    const runtime = this.collector.runtime;
    const snapshot = await runtime.snapshot();
    const out: Evidence[] = [];
    let after = 0;
    for (;;) {
      const page = await runtime.readPage(snapshot, after, 256, MiB);
      out.push(...page.entries);
      if (page.done || page.entries.length === 0) return out;
      after = page.nextAfterId;
    }
  }
}

const bytes = (n: number, fill = 7): Uint8Array => new Uint8Array(n).fill(fill);
const isBoundary = (e: Evidence): e is BoundaryEvidence => e.kind === 'boundary';
const isDatagram = (e: Evidence): e is DatagramEvidence => e.kind === 'datagram';
const actions = (es: Evidence[]): string[] => es.filter(isBoundary).map((b) => (b.reason === '' ? b.action : `${b.action}:${b.reason}`));

/** The bytes of a journal file as a new file, so reading it does not touch the one a collector owns. */
function fileEntries(file: MemoryBlockFile): Evidence[] {
  const copy = new MemoryBlockFile();
  copy.write(0, file.snapshot());
  const { journal } = MonitoringJournal.open(copy, { limitBytes: 64 * MiB });
  const snapshot = journal.snapshot();
  const out: Evidence[] = [];
  let after = 0;
  for (;;) {
    const page = journal.readPage(snapshot, after, 256, MiB);
    out.push(...page.entries);
    if (page.done || page.entries.length === 0) return out;
    after = page.nextAfterId;
  }
}

// --- Start's preconditions -----------------------------------------------------------------------------------------

async function main(): Promise<void> {
  await test('start: before the dataset is open it waits, then goes ahead once it opens', async () => {
    const rig = new Rig();
    rig.collector.attach(new FakePort());
    let result: unknown = 'pending';
    void rig.collector.start(CFG).then((r) => { result = r; });
    await settle();
    rig.clock.advance(LIMITS.handshakeMs - 1);
    await settle();
    assert.equal(result, 'pending');
    assert.equal(rig.sockets.length, 0);
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    await settle();
    assert.deepEqual(result, { ok: true });
    assert.equal(rig.last.listener, 'listening');
  });

  await test('start: before a Worker attaches it waits, then goes ahead once one does', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    let result: unknown = 'pending';
    void rig.collector.start(CFG).then((r) => { result = r; });
    await settle();
    assert.equal(result, 'pending');
    assert.equal(rig.sockets.length, 0);
    rig.collector.attach(new FakePort());
    await settle();
    assert.deepEqual(result, { ok: true });
  });

  await test('start: with neither it times out at the handshake deadline and names both', async () => {
    const rig = new Rig();
    const p = rig.collector.start(CFG);
    await settle();
    rig.clock.advance(LIMITS.handshakeMs);
    const r = await p;
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.match(r.message, /15 s/);
      assert.match(r.message, /dataset/);
      assert.match(r.message, /Worker/);
    }
    assert.equal(rig.sockets.length, 0, 'no socket was created for a start that never began');
  });

  await test('start: with a dataset but no Worker the message names only the Worker', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    const p = rig.collector.start(CFG);
    await settle();
    rig.clock.advance(LIMITS.handshakeMs);
    const r = await p;
    assert.equal(r.ok, false);
    if (!r.ok) { assert.match(r.message, /Worker/); assert.doesNotMatch(r.message, /dataset/); }
  });

  await test('start: with a Worker but no dataset the message names only the dataset', async () => {
    const rig = new Rig();
    rig.collector.attach(new FakePort());
    const p = rig.collector.start(CFG);
    await settle();
    rig.clock.advance(LIMITS.handshakeMs);
    const r = await p;
    assert.equal(r.ok, false);
    if (!r.ok) { assert.match(r.message, /dataset/); assert.doesNotMatch(r.message, /Worker/); }
  });

  await test('start: an invalid source is refused before anything is bound', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.stop('user');
    const r = await rig.collector.start({ ...CFG, bindIPv4: '0.0.0.0' });
    assert.equal(r.ok, false);
    assert.equal(rig.sockets.length, 1);
  });

  await test('start: the same configuration again is ok and binds nothing new', async () => {
    const rig = new Rig();
    await rig.listen();
    const before = rig.last;
    assert.deepEqual(await rig.collector.start({ ...CFG }), { ok: true });
    assert.equal(rig.sockets.length, 1);
    assert.equal(before.sessionId, rig.last.sessionId);
    assert.equal((await rig.entries()).filter(isBoundary).length, 1, 'one start boundary, not two');
  });

  await test('start: a different configuration while listening is refused with the reason, and nothing changes', async () => {
    const rig = new Rig();
    await rig.listen();
    for (const other of [{ ...CFG, port: 2056 }, { ...CFG, exporterIPv4: '10.0.0.2' }, { ...CFG, bindIPv4: '192.168.1.6' }, { ...CFG, storageLimitBytes: 32 * MiB }]) {
      const r = await rig.collector.start(other);
      assert.deepEqual(r, { ok: false, message: 'monitoring is already listening with a different source; stop it first' });
    }
    assert.equal(rig.sockets.length, 1);
    assert.equal(rig.last.listener, 'listening');
    assert.equal(rig.volume.opens, 1);
  });

  await test('start: a different storage limit while stopped is applied in place: no reopen, the Worker stays attached (I1)', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    const first = rig.last.sessionId;
    await rig.collector.stop('user');
    const generation = (await rig.collector.runtime.snapshot()).generation;
    assert.deepEqual(await rig.collector.start({ ...CFG, storageLimitBytes: 32 * MiB }), { ok: true });
    assert.equal(rig.volume.opens, 1, 'the dataset was not opened again');
    assert.equal(rig.volume.closes, 0, 'and not closed');
    assert.equal(port.closed, false, 'the attached port is still open');
    assert.equal(rig.last.workerAttached, true);
    assert.equal(rig.sockets.length, 2);
    assert.equal(rig.last.storage, 'open');
    assert.equal((await rig.collector.runtime.snapshot()).generation, generation, 'the same journal object');
    assert.notEqual(rig.last.sessionId, first);
    assert.deepEqual(actions(await rig.entries()), ['start', 'stop:user', 'start']);
  });

  await test('start: a limit change over a large journal does not rescan it (I1)', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round));
      rig.drain();
    }
    await rig.collector.stop('user');
    assert.ok(rig.volume.journal.size() > 8 * MiB, 'the journal is large');
    const reads = rig.volume.journal.reads;
    assert.deepEqual(await rig.collector.start({ ...CFG, storageLimitBytes: 64 * MiB }), { ok: true });
    assert.equal(rig.volume.journal.reads, reads, 'not one read: a reopen would scan every entry');
    assert.equal(rig.volume.opens, 1);
    assert.equal(rig.volume.closes, 0);
  });

  await test('start: raising the limit over a dataset the old limit filled lets Start listen again (I1)', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    for (let round = 0; round < 12 && !rig.socket.closed; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round & 0xff));
      rig.drain();
    }
    assert.equal(rig.last.storage, 'storage-limit');
    const same = await rig.collector.start(CFG);
    assert.equal(same.ok, false, 'the same limit still has no room');
    assert.deepEqual(await rig.collector.start({ ...CFG, storageLimitBytes: 64 * MiB }), { ok: true });
    assert.equal(rig.last.storage, 'open');
    assert.equal(rig.last.storageError, null);
    assert.equal(rig.last.listener, 'listening');
    assert.equal(rig.volume.opens, 1);
    assert.equal(port.closed, false);
    assert.deepEqual(actions(await rig.entries()), ['start', 'stop:storage-limit', 'start']);
  });

  await test('start: datagrams shed between the socket and the bind are counted and become a gap', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    rig.nextBinds.push('hang');
    const started = rig.collector.start(CFG);
    await settle();
    for (let i = 0; i < LIMITS.inboxDatagrams + 5; i++) rig.socket.emit(bytes(10));
    rig.socket.release();
    assert.deepEqual(await started, { ok: true });
    assert.equal(rig.last.shedDatagrams, 5, 'what was shed while binding is not forgotten');
    rig.drain();
    const gaps = (await rig.entries()).filter(isBoundary).filter((b) => b.action === 'gap');
    assert.deepEqual(gaps.map((g) => g.droppedDatagrams), [5]);
  });

  await test('start: the senders rejected while a restart binds are counted, and the last session\'s are not carried over', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(10), '10.9.9.1');
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.deepEqual(rig.last.rejectedSenders, [{ address: '10.9.9.1', count: 1 }]);
    await rig.collector.stop('user');
    rig.nextBinds.push('hang');
    const started = rig.collector.start(CFG);
    await settle();
    rig.socket.emit(bytes(10), '10.9.9.2');
    rig.clock.advance(STATUS_COALESCE_MS);
    rig.socket.release();
    assert.deepEqual(await started, { ok: true });
    assert.deepEqual(rig.last.rejectedSenders, [{ address: '10.9.9.2', count: 1 }], 'the new session starts at nothing, and keeps what arrived while it bound');
    assert.equal(rig.last.rejectedOverflow, 0);
  });

  await test('start: the same storage limit while stopped does not reopen the dataset', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.stop('user');
    assert.deepEqual(await rig.collector.start(CFG), { ok: true });
    assert.equal(rig.volume.opens, 1);
    assert.equal(rig.volume.closes, 0);
  });

  await test('start: datagrams that arrive between the bind and the start boundary follow it', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    rig.nextBinds.push('hang');
    const p = rig.collector.start(CFG);
    await settle();
    assert.equal(rig.last.listener, 'starting');
    rig.socket.emit(bytes(40, 1));
    rig.socket.release();
    assert.deepEqual(await p, { ok: true });
    rig.drain();
    const es = await rig.entries();
    assert.deepEqual(es.map((e) => e.kind), ['boundary', 'datagram']);
    assert.equal((es[1] as DatagramEvidence).sessionId, (es[0] as BoundaryEvidence).sessionId);
  });

  // --- bind failures --------------------------------------------------------------------------------------------

  const bindCases: { code: string | undefined; message: string; expect: string }[] = [
    { code: 'EADDRINUSE', message: 'bind EADDRINUSE 192.168.1.5:2055', expect: 'UDP port 2055 on 192.168.1.5 is already in use by another program' },
    { code: 'EADDRNOTAVAIL', message: 'bind EADDRNOTAVAIL', expect: '192.168.1.5 is not an address of this computer' },
    { code: 'EACCES', message: 'bind EACCES', expect: 'Windows refused UDP port 2055 on 192.168.1.5' },
    { code: undefined, message: 'something odd happened', expect: 'something odd happened' },
  ];
  for (const c of bindCases) {
    await test(`bind: ${c.code ?? 'another error'} is reported in the user's words, once, with no retry`, async () => {
      const rig = new Rig();
      await rig.collector.open(ROOT, CFG.storageLimitBytes);
      rig.collector.attach(new FakePort());
      rig.nextBinds.push({ ...(c.code === undefined ? {} : { code: c.code }), message: c.message });
      const r = await rig.collector.start(CFG);
      assert.deepEqual(r, { ok: false, message: c.expect });
      assert.equal(rig.last.listener, 'failed');
      assert.equal(rig.last.listenerError, c.expect);
      assert.equal(rig.last.sessionId, null);
      assert.equal(rig.socket.closed, true);
      rig.clock.advance(120_000);
      await settle();
      assert.equal(rig.sockets.length, 1, 'no second socket');
      assert.equal(rig.socket.binds.length, 1, 'no second bind');
      assert.equal((await rig.entries()).length, 0, 'nothing was journalled for a start that never bound');
      // The user fixes it and presses Start again.
      assert.deepEqual(await rig.collector.start(CFG), { ok: true });
      assert.equal(rig.last.listener, 'listening');
      assert.equal(rig.last.listenerError, null);
    });
  }

  await test('bind: a bind that never answers fails at the deadline and closes the socket', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    rig.nextBinds.push('hang');
    const p = rig.collector.start(CFG);
    await settle();
    rig.clock.advance(LIMITS.handshakeMs);
    const r = await p;
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.message, /took longer than 15 s/);
    assert.equal(rig.socket.closed, true);
    assert.equal(rig.last.listener, 'failed');
  });

  await test('socket error after the bind: the session stops with socket-error, the journal is flushed and the listener fails', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(50));
    rig.drain();
    rig.socket.fail('ECONNRESET', 'the socket broke');
    await settle();
    assert.equal(rig.socket.closed, true);
    assert.equal(rig.last.listener, 'failed');
    assert.equal(rig.last.listenerError, 'the socket broke');
    assert.equal(rig.last.sessionId, null);
    const snapshot = await rig.collector.runtime.snapshot();
    assert.equal(snapshot.syncedThroughEntryId, snapshot.throughEntryId);
    assert.deepEqual(actions(await rig.entries()), ['start', 'stop:socket-error']);
    assert.equal((await rig.entries()).filter(isDatagram).length, 1, 'what arrived before the error is kept');
    const before = snapshot.throughEntryId;
    const r = await rig.collector.stop('user');
    assert.deepEqual([r.ok, r.ok && r.clean], [true, true]);
    assert.equal((await rig.collector.runtime.snapshot()).throughEntryId, before, 'a Stop after the failure writes nothing');
  });

  await test('socket error: an error from a socket that was already closed is ignored', async () => {
    const rig = new Rig();
    await rig.listen();
    const old = rig.socket;
    await rig.collector.stop('user');
    old.fail('ECONNRESET', 'late');
    await settle();
    assert.equal(rig.last.listener, 'stopped');
    assert.equal(rig.last.listenerError, null);
  });

  // --- intake -------------------------------------------------------------------------------------------------------

  await test('intake: the configured exporter is journalled; anyone else is counted and never journalled', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(60, 1));
    rig.socket.emit(bytes(61, 2), '10.0.0.99');
    rig.socket.emit(bytes(62, 3), '10.0.0.99');
    rig.socket.emit(bytes(63, 4), '10.0.0.98');
    rig.drain();
    const es = await rig.entries();
    const datagrams = es.filter(isDatagram);
    assert.equal(datagrams.length, 1);
    assert.equal(datagrams[0].remoteIPv4, '10.0.0.1');
    assert.equal(datagrams[0].localIPv4, '192.168.1.5');
    assert.equal(datagrams[0].localPort, 2055);
    assert.deepEqual(Array.from(datagrams[0].bytes), Array.from(bytes(60, 1)));
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.equal(rig.last.received, 1);
    assert.deepEqual(rig.last.rejectedSenders, [{ address: '10.0.0.99', count: 2 }, { address: '10.0.0.98', count: 1 }]);
    assert.equal(rig.last.rejectedOverflow, 0);
  });

  await test('intake: the first 16 other senders are listed by arrival and the rest are one overflow count', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let i = 0; i < 20; i++) rig.socket.emit(bytes(30), `10.1.0.${i}`);
    rig.socket.emit(bytes(30), '10.1.0.3');
    rig.socket.emit(bytes(30), '10.1.0.19');
    rig.drain();
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.equal(rig.last.rejectedSenders.length, LIMITS.rejectedSenders);
    assert.deepEqual(rig.last.rejectedSenders.map((s) => s.address), Array.from({ length: 16 }, (_, i) => `10.1.0.${i}`));
    assert.equal(rig.last.rejectedSenders[3].count, 2, 'a listed sender keeps counting');
    assert.equal(rig.last.rejectedOverflow, 4 + 1, 'four unlisted senders, plus a second datagram from 10.1.0.19');
    assert.equal((await rig.entries()).filter(isDatagram).length, 0);
  });

  await test('intake: the bytes are copied at the message event, not kept as a view of the socket buffer', async () => {
    const rig = new Rig();
    await rig.listen();
    const source = bytes(80, 9);
    rig.socket.emit(source);
    source.fill(0xee);
    rig.drain();
    const [d] = (await rig.entries()).filter(isDatagram);
    assert.deepEqual(Array.from(d.bytes), Array.from(bytes(80, 9)));
  });

  await test('intake: a burst is drained in one pass per tick, not one per datagram', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let i = 0; i < 10; i++) rig.socket.emit(bytes(40, i));
    assert.equal(rig.deferred.length, 1);
    const through = (await rig.collector.runtime.snapshot()).throughEntryId;
    rig.drain();
    assert.equal((await rig.collector.runtime.snapshot()).throughEntryId, through + 10);
  });

  await test('intake: a payload past the UDP maximum is refused without a crash and counted as lost', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(new Uint8Array(LIMITS.maxPayloadBytes + 1));
    rig.drain();
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.equal(rig.last.shedDatagrams, 1);
    assert.equal((await rig.entries()).filter(isDatagram).length, 0);
    assert.equal(rig.last.listener, 'listening');
  });

  await test('intake: past the inbox count the excess is shed and counted, and a gap says how many', async () => {
    const rig = new Rig();
    await rig.listen();
    const over = 5;
    for (let i = 0; i < LIMITS.inboxDatagrams + over; i++) rig.socket.emit(bytes(40, i & 0xff));
    rig.drain();
    const es = await rig.entries();
    const [startB, gap, ...rest] = es;
    assert.equal(startB.kind, 'boundary');
    assert.ok(isBoundary(gap) && gap.action === 'gap' && gap.reason === 'intake-shed' && gap.droppedDatagrams === over, JSON.stringify(gap));
    assert.equal(rest.length, LIMITS.inboxDatagrams);
    assert.ok(rest.every(isDatagram));
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.equal(rig.last.shedDatagrams, over);
    assert.equal(rig.last.received, LIMITS.inboxDatagrams, 'the gap boundary is not a received datagram');
    // The next drain has nothing new to report.
    rig.socket.emit(bytes(40));
    rig.drain();
    assert.equal(actions(await rig.entries()).filter((a) => a.startsWith('gap')).length, 1);
  });

  await test('intake: past the inbox bytes the excess is shed too', async () => {
    const rig = new Rig();
    await rig.listen();
    const each = 60_000;
    const fit = Math.floor(LIMITS.inboxBytes / each);
    for (let i = 0; i < fit + 3; i++) rig.socket.emit(bytes(each));
    rig.drain();
    const es = await rig.entries();
    assert.equal(es.filter(isDatagram).length, fit);
    const gap = es.filter(isBoundary).find((b) => b.action === 'gap');
    assert.equal(gap?.droppedDatagrams, 3);
  });

  await test('intake: datagrams from a socket the collector has let go of are ignored', async () => {
    const rig = new Rig();
    await rig.listen();
    const old = rig.socket;
    await rig.collector.stop('user');
    const through = (await rig.collector.runtime.snapshot()).throughEntryId;
    old.emit(bytes(40));
    old.emit(bytes(40), '10.9.9.9');
    rig.drain();
    assert.equal((await rig.collector.runtime.snapshot()).throughEntryId, through);
    assert.equal(rig.last.received, 0);
    assert.deepEqual(rig.last.rejectedSenders, []);
  });

  await test('intake: counters start again with each session', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(40));
    rig.socket.emit(bytes(40), '10.7.7.7');
    rig.drain();
    await rig.collector.stop('user');
    assert.equal(rig.last.received, 1, 'a stopped status still shows the last session');
    await rig.collector.start(CFG);
    assert.equal(rig.last.received, 0);
    assert.deepEqual(rig.last.rejectedSenders, []);
  });

  await test('storage limit: the socket closes, the listener is stopped and the journal wrote its own stop', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 12 && !rig.socket.closed; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round & 0xff));
      rig.drain();
    }
    assert.equal(rig.socket.closed, true, 'a full dataset stops listening');
    assert.equal(rig.last.listener, 'stopped');
    assert.equal(rig.last.listenerError, null);
    assert.equal(rig.last.storage, 'storage-limit');
    assert.match(rig.last.storageError ?? '', /storage limit/);
    assert.equal(rig.last.sessionId, null);
    const es = await rig.entries();
    assert.deepEqual(actions(es), ['start', 'stop:storage-limit']);
    assert.ok(rig.volume.journal.size() <= CFG.storageLimitBytes, 'never past the limit');
    // Another Start does not pretend.
    const again = await rig.collector.start(CFG);
    assert.equal(again.ok, false);
    if (!again.ok) assert.match(again.message, /storage limit/);
    // And Stop on a stopped listener writes nothing.
    const stop = await rig.collector.stop('user');
    assert.deepEqual([stop.ok, stop.ok && stop.clean], [true, true]);
    assert.deepEqual(actions(await rig.entries()), ['start', 'stop:storage-limit']);
  });

  await test('storage limit: a Stop whose drain fills the journal is clean, and the journal-written stop is flushed', async () => {
    const rig = new Rig();
    await rig.listen();
    // Two drained rounds put the journal near its limit; the third is still in the inbox when Stop asks.
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round));
      rig.drain();
    }
    assert.equal(rig.socket.closed, false);
    for (let i = 0; i < 120; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, 9));
    const stop = await rig.collector.stop('user');
    assert.equal(rig.last.storage, 'storage-limit', 'the drain is what hit the limit');
    assert.ok(stop.ok);
    assert.equal(stop.ok && stop.clean, true, 'the journal wrote the stop and it was flushed');
    assert.equal(rig.last.stopReason, 'storage-limit', 'the journal ended the session, not the Stop that was asked for');
    const snapshot = await rig.collector.runtime.snapshot();
    assert.equal(snapshot.syncedThroughEntryId, snapshot.throughEntryId, 'the journal-written stop is synced');
    assert.deepEqual(actions(fileEntries(rig.volume.journal)), ['start', 'stop:storage-limit']);
    assert.equal(rig.clock.pending, 0, 'no timer is left running');
  });

  await test('storage limit: reached by an ordinary drain, the stop is flushed before the session ends', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 12 && !rig.socket.closed; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round & 0xff));
      rig.drain();
    }
    assert.equal(rig.last.storage, 'storage-limit');
    const snapshot = await rig.collector.runtime.snapshot();
    assert.equal(snapshot.syncedThroughEntryId, snapshot.throughEntryId);
  });

  // --- stop -----------------------------------------------------------------------------------------------------

  for (const reason of ['user', 'quit'] as const) {
    await test(`stop(${reason}): the socket closes, the inbox is journalled first, a stop boundary carries the reason, and it is flushed`, async () => {
      const rig = new Rig();
      await rig.listen();
      rig.socket.emit(bytes(50, 5));
      rig.socket.emit(bytes(50, 6));
      const r = await rig.collector.stop(reason);
      assert.ok(r.ok && r.clean);
      assert.equal(rig.socket.closed, true);
      assert.equal(rig.last.listener, 'stopped');
      assert.equal(rig.last.sessionId, null);
      const es = await rig.entries();
      assert.deepEqual(es.map((e) => (isBoundary(e) ? e.action : 'd')), ['start', 'd', 'd', 'stop']);
      assert.equal((es[3] as BoundaryEvidence).reason, reason);
      const s = r.snapshot!;
      assert.equal(s.syncedThroughEntryId, s.throughEntryId);
      assert.equal(s.throughEntryId, 4);
    });
  }

  await test('stop(suspend): a suspend boundary, then the stop with reason suspend', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(50));
    const r = await rig.collector.stop('suspend');
    assert.ok(r.ok && r.clean);
    assert.deepEqual(actions(await rig.entries()), ['start', 'suspend:suspend', 'stop:suspend']);
    assert.equal(rig.socket.closed, true);
  });

  await test('stop: while stopped, and a second time, it answers clean and writes nothing', async () => {
    const rig = new Rig();
    const never = await rig.collector.stop('user');
    assert.deepEqual(never, { ok: true, clean: true, snapshot: null });
    await rig.listen();
    await rig.collector.stop('user');
    const through = (await rig.collector.runtime.snapshot()).throughEntryId;
    const flushes = rig.volume.journal.flushes;
    const again = await rig.collector.stop('quit');
    assert.ok(again.ok && again.clean);
    assert.equal(again.snapshot?.throughEntryId, through);
    assert.equal((await rig.collector.runtime.snapshot()).throughEntryId, through);
    assert.equal(rig.volume.journal.flushes, flushes);
    assert.deepEqual(actions(await rig.entries()), ['start', 'stop:user']);
  });

  await test('stop: a second session after a stop is a new session id with its own boundaries', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.stop('user');
    assert.deepEqual(await rig.collector.start(CFG), { ok: true });
    await rig.collector.stop('user');
    const bs = (await rig.entries()).filter(isBoundary);
    assert.deepEqual(bs.map((b) => b.action), ['start', 'stop', 'start', 'stop']);
    assert.notEqual(bs[0].sessionId, bs[2].sessionId);
    assert.match(bs[0].sessionId, /^[0-9a-f]{32}$/);
  });

  await test('stop: not clean when the journal refuses the stop boundary', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.volume.journal.failWrites = true;
    const r = await rig.collector.stop('user');
    assert.equal(r.ok, true);
    assert.equal(r.ok && r.clean, false);
    assert.equal(rig.socket.closed, true);
    assert.equal(rig.last.listener, 'failed', 'a stop that ran into a journal failure does not read as a clean stop');
  });

  await test('stop: not clean when the flush does not take', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.volume.journal.failFlush = true;
    const r = await rig.collector.stop('user');
    assert.equal(r.ok, true);
    assert.equal(r.ok && r.clean, false);
  });

  await test('stop: while a Start waits for its dataset, the Start ends at once and the Stop answers', async () => {
    const rig = new Rig();
    let startResult: unknown = 'pending';
    void rig.collector.start(CFG).then((r) => { startResult = r; });
    await settle();
    const stop = await rig.collector.stop('user');
    await settle();
    assert.deepEqual(stop, { ok: true, clean: true, snapshot: null });
    assert.deepEqual(startResult, { ok: false, message: 'monitoring was stopped before it started listening' });
    assert.equal(rig.clock.pending, 0, 'no timer is left running');
  });

  await test('stop: asked in the same breath as a Start, it still wins', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    const started = rig.collector.start(CFG);
    const stopped = rig.collector.stop('user');
    assert.equal((await started).ok, false);
    assert.equal((await stopped).ok, true);
    assert.equal(rig.sockets.length, 0);
    assert.deepEqual(await rig.collector.start(CFG), { ok: true }, 'a Start asked for after the Stop is a fresh one');
  });

  await test('stop: while the bind is outstanding, the Start ends and the socket closes', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    rig.nextBinds.push('hang');
    const started = rig.collector.start(CFG);
    await settle();
    const stopped = await rig.collector.stop('user');
    const r = await started;
    assert.equal(r.ok, false);
    assert.equal(stopped.ok, true);
    assert.equal(rig.socket.closed, true);
    assert.equal(rig.last.listener, 'stopped');
    assert.equal(rig.clock.pending, 0);
  });

  // --- dispose ---------------------------------------------------------------------------------------------------

  await test('stopReason: null before any stop, the reason of each stop, null again once a Start succeeds', async () => {
    const rig = new Rig();
    await rig.listen();
    assert.equal(rig.last.stopReason, null, 'a running listener has not stopped');
    for (const reason of ['user', 'suspend', 'quit'] as const) {
      await rig.collector.stop(reason);
      assert.equal(rig.last.stopReason, reason);
      assert.equal(rig.collector.status().stopReason, reason);
      assert.equal(rig.last.listener, 'stopped');
      if (reason !== 'quit') {
        assert.deepEqual(await rig.collector.start(CFG), { ok: true });
        assert.equal(rig.last.stopReason, null, 'a successful Start clears it');
      }
    }
  });

  await test('stopReason: a Stop while already stopped leaves the reason of the stop that did it', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.stop('suspend');
    await rig.collector.stop('user');
    assert.equal(rig.collector.status().stopReason, 'suspend');
    assert.equal(rig.last.stopReason, 'suspend');
  });

  await test('stopReason: a refused Start does not clear it', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.stop('suspend');
    const refused = await rig.collector.start({ ...CFG, bindIPv4: '0.0.0.0' });
    assert.equal(refused.ok, false);
    assert.equal(rig.collector.status().stopReason, 'suspend');
  });

  await test('stopReason: a socket error says socket-error', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.fail('ECONNRESET', 'the socket broke');
    await settle();
    assert.equal(rig.last.listener, 'failed');
    assert.equal(rig.last.stopReason, 'socket-error');
  });

  await test('stopReason: a socket error whose final drain fills the journal says storage-limit, as a Stop does', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round));
      rig.drain();
    }
    for (let i = 0; i < 120; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, 9));
    rig.socket.fail('ECONNRESET', 'the socket broke');
    await settle();
    assert.equal(rig.last.storage, 'storage-limit', 'the drain is what hit the limit');
    assert.equal(rig.last.stopReason, 'storage-limit', 'the journal wrote that stop, not the socket');
    assert.deepEqual(actions(fileEntries(rig.volume.journal)), ['start', 'stop:storage-limit']);
  });

  await test('stopReason: a socket error whose final drain fills the journal leaves the listener as the storage ending set it', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round));
      rig.drain();
    }
    for (let i = 0; i < 120; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, 9));
    rig.socket.fail('ECONNRESET', 'the socket broke');
    await settle();
    assert.equal(rig.last.storage, 'storage-limit');
    assert.equal(rig.last.listener, 'stopped', 'the storage ending closed the session; a socket error does not reopen that account');
    assert.equal(rig.last.listenerError, null, 'and names no socket error for a stop the journal ended');
  });

  await test('stopReason: a flush that fails says storage-failed', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.volume.journal.failFlush = true;
    rig.clock.advance(LIMITS.flushMs);
    assert.equal(rig.last.listener, 'failed');
    assert.equal(rig.last.stopReason, 'storage-failed');
  });

  await test('stopReason: a Stop whose close hits a journal failure keeps the listener failed and says storage-failed', async () => {
    for (const mode of ['failWrites', 'failFlush'] as const) {
      const rig = new Rig();
      await rig.listen();
      rig.volume.journal[mode] = true;
      const r = await rig.collector.stop('user');
      assert.equal(r.ok && r.clean, false, mode);
      assert.equal(rig.last.listener, 'failed', mode);
      assert.match(rig.last.listenerError ?? '', /could not be written/, mode);
      assert.equal(rig.last.stopReason, 'storage-failed', mode);
    }
  });

  await test('stopReason: a Start aborted by a Stop records that Stop reason, suspend included', async () => {
    for (const reason of ['suspend', 'user'] as const) {
      const rig = new Rig();
      await rig.collector.open(ROOT, CFG.storageLimitBytes);
      rig.collector.attach(new FakePort());
      rig.nextBinds.push('hang');
      const started = rig.collector.start(CFG);
      await settle();
      await rig.collector.stop(reason);
      assert.equal((await started).ok, false);
      assert.equal(rig.last.stopReason, reason);
      assert.equal(rig.collector.status().stopReason, reason);
    }
  });

  await test('stopReason: a Start aborted before it reached the bind still posts why, so the UI is not left on the old reason', async () => {
    for (const queued of [false, true]) {
      const rig = new Rig();
      // No Worker port: the Start waits for one, short of the bind that would publish.
      const opening = rig.collector.open(ROOT, CFG.storageLimitBytes);
      if (!queued) await opening;
      const started = rig.collector.start(CFG);
      await settle();
      await rig.collector.stop('suspend');
      assert.equal((await started).ok, false, `queued ${queued}`);
      assert.equal(rig.collector.status().stopReason, 'suspend', `queued ${queued}`);
      assert.equal(rig.last.stopReason, 'suspend', `queued ${queued}: posted, not only held`);
    }
  });

  await test('stopReason: a full dataset says storage-limit, and a later Stop of the stopped listener leaves it', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let round = 0; round < 12 && !rig.socket.closed; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round & 0xff));
      rig.drain();
    }
    assert.equal(rig.last.storage, 'storage-limit');
    assert.equal(rig.last.stopReason, 'storage-limit');
    await rig.collector.stop('user');
    assert.equal(rig.collector.status().stopReason, 'storage-limit', 'a Stop of a stopped listener changes nothing');
  });

  await test('dispose: stops with reason quit, closes the socket, the port and the dataset, and is the same answer twice', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    rig.socket.emit(bytes(50));
    const first = rig.collector.dispose();
    const second = rig.collector.dispose();
    assert.equal(first, second);
    const r = await first;
    assert.ok(r.ok && r.clean);
    assert.equal(rig.socket.closed, true);
    assert.equal(port.closed, true);
    assert.equal(rig.volume.closes, 1);
    assert.equal(rig.last.storage, 'closed');
    assert.equal(rig.last.workerAttached, false);
    assert.deepEqual(actions(fileEntries(rig.volume.journal)), ['start', 'stop:quit']);
    assert.equal(rig.clock.pending, 0, 'no timer survives it');
  });

  /** A second process on the same files: the journal's bytes as they are now, in a fresh collector. */
  function relaunch(from: Rig): Rig {
    const rig = new Rig();
    const v: TestVolume = { journal: new TestFile(), rollups: new MemoryBlockFile(), opens: 0, closes: 0 };
    v.journal.write(0, from.volume.journal.snapshot());
    rig.volumes.set(ROOT, v);
    return rig;
  }

  await test('stopReason: a relaunch after each kind of stop reports the reason the journal holds, and a Start clears it', async () => {
    for (const reason of ['user', 'quit', 'suspend'] as const) {
      const first = new Rig();
      await first.listen();
      first.socket.emit(bytes(50));
      first.drain();
      await first.collector.stop(reason);
      await first.collector.dispose();
      const rig = relaunch(first);
      assert.deepEqual(await rig.collector.open(ROOT, CFG.storageLimitBytes), { ok: true });
      assert.equal(rig.collector.status().stopReason, reason, reason);
      assert.equal(rig.last.stopReason, reason, `${reason}: posted, not only held`);
      assert.equal(rig.last.listener, 'stopped');
      rig.collector.attach(new FakePort());
      assert.deepEqual(await rig.collector.start(CFG), { ok: true });
      assert.equal(rig.collector.status().stopReason, null, `${reason}: a Start clears it`);
    }
  });

  await test('stopReason: a relaunch after the journal filled reports storage-limit', async () => {
    const first = new Rig();
    await first.listen();
    for (let round = 0; round < 12 && !first.socket.closed; round++) {
      for (let i = 0; i < 100; i++) first.socket.emit(bytes(LIMITS.maxPayloadBytes, round & 0xff));
      first.drain();
    }
    assert.equal(first.last.stopReason, 'storage-limit');
    const rig = relaunch(first);
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    assert.equal(rig.collector.status().stopReason, 'storage-limit');
  });

  await test('stopReason: a relaunch after a run that never wrote a stop (a crash) reports none, and invents no reason', async () => {
    const first = new Rig();
    await first.listen();
    first.socket.emit(bytes(50));
    first.drain();
    // No stop, no dispose: the process is gone with the session open.
    assert.ok(!actions(fileEntries(first.volume.journal)).some((a) => a.startsWith('stop')), 'the file holds no stop');
    const rig = relaunch(first);
    assert.deepEqual(await rig.collector.open(ROOT, CFG.storageLimitBytes), { ok: true });
    assert.equal(rig.collector.status().stopReason, null);
    assert.equal(rig.last.stopReason, null);
    assert.ok(actions(fileEntries(rig.volume.journal)).some((a) => a.startsWith('interrupted')), 'the open recorded the interruption');
  });

  await test('stopReason: a journal with no boundary at all (a new one) reports none', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    assert.equal(rig.collector.status().stopReason, null);
  });

  await test('dispose: afterwards Start is refused, the runtime is unavailable and a new port is closed', async () => {
    const rig = new Rig();
    await rig.listen();
    await rig.collector.dispose();
    const r = await rig.collector.start(CFG);
    assert.equal(r.ok, false);
    await assert.rejects(rig.collector.runtime.snapshot(), RuntimeUnavailableError);
    const late = new FakePort();
    rig.collector.attach(late);
    assert.equal(late.closed, true);
    assert.equal((await rig.collector.open(ROOT, CFG.storageLimitBytes)).ok, false);
  });

  await test('dispose: a Start that is still waiting is settled', async () => {
    const rig = new Rig();
    let startResult: unknown = 'pending';
    void rig.collector.start(CFG).then((r) => { startResult = r; });
    await settle();
    const d = await rig.collector.dispose();
    await settle();
    assert.equal(d.ok, true);
    assert.notEqual(startResult, 'pending');
    assert.equal((startResult as { ok: boolean }).ok, false);
    assert.equal(rig.clock.pending, 0);
  });

  await test('dispose: before anything was opened is clean', async () => {
    const rig = new Rig();
    assert.deepEqual(await rig.collector.dispose(), { ok: true, clean: true, snapshot: null });
  });

  // --- open -------------------------------------------------------------------------------------------------------

  await test('open: asking again is ok and opens nothing', async () => {
    const rig = new Rig();
    assert.deepEqual(await rig.collector.open(ROOT, CFG.storageLimitBytes), { ok: true });
    assert.deepEqual(await rig.collector.open(ROOT, 64 * MiB), { ok: true });
    assert.equal(rig.volume.opens, 1);
    assert.equal(rig.last.storage, 'open');
  });

  await test('open: a folder that cannot be opened is a failed result and a stated storage state, and can be retried', async () => {
    const rig = new Rig();
    rig.openError = new Error('EPERM: operation not permitted');
    const r = await rig.collector.open(ROOT, CFG.storageLimitBytes);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.message, /EPERM/);
    assert.equal(rig.last.storage, 'failed');
    assert.match(rig.last.storageError ?? '', /EPERM/);
    await assert.rejects(rig.collector.runtime.snapshot(), RuntimeUnavailableError);
    rig.openError = null;
    assert.deepEqual(await rig.collector.open(ROOT, CFG.storageLimitBytes), { ok: true });
    assert.equal(rig.last.storageError, null);
  });

  await test('open: a damaged journal is reported and left byte for byte as it was', async () => {
    const first = new Rig();
    await first.listen();
    for (let i = 0; i < 5; i++) first.socket.emit(bytes(100, i));
    first.drain();
    await first.collector.stop('user');
    await first.collector.dispose();
    const file = first.volume.journal.snapshot();
    // Interior damage: a byte inside the first entry, with valid entries after it.
    file[FILE_HEADER_BYTES + 20] ^= 0xff;
    const rig = new Rig();
    const v: TestVolume = { journal: new TestFile(), rollups: new MemoryBlockFile(), opens: 0, closes: 0 };
    v.journal.write(0, file);
    rig.volumes.set(ROOT, v);
    const opened = await rig.collector.open(ROOT, CFG.storageLimitBytes);
    const attach = new FakePort();
    rig.collector.attach(attach);
    const started = await rig.collector.start(CFG);
    assert.equal(started.ok, false, JSON.stringify([opened, started]));
    assert.equal(rig.last.storage, 'refused-corrupt');
    assert.ok((rig.last.storageError ?? '').length > 0);
    assert.equal(rig.sockets.length, 0, 'nothing was bound for a dataset that cannot be written');
    assert.deepEqual(Array.from(v.journal.snapshot()), Array.from(file), 'the file is untouched');
  });

  // --- the runtime ------------------------------------------------------------------------------------------------

  await test('runtime: before the dataset is open every call is RuntimeUnavailable', async () => {
    const rig = new Rig();
    await assert.rejects(rig.collector.runtime.snapshot(), RuntimeUnavailableError);
    await assert.rejects(rig.collector.runtime.watermark(), RuntimeUnavailableError);
    await assert.rejects(rig.collector.runtime.rollupStatus(), RuntimeUnavailableError);
  });

  await test('runtime: readPage is clamped to the page constants, so a limit that cannot be a number is a full page and not an error', async () => {
    const rig = new Rig();
    await rig.listen();
    for (let i = 0; i < 400; i++) rig.socket.emit(bytes(3000, i & 0xff));
    rig.drain();
    const snapshot = await rig.collector.runtime.snapshot();
    const page = await rig.collector.runtime.readPage(snapshot, 0, Infinity, Infinity);
    assert.equal(page.entries.length, LIMITS.pageEntries);
    const big = await rig.collector.runtime.readPage(snapshot, 0, 1_000_000, 100 * MiB);
    assert.ok(big.entries.length <= LIMITS.pageEntries);
    const bytesOf = big.entries.reduce((n, e) => n + (isDatagram(e) ? e.bytes.length : 0), 0);
    assert.ok(bytesOf <= LIMITS.pageBytes, `${bytesOf} bytes`);
    // What is not a number at all is still the journal's RangeError.
    await assert.rejects(rig.collector.runtime.readPage(snapshot, 0, Number.NaN, 10), RangeError);
    await assert.rejects(rig.collector.runtime.readPage(snapshot, 0, 10, -5), RangeError);
  });

  await test('runtime: readBoundaries is clamped to a page of entries, so an absurd count is a page and the rest is still there', async () => {
    const rig = new Rig();
    await rig.listen();
    // Each session is two boundaries; 140 of them are 280 > pageEntries.
    for (let i = 0; i < 140; i++) {
      await rig.collector.stop('user');
      assert.equal((await rig.collector.start(CFG)).ok, true);
    }
    const snapshot = await rig.collector.runtime.snapshot();
    const first = await rig.collector.runtime.readBoundaries(snapshot, 0, 1e9);
    assert.equal(first.entries.length, LIMITS.pageEntries);
    assert.equal(first.done, false);
    const second = await rig.collector.runtime.readBoundaries(snapshot, first.nextAfterId, 1e9);
    assert.ok(second.entries.length > 0 && second.entries.length <= LIMITS.pageEntries);
    assert.equal(second.done, true);
    const inf = await rig.collector.runtime.readBoundaries(snapshot, 0, Infinity);
    assert.equal(inf.entries.length, LIMITS.pageEntries, 'what is not finite is a page too');
    await assert.rejects(rig.collector.runtime.readBoundaries(snapshot, 0, Number.NaN), RangeError);
    await assert.rejects(rig.collector.runtime.readBoundaries(snapshot, 0, 0), RangeError);
  });

  await test('runtime: readMinutes is clamped to the rollup read constant, so no caller\'s number reads more than it', async () => {
    const rig = new Rig();
    await rig.listen();
    const snapshot = await rig.collector.runtime.snapshot();
    const M0 = 1_700_000_000_000 - (1_700_000_000_000 % 60_000);
    const body = new Uint8Array(1_000_000).fill(9);
    // Nine stored minutes of ~1 MB are over rollupReadBytes (8 MiB); seven are under it.
    const minutes = Array.from({ length: 9 }, (_, i) => ({ sourceKey: 'a', minuteMs: M0 + i * 60_000, bytes: body }));
    await rig.collector.runtime.appendMinutes(minutes, {
      generation: snapshot.generation, throughEntryId: snapshot.throughEntryId, policyVersion: DECODER_POLICY_VERSION,
    });
    await assert.rejects(rig.collector.runtime.readMinutes('a', M0, M0 + 9 * 60_000, Infinity), RangeError);
    await assert.rejects(rig.collector.runtime.readMinutes('a', M0, M0 + 9 * 60_000, 1e12), RangeError);
    const under = await rig.collector.runtime.readMinutes('a', M0, M0 + 7 * 60_000, Infinity);
    assert.equal(under.length, 7);
    // NaN compares false against every total, so unrefused it would read all nine.
    await assert.rejects(rig.collector.runtime.readMinutes('a', M0, M0 + 9 * 60_000, Number.NaN), RangeError);
    await assert.rejects(rig.collector.runtime.readMinutes('a', M0, M0 + 9 * 60_000, -1), RangeError);
  });

  // --- appendMinutes from the Worker is bounded (M1) --------------------------------------------------------------

  await test('runtime: appendMinutes refuses a watermark past the journal, a batch past either cap and one past the limit, and writes nothing', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 100; i++) rig.socket.emit(bytes(LIMITS.maxPayloadBytes, round));
      rig.drain();
    }
    const snapshot = await rig.collector.runtime.snapshot();
    const M0 = 1_700_000_000_000 - (1_700_000_000_000 % 60_000);
    const mark = (through: number) => ({ generation: snapshot.generation, throughEntryId: through, policyVersion: DECODER_POLICY_VERSION });
    const minute = (i: number, n: number) => ({ sourceKey: 'a', minuteMs: M0 + i * 60_000, bytes: new Uint8Array(n).fill(3) });
    const runtime = rig.collector.runtime;

    // The journal's end is the most a watermark may claim to have rolled up.
    await assert.rejects(runtime.appendMinutes([minute(0, 100)], mark(snapshot.throughEntryId + 1)), RangeError);
    // Over the minute cap, and over the byte cap in one minute.
    await assert.rejects(
      runtime.appendMinutes(Array.from({ length: MAX_APPEND_MINUTES + 1 }, (_, i) => minute(i, 1)), mark(snapshot.throughEntryId)),
      RangeError,
    );
    await assert.rejects(runtime.appendMinutes([minute(0, MAX_APPEND_BYTES + 1)], mark(snapshot.throughEntryId)), RangeError);
    // Under both caps and still more than the limit leaves: 200 full datagrams are in a 16 MiB journal.
    const room = CFG.storageLimitBytes - LIMITS.closingReserveBytes - snapshot.writtenBytes - FILE_HEADER_BYTES;
    const body = 900_000;
    const count = Math.ceil(room / body) + 1;
    assert.ok(count * body <= MAX_APPEND_BYTES && count <= MAX_APPEND_MINUTES, `the case stays under the caps (room ${room})`);
    await assert.rejects(runtime.appendMinutes(Array.from({ length: count }, (_, i) => minute(i, body)), mark(snapshot.throughEntryId)), RangeError);
    assert.deepEqual(await runtime.readMinutes('a', M0, M0 + count * 60_000, MiB), [], 'a refusal writes nothing');
    assert.equal(await runtime.watermark(), null);

    // A batch the room holds goes in.
    await runtime.appendMinutes([minute(0, 100_000)], mark(snapshot.throughEntryId));
    assert.equal((await runtime.readMinutes('a', M0, M0 + 60_000, MiB)).length, 1);

    // Over the port a refusal is an error reply, not a throw out of the served call.
    port.posted.length = 0;
    port.deliver({ type: 'req', id: 77, method: 'appendMinutes', args: [[minute(1, 100)], mark(snapshot.throughEntryId + 5)] });
    await settle();
    const reply = port.posted.find((m) => m.type === 'res' && m.id === 77);
    assert.equal(reply?.ok, false);
    assert.equal(reply?.error?.name, 'RangeError');
  });

  await test('runtime: it reads the dataset as it is now, across a reopen for a new storage limit', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    await rig.collector.stop('user');
    const served = createRuntimeClient(clientSide(port), { requestMs: 1000, setTimer: rig.clock.setTimer });
    const before = await Promise.race([served.snapshot(), settle().then(() => null)]);
    void before;
    await rig.collector.start({ ...CFG, storageLimitBytes: 32 * MiB });
    const snapshot = await rig.collector.runtime.snapshot();
    assert.ok(snapshot.throughEntryId >= 3);
  });

  // --- the Worker attaches --------------------------------------------------------------------------------------

  await test('attach: a new port replaces and closes the old one, and the status says a Worker is attached', async () => {
    const rig = new Rig();
    const a = await rig.listen();
    assert.equal(rig.last.workerAttached, true);
    const b = new FakePort();
    rig.collector.attach(b);
    assert.equal(a.closed, true);
    assert.equal(b.closed, false);
    a.fireClose();
    assert.equal(rig.last.workerAttached, true, 'the closing of a replaced port is not the Worker leaving');
    b.fireClose();
    assert.equal(rig.last.workerAttached, false);
  });

  // --- the live feed ---------------------------------------------------------------------------------------------

  await test('live: nothing is pushed without a Worker, and the entries stay in the journal', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    const port = new FakePort();
    rig.collector.attach(port);
    await rig.collector.start(CFG);
    port.fireClose();
    port.posted.length = 0;
    rig.socket.emit(bytes(50));
    rig.drain();
    assert.equal(port.posted.length, 0);
    assert.equal((await rig.entries()).filter(isDatagram).length, 1);
  });

  await test('live: a Worker that attaches later starts at the journal end and is pushed only what follows', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    const a = new FakePort();
    rig.collector.attach(a);
    await rig.collector.start(CFG);
    rig.socket.emit(bytes(50, 1));
    rig.socket.emit(bytes(50, 2));
    rig.drain();
    a.fireClose();
    rig.socket.emit(bytes(50, 3));
    rig.drain();
    const end = (await rig.collector.runtime.snapshot()).throughEntryId;
    const b = new FakePort();
    rig.collector.attach(b);
    assert.equal(b.posted.length, 0, 'what was journalled before it attached is its own read to make');
    rig.socket.emit(bytes(50, 4));
    rig.drain();
    assert.deepEqual(b.pushed.map((e) => e.ref.entryId), [end + 1]);
  });

  await test('live: only journalled entries are pushed, in order and complete, with shed and rejected datagrams in none of them', async () => {
    const rig = new Rig();
    const port = new FakePort();
    port.autoAck = true;
    await rig.listen(CFG, port);
    for (let i = 0; i < LIMITS.inboxDatagrams + 10; i++) rig.socket.emit(bytes(40, i & 0xff));
    for (let i = 0; i < 30; i++) rig.socket.emit(bytes(40), '10.5.5.5');
    rig.drain();
    await settle();
    rig.socket.emit(bytes(33, 9));
    rig.drain();
    await settle();
    const journal = await rig.entries();
    const pushed = port.pushed;
    assert.deepEqual(pushed.map((e) => e.ref.entryId), journal.map((e) => e.ref.entryId));
    assert.deepEqual(pushed.map((e) => e.kind), journal.map((e) => e.kind));
    assert.ok(pushed.filter(isDatagram).every((d) => d.remoteIPv4 === CFG.exporterIPv4));
    assert.equal(pushed.filter(isDatagram).length, LIMITS.inboxDatagrams + 1);
  });

  await test('live: never more than the credit unacknowledged, and an ack releases exactly one more push', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    port.ack();
    for (let i = 0; i < 600; i++) rig.socket.emit(bytes(40, i & 0xff));
    rig.drain();
    assert.equal(port.pushes.length, 1 + LIMITS.liveCreditBatches, 'the start boundary, then four batches');
    for (let n = 0; n < 6; n++) {
      port.ack();
      const unacked = port.pushes.length - 1 - (n + 1);
      assert.ok(unacked <= LIMITS.liveCreditBatches, `${unacked} unacknowledged`);
    }
    assert.equal(port.pushes.length, 1 + LIMITS.liveCreditBatches + 6);
    // Fully caught up once every ack is returned.
    for (let n = 0; n < 20; n++) port.ack();
    assert.deepEqual(port.pushed.map((e) => e.ref.entryId), (await rig.entries()).map((e) => e.ref.entryId));
  });

  await test('live: a batch is at most 64 datagrams and about 256 KiB', async () => {
    const rig = new Rig();
    const port = new FakePort();
    port.autoAck = true;
    await rig.listen(CFG, port);
    for (let i = 0; i < 200; i++) rig.socket.emit(bytes(100));
    for (let i = 0; i < 60; i++) rig.socket.emit(bytes(20_000));
    rig.drain();
    await settle();
    assert.ok(port.pushes.length > 0);
    for (const batch of port.pushes) {
      assert.ok(batch.length <= LIMITS.liveBatchDatagrams, `${batch.length} entries`);
      const payload = batch.reduce((n, e) => n + (isDatagram(e) ? e.bytes.length : 0), 0);
      assert.ok(batch.length === 1 || payload <= LIMITS.liveBatchBytes, `${payload} bytes in ${batch.length} entries`);
    }
    assert.ok(port.pushes.some((b) => b.length === LIMITS.liveBatchDatagrams), 'the count limit is reached');
    assert.ok(port.pushes.some((b) => b.length < LIMITS.liveBatchDatagrams && b.length > 1), 'the byte limit cuts a batch short');
    assert.equal(port.pushed.length, (await rig.entries()).length);
  });

  await test('live: the cursor resumes after a re-attach at the journal end, and the old port\'s acks give the new one no credit', async () => {
    const rig = new Rig();
    const a = await rig.listen();
    for (let i = 0; i < 400; i++) rig.socket.emit(bytes(40));
    rig.drain();
    assert.equal(a.pushes.length, LIMITS.liveCreditBatches, 'the old port is out of credit');
    const b = new FakePort();
    rig.collector.attach(b);
    for (let i = 0; i < 5; i++) a.deliver({ type: 'live-ack' });
    for (let i = 0; i < 600; i++) rig.socket.emit(bytes(40));
    rig.drain();
    assert.equal(b.pushes.length, LIMITS.liveCreditBatches, 'a fresh credit, untouched by the old port\'s acks');
    assert.equal(a.pushes.length, LIMITS.liveCreditBatches, 'the old port is never pushed to again');
    const end = (await rig.entries()).length - 600;
    assert.equal(b.pushed[0].ref.entryId, end + 1, 'and starts where the journal was when it attached');
    b.ack(40);
    assert.equal(b.pushed.length, 600);
  });

  await test('live: a push to a port that throws leaves the cursor where it was and is tried again', async () => {
    const rig = new Rig();
    const port = await rig.listen();
    port.ack();
    port.closed = true;
    rig.socket.emit(bytes(40, 1));
    rig.drain();
    assert.ok(rig.logs.some((l) => /live feed/.test(l)));
    port.closed = false;
    rig.socket.emit(bytes(40, 2));
    rig.drain();
    assert.deepEqual(port.pushed.slice(1).map((e) => (e as DatagramEvidence).bytes[0]), [1, 2]);
  });

  // --- runtimeRpc: live-ack and busy -------------------------------------------------------------------------------

  await test('rpc: the client answers a push with live-ack only after its handlers have settled', async () => {
    const { server, client } = portPair();
    const wire = createRuntimeClient(client, { requestMs: 1000, setTimer: () => () => undefined });
    const acks: unknown[] = [];
    server.onMessage((m) => acks.push(m));
    let release!: () => void;
    wire.onLive(() => new Promise<void>((resolve) => { release = resolve; }));
    wire.onLive(() => undefined);
    server.postMessage({ type: 'live', entries: [] });
    await settle();
    assert.deepEqual(acks, [], 'the handler has not finished');
    release();
    await settle();
    assert.deepEqual(acks, [{ type: 'live-ack' }]);
  });

  await test('rpc: a handler that throws or rejects still returns the credit', async () => {
    const { server, client } = portPair();
    const wire = createRuntimeClient(client, { requestMs: 1000, setTimer: () => () => undefined });
    const acks: unknown[] = [];
    server.onMessage((m) => acks.push(m));
    wire.onLive(() => { throw new Error('sync'); });
    wire.onLive(() => Promise.reject(new Error('async')));
    server.postMessage({ type: 'live', entries: [] });
    await settle();
    assert.deepEqual(acks, [{ type: 'live-ack' }]);
  });

  await test('rpc: handlers are still called at once and in order for each push', async () => {
    const { server, client } = portPair();
    const wire = createRuntimeClient(client, { requestMs: 1000, setTimer: () => () => undefined });
    const seen: string[] = [];
    wire.onLive(() => { seen.push('a'); });
    wire.onLive(() => { seen.push('b'); });
    server.postMessage({ type: 'live', entries: [] });
    await settle();
    assert.deepEqual(seen, ['a', 'b'], 'both, in registration order');
  });

  await test('rpc: serveRuntime reports each live-ack once through onLiveAck', async () => {
    const { server, client } = portPair();
    let acks = 0;
    serveRuntime(server, stubRuntime(), { onLiveAck: () => { acks++; } });
    client.postMessage({ type: 'live-ack' });
    client.postMessage({ type: 'live-ack' });
    await settle();
    assert.equal(acks, 2);
  });

  await test('rpc: past maxInFlight the next request is refused at once as busy, and room returns when one is answered', async () => {
    const { server, client } = portPair();
    const gates: (() => void)[] = [];
    const runtime = stubRuntime({
      snapshot: () => new Promise((resolve) => { gates.push(() => resolve({ generation: 'a'.repeat(32), throughEntryId: 0, writtenBytes: 0, syncedThroughEntryId: 0 })); }),
    });
    serveRuntime(server, runtime, { maxInFlight: 2 });
    const wire = createRuntimeClient(client, { requestMs: 1000, setTimer: () => () => undefined });
    const one = wire.snapshot();
    const two = wire.snapshot();
    await settle();
    const three = wire.snapshot();
    await assert.rejects(three, (e: unknown) => e instanceof RuntimeUnavailableError && /busy/.test((e as Error).message));
    assert.equal(gates.length, 2, 'the refused call never reached the runtime');
    gates[0]();
    await one;
    const four = wire.snapshot();
    await settle();
    assert.equal(gates.length, 3, 'a freed slot admits the next call');
    gates[1]();
    gates[2]();
    await two;
    await four;
  });

  await test('rpc: a failed reply (the client port gone) does not become an unhandled rejection', async () => {
    const { server, client } = portPair();
    serveRuntime(server, stubRuntime({ snapshot: async () => ({ generation: 'a'.repeat(32), throughEntryId: 0, writtenBytes: 0, syncedThroughEntryId: 0 }) }));
    const original = server.postMessage;
    server.postMessage = () => { throw new Error('closed'); };
    let unhandled = false;
    const onUnhandled = (): void => { unhandled = true; };
    process.once('unhandledRejection', onUnhandled);
    client.postMessage({ type: 'req', id: 1, method: 'snapshot', args: [] });
    await settle();
    process.off('unhandledRejection', onUnhandled);
    server.postMessage = original;
    assert.equal(unhandled, false);
  });

  // --- the flush timer and status ---------------------------------------------------------------------------------

  await test('flush: the journal is flushed every second while listening, and the timer stops with the session', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(50));
    rig.drain();
    const flushes = rig.volume.journal.flushes;
    assert.ok((await rig.collector.runtime.snapshot()).syncedThroughEntryId < (await rig.collector.runtime.snapshot()).throughEntryId);
    rig.clock.advance(LIMITS.flushMs);
    assert.equal(rig.volume.journal.flushes, flushes + 1);
    const s = await rig.collector.runtime.snapshot();
    assert.equal(s.syncedThroughEntryId, s.throughEntryId);
    await rig.collector.stop('user');
    assert.equal(rig.clock.pending, 0);
  });

  await test('flush: a flush that fails ends the session, closes the socket and fails the listener', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.volume.journal.failFlush = true;
    rig.clock.advance(LIMITS.flushMs);
    assert.equal(rig.socket.closed, true);
    assert.equal(rig.last.listener, 'failed');
    assert.match(rig.last.listenerError ?? '', /could not be written/);
    assert.equal(rig.last.storage, 'failed');
  });

  await test('status: a listener or storage change is posted at once, in the order it happened', async () => {
    const rig = new Rig();
    await rig.collector.open(ROOT, CFG.storageLimitBytes);
    rig.collector.attach(new FakePort());
    rig.nextBinds.push('hang');
    const seen = rig.statuses.length;
    const p = rig.collector.start(CFG);
    await settle();
    rig.socket.release();
    await p;
    assert.deepEqual(rig.statuses.slice(seen).map((s) => s.listener), ['starting', 'listening']);
    await rig.collector.stop('user');
    assert.equal(rig.last.listener, 'stopped');
  });

  await test('status: counter changes are coalesced to one post per interval, carrying the latest numbers', async () => {
    const rig = new Rig();
    await rig.listen();
    const base = rig.statuses.length;
    for (let i = 0; i < 20; i++) {
      rig.socket.emit(bytes(40));
      rig.drain();
      rig.clock.advance(5);
    }
    assert.equal(rig.statuses.length, base, 'nothing inside the interval');
    rig.clock.advance(STATUS_COALESCE_MS);
    assert.equal(rig.statuses.length, base + 1);
    assert.equal(rig.last.received, 20);
    rig.clock.advance(2 * STATUS_COALESCE_MS); // short of the one-second flush tick, which would post a sync
    assert.equal(rig.statuses.length, base + 1, 'and nothing more with nothing new');
    rig.socket.emit(bytes(40));
    rig.drain();
    assert.equal(rig.statuses.length, base + 2, 'an interval that has passed posts at once');
    assert.equal(rig.last.received, 21);
  });

  await test('status: every posted status is one control.ts can read back', async () => {
    const rig = new Rig();
    await rig.listen();
    rig.socket.emit(bytes(40));
    rig.socket.emit(bytes(40), '10.4.4.4');
    rig.drain();
    rig.clock.advance(LIMITS.flushMs);
    await rig.collector.stop('suspend');
    await rig.collector.dispose();
    assert.ok(rig.statuses.length > 5);
    assert.deepEqual(rig.badStatuses, []);
  });

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

// --- rpc helpers ---------------------------------------------------------------------------------------------------

/** Two ends of one in-memory channel; delivery is a microtask later, as a port's is. */
function portPair(): { server: RpcPort & { postMessage(m: unknown): void }; client: RpcPort } {
  let toServer: ((m: unknown) => void) | null = null;
  let toClient: ((m: unknown) => void) | null = null;
  const server: RpcPort = {
    postMessage: (m) => { const h = toClient; if (h !== null) queueMicrotask(() => h(structuredClone(m))); },
    onMessage: (h) => { toServer = h; },
  };
  const client: RpcPort = {
    postMessage: (m) => { const h = toServer; if (h !== null) queueMicrotask(() => h(structuredClone(m))); },
    onMessage: (h) => { toClient = h; },
  };
  return { server, client };
}

/** A port as the Worker's end of a collector's `FakePort`, for the one case that wants a client on it. */
function clientSide(port: FakePort): RpcPort {
  return {
    postMessage: (m) => port.deliver(m),
    onMessage: () => undefined,
  };
}

function stubRuntime(overrides: Partial<Omit<HostRuntime, 'onLive'>> = {}): Omit<HostRuntime, 'onLive'> {
  const nope = async (): Promise<never> => { throw new Error('not stubbed'); };
  return {
    snapshot: nope, readPage: nope, readEvidence: nope, locate: nope, readBoundaries: nope, watermark: nope,
    readMinutes: nope, sources: nope, appendMinutes: nope, rollupStatus: nope, resetRollups: nope,
    ...overrides,
  };
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
