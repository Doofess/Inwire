/**
 * What do frame records cost as one `Uint8Array` per frame, on the two hops
 * they travel live, against one slab per batch?
 *
 *   npx --node-options=--expose-gc tsx scripts/perf/record-transport.ts --pcap some.pcapng [--frames 100000] [--batches 256,2048] [--runs 5]
 *
 * The records are real: each frame of the capture goes through the dissector,
 * whose `FrameRecorder` writes the record (ADR 0049).
 *
 *  - **Hop 1, shard -> coordinator**: today every record is its own ArrayBuffer
 *    in the transfer list (`collect` / `whole` in `shard.ts`). Against: one
 *    slab (bytes + ids + ends) transferred, built by concatenation.
 *  - **Hop 2, coordinator -> store**: today `{ type: 'appendRecords', frames:
 *    { id, record }[] }`, copied (the store is a `MessagePortMain` in a utility
 *    process, which drops a message with a transfer list; `postFlushed` in
 *    `pipeline.worker.ts`). Against: a slab of the same records, copied, as
 *    `frameSlab.ts` does for frame bytes.
 *
 * Every figure is nanoseconds a record, the median of `--runs` passes over the
 * whole batch list after one warm-up pass. "send" is the `postMessage` call
 * (serialize or transfer), "recv" the time from the call returning to the
 * handler having run (deserialize, plus cutting views for a slab), minus the
 * same measure for an empty message (the event loop's wake-up). "build" is the
 * slab's concatenation.
 *
 * The channel is a node:worker_threads `MessageChannel` inside ONE thread, so
 * the sender's and receiver's work are timed on the same clock but never run
 * in parallel, and the structured clone is V8's, not Electron's
 * MessagePortMain wire (which also serializes with V8, then crosses a pipe).
 * `derived` buffers are carried by "today" where a frame has one and omitted
 * from the slab; the count is printed.
 *
 * A measurement with no right answer, so not a test (`check.ts` NOT_TESTS).
 */
import { readFileSync } from 'node:fs';
import { MessageChannel, type MessagePort } from 'node:worker_threads';
import { deserialize, serialize } from 'node:v8';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';

function arg(name: string): string | undefined {
  const at = process.argv.indexOf(name);
  return at > 0 ? process.argv[at + 1] : undefined;
}

const pcap = arg('--pcap');
if (!pcap) {
  console.log('usage: npx --node-options=--expose-gc tsx scripts/perf/record-transport.ts --pcap some.pcapng [--frames 100000] [--batches 256,2048] [--runs 5]');
  process.exit(2);
}
const maxFrames = Number(arg('--frames') ?? 100_000);
const BATCHES = (arg('--batches') ?? '256,2048').split(',').map(Number);
const RUNS = Number(arg('--runs') ?? 5);
const FPS = 60_000;

interface Rec { id: number; record: Uint8Array; derived: Uint8Array | null }

async function dissect(): Promise<{ recs: Rec[]; failed: number }> {
  const file = new File([new Uint8Array(readFileSync(pcap!))], 'capture.pcapng');
  const { frames } = await PcapService.extractFrames(file, maxFrames);
  const clock = new FrameClock();
  const sequencer = new Sequencer();
  const dissector = new FrameDissector({
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  }, undefined, null);
  const recs: Rec[] = [];
  let failed = 0;
  frames.forEach((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    try {
      const out = dissector.dissect({
        id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
        origLen: frame.origLen, linktype: frame.linktype,
        facts: { nanosRemainder: frame.tsPrecision > 6 ? Number(frame.tsNanos % 1000n) : undefined },
      });
      // Own buffers, as a record is once it has crossed a hop.
      recs.push({ id: i + 1, record: out.record.slice(), derived: out.derived ? out.derived.slice() : null });
    } catch { failed++; }
  });
  return { recs, failed };
}

const now = () => Number(process.hrtime.bigint());
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const pct = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];

interface Slab { ids: Float64Array; ends: Uint32Array; bytes: Uint8Array }

function build(batch: Rec[]): Slab {
  const n = batch.length;
  let total = 0;
  for (let i = 0; i < n; i++) total += batch[i].record.length;
  const ids = new Float64Array(n);
  const ends = new Uint32Array(n);
  const bytes = new Uint8Array(total);
  let at = 0;
  for (let i = 0; i < n; i++) {
    ids[i] = batch[i].id;
    bytes.set(batch[i].record, at);
    at += batch[i].record.length;
    ends[i] = at;
  }
  return { ids, ends, bytes };
}

/** The records back as views, as a receiver that wants one per frame would. */
function cut(slab: Slab): number {
  let from = 0;
  let sum = 0;
  for (let i = 0; i < slab.ids.length; i++) {
    sum += slab.bytes.subarray(from, slab.ends[i]).length + slab.ids[i];
    from = slab.ends[i];
  }
  return sum;
}

let sink = 0;

/** One message across a real MessageChannel: ns in the post call, ns until the handler is done. */
function roundTrip(
  from: MessagePort, to: MessagePort, message: unknown, transfer: ArrayBuffer[],
  onReceive: (m: any) => void, // eslint-disable-line @typescript-eslint/no-explicit-any
): Promise<{ send: number; recv: number }> {
  return new Promise((resolve) => {
    let postEnd = 0;
    let send = 0;
    to.once('message', (m: unknown) => {
      const entered = now();
      onReceive(m);
      resolve({ send, recv: entered - postEnd + (now() - entered) });
    });
    const t0 = now();
    from.postMessage(message, transfer as never);
    postEnd = now();
    send = postEnd - t0;
  });
}

interface Cost { send: number; recv: number; build: number }

async function pass(
  batches: Rec[][], one: (batch: Rec[]) => Promise<Cost>,
): Promise<Cost> {
  const total = { send: 0, recv: 0, build: 0 };
  let n = 0;
  for (const batch of batches) {
    const c = await one(batch);
    total.send += c.send; total.recv += c.recv; total.build += c.build;
    n += batch.length;
  }
  return { send: total.send / n, recv: total.recv / n, build: total.build / n };
}

async function measure(batches: Rec[][], one: (batch: Rec[]) => Promise<Cost>): Promise<Cost> {
  await pass(batches, one);
  const runs: Cost[] = [];
  for (let i = 0; i < RUNS; i++) {
    (globalThis as { gc?: () => void }).gc?.();
    runs.push(await pass(batches, one));
  }
  return {
    send: median(runs.map((r) => r.send)), recv: median(runs.map((r) => r.recv)), build: median(runs.map((r) => r.build)),
  };
}

function fresh(batch: Rec[]): Rec[] {
  return batch.map((r) => ({ id: r.id, record: r.record.slice(), derived: r.derived ? r.derived.slice() : null }));
}

async function main(): Promise<void> {
  const { recs, failed } = await dissect();
  const sizes = recs.map((r) => r.record.length).sort((a, b) => a - b);
  const total = sizes.reduce((a, b) => a + b, 0);
  const derived = recs.filter((r) => r.derived !== null && r.derived.length > 0);
  console.log(`node ${process.version}, ${process.platform} ${process.arch}, gc ${(globalThis as { gc?: unknown }).gc ? 'exposed' : 'not exposed'}`);
  console.log(`${recs.length.toLocaleString()} frames read from ${pcap} (${failed} failed to dissect)`);
  console.log(`record bytes: mean ${(total / recs.length).toFixed(1)}, p50 ${pct(sizes, 0.5)}, p99 ${pct(sizes, 0.99)}, max ${sizes[sizes.length - 1]}, total ${(total / 1e6).toFixed(1)} MB`);
  console.log(`no record: ${sizes.filter((s) => s === 0).length}, with derived: ${derived.length}`
    + ` (derived mean ${derived.length ? (derived.reduce((a, r) => a + r.derived!.length, 0) / derived.length).toFixed(0) : 0} B)`);
  console.log(`${RUNS} runs after one warm-up, median; ns a record; channel is one thread's MessageChannel\n`);

  const { port1, port2 } = new MessageChannel();
  // The empty-message baseline: the event loop's wake-up, subtracted from every recv.
  const wakes: number[] = [];
  for (let i = 0; i < 400; i++) wakes.push((await roundTrip(port1, port2, { type: 'x' }, [], () => { /* nothing */ })).recv);
  const wake = median(wakes.slice(100));
  console.log(`empty-message wake-up ${wake} ns a message (subtracted per message)\n`);
  const sub = (c: Cost, batch: number): Cost => ({ ...c, recv: Math.max(0, c.recv - wake / batch) });

  const projection: string[] = [];
  for (const size of BATCHES) {
    const batches: Rec[][] = [];
    for (let i = 0; i < recs.length; i += size) batches.push(recs.slice(i, i + size));
    const mean = recs.length / batches.length;

    // Hop 1 today: per-frame buffers, all in the transfer list. Fresh copies each
    // time (a transfer detaches), made outside the clock.
    const hop1Today = await measure(batches, async (batch) => {
      const frames = fresh(batch);
      const transfer: ArrayBuffer[] = [];
      for (const f of frames) {
        if (f.record.byteLength > 0) transfer.push(f.record.buffer as ArrayBuffer);
        if (f.derived && f.derived.byteLength > 0) transfer.push(f.derived.buffer as ArrayBuffer);
      }
      const r = await roundTrip(port1, port2, { type: 'results', frames }, transfer, (m: { frames: Rec[] }) => { sink += m.frames.length; });
      return { send: r.send, recv: r.recv, build: 0 };
    });
    // Hop 1 slab: built from the per-frame records, one buffer per column transferred.
    const hop1Slab = await measure(batches, async (batch) => {
      const t0 = now();
      const slab = build(batch);
      const buildNs = now() - t0;
      const r = await roundTrip(port1, port2, { type: 'results', ...slab },
        [slab.bytes.buffer as ArrayBuffer, slab.ids.buffer as ArrayBuffer, slab.ends.buffer as ArrayBuffer],
        (m: Slab) => { sink += cut(m); });
      return { send: r.send, recv: r.recv, build: buildNs };
    });
    // Hop 2 today: the {id, record}[] array, copied.
    const hop2Today = await measure(batches, async (batch) => {
      const frames = batch.map((r) => ({ id: r.id, record: r.record }));
      const r = await roundTrip(port1, port2, { type: 'appendRecords', frames }, [], (m: { frames: unknown[] }) => { sink += m.frames.length; });
      return { send: r.send, recv: r.recv, build: 0 };
    });
    // Hop 2 slab: built, then copied (no transfer list).
    const hop2Slab = await measure(batches, async (batch) => {
      const t0 = now();
      const slab = build(batch);
      const buildNs = now() - t0;
      const r = await roundTrip(port1, port2, { type: 'appendRecords', ...slab }, [], (m: Slab) => { sink += cut(m); });
      return { send: r.send, recv: r.recv, build: buildNs };
    });
    // v8 alone, as row-codec does: no channel, no event loop.
    const v8Today = await measure(batches, async (batch) => {
      const frames = batch.map((r) => ({ id: r.id, record: r.record }));
      const t0 = now();
      const buf = serialize({ type: 'appendRecords', frames });
      const t1 = now();
      sink += (deserialize(buf) as { frames: unknown[] }).frames.length;
      return { send: t1 - t0, recv: now() - t1, build: 0 };
    });
    const v8Slab = await measure(batches, async (batch) => {
      const t0 = now();
      const slab = build(batch);
      const t1 = now();
      const buf = serialize({ type: 'appendRecords', ...slab });
      const t2 = now();
      sink += cut(deserialize(buf) as Slab);
      return { send: t2 - t1, recv: now() - t2, build: t1 - t0 };
    });

    const h1t = sub(hop1Today, mean);
    const h1s = sub(hop1Slab, mean);
    const h2t = sub(hop2Today, mean);
    const h2s = sub(hop2Slab, mean);
    const row = (label: string, c: Cost) =>
      `  ${label.padEnd(30)} ${c.build.toFixed(0).padStart(7)} ${c.send.toFixed(0).padStart(7)} ${c.recv.toFixed(0).padStart(7)} ${(c.build + c.send + c.recv).toFixed(0).padStart(8)}`;
    const sample = batches[0];
    const todayBytes = serialize({ type: 'appendRecords', frames: sample.map((r) => ({ id: r.id, record: r.record })) }).byteLength / sample.length;
    const slabBytes = serialize({ type: 'appendRecords', ...build(sample) }).byteLength / sample.length;
    console.log(`batch of ${size} frames (${batches.length} messages)`);
    console.log(`  ${'ns a record'.padEnd(30)} ${'build'.padStart(7)} ${'send'.padStart(7)} ${'recv'.padStart(7)} ${'total'.padStart(8)}`);
    console.log(row('hop 1 today (transfer N bufs)', h1t));
    console.log(row('hop 1 slab (transfer 3 bufs)', h1s));
    console.log(row('hop 2 today (copy {id,rec}[])', h2t));
    console.log(row('hop 2 slab (copy 3 columns)', h2s));
    console.log(row('v8 serialize/deser, array', v8Today));
    console.log(row('v8 serialize/deser, slab', v8Slab));
    console.log(`  v8 wire bytes a record: today ${todayBytes.toFixed(1)}, slab ${slabBytes.toFixed(1)}\n`);

    const ms = (ns: number) => ((ns * FPS) / 1e6).toFixed(1);
    projection.push(`batch ${size}:`
      + `\n    coordinator today = hop 1 recv ${ms(h1t.recv)} + hop 2 send ${ms(h2t.send)} = ${ms(h1t.recv + h2t.send)} ms per second`
      + `\n    coordinator slab  = hop 1 recv ${ms(h1s.recv)} + hop 2 build ${ms(h2s.build)} + hop 2 send ${ms(h2s.send)} = ${ms(h1s.recv + h2s.build + h2s.send)} ms per second`
      + `\n    store receive hop 2: today ${ms(h2t.recv)} ms, slab ${ms(h2s.recv)} ms per second`
      + `\n    shard send hop 1 (per second of all shards): today ${ms(h1t.send)} ms, slab ${ms(h1s.build + h1s.send)} ms (build ${ms(h1s.build)})`);
  }
  console.log(`projection at ${FPS.toLocaleString()} frames a second (ms of one thread's time per second)`);
  for (const p of projection) console.log(`  ${p}`);
  port1.close();
  port2.close();
  if (sink === -1) console.log(sink);
}

void main();
