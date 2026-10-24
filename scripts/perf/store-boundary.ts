/**
 * What a frame costs to reach the capture store, and where that cost is.
 *
 *   npx tsx scripts/perf/store-boundary.ts
 *
 * ## The number ADR 0028 has been waiting for
 *
 * `captureClient.ts`'s header reasons from ADR 0007's 5.1 µs same-process
 * `Packet` clone to "~178 ms of main-thread time per second of capture". The
 * store is a `utilityProcess` now, so the hop is serialize + pipe +
 * deserialize and that arithmetic no longer holds. The migration plan named
 * measuring `append` across the boundary as the first step of any decision
 * about where the store lives, and it had not been done.
 *
 * It stopped being theoretical: driving the app with `serveStub.ts --burst`,
 * `ordinalOf` keeps answering -1, so the list never addresses the capture and
 * a whole-capture filter has nothing to scan. The first guess was that the
 * store had fallen behind. **This measurement says it had not** - it takes
 * 31,000 frames a second including the hop, and was being fed a fraction of
 * that - which is the main thing it has been good for so far: ruling out the
 * obvious answer before anyone built on it.
 *
 * ## What is measured, and what each part rules out
 *
 * Four costs, separately, so the answer names one of them:
 *
 *   1. **The writer.** `CaptureWriter` over `NodeBlockFile`, in this process,
 *      no boundary at all. The floor. Measured again with the store's
 *      `StreamDigest.feed` after each batch, as `CaptureHost.onAppend` does it
 *      (ADR 0055), which the ADR expects to cost about a map lookup a row.
 *   2. **The per-frame `writeSync`.** The writer writes each frame's raw bytes
 *      on its own, which is one syscall a frame; compared against the same
 *      bytes in one write per batch. This one is a **trap**, and it is left in
 *      because it is instructive: the standalone comparison says batching
 *      would recover 10-12% of the writer, and batching the writer for real
 *      made it 3% SLOWER. Copying 1,100 bytes a frame into a coalescing
 *      buffer costs more than a `writeSync` to a file the OS has cached. A
 *      microbenchmark of a part is not a measurement of the whole.
 *   3. **The clone.** `v8.serialize` + `v8.deserialize` over a batch, which is
 *      what a `postMessage` across a process boundary does either side of the
 *      pipe. Not `structuredClone`, which the engine can shortcut in-process.
 *   4. **The whole hop.** A real `worker_threads` `MessagePort`, batch in and
 *      acknowledgement out, which adds the transport and the event loop to (3).
 *
 * A `worker_threads` port is not a `MessagePortMain`, and this says so rather
 * than pretending: what it shares is the serializer, the copy and the loop
 * turn, which is where the cost is. What it does not share is Electron's pipe.
 *
 * ## Not an assertion
 *
 * There is no right answer to hold any of these to. `scripts/check.ts` lists
 * it under NOT_TESTS with the others.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { serialize, deserialize } from 'node:v8';
import { deflateRawSync } from 'node:zlib';
import { Worker, isMainThread, parentPort } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { CaptureWriter } from '../../src/services/capture/captureWriter';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { StreamDigest } from '../../src/services/conversation/streamDigest';
import type { Packet } from '../../src/types/packet';

/**
 * A frame shaped like one the buffer actually holds.
 *
 * 24.7 field entries and ~1,100 bytes of frame are the measured averages over
 * both fixtures (`denseFields.ts`, `docs/decisions/0017`). A synthetic packet
 * with an empty bag and eight bytes of payload clones several times faster
 * than a real one and would make every number here flattering.
 */
function frame(id: number): Packet {
  const fields: Record<string, string | number> = {};
  for (let i = 0; i < 22; i++) fields[`proto.field${i}`] = i % 3 === 0 ? `v${id % 97}` : id + i;
  // Three of the 25 are the ones the stream digest reads, so its fold does the
  // work a real TCP row asks of it rather than returning early.
  fields['tcp.flags.ack'] = 1;
  fields['tcp.seq'] = id * 1100;
  fields['tcp.len'] = 1040;
  return {
    id,
    streamId: id & 0x0fff,
    tsUs: 1_788_000_000_000_000 + id * 300,
    timeDelta: 0.0003,
    relativeTime: id / 3000,
    source: '2001:db8::1',
    destination: '2606:4700:4700::1111',
    sourcePort: 49152 + (id & 0x0fff),
    destPort: 443,
    protocol: 'TCP',
    protocolLabel: 'TLSv1.3',
    info: `Application Data, seq=${id}`,
    status: 'ok',
    length: 1100,
    interfaceName: 'Ethernet',
    layers: [],
    rawBytes: new Uint8Array(1100),
    frameProtocols: ['frame', 'eth', 'ipv6', 'tcp', 'tls'],
    analysisFlags: [],
    fields,
  } as unknown as Packet;
}

/**
 * ## The stream digest's snapshot at Stop (ADR 0055, final review I3)
 *
 *   npx tsx scripts/perf/store-boundary.ts --digest-snapshot
 *
 * Not part of the four measurements above: it runs alone, because it builds
 * digests of up to 500,000 streams and wants a big heap. Re-launches itself
 * with `--expose-gc --max-old-space-size=8192` when it has neither.
 *
 * What Stop pays inside its barrier: `snapshot()` plus `encodeDigest` over a
 * digest of N streams. Three shapes, the ones the review named: 100k and 300k
 * streams that opened, exchanged data and closed (8 rows each), and 500k that
 * were a SYN answered by an RST (2 rows each). Per shape: milliseconds,
 * output bytes, and the heap the call left behind without a collection
 * (`heapUsed + arrayBuffers`, a floor under the true peak, which is the
 * number that reached the heap guard). A shape that throws prints the throw.
 *
 * Recorded 2026-10-24, before and after the chunked codec (format 1 -> 2);
 * the table is in the commit message and `docs/history.md`'s I3 entry.
 */
async function measureDigestSnapshot(): Promise<void> {
  if (typeof globalThis.gc !== 'function') {
    const { spawnSync } = await import('node:child_process');
    const child = spawnSync(process.execPath,
      ['--expose-gc', '--max-old-space-size=8192', ...process.execArgv, ...process.argv.slice(1)],
      { stdio: 'inherit' });
    process.exit(child.status ?? 1);
  }
  const { StreamDigest } = await import('../../src/services/conversation/streamDigest');
  const { decodeDigest, encodeDigest } = await import('../../src/services/conversation/digestCodec');
  const { inflateRawSync } = await import('node:zlib');
  // What the store's utilityProcess injects (`electron/store/entry.ts`); the
  // host's own default is fflate, which is 5x slower and not what ships.
  const deflate = (b: Uint8Array): Uint8Array => deflateRawSync(b, { level: 1 });
  const inflate = (b: Uint8Array): Uint8Array => inflateRawSync(b);
  const mb = (n: number) => `${(n / 1048576).toFixed(0)} MB`;
  const used = () => { const m = process.memoryUsage(); return m.heapUsed + m.arrayBuffers; };

  let nextId = 1;
  const tcp = (stream: number, fromClient: boolean, flags: string, seq: number, ack: number, len: number): Packet => {
    const id = nextId++;
    return {
      id, relativeTime: id / 1000, length: 60 + len, protocol: 'TCP', streamId: stream,
      source: fromClient ? `10.${(stream >> 16) & 255}.${(stream >> 8) & 255}.${stream & 255}` : '93.184.216.34',
      destination: fromClient ? '93.184.216.34' : `10.${(stream >> 16) & 255}.${(stream >> 8) & 255}.${stream & 255}`,
      sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
      frameProtocols: ['eth', 'ip', 'tcp'],
      fields: {
        'tcp.flags.syn': flags.includes('S') ? 1 : 0, 'tcp.flags.ack': flags.includes('A') ? 1 : 0,
        'tcp.flags.fin': flags.includes('F') ? 1 : 0, 'tcp.flags.reset': flags.includes('R') ? 1 : 0,
        'tcp.seq': seq, 'tcp.ack': ack, 'tcp.len': len,
      },
    } as unknown as Packet;
  };
  const closed = (d: InstanceType<typeof StreamDigest>, s: number): void => {
    for (const r of [
      tcp(s, true, 'S', 0, 0, 0), tcp(s, false, 'SA', 0, 1, 0), tcp(s, true, 'A', 1, 1, 0),
      tcp(s, true, 'A', 1, 1, 100), tcp(s, false, 'A', 1, 101, 1000),
      tcp(s, true, 'FA', 101, 1001, 0), tcp(s, false, 'FA', 1001, 102, 0), tcp(s, true, 'A', 102, 1002, 0),
    ]) d.feed(r);
  };
  const refused = (d: InstanceType<typeof StreamDigest>, s: number): void => {
    d.feed(tcp(s, true, 'S', 0, 0, 0));
    d.feed(tcp(s, false, 'RA', 0, 1, 0));
  };

  console.log('\nstream digest snapshot at Stop: snapshot() + encodeDigest, native deflate level 1\n');
  console.log('  shape                      streams   encode ms   bytes     heap left   decode+restore ms');
  for (const [name, count, fold] of [
    ['closed', 100_000, closed], ['closed', 300_000, closed], ['SYN + RST', 500_000, refused],
  ] as const) {
    nextId = 1;
    let digest: InstanceType<typeof StreamDigest> | null = new StreamDigest();
    for (let s = 1; s <= count; s++) fold(digest, s);
    globalThis.gc!();
    const base = used();
    const at = process.hrtime.bigint();
    let bytes: Uint8Array | null = null;
    let threw: string | null = null;
    try { bytes = encodeDigest(digest.snapshot(), deflate); } catch (e) { threw = (e as Error).message; }
    const ms = Number(process.hrtime.bigint() - at) / 1e6;
    const left = used() - base;
    const label = `${name}`.padEnd(24);
    if (bytes === null) {
      console.log(`  ${label} ${String(count).padStart(8)}   THREW: ${threw} (after ${ms.toFixed(0)} ms, heap ${mb(left)})`);
    } else {
      digest = null;
      globalThis.gc!();
      const back = process.hrtime.bigint();
      const decoded = decodeDigest(bytes, inflate);
      const decodedMs = Number(process.hrtime.bigint() - back) / 1e6;
      const restored = decoded === null ? null : StreamDigest.restore(decoded);
      const backMs = Number(process.hrtime.bigint() - back) / 1e6;
      console.log(`  ${label} ${String(count).padStart(8)}   ${ms.toFixed(0).padStart(9)}   ${mb(bytes.length).padStart(7)}   ${mb(left).padStart(9)}   ${backMs.toFixed(0)} (decode ${decodedMs.toFixed(0)})${restored?.size === count ? '' : '  (RESTORE FAILED)'}`);
    }
    digest = null;
    globalThis.gc!();
  }
}

const TOTAL = 100_000;
/** What one flush hands over: ten a second at the rates that hurt. */
const BATCH = 300;

function batches(): Packet[][] {
  const out: Packet[][] = [];
  for (let i = 0; i < TOTAL; i += BATCH) {
    const b: Packet[] = [];
    for (let j = 0; j < BATCH && i + j < TOTAL; j++) b.push(frame(i + j + 1));
    out.push(b);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The worker half of measurement 4. Same file, so there is one thing to read
// and `tsx` resolves it the same way it resolved the entry point.
// ---------------------------------------------------------------------------
if (!isMainThread) {
  parentPort!.on('message', (message: { done?: boolean; packets?: Packet[] }) => {
    if (message.done) { parentPort!.postMessage({ ack: true }); return; }
    // Touched, so the deserialisation is not optimised away and the cost of
    // walking the deserialised objects is included - which the store pays too.
    let n = 0;
    for (const p of message.packets!) n += p.rawBytes!.length + p.id;
    parentPort!.postMessage({ ack: true, n });
  });
} else if (process.argv.includes('--digest-snapshot')) {
  await measureDigestSnapshot();
  process.exit(0);
} else {
  const dir = mkdtempSync(path.join(tmpdir(), 'inwire-boundary-'));
  const per = (ms: number) => `${(ms * 1000 / TOTAL).toFixed(2)} us a frame`;
  const rate = (ms: number) => `${Math.round(TOTAL / (ms / 1000)).toLocaleString()} frames/s`;
  const time = async (label: string, run: () => void | Promise<void>) => {
    const at = process.hrtime.bigint();
    await run();
    const ms = Number(process.hrtime.bigint() - at) / 1e6;
    console.log(`  ${label.padEnd(46)} ${ms.toFixed(0).padStart(6)} ms   ${per(ms).padStart(18)}   ${rate(ms)}`);
    return ms;
  };

  console.log(`--- ${TOTAL.toLocaleString()} frames, ${BATCH} to a batch ---\n`);

  const work = batches();

  console.log('1. the writer, with no boundary at all\n');
  const files = {
    index: NodeBlockFile.open(path.join(dir, 'index.iwidx')),
    pfx: NodeBlockFile.open(path.join(dir, 'prefix.iwpfx')),
    sum: NodeBlockFile.open(path.join(dir, 'summary.iwsum')),
    byt: NodeBlockFile.open(path.join(dir, 'frames.iwbyt')),
    rec: NodeBlockFile.open(path.join(dir, 'records.iwrec')),
  };
  // What the store passes (`electron/store/entry.ts`): node's zlib at level
  // 1. The writer's own default is `fflate` at 6, which is measured beside it
  // because it is what the store used until a 36,000 frame-a-second burst
  // outran it - 57% of the writer was that deflate.
  const nativeDeflate = (b: Uint8Array) => new Uint8Array(deflateRawSync(b, { level: 1 }));
  const writer = new CaptureWriter(files, { deflate: nativeDeflate });
  const writerMs = await time('CaptureWriter.append + finish', () => {
    for (const b of work) writer.append(b);
    writer.finish();
  });
  for (const f of Object.values(files)) f.close();
  const digestFiles = {
    index: NodeBlockFile.open(path.join(dir, 'd-index.iwidx')),
    pfx: NodeBlockFile.open(path.join(dir, 'd-prefix.iwpfx')),
    sum: NodeBlockFile.open(path.join(dir, 'd-summary.iwsum')),
    byt: NodeBlockFile.open(path.join(dir, 'd-frames.iwbyt')),
    rec: NodeBlockFile.open(path.join(dir, 'd-records.iwrec')),
  };
  const digestWriter = new CaptureWriter(digestFiles, { deflate: nativeDeflate });
  const digest = new StreamDigest();
  const digestMs = await time('the same, plus StreamDigest.feed a frame', () => {
    for (const b of work) {
      digestWriter.append(b);
      for (const p of b) digest.feed(p);
    }
    digestWriter.finish();
  });
  for (const f of Object.values(digestFiles)) f.close();
  // The fold on its own as well: the two rows above differ by less than the
  // JIT warm-up the first one pays for the second, so their difference alone
  // read as a negative cost once the fold was cheap.
  const foldMs = await time('StreamDigest.feed alone, the same frames', () => {
    const alone = new StreamDigest();
    for (const b of work) for (const p of b) alone.feed(p);
  });
  console.log(`     -> the fold is ${(foldMs * 1000 / TOTAL).toFixed(2)} us a frame over `
    + `${digest.size.toLocaleString()} streams; the rows above differ by `
    + `${((digestMs - writerMs) * 1000 / TOTAL).toFixed(2)}`);
  const fflateFiles = {
    index: NodeBlockFile.open(path.join(dir, 'f-index.iwidx')),
    pfx: NodeBlockFile.open(path.join(dir, 'f-prefix.iwpfx')),
    sum: NodeBlockFile.open(path.join(dir, 'f-summary.iwsum')),
    byt: NodeBlockFile.open(path.join(dir, 'f-frames.iwbyt')),
    rec: NodeBlockFile.open(path.join(dir, 'f-records.iwrec')),
  };
  const fflateWriter = new CaptureWriter(fflateFiles);
  await time('the same, with fflate at level 6 (the old)', () => {
    for (const b of work) fflateWriter.append(b);
    fflateWriter.finish();
  });
  for (const f of Object.values(fflateFiles)) f.close();

  console.log('\n2. the per-frame write, which the writer does one syscall at a time\n');
  const one = NodeBlockFile.open(path.join(dir, 'one.bin'));
  const bytes = new Uint8Array(1100);
  const singleMs = await time('one writeSync a frame', () => {
    for (let i = 0; i < TOTAL; i++) one.write(i * 1100, bytes);
  });
  const packed = new Uint8Array(1100 * BATCH);
  const batchedFile = NodeBlockFile.open(path.join(dir, 'batched.bin'));
  const batchedMs = await time('the same bytes, one write a batch', () => {
    for (let i = 0; i < TOTAL / BATCH; i++) batchedFile.write(i * packed.length, packed);
  });
  one.close();
  batchedFile.close();
  console.log(`     -> the gap is ${(singleMs - batchedMs).toFixed(0)} ms, `
    + `${((singleMs - batchedMs) / writerMs * 100).toFixed(0)}% of the writer - and it is NOT`);
  console.log('        recoverable: batching the writer for real was measured 3% slower,');
  console.log('        because the copy into the coalescing buffer costs more than the');
  console.log('        syscall it saves. Left here as the trap it is.');

  console.log('\n3. the clone, which is what crossing a process boundary costs\n');
  await time('v8.serialize', () => {
    for (const b of work) serialize(b);
  });
  const wire = work.map((b) => serialize(b));
  await time('v8.deserialize', () => {
    for (const b of wire) deserialize(b);
  });
  await time('serialize + deserialize', () => {
    for (const b of work) deserialize(serialize(b));
  });
  const bytesOnWire = wire.reduce((n, b) => n + b.length, 0);
  console.log(`     -> ${(bytesOnWire / TOTAL).toFixed(0)} B a frame on the wire, `
    + `${(bytesOnWire / 1024 / 1024).toFixed(0)} MB for this run`);

  console.log('\n4. the whole hop, over a real MessagePort\n');
  const worker = new Worker(fileURLToPath(import.meta.url));
  await new Promise<void>((ready) => worker.once('online', ready));
  const hopMs = await time('postMessage a batch, wait for the ack', async () => {
    for (const b of work) {
      worker.postMessage({ packets: b });
      await new Promise<void>((acked) => worker.once('message', () => acked()));
    }
  });
  await worker.terminate();

  console.log('\n--- what this says ---\n');
  const total = hopMs + writerMs;
  console.log(`  A frame costs ${(total * 1000 / TOTAL).toFixed(2)} us to reach the store and be written:`);
  console.log(`    ${(hopMs * 1000 / TOTAL).toFixed(2)} us crossing, ${(writerMs * 1000 / TOTAL).toFixed(2)} us writing`);
  console.log(`  Sustained, that is ${Math.round(TOTAL / (total / 1000)).toLocaleString()} frames/s `
    + `against ${rate(writerMs)} for the writer alone.`);
  console.log(`  The crossing is ${(hopMs / total * 100).toFixed(0)}% of it.`);
  console.log('\n  A `postMessage` per batch is serialised here - the sender waits for the');
  console.log('  ack before posting the next. The app does not wait, which is why an');
  console.log('  overloaded store grows a queue rather than applying backpressure.');

  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  process.exit(0);
}
