/**
 * Catching the live view up from the agent's pcapng (ADR 0053 phase 4).
 *
 *   npx tsx scripts/pipeline/catch-up.ts
 *
 * A capture is played twice: once straight through, and once as the live
 * stream would arrive with holes in it - main shedding batches, the agent's
 * queue shedding them, a hole across a ring file's edge, a file deleted under
 * the catch-up, a stream that never comes back, a disk that refused frames -
 * with the agent's files growing a flush behind the stream and read back in
 * chunks of every size. `CatchUpRouter` is the Worker's own front door, so
 * what it delivers is what the Worker dissects. Every case holds the
 * delivered frames to the straight run, frame for frame: same numbers, same
 * bytes, same times, none twice, none missing except what no copy of exists.
 * Every live frame is either dissected or given back to main exactly once.
 *
 * With the fixtures present, the frames caught up are also dissected and
 * hashed against the straight run (`frameDigest.ts`), so "the same frames"
 * is shown to mean "the same trees, rows and records" too. Without them the
 * frame-level cases still run, on frames made here.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  CatchUp, CatchUpRouter, CaptureFiles, HOLD_MAX_FRAMES, REJOIN_WITHIN, type FileFrame, type SeqFrame,
} from '../../src/services/pipeline/catchUp';
import { PcapngTail } from '../../src/services/pipeline/pcapngTail';
import { HOLE_MIN_FRAMES, LiveFlow } from '../../src/services/pipeline/liveFlow';
import { PcapService } from '../../src/services/pcapParser';
import { FIXTURES } from './arrival';
import { digestCapture } from './frameDigest';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

// --- frames and files ------------------------------------------------------------

interface Frame extends SeqFrame { live?: boolean }

/** The agent's layout: SHB, one IDB with a name and nanosecond stamps, EPBs. */
function fileHeader(): Uint8Array {
  const name = new TextEncoder().encode('\\Device\\NPF_{TEST}');
  const namePad = (4 - (name.length % 4)) % 4;
  const idbOptions = 4 + name.length + namePad + 4 + 4 + 4;
  const idbLength = 16 + idbOptions + 4;
  const out = new Uint8Array(28 + idbLength);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0x0a0d0d0a, true); v.setUint32(4, 28, true); v.setUint32(8, 0x1a2b3c4d, true);
  v.setUint16(12, 1, true); v.setUint16(14, 0, true);
  v.setBigInt64(16, -1n, true); v.setUint32(24, 28, true);
  let at = 28;
  v.setUint32(at, 1, true); v.setUint32(at + 4, idbLength, true);
  v.setUint16(at + 8, 1, true); v.setUint32(at + 12, 0, true);
  let o = at + 16;
  v.setUint16(o, 2, true); v.setUint16(o + 2, name.length, true); out.set(name, o + 4); o += 4 + name.length + namePad;
  v.setUint16(o, 9, true); v.setUint16(o + 2, 1, true); v.setUint8(o + 4, 9); o += 8;
  v.setUint16(o, 0, true); v.setUint16(o + 2, 0, true); o += 4;
  v.setUint32(o, idbLength, true);
  return out;
}

function epb(frame: SeqFrame): Uint8Array {
  const pad = (4 - (frame.bytes.length % 4)) % 4;
  const length = 32 + frame.bytes.length + pad;
  const out = new Uint8Array(length);
  const v = new DataView(out.buffer);
  const ns = BigInt(frame.tsUs) * 1000n + BigInt(frame.tsNsRem);
  v.setUint32(0, 6, true); v.setUint32(4, length, true);
  v.setUint32(8, 0, true);
  v.setUint32(12, Number(ns >> 32n), true); v.setUint32(16, Number(ns & 0xffffffffn), true);
  v.setUint32(20, frame.bytes.length, true); v.setUint32(24, frame.origLen, true);
  out.set(frame.bytes, 28);
  v.setUint32(length - 4, length, true);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0x1_0000_0000; };
}

/** Frames made here: varied lengths and bytes, a nanosecond clock. */
function madeFrames(n: number): Frame[] {
  const random = rng(7);
  const out: Frame[] = [];
  let ns = 1_790_000_000_000_000_000n;
  for (let seq = 0; seq < n; seq++) {
    const bytes = new Uint8Array(60 + Math.floor(random() * 1400));
    for (let i = 0; i < bytes.length; i++) bytes[i] = (seq * 31 + i * 7) & 0xff;
    ns += BigInt(1 + Math.floor(random() * 20_000));
    out.push({ seq, tsUs: Number(ns / 1000n), tsNsRem: Number(ns % 1000n), origLen: bytes.length + (seq % 5 === 0 ? 100 : 0), bytes });
  }
  return out;
}

// --- one run -------------------------------------------------------------------

interface Plan {
  /** Frames per ring file; Infinity is one file. */
  perFile?: number;
  /** Batches main sheds (a `shed` message in their place). */
  mainShed?: Set<number>;
  /** Batches the agent's queue sheds (they simply never arrive). */
  agentShed?: Set<number>;
  /** Frames the agent's writer refused: numbered and sent, not in the file. */
  writerDrops?: Set<number>;
  /** After this many batches, a file is deleted before it is read (index). */
  deleteFile?: { index: number; atBatch: number };
  /** Reads main answers per batch time; few makes the file slower than live. */
  readsPerStep?: number;
  /** How many frames the file trails the stream by - its flush. */
  lag?: number;
  batch?: number;
  seed?: number;
  /** Live frames arrive a few places out of order, as two adapters' do. */
  skew?: boolean;
  /** Batches the Worker's port runs behind the agent by. */
  portDelay?: number;
  /** The capture stops as the stream ends, with the catch-up still reading. */
  stopAtEnd?: boolean;
}

interface Run {
  delivered: Frame[];
  holes: { at: number; size: number }[];
  released: number;
  liveArrived: number;
  liveDelivered: number;
  catchUp: CatchUp<Frame>;
  ended: string[];
  /** What the live flow counts as skipped when the run ends. */
  skipped: number;
  /** Still catching up when the run ended - before the capture stopped it. */
  activeAtEnd: boolean;
}

function run(frames: Frame[], plan: Plan): Run {
  const perFile = plan.perFile ?? Number.POSITIVE_INFINITY;
  const batch = plan.batch ?? 300;
  const lag = plan.lag ?? 2000;
  const random = rng(plan.seed ?? 11);
  const fileIndexOf = (seq: number) => (Number.isFinite(perFile) ? Math.floor(seq / perFile) + 1 : 1);
  const nameOf = (index: number) => (Number.isFinite(perFile) ? `capture_${String(index).padStart(5, '0')}_20261009120000.pcapng` : 'capture.pcapng');
  // Each file's bytes as the agent writes them, and where each frame ends in it.
  const files = new Map<string, {
    bytes: Uint8Array; endOf: Map<number, number>; firstSeq: number; lastSeq: number; closed: boolean; deleted: boolean;
  }>();
  {
    const groups = new Map<number, Frame[]>();
    for (const f of frames) {
      const index = fileIndexOf(f.seq);
      if (!groups.has(index)) groups.set(index, []);
      groups.get(index)!.push(f);
    }
    for (const [index, group] of groups) {
      const parts = [fileHeader()];
      const endOf = new Map<number, number>();
      let at = parts[0].length;
      for (const f of group) {
        if (plan.writerDrops?.has(f.seq)) { endOf.set(f.seq, at); continue; }
        const block = epb(f);
        parts.push(block);
        at += block.length;
        endOf.set(f.seq, at);
      }
      files.set(nameOf(index), {
        bytes: concat(parts), endOf, firstSeq: group[0].seq, lastSeq: group[group.length - 1].seq, closed: false, deleted: false,
      });
    }
  }

  const known = new CaptureFiles();
  const flow = new LiveFlow();
  const catchUp = new CatchUp<Frame>(known);
  const delivered: Frame[] = [];
  const holes: { at: number; size: number }[] = [];
  let released = 0;
  let liveDelivered = 0;
  let liveArrived = 0;
  const ended: string[] = [];
  const router = new CatchUpRouter<Frame>(
    flow, catchUp,
    (f: FileFrame) => ({ seq: f.seq, tsUs: f.tsUs, tsNsRem: f.tsNsRem, origLen: f.origLen, bytes: f.bytes }),
    (f, hole) => { delivered.push(f); if (f.live) liveDelivered++; if (hole > 0) holes.push({ at: f.seq, size: hole }); },
    () => { released++; },
    HOLE_MIN_FRAMES,
  );
  router.enable(true);

  // What the agent has made visible: frames numbered below this are flushed.
  let sentSeq = 0;
  let announced = 0;
  const visibleSeq = () => Math.max(0, sentSeq - lag);
  const announce = () => {
    // Boundaries and file names before the frames, closes once flushed.
    while (announced < frames.length && frames[announced].seq < sentSeq) {
      const seq = frames[announced].seq;
      const index = fileIndexOf(seq);
      if (seq === 0 || fileIndexOf(seq - 1) !== index) {
        known.file(index, nameOf(index), 'open', null);
        known.boundary(index, seq);
        if (index > 1) {
          files.get(nameOf(index - 1))!.closed = true;
          known.file(index - 1, nameOf(index - 1), 'closed', null);
        }
      }
      announced++;
    }
  };
  let pendingRetry = 0;
  const serve = (budget: number) => {
    for (let r = 0; r < budget; r++) {
      if (pendingRetry > 0) { pendingRetry--; return; }
      const want = catchUp.wantRead();
      if (want === null) return;
      const file = files.get(want.name);
      if (file === undefined || file.deleted) {
        const out = router.read({ bytes: null, gone: true });
        if (out.ended) ended.push(out.ended);
        continue;
      }
      // Visible: every frame flushed - all of a file the agent has closed,
      // because it closes a file by flushing it.
      const lastVisible = Math.min(file.lastSeq, visibleSeq() - 1);
      const visible = file.closed ? file.bytes.length
        : lastVisible < file.firstSeq ? fileHeader().length : file.endOf.get(lastVisible)!;
      const room = Math.max(0, visible - want.offset);
      const take = Math.min(room, want.length, 1 + Math.floor(random() * 65_536));
      const out = router.read({ bytes: file.bytes.slice(want.offset, want.offset + take), gone: false });
      if (out.ended) ended.push(out.ended);
      if (out.retryMs !== undefined && out.retryMs > 0) pendingRetry = 1;
    }
  };

  // Batches in the port, not yet handled - a Worker running behind its own
  // file sees the file's frames before the live copies of them.
  const port: { no: number; group: Frame[] }[] = [];
  const handle = ({ no: batchNo, group }: { no: number; group: Frame[] }) => {
    if (plan.mainShed?.has(batchNo)) {
      router.shed(group[0].seq, group.length);
    } else if (!plan.agentShed?.has(batchNo)) {
      const order = group.slice();
      // Two adapters racing to the queue: neighbours a few places out of order.
      if (plan.skew) {
        for (let k = 0; k < 8; k++) {
          const i = Math.floor(random() * (order.length - 3));
          const j = i + 1 + Math.floor(random() * 3);
          [order[i], order[j]] = [order[j], order[i]];
        }
      }
      for (const f of order) { liveArrived++; router.arrive({ ...f, live: true }); }
    }
  };
  let batchNo = 0;
  for (let at = 0; at < frames.length; at += batch, batchNo++) {
    const group = frames.slice(at, at + batch);
    sentSeq = group[group.length - 1].seq + 1;
    announce();
    if (plan.deleteFile && batchNo === plan.deleteFile.atBatch) {
      const file = files.get(nameOf(plan.deleteFile.index));
      if (file) { file.deleted = true; known.file(plan.deleteFile.index, nameOf(plan.deleteFile.index), 'deleted', null); }
    }
    port.push({ no: batchNo, group });
    while (port.length > (plan.portDelay ?? 0)) handle(port.shift()!);
    serve(plan.readsPerStep ?? 4);
  }
  while (port.length > 0) { handle(port.shift()!); serve(plan.readsPerStep ?? 4); }
  // The stream has ended; unless the capture stops now, the file is read on.
  sentSeq = frames.length + lag;
  announce();
  if (!plan.stopAtEnd) for (let i = 0; i < 20_000 && catchUp.active; i++) serve(4);
  const activeAtEnd = catchUp.active;
  router.stop();
  return { delivered, holes, released, liveArrived, liveDelivered, catchUp, ended, skipped: flow.skippedFrames, activeAtEnd };
}

/** The first way `got` differs from `want`, or null. */
function sameFrames(want: Frame[], got: Frame[]): string | null {
  if (got.length !== want.length) {
    for (let i = 0; i < Math.min(want.length, got.length); i++) {
      if (got[i].seq !== want[i].seq) return `${got.length} frames against ${want.length}; first difference at ${i}: seq ${got[i].seq} for ${want[i].seq}`;
    }
    return `${got.length} frames against ${want.length}`;
  }
  for (let i = 0; i < want.length; i++) {
    const a = want[i]; const b = got[i];
    if (a.seq !== b.seq || a.tsUs !== b.tsUs || a.tsNsRem !== b.tsNsRem || a.origLen !== b.origLen || a.bytes.length !== b.bytes.length) {
      return `frame ${i}: seq ${b.seq} for ${a.seq}`;
    }
    for (let j = 0; j < a.bytes.length; j++) if (a.bytes[j] !== b.bytes[j]) return `frame ${i} (seq ${a.seq}): byte ${j} differs`;
  }
  return null;
}

function holdsEveryLiveFrameOnce(r: Run): boolean {
  return r.liveDelivered + r.released === r.liveArrived;
}

// --- the cases -----------------------------------------------------------------

async function cases(label: string, frames: Frame[]): Promise<Frame[] | null> {
  const n = frames.length;
  const batches = Math.ceil(n / 300);
  const mid = Math.floor(batches / 2);

  {
    const r = run(frames, {});
    check(`${label}: no hole - every frame live, nothing read from the file`,
      sameFrames(frames, r.delivered) === null && r.catchUp.stats.started === 0 && r.liveDelivered === n);
  }

  let caughtUp: Frame[] | null = null;
  {
    const shed = new Set([mid, mid + 1, mid + 2, mid + 3, mid + 4]);
    const r = run(frames, { mainShed: shed });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: main sheds five batches - the view is the straight run, frame for frame`, diff === null, diff ?? '');
    check(`${label}: ...caught up once, rejoined once, and no hole left to mark`,
      r.catchUp.stats.started === 1 && r.catchUp.stats.rejoined === 1 && r.holes.length === 0,
      JSON.stringify({ stats: r.catchUp.stats, holes: r.holes }));
    check(`${label}: ...every live frame dissected or given back to main, once`, holdsEveryLiveFrameOnce(r),
      `${r.liveDelivered} + ${r.released} vs ${r.liveArrived}`);
    caughtUp = r.delivered;
  }
  {
    const r = run(frames, { agentShed: new Set([mid - 3, mid - 2]) });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: the agent's queue sheds (no message, just a gap in the numbers) - caught up`,
      diff === null && r.catchUp.stats.rejoined === 1 && r.holes.length === 0, diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    const shed = new Set<number>();
    for (let b = 3; b < batches - 3; b += 7) { shed.add(b); shed.add(b + 1); }
    const agent = new Set<number>();
    for (let b = 6; b < batches - 3; b += 11) agent.add(b);
    for (const b of agent) shed.delete(b);
    const r = run(frames, { mainShed: shed, agentShed: agent, seed: 3 });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: many holes, both kinds, chunks of every size - the straight run`,
      diff === null && r.holes.length === 0 && holdsEveryLiveFrameOnce(r),
      diff ?? JSON.stringify({ stats: r.catchUp.stats, holes: r.holes.slice(0, 3) }));
  }
  {
    // Two adapters' frames arrive a few places out of order, and holes cut
    // through them: a late live frame from before a hole is still dissected,
    // one the file already delivered is not dissected again. The Worker's
    // ordering window puts them back in order; here, every frame once is the
    // claim, so both sides are compared in number order.
    const shed = new Set<number>();
    for (let b = 3; b < batches - 3; b += 9) shed.add(b);
    const r = run(frames, { mainShed: shed, skew: true, seed: 5 });
    const bySeq = r.delivered.slice().sort((a, b) => a.seq - b.seq);
    const diff = sameFrames(frames, bySeq);
    check(`${label}: holes through frames that arrive out of order - every frame once`,
      diff === null && holdsEveryLiveFrameOnce(r), diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    // The port runs behind the file: by the time live frames are handled the
    // file has delivered them already. They are not dissected twice, and
    // the rejoin waits for a live frame the file has not reached.
    const shed = new Set<number>();
    for (let b = 4; b < batches - 12; b += 13) { shed.add(b); shed.add(b + 1); }
    const r = run(frames, { mainShed: shed, portDelay: 8, lag: 100, readsPerStep: 12, seed: 9 });
    const bySeq = r.delivered.slice().sort((a, b) => a.seq - b.seq);
    const diff = sameFrames(frames, bySeq);
    check(`${label}: the live stream running behind its own file - every frame once, no misalignment`,
      diff === null && r.catchUp.stats.misaligned === 0 && holdsEveryLiveFrameOnce(r) && r.catchUp.stats.rejoined === r.catchUp.stats.started,
      diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    // A hole across the edge of a ring file: the file it starts in is
    // finished, and the catch-up moves on to the next one by its boundary.
    const perFile = 1000;
    const edgeBatch = Math.floor((perFile * 3) / 300);
    const r = run(frames, { perFile, mainShed: new Set([edgeBatch - 1, edgeBatch, edgeBatch + 1]) });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: a hole across a ring file's edge - read on into the next file`,
      diff === null && r.catchUp.stats.rejoined >= 1 && r.holes.length === 0, diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    // A file slower than live - one read a batch - holds frames until the
    // hold is too big, lets them go, and rejoins once live is gone.
    const shed = new Set<number>();
    for (let b = 2; b < 8; b++) shed.add(b);
    const r = run(frames, { mainShed: shed, readsPerStep: 1, lag: 50 });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: a file read slower than live - still the straight run, every live frame accounted for`,
      diff === null && holdsEveryLiveFrameOnce(r), diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    // The stream never comes back after the hole: the rest is all file.
    const shed = new Set<number>();
    for (let b = mid; b < batches; b++) shed.add(b);
    const r = run(frames, { mainShed: shed });
    const diff = sameFrames(frames, r.delivered);
    check(`${label}: live never resumes - the file delivers the rest of the capture, and the view is level, not still "catching up"`,
      diff === null && r.holes.length === 0 && !r.activeAtEnd, diff ?? JSON.stringify(r.catchUp.stats));
  }
  {
    // The capture stops while the catch-up is far behind, holding nothing:
    // what it had not read is counted as skipped - exactly - not silently
    // missing, which is what a catch-up that simply ended would leave.
    const shed = new Set<number>();
    for (let b = 3; b < batches; b++) if (b % 2 === 1) shed.add(b);
    const r = run(frames, { mainShed: shed, readsPerStep: 1, lag: 50, stopAtEnd: true });
    const missing = n - r.delivered.length;
    check(`${label}: the capture stops mid catch-up - every frame not dissected is counted as skipped`,
      missing > 0 && r.skipped === missing && holdsEveryLiveFrameOnce(r), JSON.stringify({ missing, skipped: r.skipped, stats: r.catchUp.stats }));
  }
  {
    // The ring deletes a file before the catch-up has read it: its frames
    // that never arrived live are gone, and that is marked - once, the right size.
    const perFile = 1000;
    const fileTwoFirstBatch = Math.ceil(perFile / 300);
    const shed = new Set<number>();
    for (let b = fileTwoFirstBatch + 1; b < fileTwoFirstBatch + 5; b++) shed.add(b);
    const r = run(frames, { perFile, mainShed: shed, deleteFile: { index: 2, atBatch: fileTwoFirstBatch + 1 }, readsPerStep: 4, lag: 3000 });
    const lost = new Set<number>();
    for (const b of shed) for (let s = b * 300; s < Math.min(n, b * 300 + 300); s++) if (s >= perFile && s < 2 * perFile) lost.add(s);
    const want = frames.filter((f) => !lost.has(f.seq));
    const diff = sameFrames(want, r.delivered);
    const marked = r.holes.reduce((t, h) => t + h.size, 0);
    check(`${label}: a ring file deleted under the catch-up - its unread frames are lost, and marked, the rest caught up`,
      diff === null && marked === lost.size, diff ?? `marked ${marked}, lost ${lost.size}, ${JSON.stringify(r.holes)}`);
  }
  {
    // The writer refused a frame before the hole: the file's counting is off,
    // so the frame before the hole is not where it should be, and nothing is
    // read - the hole is marked, as before catch-up existed.
    const shed = new Set([mid, mid + 1]);
    const r = run(frames, { mainShed: shed, writerDrops: new Set([Math.floor(mid * 300 / 2)]) });
    const want = frames.filter((f) => !(f.seq >= mid * 300 && f.seq < (mid + 2) * 300));
    const diff = sameFrames(want, r.delivered);
    check(`${label}: a frame the writer refused before the hole - nothing read from the file, the hole marked`,
      diff === null && r.ended.includes('anchorMismatch') && r.holes.length === 1 && r.holes[0].size === 600
      && r.catchUp.off === 'anchorMismatch',
      diff ?? JSON.stringify({ ended: r.ended, holes: r.holes }));
  }
  {
    // ...and inside the hole: the frames after it are numbered one low, so
    // the first held frame turns up a number early. The rejoin finds it by
    // its bytes - nothing twice - and catch-up is off for the capture.
    const shed = new Set([mid, mid + 1, mid + 2]);
    const dropped = mid * 300 + 100;
    const r = run(frames, { mainShed: shed, writerDrops: new Set([dropped]) });
    // The frames after the refused one are numbered one low - which is the
    // file's fault and what turns catch-up off - so they are held to the
    // straight run by everything but their number.
    const want = frames.filter((f) => f.seq !== dropped);
    const diff = sameFrames(want, r.delivered.map((f, i) => ({ ...f, seq: want[i]?.seq ?? -1 })));
    check(`${label}: a frame the writer refused inside the hole - no frame twice, only the refused one missing`,
      diff === null && r.catchUp.stats.misaligned === 1 && r.catchUp.off === 'misaligned',
      diff ?? JSON.stringify({ got: r.delivered.length, want: want.length, stats: r.catchUp.stats }));
  }
  return caughtUp;
}

// --- the reader on its own ---------------------------------------------------------

{
  // A file growing seven bytes at a time, read from wherever the reader says.
  const frames = madeFrames(50);
  const file = concat([fileHeader(), ...frames.map(epb)]);
  const tail = new PcapngTail(0);
  const got: number[] = [];
  for (let written = 7; written < file.length + 7; written += 7) {
    tail.push(file.subarray(tail.readOffset, Math.min(file.length, written)));
    let f;
    while ((f = tail.next()) !== null) got.push(f.tsUs);
  }
  check('the reader: a file growing seven bytes at a time - every frame, in order, at the right time',
    got.length === 50 && got.every((ts, i) => ts === frames[i].tsUs));
  check('...and the offset to read next is the end of the file', tail.readOffset === file.length);
  check('...and it read the adapter\'s name', tail.idbNames[0] === '\\Device\\NPF_{TEST}');
}
{
  // Windows extends a file before it fills it, so a read can run into zeros
  // where the next frames will be. Read then, and again once written, every
  // frame comes out as written - none from the zeros, none twice.
  const frames = madeFrames(40);
  const file = concat([fileHeader(), ...frames.map(epb)]);
  const cut = fileHeader().length + frames.slice(0, 20).reduce((n, f) => n + epb(f).length, 0) + 37;
  const early = file.slice();
  early.fill(0, cut);
  const tail = new PcapngTail(0);
  const got: Uint8Array[] = [];
  let f;
  tail.push(early.subarray(0, early.length));
  while ((f = tail.next()) !== null) got.push(f.bytes);
  const afterEarly = got.length;
  tail.push(file.subarray(tail.readOffset));
  while ((f = tail.next()) !== null) got.push(f.bytes);
  check('the reader: zeros a writer had not filled yet are read again, not taken - every frame once, as written',
    afterEarly === 20 && got.length === 40 && got.every((b, i) => b.length === frames[i].bytes.length && b.every((x, j) => x === frames[i].bytes[j])),
    `${afterEarly} then ${got.length}`);
  const stuck = new PcapngTail(0);
  let threw = false;
  try {
    for (let i = 0; i < 100; i++) { stuck.push(early.subarray(stuck.readOffset)); while (stuck.next() !== null) { /* frames */ } }
  } catch { threw = true; }
  check('...and a block that never closes is, in the end, a corrupt file', threw);
}

// --- run them --------------------------------------------------------------------

check('the bounds are what the rejoin was sized by', REJOIN_WITHIN < HOLD_MAX_FRAMES);
await cases('made', madeFrames(30_000));

const scratch = mkdtempSync(path.join(tmpdir(), 'inwire-catchup-'));
try {
  for (const fixture of FIXTURES.filter((f) => f.name === 'inwire' || f.name === 'bulk')) {
    if (!existsSync(fixture.path)) { console.log(`SKIP  ${fixture.name}: ${fixture.path} is not present - see test/fixtures/README.md`); continue; }
    const file = new File([new Uint8Array(readFileSync(fixture.path))], 'capture.pcap');
    const { frames: extracted } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
    const frames: Frame[] = extracted.map((f, seq) => ({
      seq, tsUs: Number(f.tsNanos / 1000n), tsNsRem: Number(f.tsNanos % 1000n), origLen: f.origLen, bytes: f.rawBytes.slice(),
    }));
    const caughtUp = await cases(fixture.name, frames);
    if (caughtUp === null) continue;
    // The same frames, dissected: the straight run against the one caught up.
    const straight = path.join(scratch, `${fixture.name}-straight.pcapng`);
    const after = path.join(scratch, `${fixture.name}-caughtup.pcapng`);
    writeFileSync(straight, concat([fileHeader(), ...frames.map(epb)]));
    writeFileSync(after, concat([fileHeader(), ...caughtUp.map(epb)]));
    const [a, b] = [await digestCapture(straight), await digestCapture(after)];
    const first = a.findIndex((h, i) => h !== b[i]);
    check(`${fixture.name}: dissected, the caught-up frames hash as the straight run's - rows, trees, records (${a.length.toLocaleString('en-US')} frames)`,
      a.length === b.length && first === -1, `first difference at frame ${first + 1}`);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nAll catch-up checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
