/**
 * The catch-up reader's parse as a pure function (ADR 0053, "Catch-up past the
 * ceiling, 2026-11-04"): what one read of the agent's pcapng becomes - frames in
 * slabs, their fixed fields in columns - and the state the next read starts from.
 *
 *   npx tsx scripts/pipeline/read-parse.ts
 *
 * The reference for every frame is `PcapngTail` read in one piece. Every parse is
 * sent through `v8.serialize` before it is read: the reader's reply crosses a
 * thread, so a test that hands objects over in one context would hide what the
 * crossing drops.
 */
import { readFileSync } from 'node:fs';
import v8 from 'node:v8';
import { MAX_CAPLEN, type SeqFrame } from '../../src/services/pipeline/catchUp';
import { PcapngTail, STALL_LIMIT, startState, type TailFrame, type TailState } from '../../src/services/pipeline/pcapngTail';
import { ParsedTail } from '../../src/services/pipeline/parsedTail';
import { SLAB_BYTES, answerParse, parseRead, parseTransfer, type ReadParse } from '../../src/services/pipeline/readParse';
import { concat, customBlock, epb, fileHeader, idbBlock, madeFrames, rng, shbBlock } from './madePcapng';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const across = <T>(x: T): T => v8.deserialize(v8.serialize(x)) as T;
const DEVICE = '\\Device\\NPF_{TEST}';

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.from(a.buffer, a.byteOffset, a.length).equals(Buffer.from(b.buffer, b.byteOffset, b.length));
}

interface Ref extends TailFrame { blockAt: number }

/** What PcapngTail gives for a whole file in one push. */
function reference(file: Uint8Array): Ref[] {
  const tail = new PcapngTail(0);
  tail.push(file);
  const out: Ref[] = [];
  let f;
  while ((f = tail.next()) !== null) out.push({ ...f, blockAt: tail.blockAt });
  return out;
}

function frameOf(p: ReadParse, i: number): Ref {
  return {
    idb: p.idb[i], tsUs: p.tsUs[i], tsNsRem: p.tsNsRem[i], origLen: p.origLen[i], capLen: p.capLen[i],
    bytes: new Uint8Array(p.slabs[p.slab[i]], p.slabAt[i], p.capLen[i]), blockAt: p.blockAt[i],
  };
}

/** The first way a parse differs from the reference, or ''. */
function differs(p: ReadParse, ref: Ref[]): string {
  if (p.count !== ref.length) return `${p.count} frames, reference has ${ref.length}`;
  for (let i = 0; i < ref.length; i++) {
    const a = frameOf(p, i);
    const r = ref[i];
    for (const key of ['idb', 'tsUs', 'tsNsRem', 'origLen', 'capLen', 'blockAt'] as const) {
      if (a[key] !== r[key]) return `frame ${i}: ${key} ${a[key]} vs ${r[key]}`;
    }
    if (!sameBytes(a.bytes, r.bytes)) return `frame ${i}: bytes differ`;
  }
  return '';
}

/** The first way the slabs break their rules, or ''. */
function slabProblems(p: ReadParse): string {
  const sums = p.slabs.map(() => 0);
  const counts = p.slabs.map(() => 0);
  for (let i = 0; i < p.count; i++) {
    const s = p.slab[i];
    if (s >= p.slabs.length) return `frame ${i}: slab ${s} of ${p.slabs.length}`;
    if (i > 0 && s < p.slab[i - 1]) return `frame ${i}: slab went down`;
    if (i > 0 && s === p.slab[i - 1] && p.slabAt[i] !== p.slabAt[i - 1] + p.capLen[i - 1]) return `frame ${i}: not contiguous`;
    if ((i === 0 || s !== p.slab[i - 1]) && p.slabAt[i] !== 0) return `frame ${i}: first of its slab, not at 0`;
    sums[s] += p.capLen[i];
    counts[s]++;
  }
  for (let s = 0; s < p.slabs.length; s++) {
    if (counts[s] === 0) return `slab ${s} holds no frame`;
    if (p.slabs[s].byteLength !== sums[s]) return `slab ${s}: ${p.slabs[s].byteLength} bytes for ${sums[s]} of frames`;
    if (sums[s] > SLAB_BYTES && counts[s] !== 1) return `slab ${s}: ${sums[s]} bytes over ${counts[s]} frames`;
  }
  return '';
}

// --- the builders ---------------------------------------------------------------

check('madePcapng: fileHeader is the SHB and the named IDB, byte for byte',
  sameBytes(fileHeader(), concat([shbBlock(), idbBlock(DEVICE)])));

// --- a whole file -----------------------------------------------------------------

const frames = madeFrames(3000);
const file = concat([fileHeader(), ...frames.map(epb)]);
const ref = reference(file);
{
  const p = across(parseRead(startState(), file));
  check('parseRead: a whole file - every frame PcapngTail gives, field for field and byte for byte',
    p.count === 3000 && differs(p, ref) === '' && p.end.offset === file.length && p.error === null && p.end.idbNames[0] === DEVICE
      && p.start === 0 && p.length === file.length,
    `${differs(p, ref)} count ${p.count} end ${p.end.offset}/${file.length} error ${p.error}`);
  check('parseRead: slabs hold at most SLAB_BYTES, exactly their frames, in file order',
    slabProblems(p) === '' && p.slabs.length > 1, slabProblems(p));
}

// --- frames as big as a slab --------------------------------------------------------

{
  const sized = (seq: number, n: number): SeqFrame => {
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = (seq * 13 + i * 5) & 0xff;
    return { seq, tsUs: 1_790_000_000_000_000 + seq, tsNsRem: seq % 1000, origLen: n, bytes };
  };
  const sizes = [100, 90, MAX_CAPLEN, 80, 70, 60, MAX_CAPLEN, MAX_CAPLEN, 50, SLAB_BYTES + 40_000, 40, 30];
  const made = sizes.map((n, i) => sized(i, n));
  const f = concat([fileHeader(), ...made.map(epb)]);
  const p = across(parseRead(startState(), f));
  const alone = (i: number) => p.slab.filter((s) => s === p.slab[i]).length === 1;
  const bigOnes = sizes.map((n, i) => (n >= MAX_CAPLEN ? i : -1)).filter((i) => i >= 0);
  check('parseRead: a frame of MAX_CAPLEN has a slab no other frame shares',
    differs(p, reference(f)) === '' && slabProblems(p) === '' && bigOnes.every(alone) && p.error === null,
    `${differs(p, reference(f))} ${slabProblems(p)} alone: ${bigOnes.map(alone).join()}`);
}

// --- a file as it grows ------------------------------------------------------------

{
  const few = madeFrames(50);
  const f = concat([fileHeader(), ...few.map(epb)]);
  let state: TailState = startState();
  const got: number[] = [];
  let reads = 0;
  let bad = '';
  for (let written = 7; state.offset < f.length && reads < 100_000; written += 7, reads++) {
    const p = across(parseRead(state, f.subarray(state.offset, Math.min(f.length, written))));
    if (p.error !== null) bad = p.error;
    for (let i = 0; i < p.count; i++) got.push(p.tsUs[i]);
    state = p.end;
  }
  check('parseRead: a file growing seven bytes at a time, each read parsed from the last end state - every frame once, in order',
    got.length === 50 && got.every((ts, i) => ts === few[i].tsUs) && state.offset === f.length && bad === '',
    `${got.length} frames, end ${state.offset}/${f.length} ${bad}`);
}

// --- a read that ends in a block ----------------------------------------------------

{
  const k = 1200;
  const blockStart = fileHeader().length + frames.slice(0, k).reduce((n, f) => n + epb(f).length, 0);
  const p = across(parseRead(startState(), file.subarray(0, blockStart + epb(frames[k]).length - 9)));
  check('parseRead: a read that ends inside a block stops before it',
    p.count === k && p.end.offset === blockStart && p.error === null, `${p.count} frames, end ${p.end.offset} vs ${blockStart}`);
}

// --- the head of a read -------------------------------------------------------------

{
  const afterHeader = across(parseRead(startState(), fileHeader())).end;
  const first = across(parseRead(afterHeader, file.subarray(afterHeader.offset)));
  const short = across(parseRead(afterHeader, file.subarray(afterHeader.offset, afterHeader.offset + 7)));
  const empty = across(parseRead(afterHeader, new Uint8Array(0)));
  const atStart = across(parseRead(startState(), file));
  check('parseRead: head is the block at the read\'s start, null under eight bytes',
    first.head !== null && first.head.type === 6 && first.head.length === epb(frames[0]).length
      && short.head === null && empty.head === null && empty.count === 0
      && atStart.head !== null && atStart.head.type === 0x0a0d0d0a && atStart.head.length === 28,
    JSON.stringify([first.head, short.head, atStart.head]));
}

// --- a block that never closes ------------------------------------------------------

{
  const cut = fileHeader().length + frames.slice(0, 20).reduce((n, f) => n + epb(f).length, 0) + 37;
  const early = file.slice();
  early.fill(0, cut);
  let state: TailState = startState();
  const errors: (string | null)[] = [];
  let first = -1;
  for (let read = 1; read <= STALL_LIMIT + 1; read++) {
    const p = across(parseRead(state, early.subarray(state.offset)));
    if (read === 1) first = p.count;
    errors.push(p.error);
    state = p.end;
  }
  check('parseRead: a block that never closes is an error on the read after STALL_LIMIT',
    first === 20 && errors.slice(0, STALL_LIMIT).every((e) => e === null) && typeof errors[STALL_LIMIT] === 'string',
    `first read ${first} frames; errors ${JSON.stringify(errors.map((e) => e === null ? 0 : 1).join(''))}`);
}

// --- a second IDB -------------------------------------------------------------------

{
  const ten = madeFrames(20);
  const f = concat([shbBlock(), idbBlock('A'), ...ten.slice(0, 10).map(epb), idbBlock('B'), ...ten.slice(10).map(epb)]);
  const p = across(parseRead(startState(), f));
  let ok = p.count === 20 && p.error === null;
  for (let i = 0; ok && i < 20; i++) {
    const names = p.sections[p.section[i]].idbNames;
    ok = i < 10 ? names.length === 1 && names[0] === 'A' : names.length === 2 && names[0] === 'A' && names[1] === 'B';
  }
  check('parseRead: a second IDB mid-file - frames before it see one name, frames after it two',
    ok && p.sections.length === 2 && p.end.idbNames.join() === 'A,B', JSON.stringify(p.sections.map((s) => s.idbNames)));
}

// --- bytes that are a view ----------------------------------------------------------

{
  const big = new Uint8Array(13 + file.length + 9).fill(0xa5);
  big.set(file, 13);
  const p = across(parseRead(startState(), big.subarray(13, 13 + file.length)));
  check('parseRead: bytes that are a view at an odd offset inside a larger buffer give the same frames',
    differs(p, ref) === '' && p.end.offset === file.length && p.error === null && p.length === file.length, differs(p, ref));
}

// --- PcapngTail's new members -------------------------------------------------------

{
  const tail = new PcapngTail(0);
  tail.push(file);
  for (let i = 0; i < 700; i++) tail.next();
  const state = across(tail.save());
  const restored = PcapngTail.restore(state);
  restored.push(file.subarray(restored.readOffset));
  const rest: Ref[] = [];
  const original: Ref[] = [];
  let f;
  while ((f = tail.next()) !== null) original.push({ ...f, blockAt: tail.blockAt });
  while ((f = restored.next()) !== null) rest.push({ ...f, blockAt: restored.blockAt });
  const same = rest.length === 2300 && original.length === 2300 && rest.every((r, i) => {
    const o = original[i];
    return r.idb === o.idb && r.tsUs === o.tsUs && r.tsNsRem === o.tsNsRem && r.origLen === o.origLen && r.blockAt === o.blockAt && sameBytes(r.bytes, o.bytes);
  });
  check('PcapngTail: restore(save()) reads on from position with the same frames',
    same && state.offset === ref[700].blockAt && restored.sectionNo === 0 && tail.sectionNo === 2,
    `${rest.length} vs ${original.length}; offset ${state.offset} vs ${ref[700].blockAt}`);
  // A save is a copy: what the tail does next does not reach it.
  state.idbNames.push('x');
  state.nsPerTick.push(5);
  const section = tail.section();
  section.idbNames.push('y');
  section.nsPerTick.push(6);
  check('...and a save and a section are copies, not the tail\'s own arrays',
    tail.section().idbNames.length === 1 && tail.section().nsPerTick.length === 1
      && tail.save().idbNames.length === 1 && tail.save().nsPerTick.length === 1 && restored.section().idbNames.length === 1);
}
{
  const a = new PcapngTail(0);
  const b = new PcapngTail(0);
  a.push(file);
  b.push(file);
  let ok = true;
  let views = true;
  let n = 0;
  for (;;) {
    const x = a.next();
    const y = b.next('view');
    if (x === null || y === null) { ok = x === null && y === null; break; }
    ok = ok && sameBytes(x.bytes, y.bytes) && x.capLen === y.capLen;
    views = views && y.bytes.buffer.byteLength > y.bytes.length;
    n++;
  }
  check('PcapngTail: next(\'view\') gives next(true)\'s bytes', ok && n === 3000 && views, `${n} frames, views ${views}`);
}

// --- the Worker's answer ------------------------------------------------------------

{
  const { reply, transfer } = answerParse({ type: 'parse', requestId: 41, state: startState(), bytes: file });
  const parsed = reply.type === 'parsed' ? reply.parse : null;
  check('answerParse: a request is answered with its parse and every buffer in it to transfer',
    reply.type === 'parsed' && reply.requestId === 41 && parsed !== null
      && transfer.length === 10 + parsed.slabs.length && parsed.slabs.every((s) => transfer.includes(s))
      && new Set(transfer).size === transfer.length && transfer.length === parseTransfer(parsed).length,
    `${reply.type} ${transfer.length}`);
  // The list is real: structured clone with it moves every buffer, none left behind or named twice.
  let moved = false;
  if (parsed !== null) {
    const bytesBefore = parsed.slabs.reduce((n, s) => n + s.byteLength, 0);
    const sent = structuredClone(reply, { transfer });
    moved = sent.type === 'parsed' && sent.parse.slabs.reduce((n, s) => n + s.byteLength, 0) === bytesBefore
      && parsed.slabs.every((s) => s.byteLength === 0) && parsed.tsUs.byteLength === 0;
  }
  check('...and transferring that list moves every slab and column', moved);
  const failed = answerParse({ type: 'parse', requestId: 42, state: null as unknown as TailState, bytes: file });
  check('answerParse: a request it cannot parse is answered with a failure, not a throw',
    failed.reply.type === 'failure' && failed.reply.message.length > 0 && failed.transfer.length === 0);
}

// --- ParsedTail: what CatchUp reads a file through, over the reader's parses -----

/** One read as the coordinator gets it: parsed from where the tail says, across a thread. */
function read(t: ParsedTail, bytes: Uint8Array): boolean {
  return t.take(across(parseRead(t.nextRead(), bytes)));
}

interface Seen { key: string; bytes: Uint8Array }

/** A frame and where the tail it came from stands after it. */
function seen(f: TailFrame, t: { position: number; blockAt: number; idbNames: readonly (string | null)[] }): Seen {
  return { key: [f.idb, f.tsUs, f.tsNsRem, f.origLen, f.capLen, t.position, t.blockAt, t.idbNames.join()].join('|'), bytes: f.bytes };
}

/** The first way two runs differ, or ''. */
function seenDiffers(a: Seen[], b: Seen[]): string {
  if (a.length !== b.length) return `${a.length} frames vs ${b.length}`;
  for (let i = 0; i < a.length; i++) {
    if (a[i].key !== b[i].key) return `frame ${i}: ${a[i].key} vs ${b[i].key}`;
    if (!sameBytes(a[i].bytes, b[i].bytes)) return `frame ${i}: bytes differ`;
  }
  return '';
}

// A file with a second IDB half way, and a block no one reads between it and the next frame.
const twoFrames = madeFrames(3000);
const twoIdb = concat([shbBlock(), idbBlock('A'), ...twoFrames.slice(0, 1500).map(epb), idbBlock('B'), customBlock(), ...twoFrames.slice(1500).map(epb)]);
/** What PcapngTail gives for `twoIdb` in one push, with where it stands after each frame. */
const twoRef: Seen[] = (() => {
  const tail = new PcapngTail(0);
  tail.push(twoIdb);
  const out: Seen[] = [];
  let f;
  while ((f = tail.next()) !== null) out.push(seen(f, tail));
  return out;
})();

{
  const few = madeFrames(50);
  const f = concat([fileHeader(), ...few.map(epb)]);
  const t = new ParsedTail();
  const got: number[] = [];
  for (let written = 7; written < f.length + 7; written += 7) {
    read(t, f.subarray(t.readOffset, Math.min(f.length, written)));
    let x;
    while ((x = t.next()) !== null) got.push(x.tsUs);
  }
  check('ParsedTail: a file growing seven bytes at a time - every frame, in order; the offset to read next is the end of the file; the adapter\'s name',
    got.length === 50 && got.every((ts, i) => ts === few[i].tsUs) && t.readOffset === f.length && t.position === f.length && t.idbNames[0] === DEVICE,
    `${got.length} frames, readOffset ${t.readOffset}/${f.length}, name ${t.idbNames[0]}`);
}

{
  const random = rng(5);
  const p = new PcapngTail(0);
  const q = new ParsedTail();
  const fromP: Seen[] = [];
  const fromQ: Seen[] = [];
  let f;
  for (let round = 0; round < 400; round++) {
    const n = 1 + Math.floor(random() * 65_536);
    const pull = Math.floor(random() * 61);
    p.push(twoIdb.subarray(p.readOffset, Math.min(twoIdb.length, p.readOffset + n)));
    read(q, twoIdb.subarray(q.readOffset, Math.min(twoIdb.length, q.readOffset + n)));
    for (let i = 0; i < pull && (f = p.next()) !== null; i++) fromP.push(seen(f, p));
    for (let i = 0; i < pull && (f = q.next()) !== null; i++) fromQ.push(seen(f, q));
  }
  p.push(twoIdb.subarray(p.readOffset));
  read(q, twoIdb.subarray(q.readOffset));
  while ((f = p.next()) !== null) fromP.push(seen(f, p));
  while ((f = q.next()) !== null) fromQ.push(seen(f, q));
  check('ParsedTail: read and taken as PcapngTail is - the same frames, and the same position, blockAt and names after each',
    seenDiffers(fromP, fromQ) === '' && seenDiffers(fromQ, twoRef) === '' && fromQ.length === 3000
      && q.position === twoIdb.length && q.idbNames.join() === 'A,B',
    `${seenDiffers(fromP, fromQ)} / ${seenDiffers(fromQ, twoRef)}`);
}

{
  const forty = madeFrames(40);
  const f = concat([fileHeader(), ...forty.map(epb)]);
  const cut = fileHeader().length + forty.slice(0, 20).reduce((n, x) => n + epb(x).length, 0) + 37;
  const blockStart = cut - 37;
  const early = f.slice();
  early.fill(0, cut);
  const t = new ParsedTail();
  const got: Uint8Array[] = [];
  let x;
  read(t, early);
  while ((x = t.next()) !== null) got.push(x.bytes);
  const afterEarly = got.length;
  const atStall = t.save();
  read(t, f.subarray(t.readOffset));
  while ((x = t.next()) !== null) got.push(x.bytes);
  check('ParsedTail: zeros a writer had not filled yet are read again, not taken - every frame once, as written',
    afterEarly === 20 && got.length === 40 && got.every((b, i) => sameBytes(b, forty[i].bytes)),
    `${afterEarly} then ${got.length}`);
  check('...and save() where it stalled is that block, with the stall counted',
    atStall.offset === blockStart && atStall.stalled === 1, JSON.stringify({ offset: atStall.offset, blockStart, stalled: atStall.stalled }));

  const stuck = new ParsedTail();
  let threw = false;
  let reads = 0;
  try {
    for (; reads < 100; reads++) { read(stuck, early.subarray(stuck.readOffset)); while (stuck.next() !== null) { /* frames */ } }
  } catch { threw = true; }
  // Not taken, and answered all the same: a refusal is read again at once,
  // which here would be for ever. The caller reads on to the error instead.
  const stuckAt = stuck.readOffset;
  const answered = read(stuck, f.subarray(stuck.readOffset));
  let threwAgain = false;
  try { stuck.next(); } catch { threwAgain = true; }
  check('...and a block that never closes throws in the end, on the read after STALL_LIMIT; a read after it is not taken, but answered, and next() throws again',
    threw && reads === STALL_LIMIT && answered && stuck.readOffset === stuckAt && threwAgain,
    `threw ${threw} on read ${reads + 1}, answered ${answered}, readOffset ${stuck.readOffset} vs ${stuckAt}, threw again ${threwAgain}`);
}

{
  // A packet longer than its block, the trailing length right, is corrupt.
  // The tail throws there and stays there, so whatever reads on from its state
  // meets the same block, never the frames after it.
  const twelve = madeFrames(12);
  const bad = epb(twelve[5]);
  new DataView(bad.buffer, bad.byteOffset, bad.byteLength).setUint32(20, bad.length, true);
  const f = concat([fileHeader(), ...twelve.slice(0, 5).map(epb), bad, ...twelve.slice(6).map(epb)]);
  const blockStart = fileHeader().length + twelve.slice(0, 5).reduce((n, x) => n + epb(x).length, 0);
  const tail = new PcapngTail(0);
  tail.push(f);
  let got = 0;
  let threw = 0;
  try { while (tail.next() !== null) got++; } catch { threw++; }
  try { tail.next(); } catch { threw++; }
  const at = tail.save();
  check('PcapngTail: a packet longer than its block throws there, and again, with its state still at the block',
    got === 5 && threw === 2 && at.offset === blockStart, JSON.stringify({ got, threw, offset: at.offset, blockStart }));
  const p = parseRead(startState(), f);
  check('parseRead: ...so a parse that meets it ends at the block, with the error',
    p.count === 5 && p.error !== null && p.end.offset === blockStart, JSON.stringify({ count: p.count, error: p.error, end: p.end.offset, blockStart }));
  const t = new ParsedTail();
  read(t, f);
  const before: number[] = [];
  let x;
  try { while ((x = t.next()) !== null) before.push(x.tsUs); } catch { /* the corrupt block */ }
  const restored = PcapngTail.restore(t.save());
  restored.push(f.subarray(t.save().offset));
  let restoredThrew = false;
  try { restored.next(); } catch { restoredThrew = true; }
  check('ParsedTail: ...and a PcapngTail restored from it, nothing waiting, meets the corrupt block again',
    before.length === 5 && restoredThrew, `${before.length} frames, restored threw ${restoredThrew}`);
}

{
  const header = fileHeader().length;
  const epbAt = ref[100].blockAt;
  let same = true;
  let nullBefore = true;
  const heads: string[] = [];
  for (const at of [epbAt, epbAt + 12]) {
    const p = new PcapngTail(0);
    const q = new ParsedTail();
    p.push(file.subarray(0, header));
    read(q, file.subarray(0, header));
    while (p.next() !== null) { /* the header */ }
    while (q.next() !== null) { /* the header */ }
    p.jump(at);
    q.jump(at);
    nullBefore = nullBefore && p.blockHead() === null && q.blockHead() === null && q.readOffset === at && q.position === at;
    p.push(file.subarray(at, at + 4096));
    read(q, file.subarray(at, at + 4096));
    const a = JSON.stringify(p.blockHead());
    const b = JSON.stringify(q.blockHead());
    heads.push(`${a} vs ${b}`);
    same = same && a === b && a !== 'null';
  }
  check('ParsedTail: blockHead where a jump landed is PcapngTail\'s, at an EPB and twelve bytes inside one; null before bytes arrive',
    same && nullBefore, heads.join('; '));
}

{
  const t = new ParsedTail();
  read(t, file.subarray(0, 100_000));
  for (let i = 0; i < 10; i++) t.next();
  const position = t.position;
  const readOffset = t.readOffset;
  const elsewhere = across(parseRead({ ...t.nextRead(), offset: readOffset + 4 }, file.subarray(readOffset + 4, readOffset + 50_000)));
  const refused = !t.take(elsewhere);
  const unmoved = t.position === position && t.readOffset === readOffset;
  const after = t.next();
  check('ParsedTail: a parse that does not begin where the next read does is refused, and changes nothing',
    refused && unmoved && after !== null && after.tsUs === ref[10].tsUs && sameBytes(after.bytes, ref[10].bytes),
    `refused ${refused}, unmoved ${unmoved}, next ${after?.tsUs} vs ${ref[10].tsUs}`);
}

{
  let ok = true;
  const details: string[] = [];
  for (const at of [700, 1600]) {
    // PcapngTail's save into a ParsedTail.
    const p = new PcapngTail(0);
    p.push(twoIdb);
    for (let i = 0; i < at; i++) p.next();
    const q = new ParsedTail(across(p.save()));
    read(q, twoIdb.subarray(q.readOffset));
    const fromQ: Seen[] = [];
    let f;
    while ((f = q.next()) !== null) fromQ.push(seen(f, q));
    // ParsedTail's save into a PcapngTail.
    const q2 = new ParsedTail();
    read(q2, twoIdb);
    for (let i = 0; i < at; i++) q2.next();
    const p2 = PcapngTail.restore(across(q2.save()));
    p2.push(twoIdb.subarray(p2.readOffset));
    const fromP: Seen[] = [];
    while ((f = p2.next()) !== null) fromP.push(seen(f, p2));
    const a = seenDiffers(fromQ, twoRef.slice(at));
    const b = seenDiffers(fromP, twoRef.slice(at));
    ok = ok && a === '' && b === '' && fromQ.length === 3000 - at;
    details.push(`at ${at}: ${a} / ${b}`);
  }
  check('ParsedTail and PcapngTail: each restored from the other\'s save() reads on with the same frames', ok, details.join('; '));
}

// --- the read a view is sent as: the buffer goes, the view with it ------------------------

{
  // The Worker sends main's bytes to the reader without copying them first:
  // the buffer is transferred and the view travels with it, offset and all.
  const big = new Uint8Array(13 + file.length + 9).fill(0xa5);
  big.set(file, 13);
  const view = big.subarray(13, 13 + file.length);
  const sent = structuredClone({ type: 'parse' as const, requestId: 7, state: startState(), bytes: view }, { transfer: [view.buffer as ArrayBuffer] });
  const detached = big.buffer.byteLength === 0;
  const { reply } = answerParse(sent);
  const p = reply.type === 'parsed' ? reply.parse : null;
  check('a view transferred with its buffer (odd offset, larger buffer) parses as the whole file does',
    detached && sent.bytes.byteOffset === 13 && p !== null && differs(p, ref) === '' && p.end.offset === file.length,
    `${detached} ${sent.bytes.byteOffset} ${p === null ? reply.type : differs(p, ref)}`);
}

// --- the Worker's wiring ------------------------------------------------------------
//
// `src/workers/pipeline.worker.ts` is not importable here: it starts itself at
// load and needs a Worker scope. Its reader wiring is held by reading the source,
// which is all tsx can reach.

{
  const source = readFileSync(new URL('../../src/workers/pipeline.worker.ts', import.meta.url), 'utf8');
  /** One top-level function's text, from its `function` line to the closing brace at column 0. */
  const fn = (name: string): string => {
    const start = source.search(new RegExp(`^function ${name}\\(`, 'm'));
    if (start < 0) return '';
    const end = source.indexOf('\n}\n', start);
    return source.slice(start, end + 3);
  };
  const handlers = source.slice(source.indexOf("name: READER_NAME"), source.indexOf('parallel = { coordinator'));
  check('A2: the reader\'s message handler is bound to its own Worker: it names it, and the receiver checks it is still the current one',
    /receiveFromReader\(reader,/.test(handlers) && /if \(parallel\?\.reader !== r\) return;/.test(fn('receiveFromReader')),
    handlers.trim().slice(0, 200));
  check('...and so is its error handler, and readerDown terminates the Worker it was told of, not whichever is current',
    /readerDown\(reader,/.test(handlers) && /\br\.terminate\(\)/.test(fn('readerDown')) && !/parallel\.reader\.terminate\(\)/.test(fn('readerDown'))
    && /if \(parallel\?\.reader !== r\) return;/.test(fn('readerDown')),
    fn('readerDown').slice(0, 200));
  check('A1: a threads change is one change of reader - startParallel stops without telling catch-up, and tells it once the new reader stands',
    /function stopParallel\(restarting = false\)/.test(source) && /if \(!restarting\) readerChanged\(\)/.test(fn('stopParallel'))
    && /const replaced = stopParallel\(true\)/.test(fn('startParallel')) && /readerChanged\(replaced\)/.test(fn('startParallel')),
    fn('stopParallel').slice(0, 300));
  const captured = fn('receiveCaptured');
  check('A3: the reader gets main\'s bytes as they are - no copy of them first, their buffer transferred with them',
    captured.includes("type: 'parse'") && !/asArrayBuffer\(/.test(captured) && /\[bytes\.buffer as ArrayBuffer\]/.test(captured),
    captured.slice(0, 300));
}

console.log(failures === 0 ? '\nAll read-parse checks passed.' : `\n${failures} read-parse check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
