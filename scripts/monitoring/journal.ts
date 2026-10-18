/**
 * The evidence journal, its rollup sidecar and their codecs (ADR 0059).
 *
 *   npx tsx scripts/monitoring/journal.ts
 *
 * Stored-format parsing only: nothing here decodes NetFlow. The journal is the
 * only authority over what was received, so every case that can lose or
 * invent an entry is driven here - against a `MemoryBlockFile` **and** a real
 * file, truncated and corrupted at chosen offsets, because a memory file is a
 * faithful model of the interface and no model at all of a disk.
 *
 * The ADR's test vector is asserted at the codec level, byte for byte. It pins
 * framing, not the boundary schema: its boundary body `{"action":"start"}` has
 * no `sessionId`, and its datagram precedes any `start`, so pushing it through
 * `MonitoringJournal` would test the schema checks instead of the bytes.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { MemoryBlockFile, type BlockFile } from '../../src/services/capture/blockFile';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import {
  DECODER_POLICY_VERSION, FORMAT_VERSION, LIMITS,
  type BoundaryEvidence, type DatagramEvidence, type Evidence, type MinuteRollup,
} from '../../src/services/monitoring/types';
import {
  FILE_HEADER_BYTES, JOURNAL_FRAMING, KIND_BOUNDARY, KIND_DATAGRAM, ROLLUP_FRAMING,
  crc32, decodeDatagramBody, decodeFileHeader, encodeDatagramBody, encodeEntry, encodeFileHeader,
  parseEntryHeader,
} from '../../src/services/monitoring/journalCodec';
import {
  MonitoringJournal, StaleGenerationError, recoverJournal,
  type EvidenceInput, type JournalOptions,
} from '../../src/services/monitoring/journal';
import { MAX_APPEND_BYTES, MAX_APPEND_MINUTES, RollupStore } from '../../src/services/monitoring/rollupStore';
import { MAX_ROLLUP_INFLATED_BYTES, decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { EntryIndex, INDEX_STRIDE } from '../../src/services/monitoring/index';
import { monitoringRoot, openMonitoringVolume } from '../../electron/monitoring/volume';

let failures = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`.slice(0, 900));
  }
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex').replace(/(.{2})/g, '$1 ').trim();
const fromHex = (s: string) => Uint8Array.from(s.split(/\s+/).filter(Boolean).map((h) => parseInt(h, 16)));
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const deflate = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b, { level: 1 }));
/** The contract is `inflate(bytes, maxOutput)`: node's zlib takes the bound as `maxOutputLength`. */
const inflate = (b: Uint8Array, maxOutput: number): Uint8Array => new Uint8Array(inflateRawSync(b, { maxOutputLength: maxOutput }));

function readAll(file: BlockFile): Uint8Array {
  const out = new Uint8Array(file.size());
  file.read(0, out);
  return out;
}

/** Where each entry of a valid journal or sidecar image starts, in id order. */
function entryStarts(image: Uint8Array): number[] {
  const out: number[] = [];
  const v = new DataView(image.buffer, image.byteOffset, image.byteLength);
  let off = FILE_HEADER_BYTES;
  while (off + 24 <= image.length) {
    out.push(off);
    off += 24 + v.getUint32(off + 4, true);
  }
  return out;
}

/** Recomputes the CRC of the entry at `off` after a field was changed, so only that field is wrong. */
function reseal(image: Uint8Array, off: number): void {
  const v = new DataView(image.buffer, image.byteOffset, image.byteLength);
  const length = v.getUint32(off + 4, true);
  v.setUint32(off + 20, crc32(image.subarray(off + 24, off + 24 + length), crc32(image.subarray(off, off + 20))), true);
}

// --- the ADR's vector --------------------------------------------------------------

const VECTOR_HEADER = `
49 4e 57 49 52 45 4d 4a 01 00 01 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e2 31 78 45`;
const VECTOR_ENTRY_1 = `
49 57 4a 45 1c 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 fe 88 ca 1b
7b 68 e5 cf 8b 01 00 00 c0 00 02 0a 07 08 c0 00 02 01 50 c3 00 00 00 00 00 05 00 00`;
const VECTOR_ENTRY_2 = `
49 57 4a 45 12 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 9c 76 68 a6
7b 22 61 63 74 69 6f 6e 22 3a 22 73 74 61 72 74 22 7d`;

test('CRC-32/ISO-HDLC check value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
  const a = new TextEncoder().encode('1234');
  const b = new TextEncoder().encode('56789');
  assert.equal(crc32(b, crc32(a)), 0xcbf43926, 'continuing a CRC over a second span');
});

test('ADR 0059 vector: file header, byte for byte', () => {
  const generation = Uint8Array.from({ length: 16 }, (_, i) => i);
  const header = encodeFileHeader(JOURNAL_FRAMING, { generation, createdMs: 1_700_000_000_000 });
  assert.equal(hex(header), hex(fromHex(VECTOR_HEADER)));
  const back = decodeFileHeader(JOURNAL_FRAMING, header);
  assert.ok(back.ok);
  if (back.ok) {
    assert.equal(back.formatVersion, 1);
    assert.equal(back.policyVersion, 1);
    assert.equal(hex(back.generation), hex(generation));
    assert.equal(back.createdMs, 1_700_000_000_000);
  }
});

test('ADR 0059 vector: datagram entry and boundary entry, byte for byte', () => {
  const body = encodeDatagramBody({
    receivedMs: 1_700_000_000_123, localIPv4: '192.0.2.10', localPort: 2055,
    remoteIPv4: '192.0.2.1', remotePort: 50000, payload: Uint8Array.from([0, 5, 0, 0]),
  });
  const e1 = encodeEntry(JOURNAL_FRAMING, 1, KIND_DATAGRAM, body);
  assert.equal(hex(e1), hex(fromHex(VECTOR_ENTRY_1)));
  const e2 = encodeEntry(JOURNAL_FRAMING, 2, KIND_BOUNDARY, new TextEncoder().encode('{"action":"start"}'));
  assert.equal(hex(e2), hex(fromHex(VECTOR_ENTRY_2)));

  // And back: the header, then the body, then the receipt metadata.
  const h = parseEntryHeader(JOURNAL_FRAMING, e1.subarray(0, 24));
  assert.ok(h.ok);
  if (h.ok) {
    assert.equal(h.bodyLength, 0x1c);
    assert.equal(h.entryId, 1);
    assert.equal(h.kind, KIND_DATAGRAM);
    assert.equal(crc32(e1.subarray(24), crc32(e1.subarray(0, 20))), h.crc);
  }
  const d = decodeDatagramBody(e1.subarray(24));
  assert.ok(d.ok);
  if (d.ok) {
    assert.equal(d.value.receivedMs, 1_700_000_000_123);
    assert.equal(d.value.localIPv4, '192.0.2.10');
    assert.equal(d.value.localPort, 2055);
    assert.equal(d.value.remoteIPv4, '192.0.2.1');
    assert.equal(d.value.remotePort, 50000);
    assert.equal(hex(d.value.payload), '00 05 00 00');
  }
});

test('the codec refuses a declared body over the cap before reading it', () => {
  const header = new Uint8Array(24);
  const v = new DataView(header.buffer);
  v.setUint32(0, 0x454a5749, true);
  v.setUint32(4, LIMITS.maxBodyBytes + 1, true);
  v.setBigUint64(8, 1n, true);
  header[16] = KIND_DATAGRAM;
  const h = parseEntryHeader(JOURNAL_FRAMING, header);
  assert.equal(h.ok, false);
  assert.throws(() => encodeEntry(JOURNAL_FRAMING, 1, KIND_DATAGRAM, new Uint8Array(LIMITS.maxBodyBytes + 1)), RangeError);
  // The sidecar's own cap is 1 MiB, with the same framing.
  assert.ok(ROLLUP_FRAMING.maxBodyBytes >= 1 << 20);
  assert.equal(encodeEntry(ROLLUP_FRAMING, 1, 1, new Uint8Array(1 << 20)).length, 24 + (1 << 20));
});

test('a journal header and a sidecar header are not interchangeable', () => {
  const g = new Uint8Array(16);
  const rollup = encodeFileHeader(ROLLUP_FRAMING, { generation: g, createdMs: 5 });
  assert.equal(new TextDecoder().decode(rollup.subarray(0, 8)), 'INWIREMR');
  assert.equal(decodeFileHeader(JOURNAL_FRAMING, rollup).ok, false);
});

// --- helpers ---------------------------------------------------------------------------

const GEN_BYTES = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const GEN = hex(GEN_BYTES).replace(/ /g, '');
const T0 = 1_700_000_000_000;
const rnd = (n: number): Uint8Array => GEN_BYTES.slice(0, n);

function options(over: Partial<JournalOptions> = {}): JournalOptions {
  return { limitBytes: 1 << 30, randomBytes: rnd, nowMs: () => T0, ...over };
}
function dg(receivedMs: number, payload: Uint8Array | number[] = [1, 2, 3], remotePort = 50000): EvidenceInput {
  return {
    kind: 'datagram', receivedMs, localIPv4: '192.0.2.10', localPort: 2055,
    remoteIPv4: '192.0.2.1', remotePort, bytes: Uint8Array.from(payload),
  };
}
function bnd(action: BoundaryEvidence['action'], sessionId: string, receivedMs: number, reason = '', droppedDatagrams: number | null = null): EvidenceInput {
  return { kind: 'boundary', sessionId, receivedMs, action, reason, droppedDatagrams };
}

/** A file backend that can be reopened, loaded with bytes and measured. */
class Rig {
  file: BlockFile;
  constructor(readonly kind: 'memory' | 'disk', private readonly filePath: string | null) {
    this.file = kind === 'memory' ? new MemoryBlockFile() : NodeBlockFile.open(filePath!);
  }
  reopen(): BlockFile {
    if (this.kind === 'disk') {
      this.file.close();
      this.file = NodeBlockFile.open(this.filePath!);
    }
    return this.file;
  }
  load(bytes: Uint8Array): BlockFile {
    this.file.truncate(0);
    this.file.write(0, bytes);
    return this.reopen();
  }
}

const tmpRoot = mkdtempSync(path.join(tmpdir(), 'inwire-journal-'));
let rigCount = 0;
const openRigs: Rig[] = [];
function newRig(kind: 'memory' | 'disk'): Rig {
  const rig = new Rig(kind, kind === 'disk' ? path.join(tmpRoot, `f${rigCount++}`, 'file.bin') : null);
  openRigs.push(rig);
  return rig;
}

function open(file: BlockFile, over: Partial<JournalOptions> = {}) {
  return MonitoringJournal.open(file, options(over));
}

/** start, datagrams carrying payloads of the given sizes; no stop. */
function build(file: BlockFile, payloadSizes: number[], session = 'S1'): MonitoringJournal {
  const { journal } = open(file);
  const inputs: EvidenceInput[] = [bnd('start', session, T0 + 1)];
  payloadSizes.forEach((n, i) => inputs.push(dg(T0 + 10 + i, Uint8Array.from({ length: n }, (_, k) => (k + i) & 0xff))));
  const r = journal.append(inputs);
  assert.equal(r.refused, 0);
  return journal;
}

// --- the journal, over each backend -----------------------------------------------------

function journalCases(kind: 'memory' | 'disk'): void {
  const tag = (s: string) => `[${kind}] ${s}`;

  test(tag('an empty file gets a header; the generation comes from randomBytes and is fixed'), () => {
    const rig = newRig(kind);
    const { journal, recovery } = open(rig.file);
    assert.equal(recovery.status, 'empty');
    assert.equal(rig.file.size(), FILE_HEADER_BYTES);
    assert.equal(journal.snapshot().generation, GEN);
    assert.deepEqual(journal.snapshot(), { generation: GEN, throughEntryId: 0, writtenBytes: 64, syncedThroughEntryId: 0 });
    assert.equal(journal.state, 'open');
    // A non-empty file's generation is read, never replaced.
    const again = open(rig.reopen(), { randomBytes: () => new Uint8Array(16).fill(7) });
    assert.equal(again.journal.snapshot().generation, GEN);
    assert.equal(again.recovery.status, 'ok');
    assert.equal(again.recovery.generation, GEN);
  });

  test(tag('zero inputs: an empty append, a zero-length payload'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const before = journal.snapshot();
    const empty = journal.append([]);
    assert.deepEqual(empty, { snapshot: before, appended: 0, refused: 0, state: 'open' });
    assert.equal(journal.append([bnd('start', 'S1', T0)]).appended, 1);
    const r = journal.append([dg(T0 + 1, [])]);
    assert.equal(r.appended, 1);
    const got = journal.readEvidence({ generation: GEN, entryId: 2 }) as DatagramEvidence;
    assert.equal(got.bytes.length, 0);
  });

  test(tag('exact round trip through close and reopen, bytes included'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const payload = Uint8Array.from({ length: 300 }, (_, i) => (i * 7) & 0xff);
    const r = journal.append([
      bnd('start', 'S1', T0 + 5, 'user'),
      dg(T0 + 6, payload, 40001),
      bnd('gap', 'S1', T0 + 7, 'inbox full', 12),
      dg(T0 + 8, [9], 40002),
      bnd('stop', 'S1', T0 + 9, 'user', 3),
    ]);
    assert.equal(r.appended, 5);
    assert.equal(r.snapshot.throughEntryId, 5);
    const expected: Evidence[] = [
      { kind: 'boundary', ref: { generation: GEN, entryId: 1 }, sessionId: 'S1', receivedMs: T0 + 5, action: 'start', reason: 'user', droppedDatagrams: null },
      { kind: 'datagram', ref: { generation: GEN, entryId: 2 }, sessionId: 'S1', receivedMs: T0 + 6, receiveOrdinal: 2, localIPv4: '192.0.2.10', localPort: 2055, remoteIPv4: '192.0.2.1', remotePort: 40001, bytes: payload },
      { kind: 'boundary', ref: { generation: GEN, entryId: 3 }, sessionId: 'S1', receivedMs: T0 + 7, action: 'gap', reason: 'inbox full', droppedDatagrams: 12 },
      { kind: 'datagram', ref: { generation: GEN, entryId: 4 }, sessionId: 'S1', receivedMs: T0 + 8, receiveOrdinal: 4, localIPv4: '192.0.2.10', localPort: 2055, remoteIPv4: '192.0.2.1', remotePort: 40002, bytes: Uint8Array.from([9]) },
      { kind: 'boundary', ref: { generation: GEN, entryId: 5 }, sessionId: 'S1', receivedMs: T0 + 9, action: 'stop', reason: 'user', droppedDatagrams: 3 },
    ];
    const reopened = open(rig.reopen()).journal;
    expected.forEach((e) => assert.deepEqual(reopened.readEvidence(e.ref), e));
    assert.equal(reopened.snapshot().throughEntryId, 5);
    assert.deepEqual(reopened.readPage(reopened.snapshot(), 0, 100, 1 << 20).entries, expected);
    // The recovery view agrees with the open.
    const rec = recoverJournal(rig.file);
    assert.equal(rec.status, 'ok');
    assert.equal(rec.completeEntries, 5);
    assert.equal(rec.lastEntryId, 5);
    assert.equal(rec.validBytes, rig.file.size());
    assert.equal(rec.tornTail, null);
  });

  test(tag('a datagram with no open session is refused; a closed session closes it again'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    assert.deepEqual([journal.append([dg(T0)]).appended, journal.state], [0, 'open']);
    journal.append([bnd('start', 'S1', T0)]);
    assert.equal(journal.append([dg(T0 + 1)]).appended, 1);
    journal.append([bnd('stop', 'S1', T0 + 2)]);
    const r = journal.append([dg(T0 + 3)]);
    assert.equal(r.appended, 0);
    assert.equal(r.refused, 1);
    // A later session labels its own datagrams.
    journal.append([bnd('start', 'S2', T0 + 4), dg(T0 + 5)]);
    assert.equal((journal.readEvidence({ generation: GEN, entryId: 5 }) as DatagramEvidence).sessionId, 'S2');
    assert.equal((journal.readEvidence({ generation: GEN, entryId: 2 }) as DatagramEvidence).sessionId, 'S1');
  });

  test(tag('maximum payload accepted, one byte more refused; refusal is per entry'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    journal.append([bnd('start', 'S1', T0)]);
    const max = new Uint8Array(LIMITS.maxPayloadBytes).fill(0xab);
    const over = new Uint8Array(LIMITS.maxPayloadBytes + 1);
    const r = journal.append([dg(T0 + 1, max), dg(T0 + 2, over), dg(T0 + 3, [1])]);
    assert.deepEqual([r.appended, r.refused, r.state], [2, 1, 'open']);
    assert.equal(r.snapshot.throughEntryId, 3, 'ids stay dense: the refused one took none');
    const got = open(rig.reopen()).journal.readEvidence({ generation: GEN, entryId: 2 }) as DatagramEvidence;
    assert.equal(got.bytes.length, LIMITS.maxPayloadBytes);
    assert.equal(got.bytes[LIMITS.maxPayloadBytes - 1], 0xab);
    // Malformed addresses are refused rather than thrown at the caller.
    const bad = journal.append([{ ...dg(T0 + 4), remoteIPv4: '300.1.1.1' } as EvidenceInput]);
    assert.deepEqual([bad.appended, bad.refused], [0, 1]);
  });

  test(tag('every torn-tail offset inside the last entry keeps exactly the complete prefix'), () => {
    const rig = newRig(kind);
    const journal = build(rig.file, [10, 0, 100]);
    assert.equal(journal.snapshot().throughEntryId, 4);
    const full = readAll(rig.file);
    const lastStart = full.length - (24 + 24 + 100);
    for (let cut = lastStart; cut < full.length; cut++) {
      const file = rig.load(full.subarray(0, cut));
      const { journal: j, recovery } = open(file);
      assert.equal(recovery.status, 'ok', `cut ${cut}`);
      assert.equal(recovery.completeEntries, 3, `cut ${cut}`);
      assert.equal(recovery.lastEntryId, 3, `cut ${cut}`);
      assert.equal(recovery.validBytes, lastStart, `cut ${cut}`);
      assert.deepEqual(recovery.tornTail, cut === lastStart ? null : { fromOffset: lastStart, bytes: cut - lastStart }, `cut ${cut}`);
      // The session was left open, so exactly one interrupted marker follows.
      const snap = j.snapshot();
      assert.equal(snap.throughEntryId, 4, `cut ${cut}`);
      const marker = j.readEvidence({ generation: GEN, entryId: 4 }) as BoundaryEvidence;
      assert.deepEqual([marker.action, marker.sessionId, marker.droppedDatagrams], ['interrupted', 'S1', null]);
      assert.equal(marker.receivedMs, T0 + 11, 'the last surviving entry\'s own receipt time');
      const bytesAfterFirst = sha(readAll(file));
      const second = open(rig.reopen());
      assert.equal(second.journal.snapshot().throughEntryId, 4, `idempotent at ${cut}`);
      assert.equal(second.recovery.tornTail, null);
      assert.equal(sha(readAll(rig.file)), bytesAfterFirst, `a second open changes nothing at ${cut}`);
    }
    // Uncut, for contrast: nothing is torn and the marker comes after the last entry.
    const whole = open(rig.load(full));
    assert.equal(whole.recovery.completeEntries, 4);
    assert.equal(whole.journal.snapshot().throughEntryId, 5);
  });

  test(tag('every torn offset inside the file header leaves an empty journal, then a stable one'), () => {
    const rig = newRig(kind);
    open(rig.file);
    const header = readAll(rig.file);
    assert.equal(header.length, 64);
    for (let cut = 0; cut < 64; cut++) {
      const file = rig.load(header.subarray(0, cut));
      const rec = recoverJournal(file);
      assert.equal(rec.status, 'empty', `cut ${cut}`);
      assert.equal(rec.generation, null);
      assert.deepEqual(rec.tornTail, cut === 0 ? null : { fromOffset: 0, bytes: cut }, `cut ${cut}`);
      assert.equal(file.size(), cut, 'recoverJournal never truncates');
      const first = open(file, { randomBytes: () => new Uint8Array(16).fill(cut & 0xff) });
      assert.equal(first.journal.state, 'open');
      assert.equal(file.size(), 64, `cut ${cut}`);
      const gen = first.journal.snapshot().generation;
      const second = open(rig.reopen(), { randomBytes: () => new Uint8Array(16).fill(0xee) });
      assert.equal(second.journal.snapshot().generation, gen, `generation is fixed once written (cut ${cut})`);
      assert.equal(second.recovery.status, 'ok');
    }
    // Bytes that are not the start of our header are not ours to discard.
    const foreign = rig.load(new TextEncoder().encode('hello, world'));
    const refused = open(foreign);
    assert.equal(refused.journal.state, 'refused-corrupt');
    assert.equal(foreign.size(), 12);
  });

  test(tag('a bad torn-extent entry with a failing CRC at the very end is a torn tail'), () => {
    const rig = newRig(kind);
    build(rig.file, [10, 20]);
    const full = readAll(rig.file);
    full[full.length - 1] ^= 0xff;
    const file = rig.load(full);
    const { recovery, journal } = open(file);
    assert.equal(recovery.status, 'ok');
    assert.equal(recovery.completeEntries, 2);
    assert.equal(recovery.tornTail?.bytes, 24 + 24 + 20);
    assert.equal(journal.state, 'open');
  });

  test(tag('interior corruption: bad frame magic and bad interior CRC preserve the file and refuse append'), () => {
    for (const how of ['magic', 'crc', 'length'] as const) {
      const rig = newRig(kind);
      build(rig.file, [10, 20, 30, 40]);
      const full = readAll(rig.file);
      // Entry 4 (the second datagram), with entry 5 behind it.
      let off = 64;
      for (let id = 1; id < 4; id++) {
        const h = parseEntryHeader(JOURNAL_FRAMING, full.subarray(off, off + 24));
        assert.ok(h.ok);
        off += 24 + (h.ok ? h.bodyLength : 0);
      }
      if (how === 'magic') full[off] ^= 0xff;
      if (how === 'crc') full[off + 30] ^= 0x01;
      if (how === 'length') new DataView(full.buffer).setUint32(off + 4, LIMITS.maxBodyBytes + 1, true);
      const file = rig.load(full);
      const before = sha(readAll(file));
      const { journal, recovery } = open(file);
      assert.equal(sha(readAll(file)), before, `${how}: the file is not touched`);
      assert.equal(recovery.status, 'corrupt', how);
      assert.equal(recovery.completeEntries, 3, how);
      assert.equal(recovery.validBytes, off, how);
      assert.equal(recovery.tornTail, null, how);
      assert.ok(recovery.problem && recovery.problem.length > 0, how);
      assert.equal(journal.state, 'refused-corrupt', how);
      const snap = journal.snapshot();
      assert.equal(snap.throughEntryId, 3, how);
      assert.equal(journal.readPage(snap, 0, 100, 1 << 20).entries.length, 3, `${how}: history before the bad entry stays readable`);
      const r = journal.append([bnd('start', 'S9', T0)]);
      assert.deepEqual([r.appended, r.refused, r.state], [0, 1, 'refused-corrupt'], how);
      assert.equal(sha(readAll(file)), before, `${how}: a refused append wrote nothing`);
    }
  });

  test(tag('a corrupted interior length is corruption, never a torn tail (extent past EOF, mid-file, inside a bad-CRC extent)'), () => {
    const cases = ['past EOF, in cap', 'lands mid-file on non-entry bytes', 'bad CRC whose extent holds a valid entry'] as const;
    for (const how of cases) {
      const rig = newRig(kind);
      build(rig.file, [10, 20, 30, 40]);
      let full = readAll(rig.file);
      const starts = entryStarts(full);
      const off2 = starts[1];
      if (how === 'past EOF, in cap') {
        // The reviewer's probe: entry 2's length rewritten to 60000, in cap, past the end of a ~400 byte file.
        new DataView(full.buffer).setUint32(off2 + 4, 60_000, true);
      } else if (how === 'lands mid-file on non-entry bytes') {
        new DataView(full.buffer).setUint32(off2 + 4, 40, true);
      } else {
        // A last entry whose own checksum is wrong and whose body is a complete, valid entry.
        const inner = encodeEntry(JOURNAL_FRAMING, 6, KIND_BOUNDARY, new TextEncoder().encode(JSON.stringify({ action: 'gap', sessionId: 'S1', receivedMs: T0 })));
        const outer = encodeEntry(JOURNAL_FRAMING, 6, KIND_DATAGRAM, inner);
        new DataView(outer.buffer).setUint32(20, 0x12345678, true);
        const joined = new Uint8Array(full.length + outer.length);
        joined.set(full, 0);
        joined.set(outer, full.length);
        full = joined;
      }
      const file = rig.load(full);
      const before = sha(readAll(file));
      const { journal, recovery } = open(file);
      assert.equal(recovery.status, 'corrupt', how);
      assert.equal(recovery.tornTail, null, how);
      assert.ok(recovery.problem && recovery.problem.length > 0, how);
      assert.equal(journal.state, 'refused-corrupt', how);
      assert.equal(sha(readAll(file)), before, `${how}: nothing is truncated`);
      if (how === 'past EOF, in cap') {
        assert.match(recovery.problem!, new RegExp(`offset ${off2}\\b.*follows at ${starts[2]}\\b`), 'the reason names both offsets');
        assert.equal(recovery.completeEntries, 1);
        assert.equal(recovery.validBytes, off2);
        assert.equal(journal.readPage(journal.snapshot(), 0, 100, 1 << 20).entries.length, 1, 'history before the bad entry stays readable');
      }
      const r = journal.append([bnd('start', 'S9', T0)]);
      assert.deepEqual([r.appended, r.refused, r.state], [0, 1, 'refused-corrupt'], how);
      assert.equal(sha(readAll(file)), before, `${how}: a refused append wrote nothing`);
    }
  });

  test(tag('an all-zero tail is torn and truncated; a zero run with a non-zero byte after it is corruption'), () => {
    for (const zeros of [1, 23, 24, 25, 4096]) {
      for (const sessionOpen of [true, false]) {
        const rig = newRig(kind);
        const journal = build(rig.file, [10, 20]);
        if (!sessionOpen) journal.append([bnd('stop', 'S1', T0 + 99)]);
        const valid = readAll(rig.file);
        const file = rig.load(Uint8Array.from([...valid, ...new Uint8Array(zeros)]));
        const rec = recoverJournal(file);
        assert.equal(rec.status, 'ok', `${zeros} zeros`);
        assert.deepEqual(rec.tornTail, { fromOffset: valid.length, bytes: zeros }, `${zeros} zeros`);
        const reopened = open(file);
        assert.equal(reopened.journal.state, 'open');
        // Start + two datagrams = 3 entries; a stop makes 4; an interrupted marker makes 4 as well.
        if (sessionOpen) assert.ok(file.size() > valid.length && file.size() < valid.length + 400, 'the zeros are gone, a marker follows');
        else assert.equal(file.size(), valid.length, 'the zeros are gone');
        assert.equal(reopened.journal.snapshot().throughEntryId, 4, `${zeros} zeros`);
        const last = reopened.journal.readEvidence({ generation: GEN, entryId: reopened.journal.snapshot().throughEntryId }) as BoundaryEvidence;
        assert.equal(last.action, sessionOpen ? 'interrupted' : 'stop', `${zeros} zeros: an interrupted marker only when a session was open`);
        assert.equal(sha(readAll(file).subarray(0, valid.length)), sha(valid), 'the valid part is untouched');
      }
    }
    // Zeros, then one non-zero byte: the zeros are not the whole story.
    const rig = newRig(kind);
    build(rig.file, [10, 20]);
    const valid = readAll(rig.file);
    const tail = new Uint8Array(4096);
    tail[tail.length - 1] = 1;
    const file = rig.load(Uint8Array.from([...valid, ...tail]));
    const before = sha(readAll(file));
    const { journal, recovery } = open(file);
    assert.equal(recovery.status, 'corrupt');
    assert.equal(recovery.tornTail, null);
    assert.equal(journal.state, 'refused-corrupt');
    assert.equal(sha(readAll(file)), before);
  });

  test(tag('a non-zero flags or reserved byte is corruption even under a valid CRC (entry header and datagram metadata)'), () => {
    const fields: [string, number][] = [
      ['entry flags (byte 17)', 17],
      ['entry reserved (byte 18)', 18],
      ['entry reserved (byte 19)', 19],
      ['datagram metadata reserved (body byte 20)', 24 + 20],
      ['datagram metadata reserved (body byte 23)', 24 + 23],
    ];
    for (const [name, rel] of fields) {
      // Entry 2 has entries behind it; entry 5 is the last in the file.
      for (const id of [2, 5]) {
        const rig = newRig(kind);
        build(rig.file, [10, 20, 30, 40]);
        const full = readAll(rig.file);
        const off = entryStarts(full)[id - 1];
        full[off + rel] = 0x01;
        reseal(full, off);
        const file = rig.load(full);
        const before = sha(readAll(file));
        const { journal, recovery } = open(file);
        assert.equal(recovery.status, 'corrupt', `${name} in entry ${id}`);
        assert.equal(recovery.tornTail, null, `${name} in entry ${id}`);
        assert.equal(recovery.completeEntries, id - 1, `${name} in entry ${id}`);
        assert.equal(journal.state, 'refused-corrupt', `${name} in entry ${id}`);
        assert.equal(sha(readAll(file)), before, `${name} in entry ${id}`);
      }
    }
    // The control: the same edit with a zero byte is the original file, and reads fine.
    const rig = newRig(kind);
    build(rig.file, [10, 20]);
    const full = readAll(rig.file);
    reseal(full, entryStarts(full)[1]);
    assert.equal(recoverJournal(rig.load(full)).status, 'ok');
  });

  test(tag('every boundary is held to the limit; a forced one that does not fit is not written and the session stays open'), () => {
    // 1. Boundaries that do not close a session stop short of the limit by the reserve, like datagrams.
    //    The reviewer's case: fill to just under limit - reserve, then many gaps, then a datagram.
    {
      const reserve = LIMITS.closingReserveBytes;
      const other = 500;
      const limit = reserve + 4_000;
      const ceiling = limit - reserve - other; // what the file itself may reach for anything but a close
      const rig = newRig(kind);
      const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
      journal.append([bnd('start', 'S1', T0)]);
      let datagrams = 0;
      while (rig.file.size() + 130 <= ceiling && datagrams < 1_000) {
        datagrams += journal.append([dg(T0 + 1, new Uint8Array(40))]).appended;
      }
      assert.ok(datagrams > 5 && journal.state === 'open', 'the journal is filled to just under the datagram ceiling');
      let gaps = 0;
      let refused = false;
      for (let i = 0; i < 2_000 && !refused; i++) {
        const before = rig.file.size();
        const r = journal.append([bnd('gap', 'S1', T0 + 2, 'x'.repeat(200), 5)]);
        if (r.appended === 1) {
          gaps++;
          assert.ok(rig.file.size() + other <= limit - reserve, 'an accepted gap never enters the reserve');
        } else {
          refused = true;
          assert.equal(r.state, 'storage-limit');
          assert.ok(before + other <= limit - reserve, 'the refusal came before the reserve was touched');
        }
      }
      assert.ok(refused, 'gaps are refused once they would enter the reserve');
      assert.ok(gaps < 100, 'a gap does not run on to the limit');
      const last = journal.readEvidence({ generation: GEN, entryId: journal.snapshot().throughEntryId }) as BoundaryEvidence;
      assert.deepEqual([last.action, last.reason, last.sessionId], ['stop', 'storage-limit', 'S1'], 'the session is closed on disk');
      assert.ok(rig.file.size() + other <= limit, 'the dataset never exceeds the limit');
      const r = journal.append([dg(T0 + 3, new Uint8Array(40))]);
      assert.deepEqual([r.appended, r.refused, r.state], [0, 1, 'storage-limit']);
      assert.equal(open(rig.reopen(), { limitBytes: limit, otherBytes: () => other }).journal.snapshot().throughEntryId, r.snapshot.throughEntryId, 'no interrupted marker: the stop closed it');
    }

    // 1b. start, suspend and resume are held to the same ceiling.
    for (const action of ['suspend', 'resume'] as const) {
      const reserve = LIMITS.closingReserveBytes;
      const limit = reserve + 2_000;
      const rig = newRig(kind);
      const { journal } = open(rig.file, { limitBytes: limit });
      journal.append([bnd('start', 'S1', T0)]);
      if (action === 'resume') journal.append([bnd('suspend', 'S1', T0 + 1)]);
      while (rig.file.size() + 130 <= limit - reserve) journal.append([dg(T0 + 2, new Uint8Array(40))]);
      while (journal.state === 'open' && journal.snapshot().throughEntryId < 10_000) {
        journal.append([bnd(action, 'S1', T0 + 3), bnd(action === 'suspend' ? 'resume' : 'suspend', 'S1', T0 + 4)]);
      }
      assert.equal(journal.state, 'storage-limit', action);
      const last = journal.readEvidence({ generation: GEN, entryId: journal.snapshot().throughEntryId }) as BoundaryEvidence;
      assert.deepEqual([last.action, last.reason], ['stop', 'storage-limit'], action);
      assert.ok(rig.file.size() <= limit);
    }

    // 1c. A user stop may use the reserve: inside it, it is written and the journal stays open for a new session.
    {
      const reserve = LIMITS.closingReserveBytes;
      const limit = reserve + 4_000;
      let other = 0;
      const rig = newRig(kind);
      const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
      journal.append([bnd('start', 'S1', T0)]);
      while (rig.file.size() + 130 <= limit - reserve) journal.append([dg(T0 + 1, new Uint8Array(40))]);
      other = limit - reserve - rig.file.size() + 100; // the journal is now 100 bytes inside the reserve
      const r = journal.append([bnd('stop', 'S1', T0 + 2)]);
      assert.deepEqual([r.appended, r.refused, r.state], [1, 0, 'open'], 'the user stop is written from the reserve');
      const last = journal.readEvidence({ generation: GEN, entryId: r.snapshot.throughEntryId }) as BoundaryEvidence;
      assert.deepEqual([last.action, last.reason], ['stop', '']);
      assert.ok(rig.file.size() + other <= limit, 'never past the limit');
      assert.equal(journal.append([bnd('start', 'S2', T0 + 3)]).appended, 0, 'a new session does not fit inside the reserve');
    }

    // 2. otherBytes grows mid-run past what the reserve can cover.
    {
      const limit = LIMITS.closingReserveBytes + 2_000;
      let other = 0;
      const rig = newRig(kind);
      const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
      journal.append([bnd('start', 'S1', T0)]);
      assert.equal(journal.append([dg(T0 + 1, new Uint8Array(100))]).appended, 1);
      const sizeBefore = rig.file.size();
      other = limit - sizeBefore - 5; // 5 bytes of room: not enough for any boundary
      const r = journal.append([dg(T0 + 2, new Uint8Array(100))]);
      assert.deepEqual([r.appended, r.refused, r.state], [0, 1, 'storage-limit']);
      assert.equal(rig.file.size(), sizeBefore, 'the stop did not fit, so it was not written');
      assert.ok(rig.file.size() + other <= limit, 'the dataset never exceeds the limit');
      assert.equal(journal.append([bnd('stop', 'S1', T0 + 3)]).appended, 0, 'nothing more is accepted');
      // The session is open on disk. With no room the next open writes nothing and says storage-limit...
      const cramped = open(rig.reopen(), { limitBytes: limit, otherBytes: () => other });
      assert.equal(cramped.journal.state, 'storage-limit');
      assert.equal(rig.file.size(), sizeBefore);
      // ...and with room it writes the interrupted marker a crash would have.
      other = 0;
      const roomy = open(rig.reopen(), { limitBytes: limit, otherBytes: () => other });
      assert.equal(roomy.journal.state, 'open');
      const marker = roomy.journal.readEvidence({ generation: GEN, entryId: roomy.journal.snapshot().throughEntryId }) as BoundaryEvidence;
      assert.deepEqual([marker.action, marker.sessionId], ['interrupted', 'S1']);
    }
  });

  // A header written in pieces into a preallocated file: some of its bytes, then
  // zeros to EOF. Built from a real entry so the leading bytes are really a header's.
  test(tag('a torn header (some header bytes, then zeros to EOF) is a torn tail and recovers'), () => {
    for (const kept of [1, 2, 4]) {
      const rig = newRig(kind);
      build(rig.file, [10, 20, 30]);
      const full = readAll(rig.file);
      const last = entryStarts(full).at(-1)!;
      const zeros = 200;
      const image = Uint8Array.from([...full.subarray(0, last + kept), ...new Uint8Array(zeros)]);
      assert.equal(parseEntryHeader(JOURNAL_FRAMING, image.subarray(last, last + 24)).ok, false, 'the header is one that fails to parse');
      const file = rig.load(image);
      const rec = recoverJournal(file);
      assert.equal(rec.status, 'ok', `${kept} header bytes`);
      assert.equal(rec.completeEntries, 3, `${kept} header bytes`);
      assert.deepEqual(rec.tornTail, { fromOffset: last, bytes: kept + zeros }, `${kept} header bytes`);
      const { journal } = open(file);
      assert.equal(journal.state, 'open', `${kept} header bytes`);
      assert.equal(journal.snapshot().throughEntryId >= 3, true);
      assert.equal(sha(readAll(file).subarray(0, last)), sha(full.subarray(0, last)), 'the valid part is untouched');
    }
  });

  test(tag('a header that fails to parse with garbage after it stays refused-corrupt, and nothing is written'), () => {
    const rig = newRig(kind);
    build(rig.file, [10, 20, 30]);
    const full = readAll(rig.file);
    const last = entryStarts(full).at(-1)!;
    // Header bytes, zeros to the end of the header, then a non-zero byte past it.
    const tail = new Uint8Array(24 + 40);
    tail.set(full.subarray(last, last + 4), 0);
    tail[tail.length - 1] = 0x55;
    const file = rig.load(Uint8Array.from([...full.subarray(0, last), ...tail]));
    const before = sha(readAll(file));
    const { journal, recovery } = open(file);
    assert.equal(recovery.status, 'corrupt');
    assert.equal(recovery.tornTail, null);
    assert.equal(journal.state, 'refused-corrupt');
    assert.equal(sha(readAll(file)), before);
  });

  test(tag('a header that fails to parse, zeros, and then a valid entry stays refused-corrupt'), () => {
    const rig = newRig(kind);
    build(rig.file, [10, 20, 30]);
    const full = readAll(rig.file);
    const last = entryStarts(full).at(-1)!;
    const entry = full.subarray(last);
    const image = Uint8Array.from([...full.subarray(0, last), ...entry.subarray(0, 4), ...new Uint8Array(40), ...entry]);
    const file = rig.load(image);
    const before = sha(readAll(file));
    const { journal, recovery } = open(file);
    assert.equal(recovery.status, 'corrupt');
    assert.equal(recovery.tornTail, null);
    assert.equal(journal.state, 'refused-corrupt');
    assert.equal(sha(readAll(file)), before);
  });

  test(tag('setLimit changes the ceiling in place: a closed-by-limit journal takes Start again, nothing is rescanned'), () => {
    const reserve = LIMITS.closingReserveBytes;
    const other = 500;
    const limit = reserve + 4_000;
    const rig = newRig(kind);
    const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
    journal.append([bnd('start', 'S1', T0)]);
    for (let i = 0; i < 1_000 && journal.state === 'open'; i++) journal.append([dg(T0 + 1, new Uint8Array(40))]);
    assert.equal(journal.state, 'storage-limit');
    assert.equal(journal.limitBytes, limit);
    const sizeAtLimit = rig.file.size();
    // Not enough room: the same ceiling, or one too close, changes nothing about the state.
    journal.setLimit(limit);
    assert.equal(journal.state, 'storage-limit');
    journal.setLimit(sizeAtLimit + other + reserve);
    assert.equal(journal.state, 'storage-limit', 'a ceiling with no room past the reserve is not room');
    // Room: the state moves back, the same object appends, the closed session needs no marker.
    journal.setLimit(limit * 4);
    assert.equal(journal.state, 'open');
    assert.equal(journal.limitBytes, limit * 4);
    assert.equal(rig.file.size(), sizeAtLimit, 'raising the ceiling wrote nothing: the session was closed by a stop');
    assert.equal(journal.append([bnd('start', 'S2', T0 + 5)]).appended, 1);
    assert.equal(journal.append([dg(T0 + 6, [1])]).appended, 1);
    // Lowering it below what is held closes the door again at the next write.
    journal.setLimit(sizeAtLimit);
    assert.equal(journal.append([dg(T0 + 7, [1])]).appended, 0);
    assert.equal(journal.state, 'storage-limit');
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => journal.setLimit(bad), RangeError, `limit ${bad}`);
    }
  });

  test(tag('setLimit on a session the limit could not close writes the interrupted marker a crash would have'), () => {
    const limit = LIMITS.closingReserveBytes + 2_000;
    let other = 0;
    const rig = newRig(kind);
    const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
    journal.append([bnd('start', 'S1', T0)]);
    journal.append([dg(T0 + 1, new Uint8Array(100))]);
    other = limit - rig.file.size() - 5;
    assert.equal(journal.append([dg(T0 + 2, new Uint8Array(100))]).refused, 1);
    assert.equal(journal.state, 'storage-limit');
    other = 0;
    journal.setLimit(limit * 2);
    assert.equal(journal.state, 'open');
    const marker = journal.readEvidence({ generation: GEN, entryId: journal.snapshot().throughEntryId }) as BoundaryEvidence;
    assert.deepEqual([marker.action, marker.sessionId], ['interrupted', 'S1']);
    assert.equal(journal.append([bnd('start', 'S2', T0 + 9)]).appended, 1, 'the new session is accepted behind the marker');
  });

  test(tag('readPage refuses arguments that are not integers in range (they will arrive over IPC)'), () => {
    const rig = newRig(kind);
    const journal = build(rig.file, [1, 2, 3]);
    const snap = journal.snapshot();
    for (const bad of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
      assert.throws(() => journal.readPage(snap, bad, 10, 1 << 20), RangeError, `afterId ${bad}`);
    }
    for (const bad of [Number.NaN, 0, -1, 1.5, Number.POSITIVE_INFINITY]) {
      assert.throws(() => journal.readPage(snap, 0, bad, 1 << 20), RangeError, `maxEntries ${bad}`);
      assert.throws(() => journal.readPage(snap, 0, 10, bad), RangeError, `maxBytes ${bad}`);
    }
    assert.equal(journal.readPage(snap, 0, 10, 1 << 20).entries.length, 4, 'afterId 0 is the start');
  });

  test(tag('session consistency at append: refused without a write, counted, and the read side still accepts what a file holds'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const attempt = (inputs: EvidenceInput[], name: string) => {
      const before = sha(readAll(rig.file));
      const snap = journal.snapshot();
      const r = journal.append(inputs);
      assert.deepEqual([r.appended, r.refused, r.state], [0, inputs.length, 'open'], name);
      assert.deepEqual(r.snapshot, snap, name);
      assert.equal(sha(readAll(rig.file)), before, `${name}: nothing written`);
    };
    // No session open.
    for (const action of ['stop', 'suspend', 'resume', 'interrupted'] as const) attempt([bnd(action, 'S1', T0)], `${action} with no session`);
    assert.equal(journal.append([bnd('start', 'S1', T0)]).appended, 1);
    // A session is open.
    attempt([bnd('start', 'S2', T0 + 1)], 'start while a session is open');
    attempt([bnd('start', 'S1', T0 + 1)], 'a second start of the same session');
    for (const action of ['stop', 'suspend', 'resume', 'interrupted'] as const) attempt([bnd(action, 'S2', T0 + 1)], `${action} naming another session`);
    // The legitimate sequence still works, in order.
    const ok = journal.append([bnd('suspend', 'S1', T0 + 2), bnd('resume', 'S1', T0 + 3), dg(T0 + 4), bnd('stop', 'S1', T0 + 5)]);
    assert.deepEqual([ok.appended, ok.refused], [4, 0]);
    attempt([bnd('stop', 'S1', T0 + 6)], 'a second stop');
    assert.equal(journal.append([bnd('start', 'S2', T0 + 7)]).appended, 1, 'a new session after a stop');
    // The read side accepts what files contain: a double start, a stop naming nobody, a stop with nothing open.
    const json = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    const b = (action: string, sessionId: string) => json({ action, sessionId, receivedMs: T0, reason: '', droppedDatagrams: null });
    const entries = [
      encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, b('start', 'S1')),
      encodeEntry(JOURNAL_FRAMING, 2, KIND_BOUNDARY, b('start', 'S2')),
      encodeEntry(JOURNAL_FRAMING, 3, KIND_BOUNDARY, b('stop', 'ZZ')),
      encodeEntry(JOURNAL_FRAMING, 4, KIND_BOUNDARY, b('resume', 'S9')),
    ];
    const image = new Uint8Array(64 + entries.reduce((n, e) => n + e.length, 0));
    image.set(encodeFileHeader(JOURNAL_FRAMING, { generation: GEN_BYTES, createdMs: T0 }), 0);
    let at = 64;
    for (const e of entries) { image.set(e, at); at += e.length; }
    const rec = recoverJournal(newRig(kind).load(image));
    assert.equal(rec.status, 'ok', 'an existing file is never made corrupt by the writer\'s rules');
    assert.equal(rec.completeEntries, 4);
  });

  test(tag('a randomBytes of the wrong length is a RangeError before any write'), () => {
    for (const n of [0, 15, 17, 32]) {
      const rig = newRig(kind);
      assert.throws(() => open(rig.file, { randomBytes: () => new Uint8Array(n) }), RangeError, `length ${n}`);
      assert.equal(rig.file.size(), 0, `length ${n}: the file was not touched`);
    }
  });

  test(tag('corruption of meaning: skipped id, orphan datagram, bad boundary JSON are all preserved'), () => {
    const bodyOf = (n: number) => encodeDatagramBody({ receivedMs: T0, localIPv4: '1.1.1.1', localPort: 1, remoteIPv4: '2.2.2.2', remotePort: 2, payload: Uint8Array.from([n]) });
    const json = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    const header = encodeFileHeader(JOURNAL_FRAMING, { generation: GEN_BYTES, createdMs: T0 });
    const start = json({ action: 'start', sessionId: 'S1', receivedMs: T0, reason: '', droppedDatagrams: null });
    const cases: [string, Uint8Array[]][] = [
      ['skipped id', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, start), encodeEntry(JOURNAL_FRAMING, 3, KIND_DATAGRAM, bodyOf(1))]],
      ['repeated id', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, start), encodeEntry(JOURNAL_FRAMING, 1, KIND_DATAGRAM, bodyOf(1))]],
      ['datagram before any start', [encodeEntry(JOURNAL_FRAMING, 1, KIND_DATAGRAM, bodyOf(1))]],
      ['unknown action', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, json({ action: 'explode', sessionId: 'S1', receivedMs: T0 }))]],
      ['unparsable JSON', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, new TextEncoder().encode('{"action":'))]],
      ['wrong-typed sessionId', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, json({ action: 'start', sessionId: 7, receivedMs: T0 }))]],
      ['the ADR vector\'s sessionless start', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, new TextEncoder().encode('{"action":"start"}'))]],
      ['unknown kind', [encodeEntry(JOURNAL_FRAMING, 1, 9, start)]],
      ['datagram body shorter than its metadata', [encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, start), encodeEntry(JOURNAL_FRAMING, 2, KIND_DATAGRAM, new Uint8Array(10))]],
    ];
    for (const [name, entries] of cases) {
      const bytes = new Uint8Array(64 + entries.reduce((n, e) => n + e.length, 0));
      bytes.set(header, 0);
      let at = 64;
      for (const e of entries) { bytes.set(e, at); at += e.length; }
      const rig = newRig(kind);
      const file = rig.load(bytes);
      const before = sha(bytes);
      const { journal, recovery } = open(file);
      assert.equal(recovery.status, 'corrupt', name);
      assert.equal(journal.state, 'refused-corrupt', name);
      assert.equal(sha(readAll(file)), before, name);
    }
    // Missing optional fields default rather than corrupt.
    const rig = newRig(kind);
    const sparse = encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, json({ action: 'start', sessionId: 'S1', receivedMs: T0, extra: 'ignored' }));
    const bytes = new Uint8Array(64 + sparse.length);
    bytes.set(header, 0);
    bytes.set(sparse, 64);
    const { journal, recovery } = open(rig.load(bytes));
    assert.equal(recovery.status, 'ok');
    const b = journal.readEvidence({ generation: GEN, entryId: 1 }) as BoundaryEvidence;
    assert.deepEqual([b.reason, b.droppedDatagrams], ['', null]);
  });

  test(tag('unknown format version and unknown decoder-policy version: preserved and refused'), () => {
    for (const [name, over] of [['format', { formatVersion: FORMAT_VERSION + 1 }], ['policy', { policyVersion: DECODER_POLICY_VERSION + 1 }]] as const) {
      const rig = newRig(kind);
      const header = encodeFileHeader(JOURNAL_FRAMING, { generation: GEN_BYTES, createdMs: T0, ...over });
      const tail = encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, new TextEncoder().encode('whatever a future decoder wrote'));
      const bytes = new Uint8Array(64 + tail.length);
      bytes.set(header, 0);
      bytes.set(tail, 64);
      const file = rig.load(bytes);
      const before = sha(bytes);
      const rec = recoverJournal(file);
      assert.equal(rec.status, 'unknown-version', name);
      assert.ok(rec.problem, name);
      const { journal, recovery } = open(file);
      assert.equal(recovery.status, 'unknown-version', name);
      assert.equal(journal.state, 'refused-version', name);
      assert.equal(sha(readAll(file)), before, name);
      const r = journal.append([bnd('start', 'S1', T0)]);
      assert.deepEqual([r.appended, r.refused, r.state], [0, 1, 'refused-version'], name);
      assert.equal(sha(readAll(file)), before, name);
      assert.equal(journal.readEvidence({ generation: GEN, entryId: 1 }), null, 'never reinterpreted under another policy');
    }
  });

  test(tag('a write error mid-append: truncate back, fail, snapshot as before the failing entry'), () => {
    for (const partial of [false, true]) {
      const rig = newRig(kind);
      const faulty = new FaultyFile(rig.file);
      const { journal } = open(faulty);
      journal.append([bnd('start', 'S1', T0)]);
      const before = journal.snapshot();
      const sizeBefore = faulty.size();
      faulty.failAtWrite = faulty.writes + 2;
      faulty.partial = partial;
      const r = journal.append([dg(T0 + 1), dg(T0 + 2), dg(T0 + 3)]);
      assert.equal(r.state, 'failed');
      assert.equal(r.appended, 1);
      assert.equal(r.refused, 2);
      assert.equal(r.snapshot.throughEntryId, before.throughEntryId + 1, 'the entry before the failing one stands');
      assert.equal(faulty.size(), sizeBefore + 24 + 24 + 3, `partial=${partial}: truncated back to the last complete entry`);
      const stuck = journal.append([dg(T0 + 4)]);
      assert.deepEqual([stuck.appended, stuck.refused, stuck.state], [0, 1, 'failed']);
      assert.deepEqual(stuck.snapshot, r.snapshot);
      // What is on disk is a clean journal of two entries.
      const reopened = open(rig.reopen());
      assert.equal(reopened.recovery.completeEntries, 2);
      assert.equal(reopened.recovery.tornTail, null);
    }
  });

  test(tag('a flush error: failed, written and synced watermarks unchanged'), () => {
    const rig = newRig(kind);
    const faulty = new FaultyFile(rig.file);
    const { journal } = open(faulty);
    journal.append([bnd('start', 'S1', T0), dg(T0 + 1)]);
    assert.equal(journal.snapshot().syncedThroughEntryId, 0, 'an append is never called durable');
    const ok = journal.flush();
    assert.equal(ok.syncedThroughEntryId, 2);
    journal.append([dg(T0 + 2)]);
    assert.deepEqual([journal.snapshot().throughEntryId, journal.snapshot().syncedThroughEntryId], [3, 2]);
    faulty.failFlush = true;
    const after = journal.flush();
    assert.equal(journal.state, 'failed');
    assert.deepEqual(after, { ...journal.snapshot() });
    assert.deepEqual([after.throughEntryId, after.syncedThroughEntryId], [3, 2]);
    assert.equal(journal.append([dg(T0 + 3)]).appended, 0);
  });

  test(tag('storage limit counts the sidecar; datagrams stop at limit - reserve; a stop boundary closes the session'), () => {
    const limit = LIMITS.closingReserveBytes + 6_000;
    const run = (other: number) => {
      const rig = newRig(kind);
      const { journal } = open(rig.file, { limitBytes: limit, otherBytes: () => other });
      journal.append([bnd('start', 'S1', T0)]);
      let admitted = 0;
      let last = journal.snapshot();
      for (let i = 0; i < 20; i++) {
        const r = journal.append([dg(T0 + 1 + i, new Uint8Array(1000))]);
        admitted += r.appended;
        last = r.snapshot;
        if (r.state !== 'open') break;
      }
      return { rig, journal, admitted, last };
    };
    const small = run(0);
    const big = run(2_000);
    assert.ok(small.admitted > big.admitted, 'the sidecar\'s bytes count against the same limit');
    for (const [r, other] of [[small, 0], [big, 2_000]] as const) {
      assert.equal(r.journal.state, 'storage-limit');
      assert.ok(r.rig.file.size() + other <= limit, 'never past the limit');
      const stop = r.journal.readEvidence({ generation: GEN, entryId: r.last.throughEntryId }) as BoundaryEvidence;
      assert.deepEqual([stop.kind, stop.action, stop.reason, stop.sessionId], ['boundary', 'stop', 'storage-limit', 'S1']);
      // Evidence committed before the limit is intact and readable.
      const page = r.journal.readPage(r.last, 0, 1000, 1 << 24);
      assert.equal(page.entries.length, r.last.throughEntryId);
      assert.equal(page.entries.filter((e) => e.kind === 'datagram').length, r.admitted);
      const sizeBefore = r.rig.file.size();
      const later = r.journal.append([dg(T0 + 100), bnd('start', 'S2', T0 + 101)]);
      assert.deepEqual([later.appended, later.refused, later.state], [0, 2, 'storage-limit']);
      assert.equal(r.rig.file.size(), sizeBefore);
      // The exact edge: one more datagram would have crossed limit - reserve.
      assert.ok(sizeBefore - (24 + 24 + 0 + 0) + other < limit);
    }
    // A reopen finds a stopped session, so it adds no interrupted marker.
    const reopened = open(small.rig.reopen(), { limitBytes: limit });
    assert.equal(reopened.journal.snapshot().throughEntryId, small.last.throughEntryId);
  });

  test(tag('storage limit edge: admitted while total + entry <= limit - reserve, refused one byte over'), () => {
    const entryBytes = 24 + 24 + 100;
    // Measure the start boundary, then build a limit that admits exactly two datagrams after it.
    const probe = open(newRig(kind).file).journal;
    const startBytes = probe.append([bnd('start', 'S1', T0)]).snapshot.writtenBytes - 64;
    const rig2 = newRig(kind);
    const exact = 64 + startBytes + 2 * entryBytes + LIMITS.closingReserveBytes;
    const j2 = open(rig2.file, { limitBytes: exact }).journal;
    j2.append([bnd('start', 'S1', T0)]);
    const r = j2.append([dg(T0 + 1, new Uint8Array(100)), dg(T0 + 2, new Uint8Array(100)), dg(T0 + 3, new Uint8Array(100))]);
    assert.equal(r.appended, 2);
    assert.equal(r.state, 'storage-limit');
    const rig3 = newRig(kind);
    const j3 = open(rig3.file, { limitBytes: exact - 1 }).journal;
    j3.append([bnd('start', 'S1', T0)]);
    const r3 = j3.append([dg(T0 + 1, new Uint8Array(100)), dg(T0 + 2, new Uint8Array(100))]);
    assert.equal(r3.appended, 1, 'one byte under the edge admits one fewer');
  });

  test(tag('generation: readEvidence answers null, readPage throws StaleGenerationError'), () => {
    const rig = newRig(kind);
    const journal = build(rig.file, [1, 2, 3]);
    const snap = journal.snapshot();
    assert.equal(journal.readEvidence({ generation: 'f'.repeat(32), entryId: 2 }), null);
    assert.equal(journal.readEvidence({ generation: GEN, entryId: 99 }), null);
    assert.equal(journal.readEvidence({ generation: GEN, entryId: 0 }), null);
    assert.throws(() => journal.readPage({ ...snap, generation: 'f'.repeat(32) }, 0, 10, 1 << 20), StaleGenerationError);
    assert.notEqual(journal.readEvidence({ generation: GEN, entryId: 2 }), null);
  });

  test(tag('pages: caps over the caller, a snapshot bounds the answer, an oversized entry goes alone'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    journal.append([bnd('start', 'S1', T0)]);
    const inputs: EvidenceInput[] = [];
    for (let i = 0; i < 600; i++) inputs.push(dg(T0 + 1 + i, [i & 0xff]));
    journal.append(inputs);
    const snap = journal.snapshot();
    assert.equal(snap.throughEntryId, 601);
    journal.append([dg(T0 + 9999, [1])]);
    let after = 0;
    let seen = 0;
    for (;;) {
      const page = journal.readPage(snap, after, 100_000, 1 << 30);
      assert.ok(page.entries.length <= LIMITS.pageEntries);
      page.entries.forEach((e, i) => assert.equal(e.ref.entryId, after + 1 + i));
      seen += page.entries.length;
      if (page.done) { assert.equal(page.nextAfterId, 601); break; }
      assert.equal(page.nextAfterId, after + page.entries.length);
      after = page.nextAfterId;
    }
    assert.equal(seen, 601, 'nothing past the snapshot');
    const some = journal.readPage(snap, 10, 5, 1 << 30);
    assert.deepEqual(some.entries.map((e) => e.ref.entryId), [11, 12, 13, 14, 15]);
    assert.equal(some.done, false);
    const tiny = journal.readPage(snap, 10, 50, 1);
    assert.deepEqual(tiny.entries.map((e) => e.ref.entryId), [11], 'an entry over maxBytes is returned alone');
    const end = journal.readPage(snap, 601, 10, 1 << 20);
    assert.deepEqual([end.entries.length, end.done, end.nextAfterId], [0, true, 601]);
    // Random access across the sparse index's checkpoints.
    for (const id of [1, INDEX_STRIDE, INDEX_STRIDE + 1, INDEX_STRIDE * 2 + 1, 601]) {
      assert.equal(journal.readEvidence({ generation: GEN, entryId: id })?.ref.entryId, id);
    }
    const mid = journal.readEvidence({ generation: GEN, entryId: 300 }) as DatagramEvidence;
    assert.equal(mid.sessionId, 'S1');
    assert.equal(mid.bytes[0], 298 & 0xff);
  });

  test(tag('a clock stepping back keeps ids rising and every record readable in id order'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const times = [T0 + 5000, T0 + 4000, T0 + 6000, T0 + 100, T0 + 100, T0 + 7000];
    const r = journal.append([bnd('start', 'S1', T0 + 4000), ...times.map((t, i) => dg(t, [i]))]);
    assert.equal(r.appended, 7);
    const page = open(rig.reopen()).journal.readPage(r.snapshot, 0, 100, 1 << 20);
    assert.deepEqual(page.entries.map((e) => e.ref.entryId), [1, 2, 3, 4, 5, 6, 7]);
    assert.deepEqual(page.entries.slice(1).map((e) => (e as DatagramEvidence).receivedMs), times);
    assert.deepEqual(page.entries.slice(1).map((e) => (e as DatagramEvidence).receiveOrdinal), [2, 3, 4, 5, 6, 7]);
  });

  test(tag('an interrupted marker is appended on reopen, once, and never invents a count'), () => {
    const rig = newRig(kind);
    const journal = build(rig.file, [5, 5]);
    const last = journal.snapshot().throughEntryId;
    const first = open(rig.reopen());
    assert.equal(first.journal.snapshot().throughEntryId, last + 1);
    const marker = first.journal.readEvidence({ generation: GEN, entryId: last + 1 }) as BoundaryEvidence;
    assert.deepEqual(
      [marker.action, marker.sessionId, marker.receivedMs, marker.droppedDatagrams],
      ['interrupted', 'S1', T0 + 11, null],
    );
    assert.equal(first.journal.append([dg(T0 + 50)]).appended, 0, 'interrupted closed the session');
    const second = open(rig.reopen());
    assert.equal(second.journal.snapshot().throughEntryId, last + 1, 'reopening again appends nothing');
    // A cleanly stopped session gets none.
    const clean = newRig(kind);
    const j = open(clean.file).journal;
    j.append([bnd('start', 'S1', T0), bnd('stop', 'S1', T0 + 1)]);
    assert.equal(open(clean.reopen()).journal.snapshot().throughEntryId, 2);
  });

  test(tag('watermarks: appended moves with the append, synced only with a successful flush'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const a = journal.append([bnd('start', 'S1', T0), dg(T0 + 1)]);
    assert.deepEqual([a.snapshot.throughEntryId, a.snapshot.syncedThroughEntryId], [2, 0]);
    assert.equal(a.snapshot.writtenBytes, rig.file.size());
    const f = journal.flush();
    assert.deepEqual([f.throughEntryId, f.syncedThroughEntryId], [2, 2]);
    const b = journal.append([dg(T0 + 2)]);
    assert.deepEqual([b.snapshot.throughEntryId, b.snapshot.syncedThroughEntryId], [3, 2]);
    journal.close();
    assert.equal(journal.state, 'closed');
    const c = journal.append([dg(T0 + 3)]);
    assert.deepEqual([c.appended, c.state], [0, 'closed']);
  });
}

class FaultyFile implements BlockFile {
  writes = 0;
  failAtWrite = Infinity;
  partial = false;
  failFlush = false;
  constructor(private readonly inner: BlockFile) {}
  read(offset: number, into: Uint8Array): number { return this.inner.read(offset, into); }
  write(offset: number, from: Uint8Array): void {
    this.writes++;
    if (this.writes === this.failAtWrite) {
      if (this.partial) this.inner.write(offset, from.subarray(0, Math.floor(from.length / 2)));
      throw new Error('simulated disk error');
    }
    this.inner.write(offset, from);
  }
  truncate(length: number): void { this.inner.truncate(length); }
  flush(): void { if (this.failFlush) throw new Error('simulated flush error'); this.inner.flush(); }
  size(): number { return this.inner.size(); }
  close(): void { this.inner.close(); }
}

// --- the sparse index -------------------------------------------------------------------

test('EntryIndex: checkpoints every INDEX_STRIDE entries, seek answers the nearest at or before', () => {
  const ix = new EntryIndex();
  for (let id = 1; id <= INDEX_STRIDE * 3 + 5; id++) ix.note(id, 1000 + id * 10, id === 1 ? null : 'S', 5000 + id);
  assert.equal(ix.checkpoints, 4);
  assert.deepEqual(ix.seek(1), { entryId: 1, offset: 1010, openSession: null });
  assert.equal(ix.seek(INDEX_STRIDE)?.entryId, 1);
  assert.equal(ix.seek(INDEX_STRIDE + 1)?.entryId, INDEX_STRIDE + 1);
  assert.equal(ix.seek(INDEX_STRIDE * 3 + 5)?.entryId, INDEX_STRIDE * 3 + 1);
  assert.equal(new EntryIndex().seek(1), null);
});

// --- the rollup codec -----------------------------------------------------------------------

const BIG = 2n ** 60n + 7n;
function rollup(over: Partial<MinuteRollup> = {}): MinuteRollup {
  return {
    sourceKey: '192.0.2.1/0/1', minuteMs: 1_700_000_040_000, complete: true, records: 7,
    reportedOctets: BIG, reportedPackets: 2n ** 64n - 1n,
    endpoints: [
      { address: '10.0.0.1', sentOctets: 2n ** 53n + 1n, receivedOctets: 0n },
      { address: '10.0.0.2', sentOctets: 0n, receivedOctets: 2n ** 53n + 1n },
    ],
    conversations: [
      { srcAddr: '10.0.0.1', dstAddr: '10.0.0.2', reportedOctets: 2n ** 53n + 1n, reportedPackets: 9007199254740993n },
      { srcAddr: '10.0.0.2', dstAddr: '10.0.0.1', reportedOctets: 0n, reportedPackets: 0n },
    ],
    malformed: 2, unsupported: 1, unknownSamplingRecords: 3,
    ...over,
  };
}

test('rollupCodec: round trip with bigints above 2^53, exactly', () => {
  const r = rollup();
  const bytes = encodeMinuteRollup(r, deflate);
  assert.deepEqual(decodeMinuteRollup(bytes, inflate), r);
  assert.deepEqual(encodeMinuteRollup(r, deflate), bytes, 'deterministic');
  assert.equal(new DataView(bytes.buffer, bytes.byteOffset).getUint16(0, true), DECODER_POLICY_VERSION);
});

test('rollupCodec: an incomplete minute and empty maps', () => {
  const incomplete = rollup({ complete: false, endpoints: [], conversations: [], records: 50_000 });
  assert.deepEqual(decodeMinuteRollup(encodeMinuteRollup(incomplete, deflate), inflate), incomplete);
  const empty = rollup({ endpoints: [], conversations: [], records: 0, reportedOctets: 0n, reportedPackets: 0n, malformed: 0, unsupported: 0, unknownSamplingRecords: 0 });
  assert.deepEqual(decodeMinuteRollup(encodeMinuteRollup(empty, deflate), inflate), empty);
  const unicode = rollup({ sourceKey: 'exporter/éé/0/1' });
  assert.deepEqual(decodeMinuteRollup(encodeMinuteRollup(unicode, deflate), inflate), unicode);
});

test('rollupCodec: refuses what it cannot carry or trust', () => {
  assert.throws(() => encodeMinuteRollup(rollup({ reportedOctets: 2n ** 64n }), deflate), RangeError);
  assert.throws(() => encodeMinuteRollup(rollup({ reportedOctets: -1n }), deflate), RangeError);
  assert.throws(() => encodeMinuteRollup(rollup({ records: 1.5 }), deflate), RangeError);
  const bytes = encodeMinuteRollup(rollup(), deflate);
  const other = bytes.slice();
  other[0] = DECODER_POLICY_VERSION + 1;
  assert.throws(() => decodeMinuteRollup(other, inflate), /version/i);
  assert.throws(() => decodeMinuteRollup(bytes.subarray(0, 1), inflate));
  assert.throws(() => decodeMinuteRollup(bytes.subarray(0, bytes.length - 3), inflate));
  const raw = (rollupBytes: Uint8Array) => { const o = new Uint8Array(2 + rollupBytes.length); o[0] = DECODER_POLICY_VERSION; o.set(rollupBytes, 2); return o; };
  // A count that promises more than the body holds is refused before allocating.
  const lying = inflate(bytes.subarray(2), MAX_ROLLUP_INFLATED_BYTES).slice();
  const dv = new DataView(lying.buffer);
  // The endpoint count is followed by the first endpoint, 10.0.0.1: 2 as a u32, then 0a 00 00 01.
  let patched = false;
  for (let off = 0; off + 8 <= lying.length; off++) {
    if (dv.getUint32(off, true) === 2 && lying[off + 4] === 10 && lying[off + 5] === 0 && lying[off + 6] === 0 && lying[off + 7] === 1) {
      dv.setUint32(off, 0xffffffff, true);
      patched = true;
      break;
    }
  }
  assert.ok(patched, 'the test found the endpoint count');
  assert.throws(() => decodeMinuteRollup(raw(deflate(lying)), inflate));
});

test('rollupCodec: the inflate bound is computed and the key budget is a total of endpoints and conversations', () => {
  const budget = LIMITS.minuteKeyBudget;
  assert.ok(Number.isSafeInteger(MAX_ROLLUP_INFLATED_BYTES) && MAX_ROLLUP_INFLATED_BYTES > budget * 24);
  const ep = (i: number) => ({ address: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, sentOctets: 1n, receivedOctets: 2n });
  const cv = (i: number) => ({ srcAddr: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, dstAddr: '10.9.9.9', reportedOctets: 1n, reportedPackets: 1n });
  const half = budget / 2;
  const full = rollup({ endpoints: Array.from({ length: half }, (_, i) => ep(i)), conversations: Array.from({ length: half }, (_, i) => cv(i)) });
  assert.deepEqual(decodeMinuteRollup(encodeMinuteRollup(full, deflate), inflate), full, 'a rollup at the budget round-trips');
  const onlyConversations = rollup({ endpoints: [], conversations: Array.from({ length: budget }, (_, i) => cv(i)) });
  assert.equal(decodeMinuteRollup(encodeMinuteRollup(onlyConversations, deflate), inflate).conversations.length, budget);

  // The encoder will not write what the decoder will refuse.
  assert.throws(() => encodeMinuteRollup(rollup({ endpoints: Array.from({ length: half + 1 }, (_, i) => ep(i)), conversations: Array.from({ length: half }, (_, i) => cv(i)) }), deflate), RangeError);

  // A hand-built body whose counts are over budget but honest about the bytes they carry is refused by the decoder.
  const handBuilt = (endpoints: number, conversations: number): Uint8Array => {
    const key = new TextEncoder().encode('k');
    const raw = new Uint8Array(1 + 2 + key.length + 56 + 4 + endpoints * 20 + 4 + conversations * 24);
    const v = new DataView(raw.buffer);
    let at = 0;
    raw[at++] = 1;
    v.setUint16(at, key.length, true); at += 2;
    raw.set(key, at); at += key.length;
    at += 56;
    v.setUint32(at, endpoints, true); at += 4 + endpoints * 20;
    v.setUint32(at, conversations, true);
    const out = new Uint8Array(2 + deflate(raw).length);
    new DataView(out.buffer).setUint16(0, DECODER_POLICY_VERSION, true);
    out.set(deflate(raw), 2);
    return out;
  };
  assert.doesNotThrow(() => decodeMinuteRollup(handBuilt(half, half), inflate), 'the control: exactly the budget decodes');
  assert.throws(() => decodeMinuteRollup(handBuilt(budget + 1, 0), inflate), /endpoints/, 'endpoints alone over budget');
  assert.throws(() => decodeMinuteRollup(handBuilt(0, budget + 1), inflate), /endpoints and conversations/, 'conversations alone over budget');
  assert.throws(() => decodeMinuteRollup(handBuilt(half + 1, half), inflate), /endpoints and conversations/, 'the total is what is held to the budget');

  // The codec hands the inflate its bound, and refuses an inflate that ignores it.
  const good = encodeMinuteRollup(rollup(), deflate);
  let asked = -1;
  decodeMinuteRollup(good, (b, max) => { asked = max; return inflate(b, max); });
  assert.equal(asked, MAX_ROLLUP_INFLATED_BYTES);
  assert.throws(() => decodeMinuteRollup(good, () => new Uint8Array(MAX_ROLLUP_INFLATED_BYTES + 1)), /inflates past/);
  // A real bomb: a few kilobytes that inflate to megabytes are stopped by the inflate's own limit.
  const bomb = new Uint8Array(2 + deflateRawSync(new Uint8Array(MAX_ROLLUP_INFLATED_BYTES * 4)).length);
  new DataView(bomb.buffer).setUint16(0, DECODER_POLICY_VERSION, true);
  bomb.set(deflateRawSync(new Uint8Array(MAX_ROLLUP_INFLATED_BYTES * 4)), 2);
  assert.ok(bomb.length < 50_000, 'the bomb is small on disk');
  assert.throws(() => decodeMinuteRollup(bomb, inflate));
});

// --- the sidecar ---------------------------------------------------------------------------------

const JOURNAL_INFO = { generation: GEN, throughEntryId: 100, policyVersion: DECODER_POLICY_VERSION };
const WM = (through: number) => ({ generation: GEN, throughEntryId: through, policyVersion: DECODER_POLICY_VERSION });
const MIN = 60_000;
const M0 = Math.floor(T0 / MIN) * MIN;
const mb = (n: number, len = 40) => Uint8Array.from({ length: len }, (_, i) => (n * 31 + i) & 0xff);

function sidecarCases(kind: 'memory' | 'disk'): void {
  const tag = (s: string) => `[${kind}] sidecar ${s}`;
  const openStore = (file: BlockFile, journal = JOURNAL_INFO) => RollupStore.open(file, journal, { nowMs: () => T0 });

  test(tag('round trip, ranges are half-open, sources are separate, reopen preserves'), () => {
    const rig = newRig(kind);
    const first = openStore(rig.file);
    assert.equal(first.status, 'empty');
    assert.equal(first.store.watermark(), null);
    assert.equal(first.store.size(), 64);
    first.store.appendMinutes([
      { sourceKey: 'a', minuteMs: M0, bytes: mb(1) },
      { sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(2) },
      { sourceKey: 'b', minuteMs: M0, bytes: mb(3, 0) },
    ], WM(10));
    assert.deepEqual(first.store.watermark(), WM(10));
    const check = (store: RollupStore) => {
      assert.deepEqual(store.readMinutes('a', M0, M0 + 2 * MIN, 1 << 20), [
        { minuteMs: M0, throughEntryId: 10, bytes: mb(1) }, { minuteMs: M0 + MIN, throughEntryId: 10, bytes: mb(2) },
      ]);
      assert.deepEqual(store.readMinutes('a', M0, M0 + MIN, 1 << 20).map((m) => m.minuteMs), [M0], 'toMs is exclusive');
      assert.deepEqual(store.readMinutes('a', M0 + 1, M0 + MIN, 1 << 20), []);
      assert.deepEqual(store.readMinutes('b', 0, Number.MAX_SAFE_INTEGER, 1 << 20), [{ minuteMs: M0, throughEntryId: 10, bytes: new Uint8Array(0) }]);
      assert.deepEqual(store.readMinutes('nobody', 0, Number.MAX_SAFE_INTEGER, 1 << 20), []);
    };
    check(first.store);
    const again = openStore(rig.reopen());
    assert.equal(again.status, 'ok');
    assert.deepEqual(again.store.watermark(), WM(10));
    check(again.store);
  });

  test(tag('several fragments of one minute are all returned, in journal order'), () => {
    const rig = newRig(kind);
    const { store } = openStore(rig.file);
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(1) }, { sourceKey: 'a', minuteMs: M0, bytes: mb(2) }], WM(10));
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(3) }], WM(20));
    const got = openStore(rig.reopen()).store.readMinutes('a', M0, M0 + 2 * MIN, 1 << 20);
    assert.deepEqual(got.map((m) => m.minuteMs), [M0 + MIN, M0, M0 + MIN]);
    assert.deepEqual(got.map((m) => m.bytes), [mb(1), mb(2), mb(3)]);
    assert.deepEqual(got.map((m) => m.throughEntryId), [10, 10, 20], 'each fragment names its own batch watermark');
    assert.throws(() => store.readMinutes('a', M0, M0 + 2 * MIN, 100), /maxBytes|budget|limit/i, 'a range past maxBytes is refused, not clipped');
  });

  test(tag('a truncate that throws on the torn tail is rebuild-required, not a failed open (M6)'), () => {
    const rig = newRig(kind);
    const { store } = openStore(rig.file);
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(10));
    // A torn batch: zeros past the closed one, which is what a torn append leaves.
    const closed = rig.file.size();
    rig.file.write(closed, new Uint8Array(30));
    const real = rig.reopen();
    const refusing: BlockFile = {
      read: (o, b) => real.read(o, b), write: (o, b) => real.write(o, b), flush: () => real.flush(), size: () => real.size(),
      close: () => real.close(),
      truncate: () => { throw new Error('the volume refuses'); },
    } as BlockFile;
    const opened = openStore(refusing);
    assert.equal(opened.status, 'rebuild-required');
    assert.match(opened.reason ?? '', /could not be removed/);
    assert.equal(real.size(), closed + 30, 'nothing was changed');
    // The sidecar is a cache: it refuses appends until reset.
    assert.throws(() => opened.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(2) }], WM(20)));
    // On a volume that can truncate, the same file opens clean and the closed batch is intact.
    const healthy = openStore(rig.reopen());
    assert.equal(healthy.status, 'ok');
    assert.equal(healthy.store.watermark()?.throughEntryId, 10);
    assert.equal(rig.file.size(), closed, 'the unfinished tail is cut once the volume allows it');
  });

  test(tag('appendMinutes refuses what the aggregator never sends: a watermark past the journal, too many minutes, too many bytes, a batch over the room (M1)'), () => {
    const rig = newRig(kind);
    const { store } = openStore(rig.file);
    const one = { sourceKey: 'a', minuteMs: M0, bytes: mb(1) };
    const size = rig.file.size();
    // 1. A watermark past the journal's end vouches for entries that do not exist.
    assert.throws(() => store.appendMinutes([one], WM(101), { journalThroughEntryId: 100 }), RangeError);
    store.appendMinutes([one], WM(100), { journalThroughEntryId: 100 });
    const afterOk = rig.file.size();
    assert.ok(afterOk > size, 'a watermark at the journal end is accepted');
    // 2. Minutes per call.
    const many = Array.from({ length: MAX_APPEND_MINUTES + 1 }, () => ({ sourceKey: 'a', minuteMs: M0, bytes: new Uint8Array(0) }));
    assert.throws(() => store.appendMinutes(many, WM(100)), RangeError);
    assert.doesNotThrow(() => store.appendMinutes(many.slice(1), WM(100)));
    const afterMany = rig.file.size();
    // 3. Bytes per call.
    assert.throws(() => store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: new Uint8Array(MAX_APPEND_BYTES + 1) }], WM(100)), RangeError);
    // 4. The room the limit leaves.
    assert.throws(() => store.appendMinutes([one], WM(100), { maxBatchBytes: 10 }), RangeError);
    assert.doesNotThrow(() => store.appendMinutes([one], WM(100), { maxBatchBytes: 10_000 }));
    // A refusal writes nothing.
    const afterRoom = rig.file.size();
    assert.ok(afterRoom > afterMany);
    assert.equal(store.watermark()?.throughEntryId, 100);
    assert.equal(openStore(rig.reopen()).status, 'ok', 'the file is still a clean sidecar');
  });

  test(tag('a truncated tail: every offset in the last batch keeps the last closed batch and nothing else'), () => {
    const rig = newRig(kind);
    const { store } = openStore(rig.file);
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }, { sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(2) }], WM(10));
    const batch1End = rig.file.size();
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + 2 * MIN, bytes: mb(3) }, { sourceKey: 'a', minuteMs: M0 + 3 * MIN, bytes: mb(4) }], WM(20));
    const full = readAll(rig.file);
    for (let cut = batch1End; cut < full.length; cut++) {
      const file = rig.load(full.subarray(0, cut));
      const { store: s, status } = openStore(file);
      assert.equal(status, 'ok', `cut ${cut}`);
      assert.deepEqual(s.watermark(), WM(10), `cut ${cut}`);
      assert.equal(file.size(), batch1End, `cut ${cut}: the unclosed batch is truncated`);
      assert.deepEqual(s.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20).map((m) => m.minuteMs), [M0, M0 + MIN], `cut ${cut}`);
      const second = openStore(rig.reopen());
      assert.equal(second.status, 'ok');
      assert.equal(rig.file.size(), batch1End);
    }
    // A batch missing only its closing watermark entry is the last cut above; the whole thing stands.
    const whole = openStore(rig.load(full));
    assert.deepEqual(whole.store.watermark(), WM(20));
    assert.equal(whole.store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20).length, 4);
    // A first batch torn leaves an empty sidecar.
    const fresh = openStore(rig.load(full.subarray(0, batch1End - 1)));
    assert.equal(fresh.status, 'empty');
    assert.equal(rig.file.size(), 64);
  });

  test(tag('rebuild-required: watermark past the journal, wrong generation, wrong policy, bad CRC, bad header'), () => {
    const rig = newRig(kind);
    const seed = openStore(rig.file);
    seed.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(50));
    seed.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(2) }], WM(60));
    const good = readAll(rig.file);
    const behind = openStore(rig.reopen(), { ...JOURNAL_INFO, throughEntryId: 1000 });
    assert.equal(behind.status, 'ok', 'behind is fine; the missing tail is appended later');
    const cases: [string, ReturnType<typeof openStore>][] = [
      ['past the journal', openStore(rig.reopen(), { ...JOURNAL_INFO, throughEntryId: 59 })],
      ['wrong generation', openStore(rig.reopen(), { ...JOURNAL_INFO, generation: 'b'.repeat(32) })],
      ['wrong policy', openStore(rig.reopen(), { ...JOURNAL_INFO, policyVersion: DECODER_POLICY_VERSION + 1 })],
    ];
    for (const [name, r] of cases) {
      assert.equal(r.status, 'rebuild-required', name);
      assert.ok(r.reason, name);
      assert.equal(sha(readAll(rig.file)), sha(good), `${name}: nothing is mutated until reset`);
      assert.throws(() => r.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(70)), /rebuild/i, name);
      assert.throws(() => r.store.readMinutes('a', 0, M0 + 9 * MIN, 1 << 20), /rebuild/i, name);
    }
    // A CRC failure in the middle (a flipped body byte of the first minute entry).
    const flipped = good.slice();
    flipped[64 + 24 + 10] ^= 0x40;
    const crc = openStore(rig.load(flipped));
    assert.equal(crc.status, 'rebuild-required');
    assert.equal(sha(readAll(rig.file)), sha(flipped));
    // A bad header.
    const noMagic = good.slice();
    noMagic[0] ^= 0xff;
    assert.equal(openStore(rig.load(noMagic)).status, 'rebuild-required');
    // An unknown sidecar format version is a cache we cannot read, not a journal we must keep.
    const ver = good.slice();
    new DataView(ver.buffer).setUint16(8, FORMAT_VERSION + 1, true);
    new DataView(ver.buffer).setUint32(60, crc32(ver.subarray(0, 60)), true);
    assert.equal(openStore(rig.load(ver)).status, 'rebuild-required');
    // And reset is how it recovers.
    const stale = openStore(rig.load(good), { ...JOURNAL_INFO, throughEntryId: 1 });
    assert.equal(stale.status, 'rebuild-required');
    stale.store.reset();
    assert.equal(stale.store.size(), 64);
    assert.equal(stale.store.watermark(), null);
    assert.equal(rig.file.size(), 64);
    stale.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(9) }], WM(1));
    const reopened = openStore(rig.reopen(), { ...JOURNAL_INFO, throughEntryId: 1 });
    assert.equal(reopened.status, 'ok');
    assert.deepEqual(reopened.store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20), [{ minuteMs: M0, throughEntryId: 1, bytes: mb(9) }]);
    reopened.store.reset();
    assert.equal(openStore(rig.reopen()).status, 'empty');
  });

  test(tag('a corrupted interior length is rebuild-required, never a torn tail; the file is not touched'), () => {
    const rig = newRig(kind);
    const seed = openStore(rig.file);
    seed.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(50));
    seed.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(2) }], WM(60));
    const good = readAll(rig.file);
    // The first minute entry starts at 64. 500000 is in the 1 MiB cap and far past this file's end.
    for (const [how, length] of [['extent past EOF', 500_000], ['extent ends mid-file on non-entry bytes', 40]] as const) {
      const image = good.slice();
      new DataView(image.buffer).setUint32(64 + 4, length, true);
      const file = rig.load(image);
      const r = openStore(file);
      assert.equal(r.status, 'rebuild-required', how);
      assert.ok(r.reason, how);
      assert.equal(sha(readAll(file)), sha(image), `${how}: nothing is truncated`);
      assert.throws(() => r.store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20), /rebuild/i, how);
    }
    // The torn-tail behaviour is unchanged: zeros after a closed batch are cut off, status ok.
    const withZeros = rig.load(Uint8Array.from([...good, ...new Uint8Array(4096)]));
    const cut = openStore(withZeros);
    assert.equal(cut.status, 'ok');
    assert.equal(withZeros.size(), good.length, 'an all-zero tail is truncated');
    assert.deepEqual(cut.store.watermark(), WM(60));
    // Zeros, then one non-zero byte, are not a torn tail.
    const tail = new Uint8Array(4096);
    tail[tail.length - 1] = 1;
    const dirty = Uint8Array.from([...good, ...tail]);
    const dirtyFile = rig.load(dirty);
    assert.equal(openStore(dirtyFile).status, 'rebuild-required');
    assert.equal(sha(readAll(dirtyFile)), sha(dirty));
  });

  test(tag('every minute entry of a batch must name the batch\'s closing watermark, otherwise rebuild-required'), () => {
    const rig = newRig(kind);
    const seed = openStore(rig.file);
    seed.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(50));
    const good = readAll(rig.file);
    assert.equal(openStore(rig.load(good.slice())).status, 'ok', 'the control: the untouched file opens');
    // The minute entry starts at 64 with a 24-byte header: u16 key length, 'a', u64 minuteMs, then u64 through.
    for (const through of [49, 51, 0]) {
      const image = good.slice();
      new DataView(image.buffer).setBigUint64(64 + 24 + 2 + 1 + 8, BigInt(through), true);
      reseal(image, 64);
      const file = rig.load(image);
      const r = openStore(file);
      assert.equal(r.status, 'rebuild-required', `through ${through}`);
      assert.match(r.reason ?? '', /watermark/i, `through ${through}`);
      assert.equal(sha(readAll(file)), sha(image), `through ${through}: the file is untouched`);
    }
  });

  test(tag('a sidecar whose header cannot be written reports failed instead of throwing'), () => {
    const rig = newRig(kind);
    const faulty = new FaultyFile(rig.file);
    faulty.failAtWrite = 1;
    let r!: ReturnType<typeof openStore>;
    assert.doesNotThrow(() => { r = openStore(faulty); });
    assert.equal(r.status, 'failed');
    assert.match(r.reason ?? '', /header/i);
    assert.throws(() => r.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(1)));
    assert.throws(() => r.store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20));
  });

  test(tag('entry body cap is 1 MiB, not the journal\'s 64 KiB'), () => {
    const rig = newRig(kind);
    const { store } = openStore(rig.file);
    const big = new Uint8Array(700_000).map((_, i) => i & 0xff);
    store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: big }], WM(1));
    assert.deepEqual(openStore(rig.reopen()).store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 22)[0].bytes, big);
    const before = rig.file.size();
    assert.throws(() => store.appendMinutes([{ sourceKey: 'a', minuteMs: M0 + MIN, bytes: new Uint8Array(1 << 20) }], WM(2)), RangeError);
    assert.equal(rig.file.size(), before, 'a refused batch writes nothing');
    assert.deepEqual(store.watermark(), WM(1));
  });
}

// --- the Node volume ------------------------------------------------------------------------------

test('volume: opens both files under a temp root, creates the directory, plain tsx', () => {
  const userData = path.join(tmpRoot, 'userData');
  const root = monitoringRoot(userData);
  assert.equal(root, path.join(userData, 'monitoring'));
  assert.equal(existsSync(root), false);
  const volume = openMonitoringVolume(root);
  try {
    assert.equal(statSync(root).isDirectory(), true);
    assert.equal(existsSync(path.join(root, 'journal.iwmj')), true);
    assert.equal(existsSync(path.join(root, 'rollups.iwmr')), true);
    const { journal } = MonitoringJournal.open(volume.journal, options());
    journal.append([bnd('start', 'S1', T0), dg(T0 + 1, [4, 5, 6])]);
    const store = RollupStore.open(volume.rollups, { generation: GEN, throughEntryId: 2, policyVersion: DECODER_POLICY_VERSION });
    store.store.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(2));
    assert.ok(statSync(path.join(root, 'journal.iwmj')).size > 64);
  } finally {
    volume.close();
  }
  const again = openMonitoringVolume(root);
  try {
    const { journal, recovery } = MonitoringJournal.open(again.journal, options());
    assert.equal(recovery.status, 'ok');
    assert.equal(recovery.completeEntries, 2);
    assert.equal(journal.state, 'open');
  } finally {
    again.close();
  }
});

// --- the time index and the boundary list (Task 4) ---------------------------------------------

test('EntryIndex: min and max receipt time per stride, overlap and not first/last, the open stride updates on append', () => {
  const ix = new EntryIndex();
  // Stride 0: the clock steps back half way, so first (1000) is later than last (400).
  for (let id = 1; id <= INDEX_STRIDE; id++) ix.note(id, 100 + id, null, id <= 100 ? 1000 + id : 400);
  // Stride 1: ordinary, 5000..5099, still open.
  for (let id = INDEX_STRIDE + 1; id <= INDEX_STRIDE + 100; id++) ix.note(id, 100 + id, null, 5000 + (id - INDEX_STRIDE - 1));
  const last = INDEX_STRIDE + 100;
  // 400..1100 overlap [450, 500)? The range sits in the stepped-back span, which neither first (1001) nor last (400) brackets.
  assert.deepEqual(ix.strideRanges(450, 500, last), [{ fromId: 1, toId: INDEX_STRIDE }], 'found by overlap');
  assert.deepEqual(ix.strideRanges(0, 400, last), [], 'max 1100 and min 400: nothing before 400');
  assert.deepEqual(ix.strideRanges(1101, 5000, last), [], 'between the strides: nothing');
  assert.deepEqual(ix.strideRanges(5099, 5100, last), [{ fromId: INDEX_STRIDE + 1, toId: last }], 'the open stride is clipped to the last id');
  assert.deepEqual(ix.strideRanges(0, 10_000, last), [{ fromId: 1, toId: last }], 'adjacent strides merge');
  assert.deepEqual(ix.strideRanges(0, 10_000, 10), [{ fromId: 1, toId: 10 }], 'clipped to the through id');
  // The open stride grows with an append that is later than everything in it.
  ix.note(last + 1, 9999, null, 9000);
  assert.deepEqual(ix.strideRanges(8999, 9001, last + 1), [{ fromId: INDEX_STRIDE + 1, toId: last + 1 }]);
  assert.deepEqual(new EntryIndex().strideRanges(0, 10, 100), []);
});

function timeIndexCases(kind: 'memory' | 'disk'): void {
  const tag = (s: string) => `[${kind}] ${s}`;

  test(tag('locate: merged ranges clipped to the snapshot, and a stepped-back clock is found by overlap'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    const inputs: EvidenceInput[] = [bnd('start', 'S1', T0)];
    // 600 datagrams: stride 0 and 1 ascend from T0 + 1000; stride 2 starts at a clock far behind.
    for (let i = 0; i < 600; i++) inputs.push(dg(i < 511 ? T0 + 1000 + i : T0 - 50_000 + i));
    journal.append(inputs);
    const snap = journal.snapshot();
    assert.equal(snap.throughEntryId, 601);
    const wide = journal.locate(snap, 0, T0 + 10_000_000);
    assert.deepEqual(wide, [{ fromId: 1, toId: 601 }], 'every stride overlaps; adjacent ranges merge');
    // The stepped-back entries (ids 513..601) are in stride 2 (ids 513..768) alone.
    const back = journal.locate(snap, T0 - 51_000, T0 - 40_000);
    assert.deepEqual(back, [{ fromId: 513, toId: 601 }]);
    // The first stepped-back stamp (id 513) is found alone.
    assert.deepEqual(journal.locate(snap, T0 - 49_489, T0 - 49_488), [{ fromId: 513, toId: 601 }]);
    // Between the two clocks there is nothing to read.
    assert.deepEqual(journal.locate(snap, T0 - 40_000, T0 - 1), []);
    // The snapshot clips.
    assert.deepEqual(journal.locate({ generation: GEN, throughEntryId: 300 }, 0, T0 + 10_000_000), [{ fromId: 1, toId: 300 }]);
    assert.deepEqual(journal.locate({ generation: GEN, throughEntryId: 0 }, 0, T0 + 10_000_000), []);
    // A snapshot beyond the journal's end clips to the end.
    assert.deepEqual(journal.locate({ generation: GEN, throughEntryId: 9999 }, 0, T0 + 10_000_000), [{ fromId: 1, toId: 601 }]);
    assert.throws(() => journal.locate({ generation: 'f'.repeat(32), throughEntryId: 5 }, 0, 10), StaleGenerationError);
    // The same answer after a reopen: the index is rebuilt from the scan. The reopen closes the
    // session the crash left open with an `interrupted` boundary (id 602), in the last stride.
    const reopened = open(rig.reopen()).journal;
    assert.equal(reopened.snapshot().throughEntryId, 602);
    assert.deepEqual(reopened.locate(reopened.snapshot(), T0 - 51_000, T0 - 40_000), [{ fromId: 513, toId: 602 }]);
    // Boundaries count: a lone early boundary pulls its stride's min down.
    const rig2 = newRig(kind);
    const j2 = open(rig2.file).journal;
    j2.append([bnd('start', 'S1', T0 + 500), dg(T0 + 600), bnd('gap', 'S1', T0 + 100, 'shed', 2)]);
    assert.deepEqual(j2.locate(j2.snapshot(), T0 + 100, T0 + 101), [{ fromId: 1, toId: 3 }]);
  });

  test(tag('readBoundaries: from the open scan and from appends, paged, by cursor'), () => {
    const rig = newRig(kind);
    const { journal } = open(rig.file);
    journal.append([
      bnd('start', 'S1', T0), dg(T0 + 1), bnd('gap', 'S1', T0 + 2, 'inbox full', 5), dg(T0 + 3),
      bnd('suspend', 'S1', T0 + 4, 'sleep'), bnd('resume', 'S1', T0 + 5, 'wake'), dg(T0 + 6),
    ]);
    const snap = journal.snapshot();
    const ids = (r: { entries: BoundaryEvidence[] }) => r.entries.map((e) => e.ref.entryId);
    const all = journal.readBoundaries(snap, 0, 100);
    assert.deepEqual(ids(all), [1, 3, 5, 6]);
    assert.equal(all.done, true);
    assert.equal(all.nextAfterId, 7, 'complete through the snapshot, whatever the ids in between held');
    assert.deepEqual(all.entries[1], { kind: 'boundary', ref: { generation: GEN, entryId: 3 }, sessionId: 'S1', receivedMs: T0 + 2, action: 'gap', reason: 'inbox full', droppedDatagrams: 5 });
    // Paging by two.
    const p1 = journal.readBoundaries(snap, 0, 2);
    assert.deepEqual([ids(p1), p1.done, p1.nextAfterId], [[1, 3], false, 3]);
    const p2 = journal.readBoundaries(snap, p1.nextAfterId, 2);
    assert.deepEqual([ids(p2), p2.done, p2.nextAfterId], [[5, 6], true, 7]);
    assert.deepEqual(ids(journal.readBoundaries(snap, 7, 2)), []);
    // The snapshot clips: a later boundary is not in an older answer.
    journal.append([bnd('stop', 'S1', T0 + 8, 'user')]);
    assert.deepEqual(ids(journal.readBoundaries(snap, 0, 100)), [1, 3, 5, 6]);
    assert.deepEqual(ids(journal.readBoundaries(journal.snapshot(), 0, 100)), [1, 3, 5, 6, 8]);
    // After a reopen the open scan supplies the list, plus the `interrupted` a crash earns.
    const rig2 = newRig(kind);
    const j2 = open(rig2.file).journal;
    j2.append([bnd('start', 'S9', T0), dg(T0 + 1), bnd('gap', 'S9', T0 + 2, 'x', 1), dg(T0 + 3)]);
    const again = open(rig2.reopen()).journal;
    const after = again.readBoundaries(again.snapshot(), 0, 100);
    assert.deepEqual(after.entries.map((e) => [e.ref.entryId, e.action]), [[1, 'start'], [3, 'gap'], [5, 'interrupted']]);
    // Numbers are untrusted; a foreign generation is stale.
    assert.throws(() => journal.readBoundaries(snap, -1, 1), RangeError);
    assert.throws(() => journal.readBoundaries(snap, 0, 0), RangeError);
    assert.throws(() => journal.readBoundaries(snap, 0.5, 1), RangeError);
    assert.throws(() => journal.readBoundaries({ generation: 'f'.repeat(32), throughEntryId: 5 }, 0, 1), StaleGenerationError);
  });

  test(tag('sidecar sources(): sorted keys the sidecar holds minutes for; refused while it needs a rebuild'), () => {
    const rig = newRig(kind);
    const { store } = RollupStore.open(rig.file, JOURNAL_INFO, { nowMs: () => T0 });
    assert.deepEqual(store.sources(), []);
    store.appendMinutes([
      { sourceKey: 'b/0/1', minuteMs: M0, bytes: mb(1) }, { sourceKey: 'a/0/0', minuteMs: M0, bytes: mb(2) },
      { sourceKey: 'a/0/0', minuteMs: M0 + MIN, bytes: mb(3) }, { sourceKey: 'a', minuteMs: M0, bytes: mb(4) },
    ], WM(4));
    assert.deepEqual(store.sources(), ['a', 'a/0/0', 'b/0/1']);
    const stale = RollupStore.open(rig.reopen(), { ...JOURNAL_INFO, generation: 'f'.repeat(32) }, { nowMs: () => T0 });
    assert.equal(stale.status, 'rebuild-required');
    assert.throws(() => stale.store.sources(), /needs a rebuild/);
  });

  test(tag('sidecar: each fragment keeps its own batch watermark across a reopen'), () => {
    const rig = newRig(kind);
    const first = RollupStore.open(rig.file, JOURNAL_INFO, { nowMs: () => T0 }).store;
    first.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(1) }], WM(5));
    first.appendMinutes([{ sourceKey: 'a', minuteMs: M0, bytes: mb(2) }, { sourceKey: 'a', minuteMs: M0 + MIN, bytes: mb(3) }], WM(9));
    const expected = [[0, 5], [0, 9], [MIN, 9]];
    const read = (s: RollupStore) => s.readMinutes('a', M0, M0 + 2 * MIN, 1 << 20).map((m) => [m.minuteMs - M0, m.throughEntryId]);
    assert.deepEqual(read(first), expected);
    const reopened = RollupStore.open(rig.reopen(), JOURNAL_INFO, { nowMs: () => T0 }).store;
    assert.deepEqual(read(reopened), expected);
  });
}

try {
  for (const kind of ['memory', 'disk'] as const) {
    journalCases(kind);
    sidecarCases(kind);
    timeIndexCases(kind);
  }
} finally {
  for (const rig of openRigs) {
    try { rig.file.close(); } catch { /* already closed */ }
  }
  // Removes only the directory this run created.
  rmSync(tmpRoot, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
