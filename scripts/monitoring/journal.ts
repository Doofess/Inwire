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
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
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
const inflate = (b: Uint8Array): Uint8Array => new Uint8Array(inflateRawSync(b));

function readAll(file: BlockFile): Uint8Array {
  const out = new Uint8Array(file.size());
  file.read(0, out);
  return out;
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
    const rig = newRig(kind);
    const entryBytes = 24 + 24 + 100;
    const { journal } = open(rig.file, { limitBytes: 64 + 130 + LIMITS.closingReserveBytes + entryBytes * 2, otherBytes: () => 0 });
    const start = journal.append([bnd('start', 'S1', T0)]);
    const startBytes = start.snapshot.writtenBytes - 64;
    // Rebuild a limit that admits exactly two datagrams after the start.
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
  for (let id = 1; id <= INDEX_STRIDE * 3 + 5; id++) ix.note(id, 1000 + id * 10, id === 1 ? null : 'S');
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
    malformed: 2, unsupported: 1,
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
  const empty = rollup({ endpoints: [], conversations: [], records: 0, reportedOctets: 0n, reportedPackets: 0n, malformed: 0, unsupported: 0 });
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
  const lying = inflate(bytes.subarray(2)).slice();
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
        { minuteMs: M0, bytes: mb(1) }, { minuteMs: M0 + MIN, bytes: mb(2) },
      ]);
      assert.deepEqual(store.readMinutes('a', M0, M0 + MIN, 1 << 20).map((m) => m.minuteMs), [M0], 'toMs is exclusive');
      assert.deepEqual(store.readMinutes('a', M0 + 1, M0 + MIN, 1 << 20), []);
      assert.deepEqual(store.readMinutes('b', 0, Number.MAX_SAFE_INTEGER, 1 << 20), [{ minuteMs: M0, bytes: new Uint8Array(0) }]);
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
    assert.throws(() => store.readMinutes('a', M0, M0 + 2 * MIN, 100), /maxBytes|budget|limit/i, 'a range past maxBytes is refused, not clipped');
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
    assert.deepEqual(reopened.store.readMinutes('a', 0, Number.MAX_SAFE_INTEGER, 1 << 20), [{ minuteMs: M0, bytes: mb(9) }]);
    reopened.store.reset();
    assert.equal(openStore(rig.reopen()).status, 'empty');
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

try {
  for (const kind of ['memory', 'disk'] as const) {
    journalCases(kind);
    sidecarCases(kind);
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
