/**
 * `runExport`, end to end, over a real store holding a real capture.
 *
 *   npx tsx scripts/export/run-export.ts
 *
 * Every frame of each fixture is written through a real `CaptureHost` over a
 * `MemoryVolume`, each append crossing `v8.serialize` the way it crosses the
 * store's `MessagePort`. The newest fifth is the RAM window, with the older
 * half of it evicted of its bytes the way `evictOldBytes` leaves a buffer, and
 * the rest is only on disk. Then each format is exported through the same
 * `runExport` the panel calls, into a `MemorySink`, and the file is read back
 * by something other than the code that wrote it:
 *
 *   - pcap and pcapng by `PcapService`, and pcapng by tshark when it is here;
 *   - CSV by the importer's own table reader, JSON by `JSON.parse`, Excel by
 *     exceljs, the PDF by inflating its content streams.
 *
 * What it holds the orchestrator to: every format covers the WHOLE capture,
 * not the window - the failure this phase exists to end; the filtered scope is
 * `FilterEngine` over every frame; one job anonymises with one mapping, across
 * pages and across the disk/window seam, and leaves no real address anywhere
 * in the file; a Cancel aborts the sink so nothing is committed; a dismissed
 * dialog reads nothing; and progress ends with `done === total`.
 *
 * Real captures only (ADR 0004): skips cleanly without the fixtures.
 */
import { serialize, deserialize } from 'node:v8';
import { inflateSync } from 'node:zlib';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ExcelImport from 'exceljs';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { MatchSet } from '../../src/services/capture/matchSet';
import { plainForStore } from '../../src/services/capture/storePacket';
import { FilterEngine } from '../../src/services/filterEngine';
import { NO_BYTES } from '../../src/services/packetBytes';
import { PcapService } from '../../src/services/pcapParser';
import { Anonymiser, parseIpv4 } from '../../src/services/anonymise';
import { parseDelimited } from '../../src/services/tabularReaders';
import { stripPreamble } from '../../src/services/exportSchema';
import { MemorySink, type OpenSinkResult } from '../../src/lib/saveSink';
import { runExport, type ExportRequest, type ExportRuntime } from '../../src/services/export/runExport';
import type { CaptureRowReader, FrameScope } from '../../src/services/export/exportFrames';
import {
  beginExportJob, cancelExportForChange, getExportJob,
  type ExportFormat, type ExportProgress, type ExportResult,
} from '../../src/services/export/exportJob';
import { findWiresharkTool, loadRealCaptures, runTool } from './realCaptures';
import type { FromCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const crossed = <T>(value: T): T => deserialize(serialize(value)) as T;

/** A store holding `packets`, and a reader over it shaped like `captureStore`. */
async function storeOf(packets: readonly Packet[]) {
  const volume = new MemoryVolume();
  const waiting = new Map<number, (message: FromCapture) => void>();
  const store = new CaptureHost(volume, (message) => {
    const copy = crossed(message);
    const id = (copy as { requestId?: number }).requestId;
    if (id === undefined || copy.type === 'scanProgress') return;
    const settle = waiting.get(id);
    if (settle === undefined) return;
    waiting.delete(id);
    settle(copy);
  });
  let nextId = 1;
  const ask = (build: (requestId: number) => Parameters<CaptureHost['receive']>[0]) =>
    new Promise<FromCapture>((resolve) => {
      const requestId = nextId++;
      waiting.set(requestId, resolve);
      store.receive(build(requestId));
    });

  store.receive({ type: 'open', captureId: 'cap-20260925-120000-rexp' });
  for (let i = 0; i < packets.length; i += 1000) {
    store.receive({ type: 'append', packets: crossed(packets.slice(i, i + 1000).map(plainForStore)) });
  }
  store.receive({ type: 'finish' });
  await store.drain();

  let rowReads = 0;
  const reader: CaptureRowReader = {
    async readRowsAt(from, to) {
      rowReads++;
      const answer = await ask((requestId) => ({ type: 'rowsAt', requestId, from, to }));
      return answer.type === 'blocks' ? answer.blocks : [];
    },
    async readBytes(ids) {
      const answer = await ask((requestId) => ({ type: 'read', requestId, ids: [...ids] }));
      return new Map(answer.type === 'bytes' ? answer.frames : []);
    },
    async ordinalOf(id) {
      const answer = await ask((requestId) => ({ type: 'locate', requestId, id }));
      return answer.type === 'located' ? answer.ordinal : -1;
    },
  };
  return {
    reader,
    get rowReads() { return rowReads; },
    async scan(filter: string): Promise<MatchSet | null> {
      const answer = await ask((requestId) => ({ type: 'scan', requestId, filter }));
      if (answer.type !== 'scanDone' || answer.bits === null) return null;
      return MatchSet.fromBytes(answer.frameCount, answer.bits);
    },
    close: () => store.close(),
  };
}

/** A sink as slow as a disk, so an export is still writing when it is cancelled. */
class SlowSink extends MemorySink {
  /** Called once the file has something in it - the export is mid-write. */
  onWrite: () => void = () => {};

  async write(chunk: Uint8Array): Promise<void> {
    await new Promise((resolve) => { setTimeout(resolve, 2); });
    await super.write(chunk);
    this.onWrite();
  }
}

/** Everything a request needs besides the format, scope and reader. */
const baseRequest: Omit<ExportRequest, 'format' | 'scope' | 'reader'> = {
  includeRawBytes: false,
  compress: false,
  anonymise: false,
  source: { kind: 'import', fileName: 'fixture.pcap' },
  drops: { kernel: null, agent: null, pipe: null },
  received: null,
  os: 'test OS',
  interfaces: [],
};

interface Run {
  result: ExportResult;
  sink: MemorySink;
  progress: ExportProgress[];
}

/** One export into memory. */
async function exportTo(
  request: Omit<ExportRequest, 'includeRawBytes' | 'compress' | 'anonymise' | 'source' | 'drops'
    | 'received' | 'os' | 'interfaces'> & Partial<ExportRequest>,
  runtime: ExportRuntime = {},
): Promise<Run> {
  const sink = new MemorySink();
  const progress: ExportProgress[] = [];
  const full: ExportRequest = {
    includeRawBytes: false,
    compress: false,
    anonymise: false,
    source: { kind: 'import', fileName: 'fixture.pcap' },
    drops: { kernel: null, agent: null, pipe: null },
    received: null,
    os: 'test OS',
    interfaces: [],
    ...request,
  };
  const result = await runExport(full, {
    openSink: async (): Promise<OpenSinkResult> => sink,
    now: () => Date.UTC(2026, 8, 25, 12),
    ...runtime,
    onProgress: (p) => { progress.push(p); runtime.onProgress?.(p); },
  });
  return { result, sink, progress };
}

/** Frames in a pcap or pcapng, read back by the app's own parser. */
async function reparse(bytes: Uint8Array, name: string): Promise<Packet[]> {
  const { packets } = await PcapService.parseCaptureFile(new File([bytes as BlobPart], name), Number.POSITIVE_INFINITY);
  return packets;
}

function csvRows(bytes: Uint8Array): string[][] {
  const text = new TextDecoder().decode(bytes).replace(/^﻿/, '');
  // The table only: the `# key: value` preamble and the header go.
  return stripPreamble(parseDelimited(text, ',').filter((row) => row.some((cell) => cell !== '')));
}

/**
 * Every string the PDF draws, in drawing order. Its content streams are
 * deflated, so each is inflated first; text is `(...) Tj`.
 */
function pdfStrings(bytes: Uint8Array): string[] {
  const buffer = Buffer.from(bytes);
  const latin = buffer.toString('latin1');
  const out: string[] = [];
  let at = 0;
  for (;;) {
    const start = latin.indexOf('stream', at);
    if (start < 0) break;
    const bodyStart = latin[start + 6] === '\r' ? start + 8 : start + 7;
    const end = latin.indexOf('endstream', bodyStart);
    if (end < 0) break;
    at = end + 9;
    if (latin.slice(start - 3, start) === 'end') continue;
    let body: string;
    try {
      body = inflateSync(buffer.subarray(bodyStart, end)).toString('latin1');
    } catch {
      body = latin.slice(bodyStart, end);
    }
    for (const m of body.matchAll(/\(((?:\\.|[^\\)])*)\)\s*Tj/g)) {
      out.push(m[1].replace(/\\([()\\])/g, '$1'));
    }
  }
  return out;
}

/** The value drawn right after `label` in the PDF's metadata table. */
function pdfValue(strings: readonly string[], label: string): string | undefined {
  const i = strings.indexOf(label);
  return i < 0 ? undefined : strings[i + 1];
}

const EN = new Intl.NumberFormat('en-US');

const IPV4_TOKEN = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g;
const MAC_TOKEN = /(?<![0-9a-f:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![0-9a-f:])/gi;
const IPV6_TOKEN = /(?<![0-9a-z:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z:])/gi;

/** Address-shaped tokens in `text` that are real addresses the anonymiser would have rewritten. */
function leaks(text: string, real: ReadonlySet<string>): string[] {
  const found = new Set<string>();
  for (const re of [IPV4_TOKEN, MAC_TOKEN, IPV6_TOKEN]) {
    for (const m of text.matchAll(re)) {
      const token = m[0].toLowerCase();
      if (real.has(token)) found.add(token);
    }
  }
  return [...found];
}

async function main() {
  const captures = await loadRealCaptures();
  if (captures.length === 0) {
    console.log('SKIP  no fixtures present - nothing to export');
    process.exit(0);
  }
  const tshark = findWiresharkTool('tshark');
  if (tshark === null) console.log('SKIP  tshark not found - pcapng is read back by the app only');
  const scratch = mkdtempSync(join(tmpdir(), 'inwire-run-export-'));
  const ExcelJS = ((ExcelImport as unknown as { default?: typeof ExcelImport }).default ?? ExcelImport);

  try {
    for (const { name, packets } of captures) {
      console.log(`\n--- ${name}: ${packets.length} frames ---\n`);
      const store = await storeOf(packets);
      const split = Math.floor(packets.length * 0.8);
      const tail = packets.slice(split);
      const evicted = Math.floor(tail.length / 2);
      const window = tail.map((p, i) => (i < evicted ? { ...p, rawBytes: NO_BYTES } : p));
      const whole: FrameScope = { window, filter: null };
      const total = packets.length;
      const ids = packets.map((p) => p.id);
      checkTrue(`${name}: the window is the smaller part - the disk half is what is under test`,
        window.length < total / 2);

      // ---- every format, the whole capture --------------------------------
      const pcap = await exportTo({ format: 'pcap', scope: whole, reader: store.reader });
      check(`${name}: pcap saved`, pcap.result.outcome, 'saved');
      const pcapBack = await reparse(pcap.sink.bytes(), 'x.pcap');
      check(`${name}: pcap holds the whole capture, not the window`, pcapBack.length, total);
      check(`${name}: ...every frame's bytes, disk and evicted included`,
        pcapBack.reduce((n, p) => n + p.rawBytes.length, 0), packets.reduce((n, p) => n + p.rawBytes.length, 0));

      const pcapng = await exportTo({ format: 'pcapng', scope: whole, reader: store.reader });
      check(`${name}: pcapng saved`, pcapng.result.outcome, 'saved');
      const ngBytes = pcapng.sink.bytes();
      const ngBack = await reparse(ngBytes, 'x.pcapng');
      check(`${name}: pcapng holds the whole capture`, ngBack.length, total);
      check(`${name}: ...every frame's bytes`,
        ngBack.reduce((n, p) => n + p.rawBytes.length, 0), packets.reduce((n, p) => n + p.rawBytes.length, 0));
      const shb = Buffer.from(ngBytes.subarray(0, 4096)).toString('latin1');
      checkTrue(`${name}: ...and its section comment says how many`,
        shb.includes(`Frames exported: ${EN.format(total)}`) && shb.includes(`Frames in capture: ${EN.format(total)}`));
      if (tshark !== null) {
        const file = join(scratch, `${name}.pcapng`);
        writeFileSync(file, ngBytes);
        const lines = runTool(tshark, ['-r', file, '-T', 'fields', '-e', 'frame.number'])
          .split(/\r?\n/).filter((l) => l.trim() !== '');
        check(`${name}: tshark reads the pcapng and counts the whole capture`, lines.length, total);
      }
      const writing = pcapng.progress.filter((p) => p.phase === 'writing');
      const surveying = pcapng.progress.filter((p) => p.phase === 'surveying');
      const lastWrite = writing[writing.length - 1];
      const lastSurvey = surveying[surveying.length - 1];
      check(`${name}: progress ends with done === total, writing`,
        lastWrite && [lastWrite.done, lastWrite.total], [total, total]);
      check(`${name}: ...and surveying`, lastSurvey && [lastSurvey.done, lastSurvey.total], [total, total]);
      check(`${name}: ...through the phases in order`,
        [...new Set(pcapng.progress.map((p) => p.phase))], ['choosing', 'surveying', 'writing', 'finishing']);

      const csv = await exportTo({ format: 'csv', scope: whole, reader: store.reader });
      const csvTable = csvRows(csv.sink.bytes());
      check(`${name}: csv has a row per frame of the whole capture`, csvTable.length - 1, total);
      check(`${name}: ...in capture order, by frame number`, csvTable.slice(1).map((r) => Number(r[0])), ids);
      checkTrue(`${name}: ...with the dissected fields as columns`, csvTable[0].includes('ip.src'));

      const json = await exportTo({ format: 'json', scope: whole, reader: store.reader });
      const doc = JSON.parse(new TextDecoder().decode(json.sink.bytes())) as {
        meta: { frames: { exported: number; inCapture: number } }; packets: { no: number }[];
      };
      check(`${name}: json has every frame`, doc.packets.map((p) => p.no), ids);
      check(`${name}: ...and its meta counts them`, [doc.meta.frames.exported, doc.meta.frames.inCapture], [total, total]);

      const xlsx = await exportTo({ format: 'xlsx', scope: whole, reader: store.reader });
      check(`${name}: xlsx saved`, xlsx.result.outcome, 'saved');
      const bytes = xlsx.sink.bytes();
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
      const sheet = workbook.getWorksheet('Packets');
      check(`${name}: xlsx has a row per frame of the whole capture`, sheet ? sheet.actualRowCount - 1 : -1, total);
      check(`${name}: ...the last one the capture's last frame`,
        sheet ? Number(sheet.getRow(total + 1).getCell(1).value) : -1, ids[ids.length - 1]);

      const readsBeforePdf = store.rowReads;
      const pdf = await exportTo({ format: 'pdf', scope: whole, reader: store.reader });
      check(`${name}: pdf saved`, pdf.result.outcome, 'saved');
      const strings = pdfStrings(pdf.sink.bytes());
      check(`${name}: the pdf's 'Frames in capture' is the whole capture`,
        pdfValue(strings, 'Frames in capture'), EN.format(total));
      check(`${name}: ...and so is 'Frames exported'`, pdfValue(strings, 'Frames exported'), EN.format(total));
      checkTrue(`${name}: ...having read the disk to get there`, store.rowReads > readsBeforePdf);

      // ---- the filtered scope ------------------------------------------------
      const expression = 'dns || tcp.flags.reset == 1';
      const expected = FilterEngine.filterPackets(packets, expression).map((p) => p.id);
      checkTrue(`${name}: the filter matches frames on both sides of the seam`,
        expected.some((id) => id < tail[0].id) && expected.some((id) => id >= tail[0].id));
      const matches = await store.scan(expression);
      checkTrue(`${name}: the store scanned it`, matches !== null);
      const filtered: FrameScope = { window, filter: { expression, matches } };
      const fJson = await exportTo({ format: 'json', scope: filtered, reader: store.reader });
      const fDoc = JSON.parse(new TextDecoder().decode(fJson.sink.bytes())) as { packets: { no: number }[] };
      check(`${name}: filtered json is FilterEngine over every frame`, fDoc.packets.map((p) => p.no), expected);
      const fNg = await exportTo({ format: 'pcapng', scope: filtered, reader: store.reader });
      check(`${name}: ...and so is filtered pcapng, read back`,
        (await reparse(fNg.sink.bytes(), 'f.pcapng')).length, expected.length);
      const fPdf = pdfStrings((await exportTo({ format: 'pdf', scope: filtered, reader: store.reader })).sink.bytes());
      check(`${name}: the filtered pdf exports the matches of the whole capture`,
        [pdfValue(fPdf, 'Frames exported'), pdfValue(fPdf, 'Frames in capture')],
        [EN.format(expected.length), EN.format(total)]);

      // ---- anonymised: one mapping for the whole job -------------------------
      // The real addresses the anonymiser would rewrite - its own answer, from
      // a throwaway key, decides which ones are "real" (multicast and
      // broadcast are left alone on purpose).
      const probe = new Anonymiser();
      const real = new Set<string>();
      for (const p of packets) {
        for (const a of [p.source, p.destination]) {
          const lower = a.toLowerCase();
          if (parseIpv4(a) && probe.ipv4Address(a) !== a) real.add(lower);
          else if (/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(a) && probe.mac(lower) !== lower) real.add(lower);
          else if (a.includes(':') && !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(a) && probe.ipv6Address(a) !== a) real.add(lower);
        }
      }
      checkTrue(`${name}: the capture has real addresses to hide`, real.size > 0);

      // Small pages, so one address crosses many of them.
      const PAGE = 500;
      const aJson = await exportTo(
        { format: 'json', scope: whole, reader: store.reader, anonymise: true, includeRawBytes: true },
        { pageSize: PAGE },
      );
      const aText = new TextDecoder().decode(aJson.sink.bytes());
      const aDoc = JSON.parse(aText) as { packets: { no: number; source: string }[] };
      check(`${name}: anonymised json still has every frame`, aDoc.packets.length, total);
      const byId = new Map(packets.map((p, ordinal) => [p.id, { p, ordinal }]));
      const pseudonym = new Map<string, Set<string>>();
      for (const out of aDoc.packets) {
        const src = byId.get(out.no)!.p.source;
        if (!parseIpv4(src) || !real.has(src)) continue;
        let set = pseudonym.get(src);
        if (!set) pseudonym.set(src, set = new Set());
        set.add(out.source);
      }
      check(`${name}: each real address has exactly one pseudonym across the whole file`,
        [...pseudonym.values()].filter((s) => s.size !== 1).length, 0);
      // The pair the rule is about: one frame on disk, one in the window -
      // necessarily different pages, and different halves of the reader.
      const address = [...pseudonym.keys()].find((a) =>
        packets.slice(0, split).some((p) => p.source === a) && tail.some((p) => p.source === a));
      if (address === undefined) {
        console.log(`SKIP  ${name}: no source address on both sides of the seam`);
      } else {
        const first = aDoc.packets.find((o) => byId.get(o.no)!.p.source === address)!;
        const lastSeen = [...aDoc.packets].reverse().find((o) => byId.get(o.no)!.p.source === address)!;
        checkTrue(`${name}: two frames pages apart share ${address}`,
          Math.floor(byId.get(lastSeen.no)!.ordinal / PAGE) > Math.floor(byId.get(first.no)!.ordinal / PAGE));
        checkTrue(`${name}: ...and share its pseudonym, which is not the address`,
          first.source === lastSeen.source && first.source !== address);
      }
      check(`${name}: no real address anywhere in the anonymised json`, leaks(aText, real), []);

      // The rows name the adapter the way the metadata does: the writers are
      // handed the job's anonymiser and the real adapter list, so they label
      // through the same mapping `redactMeta` used.
      const adapterName = packets[0].interfaceName;
      const live = await exportTo({
        format: 'json', scope: whole, reader: store.reader, anonymise: true,
        source: { kind: 'live', adapters: [adapterName] },
      });
      const liveDoc = JSON.parse(new TextDecoder().decode(live.sink.bytes())) as {
        meta: { source: { adapters: string[] } }; packets: { interface: string }[];
      };
      check(`${name}: an anonymised export labels the adapter in its rows as its metadata does`,
        [...new Set(liveDoc.packets.map((p) => p.interface))], liveDoc.meta.source.adapters);

      const aCsv = await exportTo({ format: 'csv', scope: whole, reader: store.reader, anonymise: true });
      check(`${name}: ...nor in the anonymised csv`, leaks(new TextDecoder().decode(aCsv.sink.bytes()), real), []);
      const aNg = await exportTo({ format: 'pcapng', scope: whole, reader: store.reader, anonymise: true });
      const aBack = await reparse(aNg.sink.bytes(), 'a.pcapng');
      check(`${name}: the anonymised pcapng keeps every frame`, aBack.length, total);
      check(`${name}: ...and re-dissected, names no real address`,
        leaks(aBack.map((p) => `${p.source} ${p.destination}`).join('\n'), real), []);
      check(`${name}: ...not in its blocks' text either`,
        leaks(Buffer.from(aNg.sink.bytes()).toString('latin1'), real).filter((a) => a.includes('.')), []);
      const aPdf = await exportTo({ format: 'pdf', scope: whole, reader: store.reader, anonymise: true });
      check(`${name}: ...nor in the anonymised pdf`, leaks(pdfStrings(aPdf.sink.bytes()).join('\n'), real), []);

      // ---- cancel -------------------------------------------------------------
      const controller = new AbortController();
      const aborted = await exportTo({ format: 'pcapng', scope: whole, reader: store.reader }, {
        signal: controller.signal,
        pageSize: PAGE,
        onProgress: (p) => { if (p.phase === 'writing' && p.done > 0) controller.abort(); },
      });
      check(`${name}: Cancel mid-write ends the export as cancelled`, aborted.result.outcome, 'canceled');
      checkTrue(`${name}: ...and aborts the sink, committing nothing`, aborted.sink.aborted && !aborted.sink.closed);
      checkTrue(`${name}: ...having stopped short of the capture`,
        (aborted.progress.filter((p) => p.phase === 'writing').pop()?.done ?? total) < total);

      const failingController = new AbortController();
      const cancelledInSurvey = await exportTo({ format: 'csv', scope: whole, reader: store.reader }, {
        signal: failingController.signal,
        onProgress: (p) => { if (p.phase === 'surveying' && p.done > 0) failingController.abort(); },
      });
      checkTrue(`${name}: Cancel during the survey commits nothing either`,
        cancelledInSurvey.result.outcome === 'canceled' && cancelledInSurvey.sink.aborted
        && !cancelledInSurvey.sink.closed && cancelledInSurvey.sink.byteLength === 0);

      const readsBefore = store.rowReads;
      const dismissed = await runExport(
        {
          format: 'csv', scope: whole, reader: store.reader, interfaces: [], includeRawBytes: false,
          compress: false, anonymise: false, source: { kind: 'session' },
          drops: { kernel: null, agent: null, pipe: null }, received: null, os: null,
        },
        { openSink: async () => ({ canceled: true }) },
      );
      check(`${name}: a dismissed save dialog is a cancel`, dismissed.outcome, 'canceled');
      check(`${name}: ...and reads nothing`, store.rowReads, readsBefore);

      // ---- compressed ---------------------------------------------------------
      const zipped = await exportTo({ format: 'pcap', scope: whole, reader: store.reader, compress: true });
      const zbytes = zipped.sink.bytes();
      checkTrue(`${name}: compress writes a zip`, zbytes[0] === 0x50 && zbytes[1] === 0x4b);
      const { unzipSync } = await import('fflate');
      const entries = Object.values(unzipSync(zbytes));
      check(`${name}: ...of one entry holding the whole capture`,
        entries.length === 1 ? (await reparse(entries[0], 'z.pcap')).length : -1, total);

      // ---- the capture changes under a running export ----------------------
      //
      // What App does before any `captureStore.begin`: cancel the job and wait
      // for it to let go of its file. Driven through the same job store the
      // panel reads, so the reason it shows is the one asserted here.
      {
        const handle = beginExportJob('pcapng');
        checkTrue(`${name}: a job starts`, handle !== null);
        const sink = new SlowSink();
        let writing!: () => void;
        const reachedWriting = new Promise<void>((resolve) => { writing = resolve; });
        sink.onWrite = () => writing();
        const running = runExport({
          ...baseRequest, format: 'pcapng', scope: whole, reader: store.reader,
        }, {
          signal: handle!.signal,
          pageSize: PAGE,
          openSink: async () => sink,
          onProgress: (p) => handle!.progress(p),
        }).then((result) => { handle!.settle(result); return result; });
        await reachedWriting;
        await cancelExportForChange('a new capture started');
        // This is where App calls `captureStore.begin`: the file must already
        // be gone.
        const goneBeforeBegin = sink.aborted && !sink.closed;
        const result = await running;
        const job = getExportJob();
        check(`${name}: a new capture cancels the running export first`, result.outcome, 'canceled');
        checkTrue(`${name}: ...its file aborted and never committed, before the store re-opens`,
          goneBeforeBegin);
        check(`${name}: ...and the panel is told why`,
          job.status === 'canceled' ? job.reason : job.status, 'a new capture started');
      }
      {
        // Belt and braces: a path that re-opened the store without cancelling
        // first. The reader refuses the next read, loudly, and nothing is kept.
        let generation = 0;
        const sink = new MemorySink();
        const result = await runExport({
          ...baseRequest, format: 'csv', scope: whole, reader: store.reader, captureIdentity: () => generation,
        }, {
          pageSize: PAGE,
          openSink: async () => sink,
          onProgress: (p) => { if (p.phase === 'writing' && p.done > 0) generation++; },
        });
        check(`${name}: a store re-opened mid-export fails the export`,
          result.outcome === 'failed' ? result.error.startsWith('the capture changed') : result.outcome, true);
        checkTrue(`${name}: ...and leaves no file`, sink.aborted && !sink.closed);
      }

      // ---- frames the store cannot supply bytes for ------------------------
      {
        // The store answers for every frame but these: the disk half's first
        // few hundred, as a store missing a stretch of `frames.iwbyt` would.
        const lost = new Set(packets.slice(0, 300).map((p) => p.id));
        const holes: CaptureRowReader = {
          readRowsAt: (from, to) => store.reader.readRowsAt(from, to),
          ordinalOf: (id) => store.reader.ordinalOf(id),
          readBytes: async (list) => {
            const found = await store.reader.readBytes(list);
            for (const id of lost) found.delete(id);
            return found;
          },
        };
        const pcapRun = await exportTo({ format: 'pcap', scope: whole, reader: holes });
        check(`${name}: frames without bytes are counted in the result`,
          pcapRun.result.outcome === 'saved' ? [pcapRun.result.frames, pcapRun.result.withoutBytes] : pcapRun.result,
          [total, lost.size]);
        check(`${name}: ...and still written, as empty records`,
          (await reparse(pcapRun.sink.bytes(), 'h.pcap')).length, total);
        const xlsxRun = await exportTo({ format: 'xlsx', scope: whole, reader: holes, includeRawBytes: true });
        const xb = xlsxRun.sink.bytes();
        const book = new ExcelJS.Workbook();
        await book.xlsx.load(xb.buffer.slice(xb.byteOffset, xb.byteOffset + xb.byteLength) as ArrayBuffer);
        const said: string[] = [];
        book.getWorksheet('Capture')?.eachRow((row) => { said.push(row.values ? JSON.stringify(row.values) : ''); });
        checkTrue(`${name}: ...and Excel's Capture sheet says how many`,
          said.some((line) => line.includes('Frames without bytes') && line.includes(EN.format(lost.size))));
      }

      // ---- a torn tail below the window, and nothing after it --------------
      {
        // Matches only below the window, and the last of them in a chunk the
        // store cannot read: no page follows the loss to carry its count.
        const tornAt = (await store.reader.readRowsAt(split - 100, split - 99))[0].firstOrdinal;
        const cut = packets[split - 100].id;
        const expression = `frame.number <= ${cut}`;
        const expectedAll = FilterEngine.filterPackets(packets, expression);
        checkTrue(`${name}: the filter's matches are all below the window`,
          expectedAll.every((p) => p.id < tail[0].id));
        const lostMatches = expectedAll.filter((p) => byId.get(p.id)!.ordinal >= tornAt).length;
        checkTrue(`${name}: ...and some of them are in the torn chunk`, lostMatches > 0);
        const torn: CaptureRowReader = {
          readRowsAt: async (from, to) => (await store.reader.readRowsAt(from, to))
            .map((b) => (b.firstOrdinal >= tornAt ? { ...b, packets: [] } : b)),
          ordinalOf: (id) => store.reader.ordinalOf(id),
          readBytes: (list) => store.reader.readBytes(list),
        };
        const tornScope: FrameScope = { window, filter: { expression, matches: await store.scan(expression) } };
        const tornRun = await exportTo({ format: 'json', scope: tornScope, reader: torn });
        const tornDoc = JSON.parse(new TextDecoder().decode(tornRun.sink.bytes())) as {
          meta: { frames: { exported: number; unreadable: number } }; packets: unknown[];
        };
        check(`${name}: the lost matches reach the metadata`,
          [tornDoc.packets.length, tornDoc.meta.frames.unreadable], [expectedAll.length - lostMatches, lostMatches]);
        check(`${name}: ...and the result`,
          tornRun.result.outcome === 'saved' ? tornRun.result.unreadable : tornRun.result, lostMatches);
        const lastTorn = tornRun.progress.filter((p) => p.phase === 'writing').pop();
        check(`${name}: ...and progress still ends with done === total`,
          lastTorn && [lastTorn.done, lastTorn.total], [expectedAll.length, expectedAll.length]);
        const ngTorn = await exportTo({ format: 'pcapng', scope: tornScope, reader: torn });
        check(`${name}: ...through the time-ordered path too`,
          ngTorn.result.outcome === 'saved' ? ngTorn.result.unreadable : ngTorn.result, lostMatches);
      }

      // ---- a scan that stopped short of the window -------------------------
      {
        // The scan's real answer for the frames that existed when it started,
        // on a capture that has since grown past it: refused and named, not
        // exported without the frames it never looked at.
        const expression = 'dns';
        const covered = Math.floor(split / 2);
        const early = new MatchSet(covered);
        FilterEngine.filterPackets(packets.slice(0, covered), expression)
          .forEach((p) => early.set(byId.get(p.id)!.ordinal));
        early.seal();
        const behind = await exportTo({
          format: 'csv', scope: { window, filter: { expression, matches: early } }, reader: store.reader,
        });
        check(`${name}: a scan behind the window is refused, saying how far`,
          behind.result.outcome === 'failed'
            ? behind.result.error.startsWith(`${EN.format(split - covered)} frames on disk arrived after`)
            : behind.result.outcome,
          true);
        checkTrue(`${name}: ...and leaves no file`, behind.sink.aborted && !behind.sink.closed);
      }

      store.close();
    }
    // ---- one adapter label, two link types, through the whole path --------
    //
    // Both fixtures merged by Wireshark's own tools, one re-labelled Raw IP,
    // as `pcapng.ts` and `whole-capture.ts` build it. Every imported frame
    // carries one label, so the disk rows' link types can only come from the
    // store's own record of them; tshark then reads the export back.
    const editcap = findWiresharkTool('editcap');
    const mergecap = findWiresharkTool('mergecap');
    if (tshark === null || editcap === null || mergecap === null || captures.length < 2) {
      console.log('SKIP  multi-link-type export: tshark, editcap, mergecap or the second fixture not found');
    } else {
      console.log('\n--- one label, two link types ---\n');
      const raw = join(scratch, 'raw.pcap');
      const merged = join(scratch, 'merged.pcapng');
      runTool(editcap, ['-T', 'rawip', captures[1].path, raw]);
      runTool(mergecap, ['-F', 'pcapng', '-w', merged, captures[0].path, raw]);
      const { packets } = await PcapService.parseCaptureFile(
        new File([new Uint8Array(readFileSync(merged))], 'merged.pcapng'), Number.POSITIVE_INFINITY);
      const store = await storeOf(packets);
      const window = packets.slice(Math.floor(packets.length * 0.8));
      const run = await exportTo({ format: 'pcapng', scope: { window, filter: null }, reader: store.reader });
      const out = join(scratch, 'merged-out.pcapng');
      writeFileSync(out, run.sink.bytes());
      const encap = (path: string) => runTool(tshark, ['-r', path, '-T', 'fields',
        '-e', 'frame.time_epoch', '-e', 'frame.encap_type', '-e', 'frame.len'])
        .split(/\r?\n/).filter(Boolean).sort();
      const reference = encap(merged);
      const ours = encap(out);
      check('merged: the exported pcapng has every frame with its own link type, time and length',
        [ours.length, ours.filter((l, i) => l !== reference[i]).slice(0, 3)], [reference.length, []]);
      store.close();
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  const formats: ExportFormat[] = ['pcap', 'pcapng', 'csv', 'json', 'xlsx', 'pdf'];
  console.log(`\nFormats driven: ${formats.join(', ')}`);
  console.log(failures === 0 ? '\nAll assertions passed.' : `\n${failures} assertion(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
