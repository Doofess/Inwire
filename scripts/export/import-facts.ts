/**
 * An imported capture file keeps what it says about how it was taken
 * (ADR 0052).
 *
 *   npx tsx scripts/export/import-facts.ts
 *
 * A pcapng file's IDBs carry its adapter's name, the capture filter and the
 * snaplen, and its ISBs what the driver received and dropped. An import used
 * to walk past all of it; now it keeps them (`captureFileFacts.ts`), the
 * metadata states them, and an exported pcapng carries them back out - so a
 * file round-trips with its filter, snaplen and drops.
 *
 * Over the real dumpcap-written captures in `test/fixtures/`, with `capinfos`
 * as the oracle for what each file says - a second reader of the same blocks,
 * not this parser's own opinion of them - and the classic pcaps for the one
 * fact their header holds. Skips cleanly without the fixtures, and skips the
 * `capinfos` cross-check without Wireshark.
 */
import { serialize, deserialize } from 'node:v8';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { PcapService } from '../../src/services/pcapParser';
import { wholeCaptureFacts, type CaptureFileFacts } from '../../src/services/captureFileFacts';
import { metaEntries, type CaptureMeta } from '../../src/services/export/captureMeta';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { plainForStore } from '../../src/services/capture/storePacket';
import { runExport, type ExportRequest } from '../../src/services/export/runExport';
import { MemorySink, type OpenSinkResult } from '../../src/lib/saveSink';
import type { CaptureRowReader } from '../../src/services/export/exportFrames';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import { OPTIONAL_CAPTURES, REAL_CAPTURES, findWiresharkTool } from './realCaptures';

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

const crossed = <T>(value: T): T => deserialize(serialize(value)) as T;
const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test', 'fixtures');
const capinfos = findWiresharkTool('capinfos');

/** What capinfos says a file's first interface and section are. */
function capinfosFacts(file: string) {
  const text = execFileSync(capinfos!, [file], { encoding: 'utf8' });
  const field = (label: string) => new RegExp(`^\\s*${label}\\s*[=:]\\s*(.*)$`, 'm').exec(text)?.[1]?.trim() ?? null;
  const length = field('Capture length');
  return {
    application: field('Capture application'),
    name: field('Name'),
    description: field('Description'),
    filter: field('Filter string'),
    snaplen: length === null ? null : Number(length),
  };
}

const metaFor = (fileName: string, facts: CaptureFileFacts): CaptureMeta => ({
  app: 'Inwire', version: 'test', os: null, generatedAt: 0,
  source: { kind: 'import', fileName, facts },
  firstUs: null, lastUs: null, frames: { exported: 0, inCapture: 0, unreadable: 0 },
  drops: { kernel: null, agent: null, pipe: null }, scope: 'capture', filter: '',
  flags: { anonymised: false, rawBytes: true, fields: false, secrets: false },
});
const entry = (meta: CaptureMeta, key: string) => metaEntries(meta).find(([k]) => k === key)?.[1];

/** A store over memory holding `packets`, read the way `captureStore` is. */
async function readerOver(packets: Parameters<typeof plainForStore>[0][]): Promise<CaptureRowReader> {
  const waiting = new Map<number, (message: FromCapture) => void>();
  const host = new CaptureHost(new MemoryVolume(), (message) => {
    const copy = crossed(message);
    const id = (copy as { requestId?: number }).requestId;
    if (id === undefined) return;
    waiting.get(id)?.(copy);
    waiting.delete(id);
  });
  let next = 1;
  const ask = (build: (requestId: number) => ToCapture) => new Promise<FromCapture>((resolve) => {
    const requestId = next++;
    waiting.set(requestId, resolve);
    host.receive(build(requestId));
  });
  host.receive({ type: 'open', captureId: 'cap-20260928-120000-0f0f' });
  host.receive({ type: 'append', packets: crossed(packets.map(plainForStore)) });
  host.receive({ type: 'finish' });
  await host.drain();
  return {
    async readRowsAt(from, to) {
      const a = await ask((requestId) => ({ type: 'rowsAt', requestId, from, to }));
      return a.type === 'blocks' ? a.blocks : [];
    },
    async readBytes(ids) {
      const a = await ask((requestId) => ({ type: 'read', requestId, ids: [...ids] }));
      return new Map(a.type === 'bytes' ? a.frames : []);
    },
    async ordinalOf(id) {
      const a = await ask((requestId) => ({ type: 'locate', requestId, id }));
      return a.type === 'located' ? a.ordinal : -1;
    },
  };
}

async function main(): Promise<void> {
  const dumpcapped = Object.entries(OPTIONAL_CAPTURES)
    .map(([name, file]) => ({ name, file: path.join(fixtures, file) }))
    .filter((f) => existsSync(f.file));
  if (dumpcapped.length === 0) {
    console.log('SKIP  the dumpcap-written fixtures are not present (test/fixtures/README.md)');
    process.exit(0);
  }
  const scratch = mkdtempSync(path.join(tmpdir(), 'inwire-import-facts-'));
  try {
    for (const { name, file } of dumpcapped) {
      console.log(`\n--- ${name} ---\n`);
      const { packets, facts } = await PcapService.parseCaptureFile(new File([readFileSync(file)], path.basename(file)));
      const first = facts.interfaces[0];
      if (capinfos !== null) {
        const said = capinfosFacts(file);
        check('the file\'s application, adapter, filter and snaplen are what capinfos reads',
          [facts.application, first?.name, first?.description, first?.filter, first?.snaplen],
          [said.application, said.name, said.description, said.filter,
            said.snaplen === null || said.snaplen >= 262_144 ? null : said.snaplen]);
      }
      const whole = wholeCaptureFacts(facts);
      check('the ISB\'s counts are read: at least the frames the file holds were received',
        whole.received !== null && whole.received >= packets.length && whole.dropped !== null, true);

      const meta = metaFor(path.basename(file), facts);
      check('the metadata states the file\'s filter',
        entry(meta, 'Capture filter'), whole.filter === undefined ? 'not available' : (whole.filter ?? 'none'));
      check('...and what captured it', entry(meta, 'Captured by'), facts.application);

      // Out again, as a pcapng export of the imported capture.
      const sink = new MemorySink();
      const request: ExportRequest = {
        format: 'pcapng', scope: { window: packets.slice(-1), filter: null }, reader: await readerOver(packets),
        includeRawBytes: true, compress: false, anonymise: false,
        source: { kind: 'import', fileName: path.basename(file), facts },
        drops: { kernel: null, agent: null, pipe: null }, received: null, os: 'test OS', interfaces: [],
      };
      await runExport(request, { openSink: async (): Promise<OpenSinkResult> => sink, now: () => 0 });
      const exported = path.join(scratch, `${name}.pcapng`);
      writeFileSync(exported, sink.bytes());
      const again = (await PcapService.parseCaptureFile(new File([sink.bytes()], `${name}.pcapng`))).facts;
      const back = wholeCaptureFacts(again);
      check('an export of it carries the same filter, snaplen and counts back out',
        [back.filter, back.snaplen, back.received, back.dropped],
        [whole.filter, whole.snaplen, whole.received, whole.dropped]);
      if (capinfos !== null) {
        check('...which capinfos reads too', capinfosFacts(exported).filter, capinfosFacts(file).filter);
      }
    }

    console.log('\n--- classic pcap ---\n');
    for (const [name, file] of Object.entries(REAL_CAPTURES)) {
      const full = path.join(fixtures, file);
      if (!existsSync(full)) continue;
      const header = readFileSync(full).subarray(0, 24);
      const snaplen = header.readUInt32LE(16);
      const { facts } = await PcapService.parseCaptureFile(new File([header], file));
      check(`${name}: a classic file's one fact, its snaplen, is kept`,
        facts.interfaces.map((f) => f.snaplen), [snaplen >= 262_144 || snaplen === 0 ? null : snaplen]);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All import fact checks passed.');
  process.exit(0);
}

void main();
