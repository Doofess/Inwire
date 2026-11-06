/**
 * An import in the Worker, through the real built app: the capture it stores is
 * the one the in-process import would store, and Cancel leaves nothing behind.
 *
 *   npm run build && npx tsx scripts/electron/import-worker-drive.ts
 *     [--frames 300000] [--pcap <file>]
 *
 * `scripts/capture/import-worker-equivalence.ts` proves the Worker route equals
 * `PcapService.streamCaptureFile` in Node, with a fake store and a fake page.
 * This is the same claim end to end, against the built app and its real store.
 *
 * ## Session 1: the stored capture equals the in-process one
 *
 * Imports a synthetic multi-window pcap (`--frames`, mixed sizes, UDP, DNS pairs
 * and a few TCP flows, so the stored records are not all alike) through the
 * Export / Import panel's own input, or `--pcap <file>` instead. Once the app has
 * sealed and closed, the capture directory is read back with `CaptureReader`
 * (imports write version 3 pack-native chunks) and compared, batch by batch and
 * without holding the capture, with `streamCaptureFile` over the same file run
 * in this process: every row (scalars, fields), every frame's bytes and every
 * frame's record, by id (its `env:now` held to the app's import window, see
 * `sameRecord`). A mismatch prints the frame id and the NAMES of the
 * fields, never a value: the `--pcap` file is the owner's private capture.
 *
 * ## Session 2: Cancel discards the import
 *
 * A fresh profile, given a previous capture by importing a small file to the end.
 * Then a large file is imported and Cancel is pressed once the bar reads 10% or
 * more. Afterwards: no new capture directory, no error dialog, the view empty
 * with the previous capture offered for Reopen, and Start enabled once an adapter
 * is chosen.
 *
 * In `check.ts`'s NOT_TESTS: it needs a build, generates a file of ~240 MB, and
 * takes a minute or more (minutes with `--pcap` on a multi-gigabyte capture).
 */
import { closeSync, existsSync, mkdtempSync, openAsBlob, openSync, readdirSync, rmSync, statSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { inflateSync } from 'fflate';
import type { Page } from 'playwright';
import { captureVolume } from '../../electron/store/volume';
import { CaptureIndex, recoverCapture } from '../../src/services/capture/captureIndex';
import { dataFilesOf } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { recordEntries } from '../../src/services/dissect/frameRecord';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';
import { canonicalRow, rowDifference } from '../capture/importEquivalenceRig';
import { launchApp } from './launchApp';
import { startStubAgent } from './stubAgent';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const FRAMES = Number(arg('frames', '600000'));
const GIVEN = arg('pcap', '');
const IMPORT_TIMEOUT_MS = 40 * 60_000;

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== '') console.log(`        ${detail}`);
}
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

if (process.platform !== 'win32') skip('the desktop app is Windows-only');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}
if (GIVEN !== '' && !existsSync(GIVEN)) skip('the --pcap file is not there');

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const MIB = 1024 * 1024;

// --- the file -----------------------------------------------------------------

/** A classic libpcap file, written here so no writer under test is the oracle. */
function writePcap(file: string, frames: number): void {
  let seed = 12345;
  const rand = (n: number) => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return (seed >>> 8) % n;
  };
  const checksum = (b: Buffer, from: number, to: number) => {
    let sum = 0;
    for (let i = from; i < to; i += 2) sum += (b[i] << 8) | b[i + 1];
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
  };
  const MAC_A = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
  const MAC_B = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02];
  const CLIENT = [192, 168, 1, 42];
  const SERVER = [10, 0, 0, 9];

  /** Ethernet + IPv4, the L4 header and payload after it; `fromClient` picks the direction. */
  const ipFrame = (i: number, proto: number, l4: Buffer, fromClient: boolean): Buffer => {
    const total = 20 + l4.length;
    const frame = Buffer.alloc(Math.max(60, 14 + total));
    Buffer.from([...(fromClient ? MAC_B : MAC_A), ...(fromClient ? MAC_A : MAC_B), 0x08, 0x00]).copy(frame, 0);
    frame[14] = 0x45;
    frame.writeUInt16BE(total, 16);
    frame.writeUInt16BE(i & 0xffff, 18);
    frame[22] = 64;
    frame[23] = proto;
    Buffer.from(fromClient ? CLIENT : SERVER).copy(frame, 26);
    Buffer.from(fromClient ? SERVER : CLIENT).copy(frame, 30);
    frame.writeUInt16BE(checksum(frame, 14, 34), 24);
    l4.copy(frame, 34);
    return frame;
  };
  const udp = (i: number, srcPort: number, dstPort: number, payload: Buffer, fromClient: boolean) => {
    const l4 = Buffer.alloc(8 + payload.length);
    l4.writeUInt16BE(srcPort, 0);
    l4.writeUInt16BE(dstPort, 2);
    l4.writeUInt16BE(l4.length, 4);
    payload.copy(l4, 8);
    return ipFrame(i, 17, l4, fromClient);
  };
  const noise = (n: number) => {
    const b = Buffer.alloc(n);
    for (let k = 0; k < n; k++) b[k] = k % 7 === 0 ? 0x20 + rand(90) : rand(256);
    return b;
  };

  // A few TCP flows: a handshake, then segments from the client and a bare ack
  // from the server now and then, with the sequence numbers followed.
  const flows = Array.from({ length: 6 }, (_, f) => ({
    port: 40_000 + f * 7, server: 9_000 + f, n: 0, seq: 1_000 + f * 100_000, ack: 5_000 + f * 100_000,
  }));
  const tcp = (i: number, flow: typeof flows[number]): Buffer => {
    const step = flow.n++;
    const header = Buffer.alloc(20);
    header[12] = 0x50;
    header.writeUInt16BE(65_535, 14);
    let payload = Buffer.alloc(0);
    let fromClient = true;
    let flags = 0x10;
    if (step === 0) flags = 0x02;
    else if (step === 1) { flags = 0x12; fromClient = false; }
    else if (step > 2 && step % 4 === 0) fromClient = false;
    else if (step > 2) { flags = 0x18; payload = noise(rand(1400)); }
    header.writeUInt16BE(fromClient ? flow.port : flow.server, 0);
    header.writeUInt16BE(fromClient ? flow.server : flow.port, 2);
    header.writeUInt32BE(fromClient ? flow.seq : flow.ack, 4);
    header.writeUInt32BE(step === 0 ? 0 : fromClient ? flow.ack : flow.seq, 8);
    header[13] = flags;
    if (step === 0) flow.seq += 1;
    else if (step === 1) flow.ack += 1;
    else if (fromClient) flow.seq += payload.length;
    return ipFrame(i, 6, Buffer.concat([header, payload]), fromClient);
  };

  let pendingDns: { id: number; port: number } | null = null;
  const dns = (i: number): Buffer => {
    const name = Buffer.from([7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0, 0, 1, 0, 1]);
    if (pendingDns === null) {
      pendingDns = { id: i & 0xffff, port: 50_000 + rand(40) };
      const q = Buffer.alloc(12 + name.length);
      q.writeUInt16BE(pendingDns.id, 0);
      q.writeUInt16BE(0x0100, 2);
      q.writeUInt16BE(1, 4);
      name.copy(q, 12);
      return udp(i, pendingDns.port, 53, q, true);
    }
    const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    const r = Buffer.alloc(12 + name.length + answer.length);
    r.writeUInt16BE(pendingDns.id, 0);
    r.writeUInt16BE(0x8180, 2);
    r.writeUInt16BE(1, 4);
    r.writeUInt16BE(1, 6);
    name.copy(r, 12);
    answer.copy(r, 12 + name.length);
    const port = pendingDns.port;
    pendingDns = null;
    return udp(i, port, 53, r, false);
  };

  const frameFor = (i: number): Buffer => {
    const k = i % 10;
    if (k < 3) return tcp(i, flows[rand(flows.length)]);
    if (k === 3) return dns(i);
    // Mixed sizes: mostly small, some medium, a few full-size.
    const size = rand(10) < 6 ? rand(120) : rand(10) < 8 ? rand(700) : 1000 + rand(458);
    return udp(i, 49_152 + rand(200), 20_000 + rand(40), noise(size), rand(2) === 0);
  };

  const fd = openSync(file, 'w');
  try {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0);
    header.writeUInt16LE(2, 4);
    header.writeUInt16LE(4, 6);
    header.writeUInt32LE(262144, 16);
    header.writeUInt32LE(1, 20);
    writeSync(fd, header);
    const BATCH = 2000;
    for (let first = 0; first < frames; first += BATCH) {
      const parts: Buffer[] = [];
      for (let i = first; i < Math.min(first + BATCH, frames); i++) {
        const frame = frameFor(i);
        const record = Buffer.alloc(16);
        record.writeUInt32LE(1_700_000_000 + Math.floor(i / 1000), 0);
        record.writeUInt32LE((i % 1000) * 1000, 4);
        record.writeUInt32LE(frame.length, 8);
        record.writeUInt32LE(frame.length, 12);
        parts.push(record, frame);
      }
      writeSync(fd, Buffer.concat(parts));
    }
  } finally {
    closeSync(fd);
  }
}

// --- the app ------------------------------------------------------------------

interface Running {
  page: Page;
  close(): Promise<void>;
}

let launches = 0;
/** One launch: the stub agent, an isolated profile, and the first-run tour skipped. */
async function launch(profile: string): Promise<Running> {
  const pipe = String.raw`\\.\pipe\inwire-import-worker-drive-${process.pid}-${launches++}`;
  const agent = await startStubAgent(pipe, 0);
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: pipe },
  });
  const page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await page.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  return {
    page,
    async close() {
      // Closing with frames in the buffer opens the quit confirm and waits forever.
      await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
      await app.close().catch(() => {});
      await agent.close();
    },
  };
}

const INPUT = 'input[type="file"][accept]';

/** Opens Export / Import and hands the panel a file through its own input. */
async function importFile(p: Page, file: string): Promise<void> {
  await p.getByLabel('Export or import a capture').click();
  await p.locator(INPUT).first().waitFor({ state: 'attached' });
  await p.locator(INPUT).first().setInputFiles(file);
}

const importedLine = (p: Page): Promise<string | null> => p.evaluate(
  () => document.body.innerText.match(/Imported [\d,]+ packets from [^\n]+/)?.[0] ?? null);

async function until(fn: () => Promise<boolean>, ms: number, every = 200): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await fn().catch(() => false)) return true;
    await sleep(every);
  }
  return false;
}

const captureDirs = (profile: string): string[] => {
  const root = path.join(profile, 'captures');
  return existsSync(root) ? readdirSync(root).filter((d) => d.startsWith('cap-')).sort() : [];
};

// --- session 1 ----------------------------------------------------------------

class Mismatch extends Error {}

/** The sealed capture, open for reading. */
function openStored(profile: string, id: string) {
  const volume = captureVolume(path.join(profile, 'captures')).open(id);
  const { records, plan, version } = recoverCapture(volume.index, (n) => dataFilesOf(volume, n));
  const index = new CaptureIndex(records.slice(0, plan.keepRecords), version, plan.floorChunk);
  return { volume, index, reader: new CaptureReader(volume, index, inflateSync) };
}

const NO_BYTES = new Uint8Array(0);

/** When the app's import ran: the clock a stored record's `env:now` must fall inside. */
interface Window { from: number; to: number }

/**
 * Two records of one frame are the same answers. Byte-equal is the common case;
 * otherwise every entry is decoded and compared, name and value, except one: the
 * `env:now` the dissection read (a certificate's validity is judged against it),
 * which is recorded at arrival ON PURPOSE so a revisit gives the arrival's
 * verdict - two runs of one file never record the same clock. The stored one must
 * be a Date inside the app's import, the in-process one a Date too.
 */
function sameRecord(want: Uint8Array, got: Uint8Array, app: Window): boolean {
  if (Buffer.compare(want, got) === 0) return true;
  const [a, b] = [recordEntries(want), recordEntries(got)];
  if (a.length !== b.length) return false;
  return a.every(([key, value], i) => {
    const [otherKey, other] = b[i];
    if (key !== otherKey) return false;
    if (key !== 'env:now') return isDeepStrictEqual(value, other);
    return value instanceof Date && other instanceof Date
      && other.getTime() >= app.from - 1000 && other.getTime() <= app.to + 1000;
  });
}

/**
 * `streamCaptureFile` over the file, in this process, each batch compared as it
 * arrives with the next rows of the stored capture: rows and records by id, the
 * frames' bytes. The stored capture is read a chunk at a time and dropped.
 */
async function compareWithInProcess(file: string, profile: string, id: string, app: Window): Promise<{ frames: number; stored: number }> {
  const { volume, index, reader } = openStored(profile, id);
  try {
    let at = index.floorOrdinal;
    let rows: Packet[] = [];
    let bytes = new Map<number, Uint8Array>();
    let pos = 0;
    const nextStored = (): { row: Packet; raw: Uint8Array } | null => {
      if (pos >= rows.length) {
        const chunk = reader.readRowsAt(at, index.frameCount)[0];
        if (chunk === undefined || chunk.packets.length === 0) return null;
        rows = chunk.packets;
        at = chunk.firstOrdinal + rows.length;
        bytes = reader.readBytes(rows.map((r) => r.id));
        pos = 0;
      }
      const row = rows[pos++];
      return { row, raw: bytes.get(row.id) ?? NO_BYTES };
    };

    let compared = 0;
    let recordDifferences = 0;
    const byProtocol = new Map<string, number>();
    const firstRecordDifferences: string[] = [];
    const outcome = await PcapService.streamCaptureFile(await openAsBlob(file) as File, (batch, records) => {
      const recordOf = new Map((records ?? []).map((r) => [r.id, r.record]));
      for (const packet of batch) {
        const stored = nextStored();
        if (stored === null) throw new Mismatch(`the stored capture ends before frame ${packet.id}`);
        if (stored.row.id !== packet.id) {
          throw new Mismatch(`frame ${packet.id}: the stored capture holds frame ${stored.row.id} at that place`);
        }
        const [x, y] = [canonicalRow({ ...packet, rawBytes: NO_BYTES }), canonicalRow({ ...stored.row, rawBytes: NO_BYTES })];
        if (x.scalars !== y.scalars || x.fields !== y.fields) {
          const d = rowDifference(x, y);
          throw new Mismatch(`frame ${packet.id}: row differs - scalar keys [${d.scalarKeys.join(', ')}], field keys [${d.fieldKeys.join(', ')}]`);
        }
        if (Buffer.compare(packet.rawBytes, stored.raw) !== 0) throw new Mismatch(`frame ${packet.id}: bytes differ`);
        const want = recordOf.get(packet.id) ?? null;
        const got = reader.readRecord(packet.id);
        if ((want === null) !== (got === null) || (want !== null && got !== null && !sameRecord(want, got, app))) {
          // Sizes and offsets only: a record holds the frame's addresses. Collected, not thrown:
          // how many frames differ, and where in the record, says more than the first.
          recordDifferences++;
          byProtocol.set(packet.protocolLabel ?? packet.protocol, (byProtocol.get(packet.protocolLabel ?? packet.protocol) ?? 0) + 1);
          if (firstRecordDifferences.length < 5) {
            const offsets: number[] = [];
            if (want !== null && got !== null) {
              for (let k = 0; k < Math.min(want.length, got.length) && offsets.length < 12; k++) if (want[k] !== got[k]) offsets.push(k);
            }
            firstRecordDifferences.push(`frame ${packet.id}: in-process ${want === null ? 'none' : `${want.length} bytes`}, `
              + `stored ${got === null ? 'none' : `${got.length} bytes`}, differing offsets [${offsets.join(', ')}]`);
          }
        }
        compared++;
      }
    }, { record: true });
    if (recordDifferences > 0) {
      throw new Mismatch(`${recordDifferences} frames' records differ (by protocol ${JSON.stringify([...byProtocol])}); first: ${firstRecordDifferences.join(' | ')}`);
    }
    if (nextStored() !== null) throw new Mismatch(`the stored capture holds more than the file's ${outcome.totalFrames} frames`);
    if (compared !== outcome.totalFrames) throw new Mismatch(`compared ${compared} of ${outcome.totalFrames} frames`);
    return { frames: compared, stored: index.frameCount };
  } finally {
    volume.close();
  }
}

async function sessionEquivalence(file: string, profile: string): Promise<void> {
  console.log('--- session 1: the stored capture equals the in-process one ---');
  let importWindow: Window = { from: 0, to: 0 };
  const app = await launch(profile);
  try {
    const startedAt = Date.now();
    await importFile(app.page, file);
    const done = await until(async () => (await importedLine(app.page)) !== null, IMPORT_TIMEOUT_MS, 500);
    importWindow = { from: startedAt, to: Date.now() };
    const seconds = (Date.now() - startedAt) / 1000;
    check('the app imported the file', done, 'no "Imported N packets from" line');
    if (!done) return;
    console.log(`      the app's import took ${seconds.toFixed(1)} s`);
  } finally {
    await app.close();
  }
  const dirs = captureDirs(profile);
  check('one sealed capture directory', dirs.length === 1, `found ${dirs.length}`);
  if (dirs.length !== 1) return;
  const startedAt = Date.now();
  try {
    const { frames, stored } = await compareWithInProcess(file, profile, dirs[0], importWindow);
    check(`stored capture equals in-process (${frames.toLocaleString()} frames, ${stored.toLocaleString()} stored, `
      + `${((Date.now() - startedAt) / 1000).toFixed(1)} s)`, frames === stored, `${frames} compared, ${stored} stored`);
  } catch (error) {
    check('stored capture equals in-process', false, error instanceof Mismatch ? error.message : String(error).split('\n')[0]);
  }
}

// --- session 2 ----------------------------------------------------------------

async function sessionCancel(small: string, large: string, profile: string): Promise<void> {
  console.log('--- session 2: Cancel discards the import ---');
  const app = await launch(profile);
  const p = app.page;
  try {
    await importFile(p, small);
    check('the previous capture imported', await until(async () => (await importedLine(p)) !== null, 120_000));
    const before = captureDirs(profile);
    check('...and is the one capture on disk', before.length === 1, `found ${before.length}`);

    await p.locator(INPUT).first().waitFor({ state: 'attached' });
    await p.locator(INPUT).first().setInputFiles(large);
    const bar = p.locator('[role="progressbar"]').first();
    const reached = await until(async () => Number(await bar.getAttribute('aria-valuenow', { timeout: 1000 })) >= 10, 120_000, 50);
    check('the bar reached 10% before the import ended (else raise --frames)', reached);
    if (!reached) return;
    await p.getByRole('button', { name: 'Cancel import' }).click();
    check('the panel says "Import cancelled"',
      await until(async () => (await p.evaluate(() => document.body.innerText)).includes('Import cancelled'), 60_000));

    // The discard is asynchronous: watch the listing settle.
    const same = await until(async () => {
      const now = captureDirs(profile);
      return now.length === before.length && now.every((d, i) => d === before[i]);
    }, 15_000, 250);
    await sleep(1500);
    const after = captureDirs(profile);
    check('no new capture directory', same && after.length === before.length && after.every((d, i) => d === before[i]),
      `before ${before.length}, after ${after.length}`);

    const dialog = await p.evaluate(() => ({
      dialogs: [...document.querySelectorAll<HTMLElement>('[role="alertdialog"]')].filter((el) => el.getClientRects().length > 0).length,
      title: document.getElementById('import-error-title') !== null,
    }));
    check('no error dialog', dialog.dialogs === 0 && !dialog.title, JSON.stringify(dialog));

    const count = await p.evaluate(() => Number(
      document.querySelector('[data-packet-counts]')?.textContent?.match(/([\d,]+)/)?.[1]?.replace(/,/g, '') ?? '-1'));
    const offered = await p.getByText(/is still on disk/).count();
    const reopen = await p.getByRole('button', { name: /Reopen/ }).count();
    check('view empty and Reopen offered', count === 0 && offered > 0 && reopen > 0,
      `packets ${count}, offer text ${offered}, Reopen buttons ${reopen}`);

    await p.getByRole('button', { name: 'Interfaces' }).click();
    await p.getByText('Ethernet', { exact: true }).first().click();
    const start = p.locator('button[data-tour="start"]');
    check('Start enabled', await until(async () => await start.isEnabled(), 10_000));
  } catch (error) {
    check('the drive ran to its end', false, String(error).split('\n').slice(0, 3).join(' | '));
  } finally {
    await app.close();
  }
}

// --- run ----------------------------------------------------------------------

const files = mkdtempSync(path.join(tmpdir(), 'inwire-worker-drive-'));
const profiles: string[] = [];
const freshProfile = () => { const d = mkdtempSync(path.join(tmpdir(), 'inwire-worker-drive-p-')); profiles.push(d); return d; };
try {
  const synthetic = path.join(files, 'worker-drive-synthetic.pcap');
  writePcap(synthetic, FRAMES);
  console.log(`wrote ${FRAMES.toLocaleString()} synthetic frames: ${Math.round(statSync(synthetic).size / MIB)} MiB`);
  if (GIVEN !== '') console.log(`session 1 imports the --pcap file: ${Math.round(statSync(GIVEN).size / MIB)} MiB`);
  await sessionEquivalence(GIVEN !== '' ? GIVEN : synthetic, freshProfile());

  const small = path.join(files, 'worker-drive-small.pcap');
  writePcap(small, 3_000);
  await sessionCancel(small, synthetic, freshProfile());
} finally {
  rmSync(files, { recursive: true, force: true });
  for (const d of profiles) rmSync(d, { recursive: true, force: true });
}

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import worker drive checks passed.');
process.exit(0);
