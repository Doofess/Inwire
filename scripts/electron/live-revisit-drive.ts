/**
 * A LIVE capture, through the real agent, and its trees rebuilt from records.
 *
 *   npm run build && npx tsx scripts/electron/live-revisit-drive.ts
 *
 * `revisit-drive.ts` imports captures, which record on the renderer's thread.
 * A live capture records in the pipeline Worker, posts its records down the
 * Worker's own store port, and is the path a person actually uses - and no
 * import reaches it. So: the built app, the installed `InwireAgent` service,
 * the real Ethernet adapter, and real traffic, made by a headless browser
 * loading pages while the capture runs.
 *
 * **The oracle is the capture itself.** After Stop, the capture's directory is
 * copied and the copy opened the way the store opens one; its frames are
 * dissected in order, here, with fresh trackers - which is what arrival did in
 * the Worker. Frames old enough to have left the Worker's 4,000-tree cache are
 * then opened in the app, so each is rebuilt from its record, and the rows
 * that need the frames before them must be the rows this dissection drew. A
 * spy on the Worker's `postMessage` requires a `detail` and no `replay`.
 *
 * Only rows that do not depend on this machine's identity are compared: a
 * live Worker learns that from the agent, and this dissection does not have
 * it.
 *
 * Not in `npm run check` (`check.ts`'s NOT_TESTS): it needs a build, the
 * installed agent, Npcap, an Ethernet adapter with traffic, and about two
 * minutes. Real capture only; no stub agent. Skips cleanly without any of it.
 */
import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { inflateSync } from 'fflate';
import { captureVolume } from '../../electron/store/volume';
import { CaptureIndex, recoverCapture } from '../../src/services/capture/captureIndex';
import { dataFilesOf } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { LINKTYPE } from '../../src/services/dissect/types';
import type { Packet, ProtocolField, ProtocolLayer } from '../../src/types/packet';

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
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

/** The Worker's tree cache (`DETAIL_CACHE_FRAMES`), with room to spare. */
const OUT_OF_CACHE = 5000;
/** Enough frames that some are well out of the cache. */
const WANT_FRAMES = 12_000;

function fieldOf(layers: ProtocolLayer[], abbrev: string): ProtocolField | undefined {
  const walk = (fields: ProtocolField[]): ProtocolField | undefined => {
    for (const f of fields) {
      if (f.abbrev === abbrev) return f;
      const inner = f.children ? walk(f.children) : undefined;
      if (inner !== undefined) return inner;
    }
    return undefined;
  };
  for (const layer of layers) {
    const found = walk(layer.fields);
    if (found !== undefined) return found;
  }
  return undefined;
}
const valueOf = (layers: ProtocolLayer[], abbrev: string) => {
  const f = fieldOf(layers, abbrev);
  return f === undefined ? undefined : String(f.value);
};
const lineOf = (layers: ProtocolLayer[], abbrev: string): [string, string] | null => {
  const f = fieldOf(layers, abbrev);
  return f === undefined ? null : [abbrev, `${f.name}:${String(f.value)}`.replace(/\s+/g, '')];
};
const numberOf = (value: string | undefined) => (value === undefined ? NaN : Number.parseInt(value, 10));

if (process.platform !== 'win32') skip('the desktop app and its agent are Windows-only');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}
try {
  const state = execFileSync('sc.exe', ['query', 'InwireAgent'], { encoding: 'utf8' });
  if (!/STATE/.test(state)) skip('the InwireAgent service is not installed');
} catch {
  skip('the InwireAgent service is not installed');
}

let playwright: typeof import('playwright');
try {
  playwright = await import('playwright');
} catch {
  skip('playwright is not installed');
}

// --- capture ------------------------------------------------------------------
const profile = mkdtempSync(path.join(tmpdir(), 'inwire-live-revisit-'));
const copyRoot = mkdtempSync(path.join(tmpdir(), 'inwire-live-revisit-copy-'));
const app = await playwright._electron.launch({
  args: ['.'],
  env: { ...process.env, INWIRE_USER_DATA: profile } as Record<string, string>,
});
let browser: Awaited<ReturnType<typeof playwright.chromium.launch>> | null = null;
try {
  const page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.addInitScript(() => {
    const sent: string[] = [];
    (window as unknown as { __sentToWorker: string[] }).__sentToWorker = sent;
    const original = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (this: Worker, message: unknown, ...rest: never[]) {
      const type = (message as { type?: unknown } | null)?.type;
      if (typeof type === 'string') sent.push(type);
      // And what the Worker says back that is a complaint: a failure it posts
      // is the only word from inside it that a person would otherwise miss.
      // One list for every Worker: MapLibre starts Workers of its own, and a
      // list per Worker let the last one started hide the pipeline's.
      const self = this as Worker & { __heard?: boolean };
      if (!self.__heard) {
        self.__heard = true;
        const shared = window as unknown as { __workerFailures?: string[] };
        const heard = (shared.__workerFailures ??= []);
        self.addEventListener('message', (event) => {
          const data = (event as MessageEvent).data as { type?: string; message?: string } | null;
          if (data?.type === 'failure') heard.push(String(data.message));
        });
      }
      return (original as (...args: unknown[]) => void).call(this, message, ...rest);
    } as Worker['postMessage'];
  });
  // The store's own counters, as it reports them to the renderer: whether it
  // attached each record, or missed it. Heard by wrapping the port's handler,
  // which `captureClient.ts` assigns once.
  await page.addInitScript(() => {
    const described = Object.getOwnPropertyDescriptor(MessagePort.prototype, 'onmessage')!;
    Object.defineProperty(MessagePort.prototype, 'onmessage', {
      configurable: true,
      get() { return described.get!.call(this); },
      set(handler: ((event: MessageEvent) => void) | null) {
        described.set!.call(this, handler === null ? null : (event: MessageEvent) => {
          const data = event.data as { type?: string; stats?: unknown } | null;
          if (data?.type === 'stats') (window as unknown as { __storeStats: unknown }).__storeStats = data.stats;
          handler(event);
        });
      },
    });
  });
  const storeStats = () => page.evaluate(() => (window as unknown as { __storeStats?: Record<string, number> }).__storeStats ?? null);
  const sentToWorker = () => page.evaluate(() => [...(window as unknown as { __sentToWorker?: string[] }).__sentToWorker ?? []]);
  await page.waitForLoadState('domcontentloaded');
  await page.evaluate(() => localStorage.setItem('inwire.tour', JSON.stringify({ completed: true })));
  await page.reload();
  await page.waitForLoadState('domcontentloaded');
  await sleep(2500);

  const counts = () => page.evaluate(() => {
    const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
    const m = text.match(/([\d,]+)\s*\/\s*([\d,]+)/);
    return m ? [Number(m[1].replace(/,/g, '')), Number(m[2].replace(/,/g, ''))] : [0, 0];
  });

  await page.getByRole('button', { name: 'Interfaces' }).click();
  const ethernet = page.getByText('Ethernet', { exact: true }).first();
  if (!(await ethernet.isVisible().catch(() => false))) {
    await sleep(5000);
  }
  await ethernet.click();
  await page.getByLabel('Start capture').click();
  console.log('--- capturing on Ethernet through the installed agent ---\n');

  // Real traffic: a headless browser loading pages - TCP, TLS, QUIC and DNS.
  browser = await playwright.chromium.launch({ channel: 'chrome', headless: true });
  const tab = await browser.newPage();
  const sites = [
    'https://www.google.com/search?q=packet+capture', 'https://en.wikipedia.org/wiki/Transmission_Control_Protocol',
    'https://github.com/', 'https://www.cloudflare.com/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP',
    'https://www.youtube.com/', 'https://en.wikipedia.org/wiki/QUIC', 'https://news.ycombinator.com/',
  ];
  const deadline = Date.now() + 120_000;
  let total = 0;
  for (let i = 0; Date.now() < deadline; i++) {
    await tab.goto(sites[i % sites.length], { waitUntil: 'load', timeout: 15_000 }).catch(() => {});
    total = (await counts())[1];
    process.stdout.write(`\r      ${total.toLocaleString()} frames captured   `);
    if (total >= WANT_FRAMES && i >= sites.length - 1) break;
  }
  console.log();
  await browser.close();
  browser = null;
  await page.getByLabel('Stop capture').click();
  await sleep(4000);
  total = (await counts())[1];
  const stats = await storeStats();
  console.log(`      the store says: ${JSON.stringify(stats)}`);
  checkTrue('the store attached records, and missed none',
    stats !== null && stats.recordsAttached > 0 && stats.recordsMissed === 0);
  // Stop waits for the Worker to let go of its tail, then seals: every frame
  // staged is written, each with its row. A finish that overtook the tail
  // left it staged until the store next closed.
  checkTrue('Stop sealed every frame the store was given', stats !== null && stats.framesWritten === stats.framesStaged);
  checkTrue('...each with its row', stats !== null && stats.framesSealedWithoutRow === 0 && stats.rowsMissed === 0);
  checkTrue(`the live capture holds more than ${OUT_OF_CACHE.toLocaleString()} frames`, total > OUT_OF_CACHE + 500);
  if (total <= OUT_OF_CACHE + 500) throw new Error('not enough traffic to leave the tree cache');

  // --- the oracle: the capture's own files, copied, dissected in order ------
  const captures = path.join(profile, 'captures');
  const newest = readdirSync(captures)
    .filter((d) => d.startsWith('cap-'))
    .sort((a, b) => statSync(path.join(captures, b)).mtimeMs - statSync(path.join(captures, a)).mtimeMs)[0];
  cpSync(path.join(captures, newest), path.join(copyRoot, newest), { recursive: true });
  const volume = captureVolume(copyRoot).open(newest);
  // Through every segment, as the store reads it: a capture the agent writes
  // a file for is filed from segment 1, even with no ring (ADR 0052).
  const { records, plan, version } = recoverCapture(volume.index, (n) => dataFilesOf(volume, n));
  const index = new CaptureIndex(records.slice(0, plan.keepRecords), version, plan.floorChunk);
  const reader = new CaptureReader(volume, index, inflateSync);
  checkTrue('the capture on disk stores its records (version 2 or later)', index.storesRecords);
  const rows: Packet[] = [];
  // A few chunks a call (`MAX_ROW_CHUNKS`), so paged to the end.
  for (let at = index.floorOrdinal; at < index.frameCount;) {
    const chunks = reader.readRowsAt(at, index.frameCount);
    if (chunks.length === 0) break;
    for (const chunk of chunks) rows.push(...chunk.packets);
    const last = chunks[chunks.length - 1];
    at = last.firstOrdinal + last.packets.length;
  }
  check('every frame the store wrote is read back from the copy', rows.length, stats?.framesWritten ?? -1);
  rows.sort((a, b) => a.id - b.id);
  const bytes = reader.readBytes(rows.map((r) => r.id));
  let withRecords = 0;
  for (const r of rows) if (reader.readRecord(r.id) !== null) withRecords += 1;
  console.log(`      ${rows.length.toLocaleString()} frames sealed on disk, ${withRecords.toLocaleString()} with a record`
    + ` (records file ${volume.rec.size().toLocaleString()} B; chunk 0 names ${index.chunkCount > 0 ? index.record(0).recLength : '-'} B)\n`);
  checkTrue('every sealed frame of the live capture has a record', withRecords === rows.length && rows.length > 0);
  {
    // Where the ones without are, as id ranges: the tail says a race with
    // Stop, a spread says the store sealed ahead of a backlogged Worker.
    const missing = rows.filter((r) => reader.readRecord(r.id) === null).map((r) => r.id);
    const ranges: string[] = [];
    for (let i = 0; i < missing.length;) {
      let j = i;
      while (j + 1 < missing.length && missing[j + 1] === missing[j] + 1) j++;
      ranges.push(i === j ? `${missing[i]}` : `${missing[i]}-${missing[j]}`);
      i = j + 1;
    }
    if (ranges.length > 0) console.log(`      without a record: ${ranges.slice(0, 20).join(', ')}${ranges.length > 20 ? ', ...' : ''}`);
    const placeholders = rows.filter((r) => r.info === 'Not dissected - frame bytes are on disk').length;
    console.log(`      rows with no protocol or info (placeholders): ${placeholders}`);
  }

  const tcp = new TcpStreamTracker();
  const icmp = new IcmpEchoTracker();
  const quic = new QuicFlowTracker();
  const dns = new DnsTracker();
  const l3 = new L3Tracker();
  const trees = new Map<number, ProtocolLayer[]>();
  for (const row of rows) {
    const own = bytes.get(row.id);
    if (own === undefined) continue;
    // No patches: a patch rewrites a row after the fact (a DNS query's
    // Response In), and none of the rows compared below is one.
    const { packet } = decodeRawEthernetPacket(own, row.id, row.tsUs, row.relativeTime, row.timeDelta,
      row.length, tcp, icmp, quic, dns, undefined, row.linkType ?? LINKTYPE.ETHERNET, l3, undefined);
    trees.set(row.id, packet.layers);
  }

  // --- what to open: old frames whose rows need the frames before them ------
  const oldest = rows.filter((r) => r.id <= total - OUT_OF_CACHE && trees.has(r.id));
  const cases: { label: string; id: number; expect: [string, string][] }[] = [];
  const push = (label: string, id: number, abbrevs: string[]) => {
    const layers = trees.get(id)!;
    const expect = abbrevs.map((a) => lineOf(layers, a)).filter((l): l is [string, string] => l !== null);
    if (expect.length > 0) cases.push({ label, id, expect });
  };
  const tcpDeep = oldest.filter((r) => {
    const t = trees.get(r.id)!;
    const rel = numberOf(valueOf(t, 'tcp.seq'));
    return rel > 1000 && rel !== numberOf(valueOf(t, 'tcp.seq_raw'));
  });
  for (const at of [0.2, 0.8]) {
    const r = tcpDeep[Math.floor(at * (tcpDeep.length - 1))];
    if (r) push('a TCP segment deep in its stream', r.id, ['tcp.seq', 'tcp.stream']);
  }
  const tlsDeep = oldest.find((r) => valueOf(trees.get(r.id)!, 'tls.record.length') !== undefined
    && numberOf(valueOf(trees.get(r.id)!, 'tcp.seq')) > 20_000);
  if (tlsDeep) push('a TLS record deep in its stream', tlsDeep.id, ['tls.record.length', 'tcp.seq']);
  const quicLater = oldest.find((r) => numberOf(valueOf(trees.get(r.id)!, 'quic.connection.number')) > 1);
  if (quicLater) push('a QUIC packet on a later connection', quicLater.id, ['quic.connection.number']);
  const udpStream = oldest.find((r) => numberOf(valueOf(trees.get(r.id)!, 'udp.stream')) > 5);
  if (udpStream) push('a UDP datagram on a later conversation', udpStream.id, ['udp.stream']);
  checkTrue('there are old frames to open', cases.length >= 3);
  const complaints = await page.evaluate(() => (window as unknown as { __workerFailures?: string[] }).__workerFailures ?? []);
  check('the Worker reported no failure during the capture', complaints, []);

  // --- open them in the app -------------------------------------------------
  const filter = page.getByPlaceholder('e.g. tcp.port == 443');
  for (const { label, id, expect } of cases) {
    const before = (await sentToWorker()).length;
    await filter.fill(`frame.number == ${id}`);
    await filter.press('Enter');
    // The frame's own row, not the list's first: the filter is answered by a
    // scan in the store, and until it lands the first row is still the last
    // case's frame - already selected, so clicking it asks for nothing and the
    // pane keeps the last tree. That is how frame 19 once "took" 15 seconds.
    const row = page.locator(`#packet-row-${id}`);
    await row.waitFor();
    await sleep(400);
    const t0 = Date.now();
    await row.click();
    let pane = '';
    while (Date.now() - t0 < 15_000) {
      pane = await page.evaluate(() => {
        const panes = [...document.querySelectorAll('div')]
          .filter((d) => d.className.includes('custom-scrollbar') && (d.textContent ?? '').includes('Frame'));
        return panes.map((d) => (d as HTMLElement).innerText).join('\n');
      });
      if (expect.every(([, line]) => pane.replace(/\s+/g, '').includes(line))) break;
      await sleep(100);
    }
    console.log(`\n      frame ${id} of ${total.toLocaleString()}: ${label} - tree on screen in ${Date.now() - t0} ms`);
    const flat = pane.replace(/\s+/g, '');
    for (const [abbrev, line] of expect) checkTrue(`frame ${id} shows its ${abbrev} row: ${line}`, flat.includes(line));
    const sent = (await sentToWorker()).slice(before);
    const fromRecord = sent.includes('detail') && !sent.includes('replay');
    checkTrue(`frame ${id}'s tree was asked for, and came from its record rather than a replay`, fromRecord);
    if (!fromRecord || !expect.every(([, line]) => flat.includes(line))) {
      console.log(`        sent to the Worker: ${JSON.stringify(sent)}`);
      console.log(`        the pane: ${JSON.stringify(pane.slice(0, 600))}`);
    }
  }
  volume.close();
} finally {
  if (browser !== null) await browser.close().catch(() => {});
  // In `finally`, not at the end of the happy path: a capture with frames in
  // it makes closing ask "Quit Inwire?" in a native box no test can answer, so
  // a drive that failed half way hung on close for ever.
  const page = app.windows()[0];
  if (page !== undefined) await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await app.close().catch(() => {});
  rmSync(copyRoot, { recursive: true, force: true });
  rmSync(profile, { recursive: true, force: true });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All live-revisit-drive checks passed.');
process.exit(0);
