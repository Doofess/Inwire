/**
 * The capture's own pcapng, written by the installed agent as the person who
 * started it (ADR 0052).
 *
 *   npm run build && npx tsx scripts/electron/capture-file-drive.ts
 *
 * `agent-rs`'s tests hold the writer to the fixtures over a real pipe, but
 * both ends there run as one user. Only the installed service - LocalSystem -
 * writing for this app - an ordinary user - shows the thing ADR 0052 exists
 * for: that the file is the user's, and that a folder the user cannot write
 * is refused rather than written with the service's rights.
 *
 * What it drives, on real traffic from a headless browser:
 *
 * - **An autostop at 5,000 packets**, set in the panel. The capture stops
 *   itself, the panel says why, and the agent's file holds exactly 5,000 EPBs
 *   - the same 5,000 frames the app's own store holds, byte for byte.
 * - **The file is laid out as dumpcap's**: SHB, one IDB for the adapter, the
 *   EPBs, an ISB - and `capinfos` reads it.
 * - **The file's owner is this user, not SYSTEM.**
 * - **A root this user cannot write is refused**: a hand-made pipe client, a
 *   real connection, names `C:\Windows` and gets `capture_failed`, and nothing
 *   is created there. Skipped when this process is elevated - elevated, it
 *   *can* write there, and the check would be proving nothing while putting a
 *   folder in the Windows directory.
 *
 * Not in `npm run check` (NOT_TESTS): it needs a build, the installed 0.5.0
 * agent, Npcap, an Ethernet adapter and real traffic. Real capture only.
 */
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { inflateSync } from 'fflate';
import { captureVolume } from '../../electron/store/volume';
import { CaptureIndex, recoverIndex } from '../../src/services/capture/captureIndex';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { FRAME_JSON, FrameReader, encodeFrame } from '../../src/services/agentFraming';
import { findWiresharkTool } from '../export/realCaptures';

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

const PACKETS = 5_000;
const AGENT_PIPE = '\\\\.\\pipe\\inwire-agent';

/** A pcapng read back block by block, strictly. */
interface Written {
  shape: string[];
  application: string;
  idbNames: string[];
  packets: Uint8Array[];
  isbReceived: (number | null)[];
}

function readPcapng(file: string): Written {
  const b = readFileSync(file);
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = (at: number) => view.getUint32(at, true);
  const options = (from: number, to: number) => {
    const out: [number, Uint8Array][] = [];
    for (let at = from; at + 4 <= to;) {
      const code = view.getUint16(at, true);
      const len = view.getUint16(at + 2, true);
      if (code === 0) break;
      out.push([code, b.subarray(at + 4, at + 4 + len)]);
      at += 4 + Math.ceil(len / 4) * 4;
    }
    return out;
  };
  const text = (o: [number, Uint8Array][], code: number) => {
    const hit = o.find(([c]) => c === code);
    return hit ? Buffer.from(hit[1]).toString('utf8') : '';
  };
  const w: Written = { shape: [], application: '', idbNames: [], packets: [], isbReceived: [] };
  for (let at = 0; at < b.length;) {
    const type = u32(at);
    const len = u32(at + 4);
    if (len < 12 || len % 4 !== 0 || at + len > b.length || u32(at + len - 4) !== len) {
      throw new Error(`${file}: a torn block at ${at}`);
    }
    const name = ({ 0x0a0d0d0a: 'SHB', 1: 'IDB', 6: 'EPB', 5: 'ISB' } as Record<number, string>)[type] ?? `0x${type.toString(16)}`;
    if (name !== 'EPB' || w.shape[w.shape.length - 1] !== 'EPB') w.shape.push(name);
    if (name === 'SHB') w.application = text(options(at + 24, at + len - 4), 4);
    if (name === 'IDB') w.idbNames.push(text(options(at + 16, at + len - 4), 2));
    if (name === 'EPB') w.packets.push(b.subarray(at + 28, at + 28 + u32(at + 20)));
    if (name === 'ISB') {
      const hit = options(at + 20, at + len - 4).find(([c]) => c === 4);
      w.isbReceived.push(hit ? Number(new DataView(hit[1].buffer, hit[1].byteOffset, 8).getBigUint64(0, true)) : null);
    }
    at += len;
  }
  return w;
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

/** Whether this process holds an elevated token: `net session` answers only then. */
function elevated(): boolean {
  return spawnSync('net', ['session'], { stdio: 'ignore' }).status === 0;
}

/**
 * A client of the installed agent's own pipe, speaking the app's framing, that
 * says what it is told to and collects what it hears.
 */
async function rawClient(commands: object[], listenMs: number): Promise<Record<string, unknown>[]> {
  const heard: Record<string, unknown>[] = [];
  const reader = new FrameReader();
  const socket = connect(AGENT_PIPE);
  await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  socket.on('data', (chunk: Buffer) => {
    for (const frame of reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))) {
      if (frame.kind === FRAME_JSON) heard.push(JSON.parse(Buffer.from(frame.payload).toString('utf8')));
    }
  });
  for (const command of commands) {
    socket.write(encodeFrame(FRAME_JSON, new TextEncoder().encode(JSON.stringify(command))));
    await sleep(300);
  }
  await sleep(listenMs);
  socket.destroy();
  return heard;
}

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

const profile = mkdtempSync(path.join(tmpdir(), 'inwire-capture-file-'));
const copyRoot = mkdtempSync(path.join(tmpdir(), 'inwire-capture-file-copy-'));
const app = await playwright._electron.launch({
  args: ['.'],
  env: { ...process.env, INWIRE_USER_DATA: profile } as Record<string, string>,
});
let browser: Awaited<ReturnType<typeof playwright.chromium.launch>> | null = null;
let page: Awaited<ReturnType<typeof app.firstWindow>> | undefined;
try {
  page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.waitForLoadState('domcontentloaded');
  await page.evaluate(() => localStorage.setItem('inwire.tour', JSON.stringify({ completed: true })));
  await page.reload();
  await page.waitForLoadState('domcontentloaded');
  await sleep(2500);

  await page.getByRole('button', { name: 'Interfaces' }).click();
  const ethernet = page.getByText('Ethernet', { exact: true }).first();
  if (!(await ethernet.isVisible().catch(() => false))) await sleep(5000);
  await ethernet.click();
  await page.getByLabel('Stop after packets').fill(String(PACKETS));
  checkTrue('Start is open with an autostop set', await page.getByLabel('Start capture').isEnabled());

  // --- the capture stops itself, and says why ----------------------------------
  await page.getByLabel('Start capture').click();
  console.log(`--- capturing until the agent stops at ${PACKETS.toLocaleString()} packets ---\n`);
  browser = await playwright.chromium.launch({ channel: 'chrome', headless: true });
  const tab = await browser.newPage();
  const sites = [
    'https://en.wikipedia.org/wiki/Pcapng', 'https://www.cloudflare.com/', 'https://github.com/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP', 'https://news.ycombinator.com/', 'https://www.youtube.com/',
  ];
  const stopped = () => page!.getByText('The last capture stopped itself: it reached its packet limit.')
    .isVisible().catch(() => false);
  const deadline = Date.now() + 180_000;
  for (let i = 0; Date.now() < deadline && !(await stopped()); i++) {
    await tab.goto(sites[i % sites.length], { waitUntil: 'load', timeout: 15_000 }).catch(() => {});
  }
  await browser.close();
  browser = null;
  checkTrue('the capture stopped itself at its limit, and the panel says why', await stopped());
  checkTrue('...and Start is offered again', await page.getByLabel('Start capture').isVisible());
  await sleep(4000);

  // --- the agent's file ----------------------------------------------------------
  const captures = path.join(profile, 'captures');
  const newest = readdirSync(captures)
    .filter((d) => d.startsWith('cap-'))
    .sort((a, b) => statSync(path.join(captures, b)).mtimeMs - statSync(path.join(captures, a)).mtimeMs)[0];
  const pcapngPath = path.join(captures, newest, 'pcapng', 'capture.pcapng');
  checkTrue('the agent wrote the capture\'s file into the capture\'s own folder', existsSync(pcapngPath));
  const owner = execFileSync('powershell', ['-NoProfile', '-Command', `(Get-Acl -LiteralPath '${pcapngPath}').Owner`],
    { encoding: 'utf8' }).trim();
  const me = execFileSync('whoami', { encoding: 'utf8' }).trim();
  console.log(`      owner ${owner}, this user ${me}`);
  check('the file is this user\'s, not SYSTEM\'s: written as the client', owner.toLowerCase(), me.toLowerCase());

  const written = readPcapng(pcapngPath);
  check('laid out as dumpcap lays it out', written.shape, ['SHB', 'IDB', 'EPB', 'ISB']);
  checkTrue('...by Inwire', written.application.startsWith('Inwire '));
  checkTrue('...one IDB, naming the adapter\'s device', written.idbNames.length === 1 && written.idbNames[0].startsWith('\\Device\\NPF_'));
  check('exactly the limit\'s frames are in the file', written.packets.length, PACKETS);
  checkTrue('an ISB counts at least what was written', (written.isbReceived[0] ?? 0) >= PACKETS);
  const capinfos = findWiresharkTool('capinfos');
  if (capinfos !== null) {
    const info = execFileSync(capinfos, ['-c', pcapngPath], { encoding: 'utf8' });
    checkTrue('capinfos reads it, and counts the same', new RegExp(`Number of packets:\\s+${PACKETS.toLocaleString('en-US')}|Number of packets:\\s+${PACKETS}`).test(info));
  }

  // --- the same frames as the app's own store ------------------------------------
  cpSync(path.join(captures, newest), path.join(copyRoot, newest), { recursive: true });
  const volume = captureVolume(copyRoot).open(newest);
  const { records, plan, version } = recoverIndex(volume.index, volume.pfx, volume.sum, volume.byt, volume.rec);
  const index = new CaptureIndex(records.slice(0, plan.keepRecords), version);
  const reader = new CaptureReader(volume, index, inflateSync);
  const ids: number[] = [];
  for (let at = 0; at < index.frameCount;) {
    const chunks = reader.readRowsAt(at, index.frameCount);
    if (chunks.length === 0) break;
    for (const chunk of chunks) ids.push(...chunk.packets.map((p) => p.id));
    const last = chunks[chunks.length - 1];
    at = last.firstOrdinal + last.packets.length;
  }
  const bytes = reader.readBytes(ids);
  check('the store holds the same number of frames as the file', ids.length, PACKETS);
  // As multisets: the store is in capture-time order and the file in the
  // agent's sequence, which one adapter makes the same order - but the check
  // is about which frames, and a sort cannot pass on a missing one.
  const stored = ids.map((id) => hex(bytes.get(id) ?? new Uint8Array())).sort();
  const filed = written.packets.map(hex).sort();
  check('...and the same frames, byte for byte',
    stored.findIndex((h, i) => h !== filed[i]), -1);

  // --- a folder this user cannot write is refused ---------------------------------
  if (elevated()) {
    console.log('SKIP  a root this user cannot write: this process is elevated, and could');
  } else {
    const forbidden = 'C:\\Windows\\inwire-capture-file-drive';
    const id = 'cap-20260928-120000-0dd1';
    const device = written.idbNames[0];
    const heard = await rawClient([
      { type: 'set_capture_root', dir: forbidden },
      { type: 'set_interfaces', interfaces: [device] },
      { type: 'start_capture', captureId: id },
    ], 3000);
    const failed = heard.find((m) => m.type === 'error' && m.code === 'capture_failed');
    console.log(`      the agent said: ${String(failed?.message ?? '(nothing)')}`);
    checkTrue('a root this user cannot write fails the capture', failed !== undefined);
    checkTrue('...and nothing was created there - the service did not write it for them',
      !existsSync(path.join(forbidden, id)));
  }
} finally {
  if (browser !== null) await browser.close().catch(() => {});
  if (page !== undefined) await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await app.close().catch(() => {});
  rmSync(profile, { recursive: true, force: true });
  rmSync(copyRoot, { recursive: true, force: true });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-file drive checks passed.');
process.exit(0);
