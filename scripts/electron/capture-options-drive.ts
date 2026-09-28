/**
 * A capture narrowed by the driver: a capture filter and a snaplen, through the
 * real agent, checked against the capture's own bytes (ADR 0050).
 *
 *   npm run build && npx tsx scripts/electron/capture-options-drive.ts
 *
 * The agent's tests read a fixture through the same open this uses, and
 * `snaplen.ts` holds the dissection of cut frames - but only this reaches the
 * whole chain a person uses: the filter typed in the panel, checked by the
 * installed agent in libpcap's words, sent with Start, applied by Npcap to a
 * real adapter, and every frame that arrives stored with its nanosecond stamp.
 *
 * **The oracle is the capture on disk, read without libpcap.** After Stop the
 * capture's directory is copied and its frames read back; each must be one
 * the filter admits - judged from its own headers here, not by asking libpcap
 * again - and no longer than the snaplen, with its wire length kept and the
 * marker on the ones whose content was cut. A typo in the filter must be
 * refused before Start, with Start blocked.
 *
 * Not in `npm run check` (`check.ts`'s NOT_TESTS): it needs a build, the
 * installed 0.5.0 agent, Npcap, an Ethernet adapter and real traffic, which a
 * headless browser makes. Real capture only; no stub agent.
 */
import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { inflateSync } from 'fflate';
import { captureVolume } from '../../electron/store/volume';
import { CaptureIndex, recoverIndex } from '../../src/services/capture/captureIndex';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { SIZE_LIMITED, bytesNotCaptured } from '../../src/services/dissect/captureShort';
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
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

/** DNS, and HTTPS over either transport: what a browser makes, and not everything. */
const FILTER = 'udp port 53 or tcp port 443 or udp port 443';
const PORTS = new Set([53, 443]);
const SNAPLEN = 96;
const CAPTURE_MS = 45_000;

/**
 * Whether a frame is one `FILTER` admits, read from its own headers. Ethernet,
 * one optional VLAN tag, IPv4 or IPv6 with no extension headers, then TCP or
 * UDP ports - exactly the frames that filter can name, and nothing libpcap is
 * asked about. Anything this cannot read is reported rather than guessed.
 */
function admitted(b: Uint8Array): boolean | null {
  let at = 12;
  let type = (b[at] << 8) | b[at + 1];
  if (type === 0x8100) { at += 4; type = (b[at] << 8) | b[at + 1]; }
  at += 2;
  let proto: number;
  if (type === 0x0800) {
    proto = b[at + 9];
    at += (b[at] & 0x0f) * 4;
  } else if (type === 0x86dd) {
    proto = b[at + 6];
    at += 40;
  } else {
    return false;
  }
  if (proto !== 6 && proto !== 17) return false;
  if (at + 4 > b.length) return null;
  const src = (b[at] << 8) | b[at + 1];
  const dst = (b[at + 2] << 8) | b[at + 3];
  if (!PORTS.has(src) && !PORTS.has(dst)) return false;
  // udp port 53, tcp port 443, udp port 443 - and not tcp port 53.
  return proto === 17 || src === 443 || dst === 443;
}

/**
 * A TCP segment's place in its direction's sequence space, from its headers
 * alone: the length comes from the IP header, never from what was kept, so a
 * cut segment is as long here as it was on the wire. An IPv4 offload frame
 * declares a length of 0 and is as long as the wire says. Null for anything
 * else - including an IPv6 frame declaring 0, which the reference's defaults
 * (`ipv6.tso_support: FALSE`, where IPv4's is TRUE) call malformed and never
 * hand to TCP. Windows sends a large ClientHello over IPv6 exactly that way, so
 * its conversation's next frames are "previous segment not captured" in
 * Wireshark too, cut or whole.
 */
function tcpSegment(b: Uint8Array, wire: number): { key: string; seq: number; end: number } | null {
  let at = 12;
  let type = (b[at] << 8) | b[at + 1];
  if (type === 0x8100) { at += 4; type = (b[at] << 8) | b[at + 1]; }
  at += 2;
  const l3 = at;
  let payload: number;
  let addresses: string;
  if (type === 0x0800) {
    if (b[at + 9] !== 6) return null;
    const ihl = (b[at] & 0x0f) * 4;
    const total = (b[at + 2] << 8) | b[at + 3];
    payload = (total === 0 ? wire - l3 : total) - ihl;
    addresses = Array.from(b.subarray(at + 12, at + 20)).join('.');
    at += ihl;
  } else if (type === 0x86dd) {
    if (b[at + 6] !== 6) return null;
    const declared = (b[at + 4] << 8) | b[at + 5];
    if (declared === 0) return null;
    payload = declared;
    addresses = Array.from(b.subarray(at + 8, at + 40)).join('.');
    at += 40;
  } else {
    return null;
  }
  if (at + 14 > b.length) return null;
  const ports = `${(b[at] << 8) | b[at + 1]}>${(b[at + 2] << 8) | b[at + 3]}`;
  const seq = ((b[at + 4] << 24) | (b[at + 5] << 16) | (b[at + 6] << 8) | b[at + 7]) >>> 0;
  const flags = b[at + 13];
  const len = payload - (b[at + 12] >> 4) * 4 + (flags & 0x02 ? 1 : 0) + (flags & 0x01 ? 1 : 0);
  return { key: `${addresses}/${ports}`, seq, end: (seq + Math.max(0, len)) >>> 0 };
}

/** `a` is after `b` in sequence space, which wraps at 2^32. */
const seqAfter = (a: number, b: number) => ((a - b) | 0) > 0;

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

const profile = mkdtempSync(path.join(tmpdir(), 'inwire-capture-options-'));
const copyRoot = mkdtempSync(path.join(tmpdir(), 'inwire-capture-options-copy-'));
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

  // --- a filter the agent refuses blocks Start, in libpcap's words -----------
  const filter = page.locator('#capture-filter');
  await filter.fill('tcp prot 443');
  const verdict = page.locator('#capture-filter-verdict');
  await page.waitForFunction(() => /syntax error/.test(document.querySelector('#capture-filter-verdict')?.textContent ?? ''));
  console.log(`      the agent said: ${(await verdict.textContent())?.trim()}`);
  checkTrue('a typo is refused by the agent, in libpcap\'s words', /syntax error/.test((await verdict.textContent()) ?? ''));
  checkTrue('...and Start is blocked while it is', await page.getByLabel('Start capture').isDisabled());

  // --- the real one, and a snaplen --------------------------------------------
  await filter.fill(FILTER);
  await page.waitForFunction(() => /dropped by the driver/.test(document.querySelector('#capture-filter-verdict')?.textContent ?? ''));
  checkTrue('a good filter compiles for the chosen adapter', true);
  await page.getByText('Keep only the first').click();
  const snaplen = page.getByLabel('Bytes kept of each packet');
  await snaplen.fill(String(SNAPLEN));
  checkTrue('Start is open again', await page.getByLabel('Start capture').isEnabled());

  await page.getByLabel('Start capture').click();
  console.log(`--- capturing "${FILTER}" at ${SNAPLEN} bytes through the installed agent ---\n`);
  // The lock follows the agent's own word that the capture started, which is a
  // round trip after the click - so it is waited for, not read at once.
  checkTrue('the options lock while the capture runs', await page.waitForFunction(
    () => (document.querySelector('#capture-filter') as HTMLInputElement | null)?.disabled === true,
    undefined, { timeout: 30_000 },
  ).then(() => true, () => false));

  browser = await playwright.chromium.launch({ channel: 'chrome', headless: true });
  const tab = await browser.newPage();
  const sites = [
    'https://en.wikipedia.org/wiki/Berkeley_Packet_Filter', 'https://www.cloudflare.com/', 'https://github.com/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP', 'https://news.ycombinator.com/', 'https://www.youtube.com/',
  ];
  const deadline = Date.now() + CAPTURE_MS;
  for (let i = 0; Date.now() < deadline; i++) {
    await tab.goto(sites[i % sites.length], { waitUntil: 'load', timeout: 15_000 }).catch(() => {});
  }
  await browser.close();
  browser = null;
  await page.getByLabel('Stop capture').click();
  await sleep(4000);

  // --- the oracle: the capture on disk ----------------------------------------
  const captures = path.join(profile, 'captures');
  const newest = readdirSync(captures)
    .filter((d) => d.startsWith('cap-'))
    .sort((a, b) => statSync(path.join(captures, b)).mtimeMs - statSync(path.join(captures, a)).mtimeMs)[0];
  cpSync(path.join(captures, newest), path.join(copyRoot, newest), { recursive: true });
  const volume = captureVolume(copyRoot).open(newest);
  const { records, plan, version } = recoverIndex(volume.index, volume.pfx, volume.sum, volume.byt, volume.rec);
  const index = new CaptureIndex(records.slice(0, plan.keepRecords), version);
  const reader = new CaptureReader(volume, index, inflateSync);
  const rows: Packet[] = [];
  for (let at = 0; at < index.frameCount;) {
    const chunks = reader.readRowsAt(at, index.frameCount);
    if (chunks.length === 0) break;
    for (const chunk of chunks) rows.push(...chunk.packets);
    const last = chunks[chunks.length - 1];
    at = last.firstOrdinal + last.packets.length;
  }
  rows.sort((a, b) => a.id - b.id);
  const bytes = reader.readBytes(rows.map((r) => r.id));
  console.log(`      ${rows.length.toLocaleString()} frames captured`);
  checkTrue('the capture caught traffic', rows.length > 200);

  // The filter, judged from each frame's own headers.
  const verdicts = rows.map((r) => admitted(bytes.get(r.id) ?? new Uint8Array()));
  const outside = rows.filter((_, i) => verdicts[i] === false);
  const unreadable = verdicts.filter((v) => v === null).length;
  console.log(`      ${unreadable} frame(s) too short to judge`);
  check('every frame is one the filter admits', outside.slice(0, 5).map((r) => `${r.id} ${r.protocolLabel ?? r.protocol} ${r.info}`), []);

  // The snaplen: kept to it, the wire length kept, the cut ones marked.
  const lengths = rows.map((r) => bytes.get(r.id)?.length ?? 0);
  check('no frame keeps more than the snaplen', lengths.filter((n) => n > SNAPLEN).length, 0);
  const cut = rows.filter((r, i) => r.length > lengths[i]);
  console.log(`      ${cut.length.toLocaleString()} of them cut, the longest ${Math.max(...rows.map((r) => r.length))} bytes on the wire`);
  checkTrue('frames longer than the snaplen were cut to it, their wire length kept', cut.length > 0
    && cut.every((r) => (bytes.get(r.id)?.length ?? 0) === SNAPLEN));
  const unmarked = cut.filter((r) => {
    const own = bytes.get(r.id)!;
    const l3 = own[12] === 0x81 && own[13] === 0x00 ? 18 : 14;
    const type = (own[l3 - 2] << 8) | own[l3 - 1];
    return bytesNotCaptured(own, l3, type, r.length) > 0 && !r.info.includes(SIZE_LIMITED);
  });
  check('every frame whose content was cut says so', unmarked.slice(0, 5).map((r) => `${r.id} ${r.info}`), []);
  // "Previous segment not captured" is right only where the headers show a hole:
  // a segment starting past everything its direction has carried so far. The
  // snaplen's failure mode was exactly the other kind - a cut segment read as a
  // short one, and the next as a hole behind it (ADR 0050).
  const reach = new Map<string, number>();
  const gapped = new Set<number>();
  for (const r of rows) {
    const segment = tcpSegment(bytes.get(r.id) ?? new Uint8Array(), r.length);
    if (segment === null) continue;
    const before = reach.get(segment.key);
    if (before !== undefined && seqAfter(segment.seq, before)) gapped.add(r.id);
    if (before === undefined || seqAfter(segment.end, before)) reach.set(segment.key, segment.end);
  }
  const lost = rows.filter((r) => (r.analysisFlags ?? []).includes('lost_segment'));
  console.log(`      "previous segment not captured" on ${lost.length} frame(s), `
    + `${gapped.size} with a hole in their headers' sequence space`);
  check('...and never where the headers show no hole', lost.filter((r) => !gapped.has(r.id))
    .slice(0, 5).map((r) => `${r.id} ${r.info}`), []);

  // Nanoseconds, all the way to disk.
  const precise = rows.filter((r) => r.tsPrecision === 9 && r.tsNanos !== undefined);
  check('every frame is stamped to the nanosecond', precise.length, rows.length);
  const finer = precise.filter((r) => r.tsNanos! % 1000n !== 0n).length;
  console.log(`      ${finer.toLocaleString()} stamps carry digits past the microsecond`);
  checkTrue('...and the digits past the microsecond are the driver\'s, not zeros', finer > precise.length / 2);
  checkTrue('...agreeing with the microseconds every row keeps',
    precise.every((r) => r.tsNanos! / 1000n === BigInt(r.tsUs)));
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
console.log('All capture-options drive checks passed.');
process.exit(0);
