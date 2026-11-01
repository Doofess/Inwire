/**
 * The import's gates and its progress, against the real app while a file is
 * being imported.
 *
 *   npm run build && npx tsx scripts/electron/import-gate-drive.ts
 *     [--frames 150000] [--frame-bytes 1400] [--shots <dir>]
 *
 * `scripts/session/import-gate.ts` pins the gates by reading `App.tsx`'s text;
 * this is the other half, the one that presses the controls. It writes a
 * synthetic classic pcap (small Ethernet/IPv4/UDP frames padded to
 * `--frame-bytes`, so the file spans several 64 MiB read windows and the bar
 * has several steps to climb) into a temp directory, launches the built app
 * against the stub agent with an isolated profile, opens Export / Import and
 * imports the file through the panel's own input. WHILE it runs it asserts:
 *
 * - the zone shows the progress, not the invitation: a progressbar whose
 *   `aria-valuenow` rises, the file's name, the sizes line, and neither
 *   "Click to upload" nor the format list;
 * - the rail's Start is disabled, a forced press of it sends nothing, and
 *   Ctrl+E starts no capture (an adapter is selected first, so a refusal is the
 *   gate's and not a missing adapter's);
 * - a second import is refused: the input is disabled, and a file dropped on
 *   the zone changes nothing and raises no dialog;
 * - the zone is as tall busy as idle, so nothing below it jumps.
 *
 * After it, the panel's own line must read `Imported N packets from <file>`
 * with exactly the N written, above the help card. The welcome's Reopen is
 * checked if the profile offers one; a fresh profile does not, and the drive
 * says so (`import-gate.ts` reads its source).
 *
 * `--shots <dir>` also photographs the Export / Import side bar mid-import and
 * after it, light and dark, at window widths 1024 and 1600 (one launch and one
 * import per width). For looking at, not asserting.
 *
 * In `check.ts`'s NOT_TESTS: it needs a build, writes a ~200 MB file, and its
 * assertions are made inside a window of seconds that the import's speed on the
 * machine sets - it says so, and fails, when the import was over before they
 * were done, rather than passing vacuously.
 */
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, rmSync, statSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Page } from 'playwright';
import { launchApp } from './launchApp';
import { startStubAgent } from './stubAgent';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const SHOTS = arg('shots', '');
const FRAMES = Number(arg('frames', SHOTS === '' ? '150000' : '400000'));
const FRAME_BYTES = Number(arg('frame-bytes', '1400'));
const FILE_NAME = 'gate-drive-synthetic.pcap';
/** The window widths of the shots; a plain run uses the app's own size, once. */
const WIDTHS = SHOTS === '' ? [null] : [1024, 1600];
const THEMES = ['light', 'dark'];

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

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// --- the file -----------------------------------------------------------------

/** A classic libpcap file, written here so no writer under test is the oracle. */
function writePcap(file: string, frames: number, frameBytes: number): void {
  const fd = openSync(file, 'w');
  try {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(0xa1b2c3d4, 0);
    header.writeUInt16LE(2, 4);
    header.writeUInt16LE(4, 6);
    header.writeUInt32LE(262144, 16);
    header.writeUInt32LE(1, 20);                     // Ethernet
    writeSync(fd, header);

    const frame = Buffer.alloc(frameBytes);
    // Ethernet
    Buffer.from([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02, 0x08, 0x00]).copy(frame, 0);
    // IPv4, UDP, 192.168.1.42 -> 10.0.0.9, its checksum computed once
    const ipTotal = frameBytes - 14;
    const ip = Buffer.from([0x45, 0x00, ipTotal >> 8, ipTotal & 0xff, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1, 42, 10, 0, 0, 9]);
    let sum = 0;
    for (let i = 0; i < 20; i += 2) sum += (ip[i] << 8) | ip[i + 1];
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    ip.writeUInt16BE(~sum & 0xffff, 10);
    ip.copy(frame, 14);
    // UDP: the source port is patched per frame below; no checksum
    frame.writeUInt16BE(40_000, 36);
    frame.writeUInt16BE(frameBytes - 34, 38);
    for (let i = 42; i < frameBytes; i++) frame[i] = 0x30 + (i % 10);

    const record = Buffer.alloc(16 + frameBytes);
    record.writeUInt32LE(frameBytes, 8);
    record.writeUInt32LE(frameBytes, 12);
    frame.copy(record, 16);
    const BATCH = 2000;
    const out = Buffer.alloc(record.length * BATCH);
    for (let first = 0; first < frames; first += BATCH) {
      const n = Math.min(BATCH, frames - first);
      for (let k = 0; k < n; k++) {
        const i = first + k;
        record.writeUInt32LE(1_700_000_000 + Math.floor(i / 1000), 0);
        record.writeUInt32LE((i % 1000) * 1000, 4);
        record.writeUInt16BE(49_152 + (i % 200), 16 + 34);     // 200 flows
        record.copy(out, k * record.length);
      }
      writeSync(fd, out, 0, n * record.length);
    }
  } finally {
    closeSync(fd);
  }
}

const files = mkdtempSync(path.join(tmpdir(), 'inwire-gate-drive-'));
const FILE = path.join(files, FILE_NAME);
writePcap(FILE, FRAMES, FRAME_BYTES);
const MIB = 1024 * 1024;
console.log(`wrote ${FRAMES.toLocaleString()} frames of ${FRAME_BYTES} bytes: ${Math.round(statSync(FILE).size / MIB)} MiB, ${FILE_NAME}\n`);
if (SHOTS !== '') mkdirSync(SHOTS, { recursive: true });

// --- one session --------------------------------------------------------------

const ZONE = 'label:has(input[type="file"][accept])';

interface Seen {
  busy: boolean;
  valueNow: number | null;
  zoneText: string;
  zoneHeight: number;
  done: { n: string; file: string } | null;
  dialog: boolean;
}

async function session(width: number | null): Promise<void> {
  const tag = width === null ? 'default window' : `${width}px window`;
  console.log(`--- ${tag} ---`);
  const pipe = String.raw`\\.\pipe\inwire-gate-drive-${process.pid}-${width ?? 0}`;
  const agent = await startStubAgent(pipe, 0);
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-gate-drive-p-'));
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: pipe },
  });
  let page: Page | null = null;
  try {
    page = await app.firstWindow();
    const p = page;
    p.setDefaultTimeout(30_000);
    await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    if (width !== null) {
      await app.evaluate(({ BrowserWindow }, [w, h]) => {
        const win = BrowserWindow.getAllWindows()[0];
        win.unmaximize();
        win.setSize(w, h);
      }, [width, width <= 1024 ? 700 : 1000] as [number, number]);
      await sleep(800);
    }
    await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});

    const setTheme = async (theme: string) => {
      await p.evaluate((t) => {
        localStorage.setItem('theme', t);
        window.dispatchEvent(new StorageEvent('storage', { key: 'theme', newValue: t, storageArea: localStorage }));
      }, theme);
      await sleep(350);
    };
    const shoot = async (name: string) => {
      if (SHOTS === '') return;
      // Import is the panel's last section and sits below the fold at 1024x700.
      // The panel's own scroller only: scrollIntoView also moves every
      // overflow-hidden ancestor and shifts the whole shell.
      await p.locator(ZONE).first().evaluate((el) => {
        const scroller = el.closest('.overflow-y-auto');
        if (scroller !== null) scroller.scrollTop = scroller.scrollHeight;
      }).catch(() => {});
      await sleep(150);
      for (const theme of THEMES) {
        await setTheme(theme);
        await p.screenshot({ path: path.join(SHOTS, `${theme}-${width}-${name}.png`) });
      }
      console.log(`      shot ${width}-${name}`);
    };
    await setTheme('light');

    // An adapter first, so that a refused Start is the gate's doing and not a
    // missing adapter's.
    await p.getByRole('button', { name: 'Interfaces' }).click();
    await p.getByText('Ethernet', { exact: true }).first().click();
    const startButton = p.locator('button[data-tour="start"]');
    await p.waitForFunction(() => {
      const b = document.querySelector<HTMLButtonElement>('button[data-tour="start"]');
      return b !== null && !b.disabled && b.getAttribute('aria-label') === 'Start capture';
    });
    check('before the import: Start is enabled with an adapter chosen', await startButton.isEnabled());

    await p.getByLabel('Export or import a capture').click();
    const zone = p.locator(ZONE).first();
    await zone.waitFor();
    const idleText = await zone.innerText();
    const idleHeight = (await zone.boundingBox())?.height ?? 0;
    check('idle: the zone invites a file and lists the formats',
      idleText.includes('Click to upload') && idleText.includes('.pcapng'), JSON.stringify(idleText));
    await shoot('0-idle');

    const startsBefore = agent.received.filter((m) => m.includes('start_capture')).length;
    const read = (): Promise<Seen> => p.evaluate((zoneSelector) => {
      const z = document.querySelector<HTMLElement>(zoneSelector);
      const bar = z?.querySelector('[role="progressbar"]') ?? null;
      const m = document.body.innerText.match(/Imported ([\d,]+) packets from ([^\n]+)/);
      const dialog = [...document.querySelectorAll<HTMLElement>('[role="alertdialog"]')]
        .some((el) => el.getClientRects().length > 0);
      return {
        busy: bar !== null,
        valueNow: bar === null ? null : Number(bar.getAttribute('aria-valuenow')),
        zoneText: z?.innerText ?? '',
        zoneHeight: z?.getBoundingClientRect().height ?? 0,
        done: m === null ? null : { n: m[1], file: m[2].trim() },
        dialog,
      };
    }, ZONE);

    // Every value the bar takes, recorded in the page as it changes: the
    // driver's own turns (a screenshot, a press) can each outlast a step.
    await p.evaluate('window.__name = (f) => f');
    await p.evaluate((zoneSelector) => {
      const w = window as unknown as { __series: number[] };
      w.__series = [];
      new MutationObserver(() => {
        const bar = document.querySelector(`${zoneSelector} [role="progressbar"]`);
        if (bar === null) return;
        const value = Number(bar.getAttribute('aria-valuenow'));
        if (w.__series[w.__series.length - 1] !== value) w.__series.push(value);
      }).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['aria-valuenow', 'role'] });
    }, ZONE);

    const startedAt = Date.now();
    await p.locator('input[type="file"][accept]').first().setInputFiles(FILE);

    // Wait for the bar, then watch to the end. Anything pressed is pressed once
    // the bar is up (in a shots run, once it has some fill to photograph), and
    // a press that finds the import over is a failure of the drive's premise,
    // said as one.
    let busySeen: Seen | null = null;
    let overBeforeDone = false;
    let assertedDuring = false;
    let shotMidway = false;
    let last: Seen | null = null;
    while (Date.now() - startedAt < 180_000) {
      const seen = await read().catch(() => null);
      if (seen === null) { await sleep(100); continue; }
      last = seen;
      if (seen.busy) {
        busySeen ??= seen;
        if (!assertedDuring) {
          assertedDuring = true;
          // Read again: the zone's text and height are what is asserted.
          await assertWhileRunning(p, agent, startButton, await read(), idleHeight, startsBefore);
          // The pressed controls took a turn of the renderer each; the import
          // must have outlived them.
          if (!(await read()).busy) overBeforeDone = true;
        } else if (SHOTS !== '' && !shotMidway && (seen.valueNow ?? 0) >= 40) {
          // With some fill to photograph, after the presses.
          shotMidway = true;
          await shoot('1-importing');
        }
      }
      if (seen.done !== null) break;
      await sleep(100);
    }
    const series = await p.evaluate(() => (window as unknown as { __series: number[] }).__series);
    const seconds = (Date.now() - startedAt) / 1000;
    console.log(`      import took ${seconds.toFixed(1)} s; bar steps seen: ${series.join(', ')}`);

    check('the bar appeared, and the gates were pressed while the import ran', busySeen !== null && assertedDuring);
    if (SHOTS !== '') check('the mid-import photographs were taken before the import ended (else raise --frames)', shotMidway);
    check('the import outlived the assertions made during it (else raise --frames)', !overBeforeDone);
    check('the bar\'s aria-valuenow rose', series.length >= 2 && series.every((v, i) => i === 0 || v >= series[i - 1]) && series[series.length - 1] > series[0],
      `saw ${JSON.stringify(series)}`);
    check('...between 0 and 100', series.every((v) => v >= 0 && v <= 100));
    check('the import took long enough to be a real window (5-15 s is the aim)', seconds >= 3, `${seconds.toFixed(1)} s`);

    check('the import ended with its result line', last?.done !== null && last?.done !== undefined, JSON.stringify(last));
    check('...naming exactly the packets written',
      last?.done?.n.replace(/,/g, '') === String(FRAMES) || (await noteSaysAll(p, FRAMES)),
      `line says ${last?.done?.n}, wrote ${FRAMES}`);
    check('...and the file', last?.done?.file === FILE_NAME, String(last?.done?.file));
    check('no dialog answered the import', last?.dialog === false);

    const after = await read();
    check('after: the zone invites a file again', after.zoneText.includes('Click to upload') && !after.busy, JSON.stringify(after.zoneText));
    check('after: the zone is as tall as before', Math.abs(after.zoneHeight - idleHeight) <= 1, `${after.zoneHeight} vs ${idleHeight}`);
    const order = await p.evaluate((zoneSelector) => {
      const resultEl = [...document.querySelectorAll<HTMLElement>('span')].find((s) => /^Imported [\d,]+ packets from /.test(s.textContent ?? ''));
      const helpEl = [...document.querySelectorAll<HTMLElement>('p')].find((s) => (s.textContent ?? '').startsWith('Spreadsheets and tables are checked'));
      const z = document.querySelector<HTMLElement>(zoneSelector);
      if (!resultEl || !helpEl || !z) return null;
      return { zoneBottom: z.getBoundingClientRect().bottom, result: resultEl.getBoundingClientRect().top, help: helpEl.getBoundingClientRect().top };
    }, ZONE);
    check('after: the result line sits under the zone and above the help card',
      order !== null && order.result >= order.zoneBottom && order.result < order.help, JSON.stringify(order));
    await shoot('2-imported');

    check('no capture was started by anything pressed meanwhile',
      agent.received.filter((m) => m.includes('start_capture')).length === startsBefore);
    await p.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  } catch (error) {
    check('the drive ran to its end', false, String(error).split('\n').slice(0, 3).join(' | '));
  } finally {
    await page?.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
    await app.close().catch(() => {});
    await agent.close();
    rmSync(profile, { recursive: true, force: true });
  }
}

/** The note that an import larger than the buffer's tail states, in place of the packet count. */
async function noteSaysAll(p: Page, frames: number): Promise<boolean> {
  const text = await p.evaluate(() => document.body.innerText);
  return new RegExp(`All ${frames.toLocaleString('en-US')} frames were imported`).test(text);
}

/** Everything pressed while the bar is up. */
async function assertWhileRunning(
  p: Page,
  agent: Awaited<ReturnType<typeof startStubAgent>>,
  startButton: ReturnType<Page['locator']>,
  seen: Seen,
  idleHeight: number,
  startsBefore: number,
): Promise<void> {
  const text = seen.zoneText;
  check('busy: the zone names the file being imported', /Importing\s+gate-drive-synthetic\.pcap/.test(text), JSON.stringify(text));
  check('busy: ...with the sizes line, e.g. "64 of 210 MB (30%)"', /\d+ of \d+(\.\d)? (MB|GB) \(\d+%\)/.test(text), JSON.stringify(text));
  check('busy: ...and neither the invitation nor the format list',
    !text.includes('Click to upload') && !text.includes('.pcapng') && !text.includes('drag'), JSON.stringify(text));
  check('busy: the zone is as tall as idle, so nothing below it jumps', Math.abs(seen.zoneHeight - idleHeight) <= 1, `${seen.zoneHeight} vs ${idleHeight}`);
  const bar = await p.locator(`${ZONE} [role="progressbar"]`).first().evaluate((el) => ({
    min: el.getAttribute('aria-valuemin'), max: el.getAttribute('aria-valuemax'), label: el.getAttribute('aria-label'),
  }));
  check('busy: the bar declares 0 to 100 and a name', bar.min === '0' && bar.max === '100' && /Importing/.test(bar.label ?? ''), JSON.stringify(bar));

  check('busy: the rail\'s Start is disabled', await startButton.isDisabled());
  check('busy: ...and says why', /Importing a file/.test(await startButton.getAttribute('title') ?? ''));
  await startButton.click({ force: true, timeout: 5000 }).catch(() => {});
  await p.keyboard.press('Control+e');
  await sleep(500);
  check('busy: a forced press of Start and Ctrl+E start no capture',
    agent.received.filter((m) => m.includes('start_capture')).length === startsBefore);
  check('busy: ...and nothing reads as capturing', await p.getByLabel('Stop capture').count() === 0);

  const reopen = p.getByRole('button', { name: /Reopen/ });
  if (await reopen.count() > 0) {
    check('busy: Reopen is disabled', await reopen.first().isDisabled());
  } else {
    console.log('      (no Reopen offered by a fresh profile: import-gate.ts reads its source)');
  }

  check('busy: the file input is shut to a second import', await p.locator('input[type="file"][accept]').first().isDisabled());
  const drop = await p.evaluate((zoneSelector) => {
    const z = document.querySelector<HTMLElement>(zoneSelector);
    if (z === null) return false;
    const data = new DataTransfer();
    data.items.add(new File([new Uint8Array(24)], 'second-import.pcap'));
    z.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: data }));
    return true;
  }, ZONE);
  await sleep(300);
  const afterDrop = await p.evaluate((zoneSelector) => ({
    zone: document.querySelector<HTMLElement>(zoneSelector)?.innerText ?? '',
    dialog: [...document.querySelectorAll<HTMLElement>('[role="alertdialog"]')].some((el) => el.getClientRects().length > 0),
  }), ZONE);
  check('busy: a file dropped on the zone is refused - the first import still shows, no dialog',
    drop && /gate-drive-synthetic\.pcap/.test(afterDrop.zone) && !/second-import/.test(afterDrop.zone) && !afterDrop.dialog,
    JSON.stringify(afterDrop));
}

try {
  for (const width of WIDTHS) await session(width);
} finally {
  rmSync(files, { recursive: true, force: true });
}

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import gate drive checks passed.');
process.exit(0);
