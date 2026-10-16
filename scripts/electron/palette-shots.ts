/**
 * The command palette, the filter field's recents and chip, and the settings
 * search and Reset, photographed - for looking at, plus one assertion.
 *
 *   npx tsx scripts/electron/palette-shots.ts --out <dir> [--themes light,dark,dim,contrast]
 *
 * Launches the built app against the stub agent, captures a few frames so the
 * match chip has something to count, and for each theme writes
 * `<theme>-<shot>.png`: the palette empty, under `>`, under `?` and under an
 * out-of-range `:`; the filter field with its recents; the applied filter's
 * chip; Settings searched for "dns"; and a changed setting with its bar and
 * Reset (ADR 0057).
 *
 * The one pass mark is Escape's place in ADR 0034's chain: with the palette
 * open over Settings, one Escape closes the palette and leaves Settings open.
 * Exits non-zero if it does not.
 *
 * In `check.ts`'s NOT_TESTS: the pictures have no right answer, and a run
 * launches the app once per theme.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';
import { launchApp } from './launchApp';

const arg = (name: string, fallback: string | null): string | null => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const OUT = arg('out', null);
if (!OUT) { console.log('usage: palette-shots.ts --out <dir> [--themes light,dark,dim,contrast]'); process.exit(2); }
const THEMES = (arg('themes', 'light,dark,dim,contrast') as string).split(',');
mkdirSync(OUT, { recursive: true });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-paletteshots-` + process.pid;
const agent = await startStubAgent(PIPE, 5);
const RECENTS = JSON.stringify(['tcp.port == 443', 'dns']);
const PALETTE = '[role="dialog"][aria-label="Command palette"]';
const FILTER = 'input[placeholder^="e.g. tcp.port"]';

let failed = false;
const verdict = (ok: boolean, what: string) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}`);
  if (!ok) failed = true;
};

for (const theme of THEMES) {
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-paletteshots-'));
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE },
  });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  // Not waitForFunction with a string: that evaluates it in the page, which the CSP forbids.
  const ready = async () => {
    const end = Date.now() + 30_000;
    while (Date.now() < end) {
      if (await p.evaluate('(document.getElementById("root")?.childElementCount ?? 0) > 0').catch(() => false)) return;
      await sleep(150);
    }
    throw new Error('the app never rendered');
  };
  await ready();
  // Strings, not functions: tsx's esbuild wraps a function in `__name`, which the page does not have.
  await p.evaluate(`localStorage.setItem('theme', ${JSON.stringify(theme)}); localStorage.setItem('inwire.recentFilters', ${JSON.stringify(RECENTS)});`);
  await p.reload();
  await ready();
  await app.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows()[0];
    w.unmaximize();
    w.setSize(1280, 800);
  });
  await sleep(800);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});

  const shot = async (name: string) => {
    await p.screenshot({ path: path.join(OUT, `${theme}-${name}.png`) });
    console.log(`  ${theme}-${name}`);
  };
  const paletteOpen = () => p.evaluate(`document.querySelector('${PALETTE}') !== null`) as Promise<boolean>;
  const settingsOpen = () => p.evaluate(`document.querySelector('[aria-label="Search settings"]') !== null`) as Promise<boolean>;
  /** Ctrl+K, then set the palette's text. */
  const openPalette = async (text: string) => {
    await p.keyboard.press('Control+K');
    await p.locator(PALETTE).waitFor();
    if (text) await p.locator(`${PALETTE} input`).fill(text);
    await sleep(350); // past the palette-in animation
  };
  const closePalette = async () => {
    await p.keyboard.press('Escape');
    await sleep(250);
  };

  try {
    // Frames for the chip to count.
    await p.getByRole('button', { name: 'Interfaces' }).click();
    await p.getByText('Ethernet', { exact: true }).first().click();
    await p.getByLabel('Start capture').click();
    await sleep(2500);
    await p.getByLabel(/Stop capture|Pause capture/).first().click().catch(() => {});
    await sleep(500);
    await p.getByRole('button', { name: 'Packets', exact: true }).click().catch(() => {});
    await sleep(300);

    await openPalette('');
    await shot('01-palette-empty');
    await closePalette();
    await openPalette('>');
    await shot('02-palette-commands');
    await closePalette();
    await openPalette('?');
    await shot('03-palette-help');
    await closePalette();
    await openPalette(':999999999');
    await shot('04-palette-goto-out-of-range');
    await closePalette();

    // The field, focused, with its two recents.
    await p.locator(FILTER).click();
    await sleep(350);
    await shot('05-filter-recents');
    await p.keyboard.press('Escape');
    // The stub's frames are DNS, so `dns` is a filter with a count worth reading.
    await p.locator(FILTER).fill('dns');
    await p.keyboard.press('Enter');
    await sleep(900);
    // Escape and a click elsewhere were both tried to close the field's
    // suggestion list; it stays up over the packet list after an applied
    // filter, so the shot has it. The chip is the thing being photographed.
    await sleep(300);
    await shot('06-filter-chip');
    await p.locator(FILTER).fill('');
    await p.keyboard.press('Enter');
    await sleep(300);

    // Settings, searched.
    await p.getByRole('button', { name: 'Settings', exact: true }).click();
    await p.getByLabel('Search settings').waitFor();
    await p.getByLabel('Search settings').fill('dns');
    await sleep(500);
    await shot('07-settings-search-dns');

    // Review focus 2: Escape closes the palette and only the palette.
    await openPalette('');
    verdict(await paletteOpen(), `${theme}: palette opens over Settings`);
    await p.keyboard.press('Escape');
    await sleep(300);
    verdict(!(await paletteOpen()), `${theme}: one Escape closed the palette`);
    verdict(await settingsOpen(), `${theme}: and Settings is still open`);

    // A changed setting: the bar and Reset.
    await p.getByLabel('Search settings').fill('');
    await sleep(300);
    const row = p.locator('#setting-row-minimap');
    if (!(await row.isVisible().catch(() => false))) {
      await p.getByRole('button', { name: 'Interface', exact: true }).click();
      await sleep(300);
    }
    await p.locator('#setting-minimap').click();
    await row.scrollIntoViewIfNeeded();
    await sleep(300);
    const box = await row.boundingBox();
    if (!box) throw new Error('the Minimap row has no box');
    const pad = 24;
    const clip = {
      x: Math.max(0, box.x - pad), y: Math.max(0, box.y - pad),
      width: box.width + pad * 2, height: box.height + pad * 2,
    };
    await p.screenshot({ path: path.join(OUT, `${theme}-08-setting-modified.png`), clip });
    console.log(`  ${theme}-08-setting-modified`);
    await shot('09-settings-modified-full');
  } catch (e) {
    console.log(`  ${theme} FAILED: ${(e as Error).message.split('\n')[0]}`);
    failed = true;
    await shot('error').catch(() => {});
  }
  // Closing with frames in the buffer opens the "Quit Inwire?" confirm.
  await p.evaluate('window.inwire?.setUnsavedCapture?.(false)').catch(() => {});
  await app.close().catch(() => {});
  rmSync(profile, { recursive: true, force: true });
}
await agent.close?.();
console.log(failed ? 'FAIL' : 'PASS');
process.exit(failed ? 1 : 0);
