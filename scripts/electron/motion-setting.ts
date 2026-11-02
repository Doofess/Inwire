/**
 * The app's motion setting reaches motion/react.
 *
 * `RootProviders` turns the setting into `MotionConfig`'s `reducedMotion`:
 * "always" animate is `never` reduce, "never" animate is `always` reduce. That
 * is one prop on a library's provider, and a major version of the library can
 * rename it, change what it covers, or stop reading it without a type error -
 * the setting would still save, and someone who chose "never" because motion
 * makes them ill would get the animation anyway.
 *
 * So this watches a real motion/react panel in the built app: the quit
 * confirm's card (`AlertCard`, `modalPanelMotion`: scale 0.96 and y 8 to rest
 * in 180 ms). motion's reduced mode drops TRANSFORM animations and keeps
 * opacity, so the card's transform is what tells the two apart. With "always"
 * it passes through in-between values for several frames; with "never" it is
 * at rest by the first frame after mount.
 *
 * Opened the way a person opens it: frames are marked unsaved and main closes
 * the window, which the quit guard turns into the renderer's confirm. Keep is
 * pressed (Cancel), the flag cleared, and the app closed normally.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { QUIT_CONFIRM_TEXT } from '../../src/lib/quitConfirm';

let failed = false;
function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
  if (!ok) failed = true;
}
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

if (process.platform !== 'win32') skip('the desktop app is Windows-only - nothing to launch here');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-motion-setting-` + process.pid;
const agent = await startStubAgent(PIPE, 1);

// Records the card's inline transform on every animation frame from its mount
// until 400 ms later, into window.__motionSamples. A string, not a function:
// tsx's esbuild wraps named functions in `__name`, which the page lacks.
const RECORD = `(() => {
  window.__motionSamples = null;
  const samples = [];
  let start = 0;
  const tick = (now) => {
    const card = document.querySelector('[role="alertdialog"] > div');
    if (card) {
      if (!start) start = now;
      samples.push(card.style.transform || 'none');
      if (now - start > 400) { window.__motionSamples = samples; return; }
    }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})()`;

/** A transform at rest: none, or one whose scale is 1 and whose translateY is 0. */
function atRest(transform: string): boolean {
  if (transform === 'none' || transform === '') return true;
  const scale = /scale\(([^)]+)\)/.exec(transform);
  const y = /translateY\(([^)]+)\)/.exec(transform);
  if (!scale && !y) return false; // a spelling this does not know is not proof of rest
  return (!scale || parseFloat(scale[1]) === 1) && (!y || parseFloat(y[1]) === 0);
}

async function framesInMotion(setting: 'always' | 'never'): Promise<{ moving: number; total: number; first: string[] }> {
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-motion-setting-'));
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE },
  });
  const page = await app.firstWindow();
  try {
    page.setDefaultTimeout(30_000);
    const ready = async () => {
      const end = Date.now() + 30_000;
      while (Date.now() < end) {
        if (await page.evaluate('(document.getElementById("root")?.childElementCount ?? 0) > 0').catch(() => false)) return;
        await sleep(150);
      }
      throw new Error('the app never rendered');
    };
    await ready();
    // The store reads its key once, at module scope, so the value goes in
    // before a reload rather than through a StorageEvent.
    await page.evaluate(`localStorage.setItem('inwire.motion', ${JSON.stringify(JSON.stringify(setting))})`);
    await page.reload();
    await ready();

    console.log(`      ${setting}: app ready, closing the window to open the quit confirm`);
    await page.evaluate(RECORD);
    await page.evaluate('window.inwire.setUnsavedCapture(true)');
    // Main's close, the one the quit guard is registered on.
    await app.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0]?.close(); });

    const end = Date.now() + 30_000;
    let samples: string[] | null = null;
    while (Date.now() < end && !samples) {
      samples = await page.evaluate('window.__motionSamples') as string[] | null;
      if (!samples) await sleep(100);
    }
    if (!samples) throw new Error('the quit confirm never showed its card');

    await page.locator('[role="alertdialog"] button', { hasText: QUIT_CONFIRM_TEXT.keep }).click({ timeout: 30_000 });
    await page.evaluate('window.inwire.setUnsavedCapture(false)');
    // Frames after the first: the first is the mount, which may show the
    // initial values before motion has run at all.
    const moving = samples.slice(1).filter((t) => !atRest(t)).length;
    return { moving, total: samples.length, first: samples.slice(0, 4) };
  } finally {
    // Unconditionally, and before the close: a step that threw with the flag
    // still set would leave app.close() waiting on a confirm nobody answers.
    await page.evaluate('window.inwire.setUnsavedCapture(false)').catch(() => {});
    await app.close();
    rmSync(profile, { recursive: true, force: true });
  }
}

// The parser first: a check that reads every transform as "at rest" passes the
// "never" half for free.
check('at rest: none, scale(1), translateY(0px)',
  atRest('none') && atRest('translateY(0px) scale(1)') && atRest('translateY(0px)') && atRest('scale(1)'));
check('moving: scale(0.98), translateY(4px)',
  !atRest('translateY(4px) scale(0.98)') && !atRest('scale(0.98)') && !atRest('translateY(4px)'));

try {
  const always = await framesInMotion('always');
  check(`"always": the card's transform animates (${always.moving} of ${always.total} frames in motion)`,
    always.moving >= 3, `first frames: ${always.first.join(' | ')}`);

  const never = await framesInMotion('never');
  check(`"never": the card's transform does not animate (${never.moving} of ${never.total} frames in motion)`,
    never.moving === 0, `first frames: ${never.first.join(' | ')}`);
} finally {
  await agent.close();
}

process.exit(failed ? 1 : 0);
