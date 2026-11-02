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
 * it passes through in-between values for several frames; with "never" it
 * snaps from its start to rest and is never in between (see `pose`).
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
import { modalPanelMotion } from '../../src/lib/modalMotion';

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
      samples.push(getComputedStyle(card).transform || 'none');
      if (now - start > 400) { window.__motionSamples = samples; return; }
    }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})()`;

/**
 * Where a sampled transform sits: at `rest`, at the panel's `start`
 * (modalPanelMotion's initial scale and y), or `between` - and only between is
 * animation. Reduced motion is a snap from start to rest, and when the snap
 * lands is the library's business: motion 12 is at rest on the frame after
 * mount, motion 14 holds the start for one more frame and then snaps. A frame
 * between the two is a frame of movement, which is what "never" must not have.
 *
 * The sample is the COMPUTED transform (`none` or a `matrix(...)`), because
 * motion 14 runs the animation through the Web Animations API and writes only
 * the end value inline - an inline-style reader saw its whole animation as
 * already at rest, in both settings.
 */
const START = modalPanelMotion.initial;
function pose(transform: string): 'rest' | 'start' | 'between' {
  if (transform === 'none' || transform === '') return 'rest';
  const matrix = /^matrix\(([^)]+)\)$/.exec(transform);
  if (!matrix) return 'between'; // a form this does not read is not proof of stillness
  const [a, b, c, d, e, f] = matrix[1].split(',').map((n) => parseFloat(n));
  if (b !== 0 || c !== 0 || e !== 0 || a !== d) return 'between';
  if (a === 1 && f === 0) return 'rest';
  if (Math.abs(a - START.scale) < 1e-6 && Math.abs(f - START.y) < 1e-6) return 'start';
  return 'between';
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
    const moving = samples.filter((t) => pose(t) === 'between').length;
    return { moving, total: samples.length, first: samples.slice(0, 4) };
  } finally {
    // Unconditionally, and before the close: a step that threw with the flag
    // still set would leave app.close() waiting on a confirm nobody answers.
    await page.evaluate('window.inwire.setUnsavedCapture(false)').catch(() => {});
    await app.close();
    rmSync(profile, { recursive: true, force: true });
  }
}

// The reader first: one that called every transform still would pass the
// "never" half for free.
check('reads none and the identity matrix as rest',
  pose('none') === 'rest' && pose('matrix(1, 0, 0, 1, 0, 0)') === 'rest');
check(`reads the panel's initial scale ${START.scale} and y ${START.y} as its start`,
  pose(`matrix(${START.scale}, 0, 0, ${START.scale}, 0, ${START.y})`) === 'start');
check('reads anything in between, or unreadable, as movement',
  pose('matrix(0.98, 0, 0, 0.98, 0, 4)') === 'between' && pose('matrix(1, 0, 0, 1, 0, 4)') === 'between'
  && pose('translateY(4px)') === 'between');

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
