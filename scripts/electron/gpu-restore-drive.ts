/**
 * The map surviving a GPU context loss, in the real app.
 *
 *   npm run build && npx tsx scripts/electron/gpu-restore-drive.ts
 *
 * A driver reset, a GPU process crash or a laptop changing graphics adapter
 * reaches the renderer as a lost WebGL context. In a terminal the tell is
 * Chromium's own `command_buffer_proxy_impl.cc ... GPU state invalid after
 * WaitForGetOffsetInRange`, which is what sent somebody looking the first time.
 *
 * MapLibre handles the WebGL half itself: `_contextLost` snapshots the style and
 * `_contextRestored` puts it back with `setStyle`, which fires `style.load` -
 * this app's existing recovery path. The part that is ours is that `GeoMap`
 * caches "is the style usable?" in `styleReadyRef`, and MapLibre has no way to
 * tell it that the style it was holding has been destroyed.
 *
 * In `NOT_TESTS`: it needs `dist/`, a real GPU context and about half a minute.
 * Run it by hand after anything touching GeoMap's style or layer lifecycle.
 *
 * ## Why it drives the app rather than calling a function
 *
 * There is no function to call. The failure is an interaction between three
 * parties - Chromium losing a context, MapLibre's restore calling `resize()`
 * before its own style has loaded, and this component answering a `moveend`
 * during that window - and none of it exists outside a running renderer with a
 * live GL context. Every other check in `scripts/` runs under plain `tsx`
 * precisely because it does not need one; this one cannot.
 *
 * ## What each assertion catches, verified by putting the bug back
 *
 *  - **nothing threw**: comment out `styleReadyRef.current = false` in GeoMap's
 *    `webglcontextlost` handler and `Style is not done loading.` reappears here,
 *    thrown out of MapLibre's own `_contextRestored`.
 *  - **the custom layers are back**: asserted by losing the context a SECOND
 *    time and reading which layers MapLibre names in its warning - it
 *    enumerates the style's custom layers, so naming them proves they are in it.
 *    This one passes with the bug in place too, and is kept deliberately: it is
 *    what stops a future "fix" from recovering quietly by dropping the layers.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ElectronApplication, Page } from 'playwright';
import { launchApp } from './launchApp';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const repoRoot = path.resolve(import.meta.dirname, '..', '..');

let app: ElectronApplication | undefined;
let profile: string | undefined;

try {
  // A temporary profile, for the reason `smoke.ts` gives: the app prunes its
  // capture directory at startup and would otherwise delete a stored capture.
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-gpu-'));
  app = await launchApp({
    args: [repoRoot], cwd: repoRoot,
    env: { ...process.env, INWIRE_USER_DATA: profile },
  });
  const page: Page = await app.firstWindow();
  // Playwright's default is NO timeout, so a control that never renders would
  // hang the run with no output rather than fail it. Same rule as `smoke.ts`.
  page.setDefaultTimeout(30_000);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(2500);

  const errors: string[] = [];
  const warnings: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'warning') warnings.push(m.text()); });

  const skip = page.getByText('Skip', { exact: true });
  if (await skip.count()) { await skip.first().click(); await page.waitForTimeout(400); }

  // The map does not exist until geo-IP lookup is consented to - the view says
  // so instead, which is why a run against a default profile sees no WebGL at
  // all. Set the preference the panel would set, and reload.
  console.log('\n--- getting a live WebGL map on screen ---\n');
  await page.evaluate(() => {
    window.localStorage.setItem('inwire.nameResolution',
      JSON.stringify({ geoIp: true, reverseDns: false, mdns: true, netbios: true }));
    location.reload();
  });
  await page.waitForTimeout(3500);
  // The rail's VIEW button, not a widget toggle - the map was a dock widget with
  // an overlay when this was written, and it is a view now. Same accessible
  // name either way, which is why the locator survived the move; the click now
  // switches views rather than opening a modal, so the wait after it is the
  // map mounting into a full pane.
  //
  // This click is no longer optional in spirit: there was a pane-sized copy of
  // the map in the Packets view, so a run that never found this button could
  // still have had a live context to lose. It is the only map there is now.
  const mapView = page.getByRole('button', { name: 'Routing Map', exact: true });
  if (await mapView.count()) { await mapView.click(); await page.waitForTimeout(7000); }

  const live = () => page.evaluate(() => {
    const c = document.querySelector('.maplibregl-canvas') as HTMLCanvasElement | null;
    const gl = c && (c.getContext('webgl2') || c.getContext('webgl'));
    return { map: Boolean(c), lost: gl ? (gl as WebGLRenderingContext).isContextLost() : null };
  });
  const before = await live();
  if (!before.map) {
    console.log('SKIP  no WebGL map on screen - this machine may have no GL context to lose');
    process.exit(0);
  }
  check('the map is up with a healthy context', before, { map: true, lost: false });

  console.log('\n--- losing the context, the way a driver reset does ---\n');
  errors.length = 0;
  await page.evaluate(() => {
    const c = document.querySelector('.maplibregl-canvas') as HTMLCanvasElement;
    const gl = (c.getContext('webgl2') || c.getContext('webgl')) as WebGLRenderingContext;
    // Held from before the loss: `getExtension` returns null on a lost context,
    // so the handle for restoring it has to be taken while it still works.
    const held = window as unknown as { __lose: WEBGL_lose_context };
    held.__lose = gl.getExtension('WEBGL_lose_context')!;
    held.__lose.loseContext();
  });
  await page.waitForTimeout(2500);
  check('the context really is lost', (await live()).lost, true);

  console.log('\n--- restoring it, the way Chromium does after a GPU crash ---\n');
  await page.evaluate(() =>
    (window as unknown as { __lose: WEBGL_lose_context }).__lose.restoreContext());
  await page.waitForTimeout(6000);

  check('the context comes back', (await live()).lost, false);
  // The assertion this script exists for. `_contextRestored` calls `resize()`
  // before its own style has loaded; `resize()` fires `moveend`; GeoMap answers
  // that with `syncConnectionsLayer()`. With `styleReadyRef` left true across
  // the loss, that lands in `addLayer` against a style that was destroyed.
  check('nothing threw during the recovery',
    errors.filter((e) => /Style is not done loading/.test(e)), []);
  checkTrue('...and nothing else threw either', errors.length === 0);

  console.log('\n--- and the custom layers are genuinely back ---\n');
  // MapLibre enumerates the style's CUSTOM layers when a context is lost, so a
  // second loss names them only if they are in the style at that moment.
  warnings.length = 0;
  await page.evaluate(() => {
    const c = document.querySelector('.maplibregl-canvas') as HTMLCanvasElement;
    const gl = (c.getContext('webgl2') || c.getContext('webgl')) as WebGLRenderingContext;
    gl.getExtension('WEBGL_lose_context')!.loseContext();
  });
  await page.waitForTimeout(2500);
  const named = warnings.filter((w) => /cannot be restored after WebGL context loss/.test(w));
  checkTrue('the arc layer was re-added', named.some((w) => w.includes("'inwire-arcs'")));
  checkTrue('the pin layer was re-added', named.some((w) => w.includes("'inwire-pins'")));
} finally {
  // `close()`, never `kill()`: killing reaches main and orphans the GPU,
  // renderer and crashpad children. Nothing here leaves frames in the buffer,
  // so `guardClose` has no box to open.
  if (app) await app.close().catch(() => {});
  if (profile) rmSync(profile, { recursive: true, force: true });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All GPU restore checks passed.');
