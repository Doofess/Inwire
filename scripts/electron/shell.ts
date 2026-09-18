/**
 * The desktop shell's decisions, held to what they are supposed to be.
 *
 *   npx tsx scripts/electron/shell.ts
 *
 * None of this needs Electron to run, and that is deliberate: every module it
 * imports (`appPaths`, `window`, `csp`, `menu`) is pure by construction, and
 * `electron/main.ts` is the thin adapter around them. The rule is the same one
 * `capture.worker.ts` states for itself - if something in the adapter starts
 * deciding anything, it belongs below.
 *
 * Three of the four groups below exist because the failure they guard is
 * **silent**:
 *
 *  - a scheme registered without `standard` makes the origin opaque, so
 *    `localStorage` *throws*, so `preferences.ts:39` catches it and returns
 *    null, so every preference resets on every launch with no error anywhere;
 *  - without `secure`, `crypto.getRandomValues` is gone and `anonymise.ts`
 *    falls back to `Math.random()` for the Crypto-PAn key - the export still
 *    works and no longer means what it promises;
 *  - a path rule that falls back to `index.html` answers a request for a
 *    JavaScript worker with HTML, which is exactly how this app has already
 *    lost a map's tiles and shipped a 1 kB "installer" twice.
 *
 * The fourth, `webPreferences`, is a security ratchet rather than a bug guard:
 * `nodeIntegrationInWorker` is renderer-wide, so turning it on would hand
 * `child_process` to the worker whose whole job is parsing bytes an attacker
 * put on the wire.
 */
import { readFileSync } from 'node:fs';
import { decideServe, MAPLIBRE_RUNTIME_ASSETS, MIME_TYPES } from '../../electron/appPaths';
import {
  developmentCsp, MAIN_OUTBOUND_HOSTS, OUTBOUND_HOSTS, productionCsp,
} from '../../electron/csp';
import {
  DEFAULT_UPDATE_FEED_URL, isAllowedDownload,
} from '../../electron/updateCenter/manifest';
import { menuTemplate } from '../../electron/menu';
import {
  APP_ORIGIN, COMMAND_LINE_SWITCHES, MIN_WINDOW_HEIGHT, MIN_WINDOW_WIDTH, SCHEME_PRIVILEGES,
  TITLE_BAR_HEIGHT, WEB_PREFERENCES, WINDOW_CONTROL_COUNT, WINDOW_CONTROL_WIDTH,
  WINDOW_IS_FRAMELESS,
} from '../../electron/window';

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
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

console.log('--- the window, field by field ---\n');

{
  // Named individually rather than compared as an object, so a FAIL says which
  // decision moved.
  check('the renderer is isolated from the preload', WEB_PREFERENCES.contextIsolation, true);
  check('the renderer has no Node', WEB_PREFERENCES.nodeIntegration, false);
  // The one that matters most. See the module header.
  check('...and neither does a worker in it', WEB_PREFERENCES.nodeIntegrationInWorker, false);
  check('...nor a subframe', WEB_PREFERENCES.nodeIntegrationInSubFrames, false);
  check('the renderer is sandboxed', WEB_PREFERENCES.sandbox, true);
  check('web security is on', WEB_PREFERENCES.webSecurity, true);
  check('insecure content is refused', WEB_PREFERENCES.allowRunningInsecureContent, false);
  // Chromium fetches a dictionary from Google on first input focus. In this
  // app that outbound request appears in the user's own capture.
  check('the spellchecker does not phone home', WEB_PREFERENCES.spellcheck, false);
  // A hidden window is still capturing, still counting toward a scheduled
  // stop, and still slicing a derive pass.
  check('a hidden window keeps running', WEB_PREFERENCES.backgroundThrottling, false);

  // The webPreference covers hidden and occluded but not minimized, which is
  // the state a machine left capturing overnight is actually in.
  check('minimizing does not throttle it either', [...COMMAND_LINE_SWITCHES].sort(), [
    'disable-background-timer-throttling',
    'disable-backgrounding-occluded-windows',
    'disable-renderer-backgrounding',
  ]);
}

console.log('\n--- the window is frameless and draws its own controls ---\n');

{
  // Comments stripped first, the same way the outbound-host drift check below
  // does it - these files explain at length what frameless costs, and a check
  // that cannot tell prose from code would fail on its own rationale. That has
  // already happened once here.
  const withoutComments = (file: string): string => readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');

  checkTrue('the window declares itself frameless', WINDOW_IS_FRAMELESS);
  checkTrue('...and main actually sets it',
    withoutComments('electron/main.ts').includes('frame: false'));

  // **The option that would undo the whole trade.** `thickFrame` defaults to
  // true, and that default is the only reason a frameless window still resizes
  // from its edges, keeps its drop shadow and keeps its minimise animation.
  // Setting it false is a one-word change that looks like tidying and costs all
  // three - so what is asserted is that the word does not appear at all.
  checkTrue('`thickFrame` is never set, at any value',
    !withoutComments('electron/window.ts').includes('thickFrame')
    && !withoutComments('electron/main.ts').includes('thickFrame'));
  // Same argument, for Windows 11's corner radius.
  checkTrue('`roundedCorners` is never set, at any value',
    !withoutComments('electron/window.ts').includes('roundedCorners')
    && !withoutComments('electron/main.ts').includes('roundedCorners'));

  // The overlay is gone with the native buttons. A `titleBarOverlay` coming
  // back would mean Windows was drawing a second set of controls on top of the
  // app's own, which is a thing that renders rather than throws.
  checkTrue('`titleBarOverlay` is gone',
    !withoutComments('electron/window.ts').includes('titleBarOverlay')
    && !withoutComments('electron/main.ts').includes('titleBarOverlay'));
  checkTrue('...and so is `titleBarStyle`',
    !withoutComments('electron/main.ts').includes('titleBarStyle'));

  // The renderer's title row is laid out against this, so a change here that
  // did not reach the CSS would leave the controls straddling the row's edge.
  check('the title row is 32px', TITLE_BAR_HEIGHT, 32);
  // And the reserve the title row uses to centre its label is three buttons
  // wide. This is the number frameless made a constant: under the overlay it
  // had to come from `env(titlebar-area-width)`, because Windows drew the
  // buttons wider at 150% scaling.
  check('three controls reserve 138px',
    WINDOW_CONTROL_WIDTH * WINDOW_CONTROL_COUNT, 138);
  checkTrue('...and the title row reserves exactly that',
    readFileSync('src/components/common/TitleRow.tsx', 'utf8')
      .includes(`w-[${WINDOW_CONTROL_WIDTH * WINDOW_CONTROL_COUNT}px]`));

  // `env(titlebar-area-width)` has no meaning without the overlay: it would
  // resolve to its fallback and silently pad by zero.
  checkTrue('nothing still reads the overlay env()',
    !readFileSync('src/index.css', 'utf8').includes('titlebar-area-width'));

  // The one that has a discarded capture behind it. `destroy()` skips the
  // `close` event, and the quit guard is registered on `close`.
  checkTrue('the close button closes the window rather than destroying it',
    withoutComments('electron/main.ts').includes('window.close()')
    && !withoutComments('electron/main.ts').includes('window.destroy()'));

  // Unchanged by the hidden title bar, and load-bearing: `role: 'editMenu'` is
  // the only source of Ctrl+C/V/A/Z for every input in the app, and Alt is what
  // reveals it. Hiding the caption strip does not hide the menu bar.
  checkTrue('the menu bar is still auto-hidden rather than gone',
    readFileSync('electron/main.ts', 'utf8').includes('autoHideMenuBar: true'));

  // The WIDTH stays 1024 now that the window also carries a 56px rail. Raising
  // it to 1280 would break half-screen snapping on a 1920px display, where
  // Windows gives a 960px window - analyser on one half with a terminal on the
  // other is a workflow this tool exists to support. (The dock was the other
  // thing this sentence used to weigh, and it is deleted.)
  //
  // The HEIGHT moved 640 -> 680 when the title row went full width: the rail
  // sits below it now, so the window has to carry the row on top of the 640 the
  // rail needed at the time. The row has since come down 40 -> 32 and the
  // minimum did not follow.
  //
  // **The status bar did NOT move it again**, and this check is what says so.
  // Its 24px came out of the rail's slack instead, leaving the budget 624 - so
  // a session that adds a strip and reaches for this constant should read the
  // reasoning on `MIN_WINDOW_HEIGHT` before changing it. Raising the minimum is
  // the expensive way to pay for chrome and it is not how the bar was paid for.
  // `scripts/session/view.ts` is the check with teeth - it derives both
  // subtractions and adds the rail up against them; this one only stops the
  // pair drifting silently.
  check('the window minimum is unchanged', [MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT], [1024, 680]);
}

console.log('\n--- the scheme, whose flags each hide a silent failure ---\n');

{
  check('standard, so the origin is not opaque', SCHEME_PRIVILEGES.standard, true);
  check('secure, so getRandomValues exists', SCHEME_PRIVILEGES.secure, true);
  check('fetch and CORS, for the four outbound hosts',
    [SCHEME_PRIVILEGES.supportFetchAPI, SCHEME_PRIVILEGES.corsEnabled], [true, true]);
  check('code cache, because the bundle is megabytes', SCHEME_PRIVILEGES.codeCache, true);
  // The service worker is being deleted; an origin that cannot register one
  // cannot inherit a stale one either.
  check('no service workers', SCHEME_PRIVILEGES.allowServiceWorkers, false);
  check('the origin is what the rest of the app is written against', APP_ORIGIN, 'app://inwire');
}

console.log('\n--- what the handler serves, and what it refuses ---\n');

{
  const kind = (p: string) => decideServe(p).kind;

  check('the root is the shell', kind('/'), 'shell');
  // No router in this app, so anything without an extension is the shell.
  check('an extension-less path is the shell', kind('/settings'), 'shell');
  check('a dotfile is not an extension', kind('/.well-known'), 'shell');

  const asset = decideServe('/assets/index-abc123.js');
  check('a script is a file', [asset.kind, asset.kind === 'file' && asset.mime],
    ['file', 'text/javascript; charset=utf-8']);

  // The canary. Both are emitted unhashed on purpose because maplibre resolves
  // them by literal name at runtime, and both must be served as JavaScript -
  // a module answered as octet-stream is refused by strict MIME checking with
  // one console line nobody reads in a packaged build.
  for (const path of MAPLIBRE_RUNTIME_ASSETS) {
    const decision = decideServe(path);
    check(`${path} is JavaScript`,
      [decision.kind, decision.kind === 'file' && decision.mime],
      ['file', 'text/javascript; charset=utf-8']);
  }
  check('the pdfjs worker is JavaScript too',
    MIME_TYPES['.mjs'], 'text/javascript; charset=utf-8');

  // The rule that replaced the SPA fallback. A missing asset must 404 rather
  // than come back as HTML: that fallback has already cost this project a map
  // with no tiles and a 1 kB installer, both silent.
  const missing = decideServe('/assets/not-here.mjs');
  check('a missing asset is still a file lookup, not the shell', missing.kind, 'file');

  check('traversal is refused', kind('/../../etc/passwd'), 'refuse');
  check('...however it is encoded', kind('/assets/%2e%2e/%2e%2e/secret'), 'refuse');
  check('a backslash is refused', kind('/assets\\..\\secret'), 'refuse');
  check('a NUL is refused', kind('/assets/x%00.js'), 'refuse');
  check('a relative path is refused', kind('assets/x.js'), 'refuse');
  check('broken percent-encoding is refused', kind('/%zz'), 'refuse');
}

console.log('\n--- the policy, and the list it has to keep up with ---\n');

{
  const production = productionCsp();
  // pdfjs will ask for eval and is told no. This is the line worth pinning:
  // it is one convenience away from being added back.
  checkTrue('production allows no eval', !production.includes('unsafe-eval'));
  checkTrue('production locks the default down', production.includes("default-src 'none'"));
  checkTrue('...and forbids framing and form posts',
    production.includes("frame-src 'none'") && production.includes("form-action 'none'"));
  // Dev needs both, and asserting the difference is what stops the dev policy
  // being shipped by accident.
  checkTrue('development allows eval, for Vite', developmentCsp('http://127.0.0.1:3000').includes('unsafe-eval'));

  for (const host of Object.values(OUTBOUND_HOSTS)) {
    checkTrue(`connect-src covers ${host}`, production.includes(host));
  }
  // The agent is a named pipe, which no policy governs because no page can
  // open one - so the port it used to listen on must NOT be allowed. A
  // `connect-src` entry nothing dials is a hole with no user.
  checkTrue('the old agent socket is not allowed', !production.includes('8999'));
  // The shaper is bundled now, so the CDN that served it must not be allowed.
  checkTrue('unpkg is not allowed to serve this app code', !production.includes('unpkg.com'));

  // The check that keeps the list honest: every literal in `src/` that names an
  // outbound host has to appear above. A CSP goes stale silently, and the
  // symptom is a feature that works in dev and not in the packaged build.
  const sources = [
    'src/services/geoIpService.ts',
    'src/components/network/PublicIdentity.tsx',
    'src/components/analytics/GeoMap.tsx',
    'src/services/agentProtocol.ts',
  ];
  // Compared on scheme+host, not on the full origin: the literals in
  // `geoIpService.ts` carry a path, and a policy entry covers a whole host.
  const hostOf = (origin: string): string => {
    const m = /^([a-z]+:\/\/[a-z0-9.-]+)/i.exec(origin);
    return m ? m[1].toLowerCase() : origin.toLowerCase();
  };
  const known = new Set(Object.values(OUTBOUND_HOSTS).map(hostOf));
  const unlisted: string[] = [];
  for (const file of sources) {
    // Comments stripped first. A URL in a comment is documentation, not a
    // request - and this check flagged one the moment a comment explained why
    // maplibre's worker URL differs between dev and a packaged build.
    const text = readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    for (const match of text.matchAll(/['"`]((?:https?|wss?):\/\/[a-z0-9.-]+)/gi)) {
      const host = hostOf(match[1]);
      if (known.has(host)) continue;
      if (!unlisted.includes(host)) unlisted.push(host);
    }
  }
  check('no outbound host in src/ is missing from the policy', unlisted, []);

  // The same rule for the other process. `net.fetch` in main is not a page and
  // no CSP governs it, so these must NOT be in the policy - a `connect-src`
  // entry the renderer never dials is the hole with no user, again. What is
  // asserted instead is that the list exists and matches what the code
  // actually reaches, because a host that escaped the record by being dialled
  // from main would defeat the point of keeping the record.
  for (const host of Object.values(MAIN_OUTBOUND_HOSTS)) {
    checkTrue(`${host} is main's to reach, not the renderer's`, !production.includes(host));
  }

  // The one that would drift. Change the feed URL and this fails until the
  // list is corrected.
  check('the recorded feed host is the one the updater dials',
    hostOf(MAIN_OUTBOUND_HOSTS.updateFeed),
    hostOf(DEFAULT_UPDATE_FEED_URL));

  // Npcap comes from the vendor and nowhere else, and `manifest.ts` is what
  // enforces it at runtime. Asserting the pair keeps the documented host and
  // the enforced one from parting company.
  checkTrue('the recorded Npcap host is the one the allowlist admits',
    isAllowedDownload('npcap', `${MAIN_OUTBOUND_HOSTS.npcap}/dist/npcap-1.88.exe`,
      DEFAULT_UPDATE_FEED_URL));
  checkTrue('...and it admits nowhere else',
    !isAllowedDownload('npcap', 'https://mirror.example/npcap-1.88.exe', DEFAULT_UPDATE_FEED_URL));
}

console.log('\n--- the menu, which is neither the default nor absent ---\n');

{
  const packaged = menuTemplate({ packaged: true });
  const development = menuTemplate({ packaged: false });
  const labels = packaged.map((item) => item.label ?? item.role);

  check('there is a menu at all', labels, ['&File', '&Edit', '&View']);
  // `Menu.setApplicationMenu(null)` would kill Ctrl+C/V/A/Z in every text
  // input on Windows: those come from this role, not from Chromium.
  check('Edit is the role, so the clipboard shortcuts exist',
    packaged.find((i) => i.label === '&Edit')?.role, 'editMenu');

  const roles = (template: typeof packaged) =>
    (template.find((i) => i.label === '&View')?.submenu as { role?: string }[])
      .map((i) => i.role).filter(Boolean);

  // A reload tears down the pipeline worker, the socket and the RAM buffer.
  // The whole reload-intent heuristic in App.tsx existed to tell that gesture
  // apart from a close; a packaged desktop app simply does not offer it.
  checkTrue('a packaged build offers no reload', !roles(packaged).includes('reload'));
  checkTrue('...and no force reload', !roles(packaged).includes('forceReload'));
  checkTrue('development still has one', roles(development).includes('reload'));
  // Kept on purpose: this app's users are the population most likely to want
  // them, and a packaged-build-only failure is miserable to diagnose without.
  checkTrue('developer tools survive in production', roles(packaged).includes('toggleDevTools'));
}

console.log(failures === 0
  ? '\nAll desktop shell checks passed.'
  : `\n${failures} desktop shell check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
