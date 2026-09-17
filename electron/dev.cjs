/**
 * `npm run dev`: the Vite server and Electron, in that order.
 *
 * Launching both at once with `concurrently` loses a race roughly a third of
 * the time - Electron reaches `loadURL` before Vite is listening and the window
 * shows `ERR_CONNECTION_REFUSED`, which reads as "the app is broken" rather
 * than "wait a second". So this polls the port and only then starts Electron.
 *
 * It also does the thing `concurrently` does not: when Electron exits, Vite is
 * killed. A stray dev server holding port 3000 is what makes the *next* run
 * fail outright, because Vite is spawned `--strictPort` below - and an orphaned
 * Electron beside it is why `npm run dev` would never return to the prompt.
 *
 * That used to read "ends up on 3001, serving an origin the agent's allowlist
 * does not know about", and both halves are gone: `--strictPort` refuses rather
 * than drifting, and there is no origin allowlist on Windows at all - the agent
 * is reached over a named pipe whose descriptor the kernel enforces.
 *
 * Note the host: `127.0.0.1`, not `0.0.0.0`. The browser build served its dev
 * bundle to the LAN so a phone could open it; a desktop app has no such reader,
 * and binding every interface is a listening socket nobody asked for. The
 * update feed below binds the same interface for the same reason.
 *
 * It also stands up a loopback update feed, so a launch does not open with a
 * DNS failure against an unregistered domain. `devFeed.cjs` says why.
 */
const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const { startDevFeed } = require('./devFeed.cjs');

// Normalised once, so "should I start a feed?" and "what do I pass the child?"
// cannot answer differently. `''` is falsy but not nullish, and the two tests
// used to disagree about exactly that value. See `start.cjs` for the same note.
const INHERITED_FEED = process.env.INWIRE_UPDATE_FEED || null;

const HOST = '127.0.0.1';
const PORT = Number(process.env.INWIRE_DEV_PORT ?? 3000);
const ORIGIN = `http://${HOST}:${PORT}`;
const root = path.join(__dirname, '..');

/** Resolves once something is listening, or rejects after `timeoutMs`. */
function waitForPort(timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect({ host: HOST, port: PORT });
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`nothing listening on ${ORIGIN}`));
        else setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

const children = [];
/** The loopback update feed, once it is listening; null when one was inherited. */
let feed = null;
/**
 * Set by `stopAll`, and read by the launch chain below.
 *
 * Vite can exit at any point, including while `startDevFeed()` is still
 * resolving - so `stopAll` can run before there is a `feed` to close. Without
 * this flag that pending listen still completes, assigns `feed`, and spawns
 * Electron against a dev server that is already gone; worse, the listening
 * socket keeps the event loop alive, so `npm run dev` never returns to the
 * prompt. The orphaned-Electron half of that predates the feed; the hang does
 * not.
 */
let stopping = false;
function stopAll(code) {
  stopping = true;
  for (const child of children) {
    if (!child.killed) child.kill();
  }
  if (feed) { const served = feed; feed = null; void served.close(); }
  process.exitCode = code ?? 0;
}

const vite = spawn(
  process.platform === 'win32' ? 'npx.cmd' : 'npx',
  ['vite', `--port=${PORT}`, `--host=${HOST}`, '--strictPort'],
  { cwd: root, stdio: 'inherit' },
);
children.push(vite);
vite.on('exit', (code) => stopAll(code ?? 0));

waitForPort()
  .then(() => (INHERITED_FEED ? null : startDevFeed()))
  .then((served) => {
    // Vite may have exited while the feed was coming up. Close what we just
    // opened and stop here - see `stopping`.
    if (stopping) {
      if (served) void served.close();
      return;
    }
    // An INWIRE_UPDATE_FEED already set wins: somebody pointing the app at
    // their own feed means it.
    feed = served;
    const electron = spawn(
      require('electron'),
      [root],
      {
        cwd: root,
        stdio: 'inherit',
        // How `main.ts` knows to load the dev server instead of `app://`, and
        // which CSP to apply.
        env: {
          ...process.env,
          INWIRE_DEV_SERVER: ORIGIN,
          INWIRE_UPDATE_FEED: INHERITED_FEED ?? served.url,
        },
      },
    );
    children.push(electron);
    electron.on('exit', (code) => stopAll(code ?? 0));
  })
  .catch((error) => {
    console.error(`[inwire] ${error.message}`);
    stopAll(1);
  });

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stopAll(0));
