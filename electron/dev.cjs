/**
 * `npm run dev`: the Vite server and Electron, in that order.
 *
 * Launching both at once with `concurrently` loses a race roughly a third of
 * the time - Electron reaches `loadURL` before Vite is listening and the window
 * shows `ERR_CONNECTION_REFUSED`, which reads as "the app is broken" rather
 * than "wait a second". So this polls the port and only then starts Electron.
 *
 * It also does the thing `concurrently` does not: when Electron exits, Vite is
 * killed. A stray dev server holding port 3000 is how the *next* run ends up
 * on 3001, quietly serving a different origin from the one the agent's
 * allowlist knows about.
 *
 * Note the host: `127.0.0.1`, not `0.0.0.0`. The browser build served its dev
 * bundle to the LAN so a phone could open it; a desktop app has no such reader,
 * and binding every interface is a listening socket nobody asked for.
 */
const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');

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
function stopAll(code) {
  for (const child of children) {
    if (!child.killed) child.kill();
  }
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
  .then(() => {
    const electron = spawn(
      require('electron'),
      [root],
      {
        cwd: root,
        stdio: 'inherit',
        // How `main.ts` knows to load the dev server instead of `app://`, and
        // which CSP to apply.
        env: { ...process.env, INWIRE_DEV_SERVER: ORIGIN },
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
