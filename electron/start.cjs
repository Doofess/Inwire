/**
 * `npm run start:app`: Electron against `app://`, with a feed it can reach.
 *
 * This used to be `electron .` in package.json, and still is in every respect
 * that matters - the same `dist/` is loaded through the same protocol handler,
 * which is the whole point of the command (`main.ts`). The wrapper exists for
 * one reason: `devFeed.cjs`, so a launch does not open with a DNS failure
 * against a domain nobody has registered. Read that file for why the feed is
 * empty by default.
 *
 * An `INWIRE_UPDATE_FEED` already in the environment wins and no server is
 * started. Somebody who has pointed the app at a feed of their own means it,
 * and a dev convenience that silently overrode them would be worse than the
 * line it removes.
 */
const { spawn } = require('node:child_process');
const path = require('node:path');
const { startDevFeed } = require('./devFeed.cjs');

const root = path.join(__dirname, '..');
// Normalised to null HERE, so the two decisions below cannot disagree. They
// did: one used truthiness and the other `??`, and `INWIRE_UPDATE_FEED=''` then
// started a feed nobody dialled and launched the app with an empty string it
// reads as unset - which is the `ERR_NAME_NOT_RESOLVED` line this file exists
// to remove.
const inherited = process.env.INWIRE_UPDATE_FEED || null;

async function main() {
  const feed = inherited ? null : await startDevFeed();
  const url = inherited ?? feed.url;
  if (feed) console.log(`[inwire] serving a dev update feed at ${url}`);

  const child = spawn(require('electron'), [root], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, INWIRE_UPDATE_FEED: url },
  });

  // The server outlives the app otherwise, and `npm run start:app` would never
  // return to the prompt - the same mistake dev.cjs calls out about a stray
  // Vite holding its port.
  const stop = async (code) => {
    if (feed) await feed.close();
    process.exitCode = code ?? 0;
  };
  child.on('exit', (code) => { void stop(code ?? 0); });
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      if (!child.killed) child.kill();
      void stop(0);
    });
  }
}

main().catch((error) => {
  console.error(`[inwire] ${error.message}`);
  process.exitCode = 1;
});
