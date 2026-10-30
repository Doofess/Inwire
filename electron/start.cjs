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
 *
 * It also keeps a record. The renderer has died of a full JavaScript heap with
 * only `[renderer] gone` to show for it (`heapLog.ts`), so this sets
 * `INWIRE_HEAP_LOG` for a heap line every ten seconds and copies everything the
 * app prints into a log file in the temp folder, one a launch, the last
 * `KEEP_LOGS` kept. The terminal sees the same output as before.
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startDevFeed } = require('./devFeed.cjs');

const root = path.join(__dirname, '..');
const LOG_DIR = path.join(os.tmpdir(), 'inwire-start-app');
const KEEP_LOGS = 5;

/** A new log file for this launch, after deleting all but the newest few of ours. */
function openLog() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  // Only names this file writes: the folder is ours, but nothing else in it is touched.
  const old = fs.readdirSync(LOG_DIR).filter((name) => /^start-app-[\d-]+T[\d-]+\.log$/.test(name)).sort();
  for (const name of old.slice(0, Math.max(0, old.length - (KEEP_LOGS - 1)))) {
    fs.rmSync(path.join(LOG_DIR, name), { force: true });
  }
  // Local time, as the heap lines print it, so the name and the lines agree.
  const now = new Date();
  const stamp = new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 19).replace(/:/g, '-');
  const file = path.join(LOG_DIR, `start-app-${stamp}.log`);
  return { file, stream: fs.createWriteStream(file) };
}
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
  const log = openLog();
  console.log(`[inwire] logging to ${log.file}`);

  const child = spawn(require('electron'), [root], {
    cwd: root,
    stdio: ['inherit', 'pipe', 'pipe'],
    env: { ...process.env, INWIRE_UPDATE_FEED: url, INWIRE_HEAP_LOG: '1' },
  });
  child.stdout.on('data', (chunk) => { process.stdout.write(chunk); log.stream.write(chunk); });
  child.stderr.on('data', (chunk) => { process.stderr.write(chunk); log.stream.write(chunk); });

  // The server outlives the app otherwise, and `npm run start:app` would never
  // return to the prompt - the same mistake dev.cjs calls out about a stray
  // Vite holding its port.
  const stop = async (code) => {
    if (feed) await feed.close();
    log.stream.end();
    process.exitCode = code ?? 0;
  };
  // 'close', not 'exit': the output pipes may still hold the last lines - the
  // ones about a crash - when the process has exited.
  child.on('close', (code) => { void stop(code ?? 0); });
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
