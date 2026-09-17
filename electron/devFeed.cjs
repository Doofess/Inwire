/**
 * A real update feed on loopback, so a development launch reaches one.
 *
 * `DEFAULT_UPDATE_FEED_URL` is `https://updates.inwire.app/manifest.json` and
 * **that domain is not registered**, so every launch of a profile that opted
 * into the check spends `FEED_TIMEOUT_MS` failing DNS and prints
 * `the update feed is not reachable: net::ERR_NAME_NOT_RESOLVED`. Nothing is
 * broken - `host.ts` handles unreachable as its ordinary case - but it is a
 * failure printed on every run, which is the shape that trains somebody to
 * stop reading their own log.
 *
 * So `dev.cjs` and `start.cjs` stand one of these up and point
 * `INWIRE_UPDATE_FEED` at it. The check then succeeds, `lastChecked` moves,
 * and the line is gone. Nothing about a packaged build changes: the override
 * is read once from the environment (`resolveFeedUrl`) and is never baked in.
 *
 * ## Why the default manifest offers nothing
 *
 * Not timidity - it is the only document this server can legally serve. A row
 * for `inwire`, `agent`, `oui` or `geoip` has `DOWNLOAD_HOSTS[id] === null`,
 * which means "the host the feed itself came from", and `hostOf` returns null
 * for anything that is not **https**. A loopback feed is http, so those rows
 * can never validate here - and `parseManifest` rejects the *whole document*
 * over one malformed row for a known id, which would trade
 * `not reachable` for `could not be read`. Npcap is the exception because its
 * allowlist names npcap.com outright.
 *
 * The cost of an empty `components` is that every row rests at `unknown`,
 * which is exactly where an unreachable feed left it - so the panel is no
 * worse, and the log is quiet. `--npcap <version>` adds the one row that can
 * be served, for driving that row by hand; `scripts/electron/update-center-drive.ts`
 * is the version of this that asserts rather than serves.
 *
 * Standalone, for a packaged or hand-launched app:
 *
 *   node electron/devFeed.cjs --npcap 1.88
 *   (then set INWIRE_UPDATE_FEED to the URL it prints)
 */
const http = require('node:http');

/** Binds 127.0.0.1 only. dev.cjs's reasoning about `--host`: no LAN reader. */
const HOST = '127.0.0.1';

/**
 * The one row a loopback feed can carry. The URL is the real npcap.com one,
 * so the host allowlist is exercised rather than bypassed; the digest is not
 * the real file's, which means pressing Update fails `verify` rather than
 * installing something. That is the right way round for a dev feed.
 */
function npcapRow(version) {
  return {
    version,
    kind: 'vendor-installer',
    minAppVersion: '1.0.0',
    url: `https://npcap.com/dist/npcap-${version}.exe`,
    sha256: '0'.repeat(64),
    size: 1320424,
  };
}

function body({ npcap }) {
  const components = {};
  if (npcap) components.npcap = npcapRow(npcap);
  return JSON.stringify({ schema: 1, generated: new Date().toISOString(), components });
}

/**
 * Resolves to `{ url, close }` once it is listening. `port` 0 is an ephemeral
 * port, which is what the runners use - nothing has to agree on a number, and
 * two checkouts running at once do not collide.
 */
function startDevFeed({ npcap = null, port = 0 } = {}) {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body({ npcap }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, HOST, () => {
      resolve({
        url: `http://${HOST}:${server.address().port}/manifest.json`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

module.exports = { startDevFeed };

if (require.main === module) {
  const flag = process.argv.indexOf('--npcap');
  const npcap = flag >= 0 ? process.argv[flag + 1] : null;
  startDevFeed({ npcap }).then(({ url }) => {
    console.log(`Serving an update feed at ${url}`);
    console.log(`Offering: ${npcap ? `npcap ${npcap}` : 'nothing (pass --npcap <version> to offer one)'}`);
    console.log(`Launch the app with INWIRE_UPDATE_FEED=${url}`);
    console.log('Ctrl+C to stop.\n');
  }).catch((error) => {
    console.error(`[inwire] ${error.message}`);
    process.exit(1);
  });
}
