/**
 * What the `app://` handler serves for a given path, as a pure decision.
 *
 * ## Why this is a function and not four lines inside the handler
 *
 * The app used to be served by `server.ts`, whose last route was
 * `app.get('*', ... sendFile index.html)`. That single line has now caused two
 * separate silent failures, both documented in `vite.config.ts`: a request for
 * `public/downloads/Inwire-Agent-Setup.exe` came back as **`index.html`
 * renamed to `.exe`**, a 1 kB "corrupted installer" with no error anywhere; and
 * a request for maplibre's tile worker came back as HTML, which the browser
 * parses as an ES module, so the worker died before registering a message
 * handler and the map rendered no tiles and reported nothing.
 *
 * Every Electron custom-scheme example on the internet reproduces that
 * fallback. This app has no router and does not need one, so the rule here is
 * the opposite: **anything that looks like a file either exists or 404s.**
 * Only an extension-less path falls back to `index.html`.
 *
 * ## The MIME table is not decoration
 *
 * A module script served as `application/octet-stream` is refused by Chromium's
 * strict MIME checking, and the only trace is a console message nobody reads in
 * a packaged build. Two of the files that matter most are `.mjs` - maplibre's
 * worker and its shared chunk, which `vite.config.ts` emits **unhashed on
 * purpose** because maplibre resolves them by literal name at runtime.
 *
 * Pure, so `scripts/electron/protocol-paths.ts` can drive every case without a
 * browser. The Electron adapter around it does nothing but read a file.
 */

/** The scheme, host and origin the packaged app is served from. */
export const APP_SCHEME = 'app';
export const APP_HOST = 'inwire';
export const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;

/**
 * Content types by extension.
 *
 * Deliberately a closed list. An unknown extension is served as
 * `application/octet-stream`, which is correct for a download and wrong for
 * anything the page loads - so a new asset kind that needs a type will fail
 * visibly on first use rather than silently at some later point.
 */
export const MIME_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8',
};

const FALLBACK_MIME = 'application/octet-stream';

export type ServeDecision =
  /** Read this path, relative to the build directory, and serve it. */
  | { kind: 'file'; relative: string; mime: string }
  /** An extension-less path: the single-page shell. */
  | { kind: 'shell' }
  /** Never touch the filesystem for this one. */
  | { kind: 'refuse'; reason: string };

/**
 * Decides what a request for `pathname` should be answered with.
 *
 * `pathname` is `new URL(request.url).pathname` - already percent-encoded, and
 * decoded here rather than by the caller so the traversal checks below run
 * against what the filesystem would actually see. A path that decodes to
 * something containing `..`, a backslash or a NUL is refused outright rather
 * than normalised, because normalising an attack into a valid path is how a
 * traversal check gets bypassed.
 */
export function decideServe(pathname: string): ServeDecision {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return { kind: 'refuse', reason: 'the path is not valid percent-encoding' };
  }

  if (decoded.includes('\0')) return { kind: 'refuse', reason: 'the path contains a NUL' };
  // Backslashes are path separators on Windows and are not legal in a URL
  // path, so a request carrying one is either an attack or a bug.
  if (decoded.includes('\\')) return { kind: 'refuse', reason: 'the path contains a backslash' };
  if (!decoded.startsWith('/')) return { kind: 'refuse', reason: 'the path is not absolute' };

  const segments = decoded.split('/').filter((s) => s.length > 0);
  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      return { kind: 'refuse', reason: 'the path tries to leave the build directory' };
    }
  }

  if (segments.length === 0) return { kind: 'shell' };

  const last = segments[segments.length - 1];
  const dot = last.lastIndexOf('.');
  // A leading dot is a dotfile, not an extension: `/.well-known` has no
  // extension, and neither does `/settings`.
  if (dot <= 0) return { kind: 'shell' };

  const extension = last.slice(dot).toLowerCase();
  return {
    kind: 'file',
    relative: segments.join('/'),
    mime: MIME_TYPES[extension] ?? FALLBACK_MIME,
  };
}

/**
 * The two files maplibre resolves by literal name at runtime.
 *
 * Named here so `scripts/electron/protocol-paths.ts` can assert they are
 * servable with a JavaScript content type. They are the app's canary: if these
 * two 404 or come back as HTML, the map renders nothing and says nothing, and
 * that failure has now arrived from three different directions (Vite's
 * pre-bundler, the Express fallback, and `defaultWorkerUrl()` under a
 * non-http scheme).
 */
export const MAPLIBRE_RUNTIME_ASSETS = [
  '/assets/maplibre-gl-worker.mjs',
  '/assets/maplibre-gl-shared.mjs',
] as const;
