import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig, type Plugin} from 'vite';

/**
 * Emits maplibre-gl's tile worker into the build.
 *
 * maplibre-gl 6 ships three files - the library, a shared chunk, and the worker
 * that fetches and parses every tile - and finds the worker at **run time** by
 * resolving `maplibre-gl-worker.mjs` as a sibling of whatever chunk it was
 * loaded from. In a production build that resolves to `/assets/`, where Rollup
 * has inlined the library and emitted no worker at all.
 *
 * A server that answers an unknown path with `index.html` then returns that
 * with a 200 - the browser parses HTML as an ES module, the worker dies before
 * it registers a message handler, and **maplibre reports nothing**. The map
 * loads its style, its sprites and its tile JSON, and then sits with every tile
 * in state `loading` for ever.
 *
 * That fallback lived in `server.ts`, which is gone; `electron/appPaths.ts`
 * deliberately 404s instead, and `scripts/electron/shell.ts` holds it to that.
 * The hazard is written down here because the fix below - emitting the worker
 * at a name maplibre can find - is what stops the request being unknown in the
 * first place, and is still required.
 *
 * `optimizeDeps.exclude` below fixes the same area in DEV, where native ESM
 * lets maplibre resolve the worker inside `node_modules`. It does nothing for a
 * build, which is why this exists and why the two are not the same fix.
 *
 * The names are exact and unhashed on purpose: maplibre computes the worker's
 * URL from its own filename, and the worker imports `./maplibre-gl-shared.mjs`
 * by that literal specifier. Hashing either would break the pair. The cost is
 * that these two are not cache-busted across a maplibre upgrade.
 */
/**
 * The right-to-left text shaper, copied in rather than fetched from a CDN.
 *
 * maplibre cannot shape or bidi-reorder Arabic or Hebrew on its own, and the
 * plugin's own npm package restricts its `exports` to an ES module entry that
 * is not a loadable script URL - which is why every example, and this app until
 * now, points `setRTLTextPlugin` at unpkg.
 *
 * That was a CDN dependency in a web page. In a signed desktop installer it is
 * **unsigned third-party JavaScript fetched and executed on launch**, and in a
 * packet analyzer it is an unexplained outbound request appearing in the user's
 * own capture. Neither is defensible, and the file is 133 kB, so it ships with
 * the app.
 *
 * Same mechanism as the worker below: read the real file out of `node_modules`
 * at build time and emit it at a fixed path, failing loudly if it moves.
 */
const RTL_TEXT_ASSET = 'assets/mapbox-gl-rtl-text.js';

function bundledMapAssets(): Plugin {
  const maplibre = ['maplibre-gl-worker.mjs', 'maplibre-gl-shared.mjs'];
  return {
    name: 'inwire:map-assets',
    apply: 'build',
    generateBundle() {
      const dir = path.resolve(__dirname, 'node_modules/maplibre-gl/dist');
      for (const file of maplibre) {
        const from = path.join(dir, file);
        if (!fs.existsSync(from)) {
          // Loud rather than silent: a missing worker is a map that renders no
          // tiles and says nothing about why, which is a day to diagnose.
          this.error(`maplibre-gl worker asset missing: ${from}`);
        }
        this.emitFile({ type: 'asset', fileName: `assets/${file}`, source: fs.readFileSync(from) });
      }

      const rtl = path.resolve(
        __dirname, 'node_modules/@mapbox/mapbox-gl-rtl-text/dist/mapbox-gl-rtl-text.js',
      );
      if (!fs.existsSync(rtl)) {
        this.error(`mapbox-gl-rtl-text missing: ${rtl}`);
      }
      this.emitFile({ type: 'asset', fileName: RTL_TEXT_ASSET, source: fs.readFileSync(rtl) });
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), bundledMapAssets()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    optimizeDeps: {
      // maplibre-gl ships its own web worker as a separate asset; esbuild's
      // dependency pre-bundler doesn't resolve that worker's URL correctly,
      // which leaves the map's tile-parsing worker silently dead (map loads
      // its style but never renders a single tile). Exclude it so Vite serves
      // it as native ESM instead, where maplibre's own build handles this
      // correctly.
      exclude: ['maplibre-gl'],
    },
    server: {
      // HMR and file watching get expensive when a tool is rewriting many
      // files at once: every save triggers a reload, and they accumulate
      // until the tab stalls. Set DISABLE_HMR=true for those sessions and
      // reload by hand when the edits are done.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {
        // local-agent/ holds the Python source and the PyInstaller build
        // output for the local capture agent - thousands of files churning
        // during a build, none of them part of the web app. Without this,
        // rebuilding the agent triggers a full page reload, which tears down
        // and reopens the live WebSocket and reads as a connect/disconnect
        // loop.
        //
        // `public/downloads/` used to be a deliberate exception here, because
        // Vite treats a public path its watcher never reports as absent and the
        // request then fell through to the SPA fallback - the browser silently
        // downloaded index.html renamed to Inwire-Agent-Setup.exe. Both halves
        // are gone: the installers no longer live under `public/` (they were
        // being packaged into the app), and there is no SPA fallback to fall
        // through to.
        ignored: ['**/local-agent/**', '**/release-artifacts/**'],
      },
    },
  };
});
