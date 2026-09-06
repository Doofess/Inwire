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
 * The request then falls through `server.ts`'s SPA fallback and comes back as
 * `index.html` with a 200 - the browser parses HTML as an ES module, the worker
 * dies before it registers a message handler, and **maplibre reports nothing**.
 * The map loads its style, its sprites and its tile JSON, and then sits with
 * every tile in state `loading` for ever. This is the exact hazard the comment
 * on `public/downloads/**` in `server.ts` describes, arrived at from the other
 * direction.
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
function maplibreWorker(): Plugin {
  const files = ['maplibre-gl-worker.mjs', 'maplibre-gl-shared.mjs'];
  return {
    name: 'inwire:maplibre-worker',
    apply: 'build',
    generateBundle() {
      const dir = path.resolve(__dirname, 'node_modules/maplibre-gl/dist');
      for (const file of files) {
        const from = path.join(dir, file);
        if (!fs.existsSync(from)) {
          // Loud rather than silent: a missing worker is a map that renders no
          // tiles and says nothing about why, which is a day to diagnose.
          this.error(`maplibre-gl worker asset missing: ${from}`);
        }
        this.emitFile({ type: 'asset', fileName: `assets/${file}`, source: fs.readFileSync(from) });
      }
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), maplibreWorker()],
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
        // public/downloads/ is deliberately NOT ignored, despite belonging to
        // the same build chain. Vite keeps a Set of public file paths built at
        // startup and refreshes it from this watcher; a path the watcher never
        // reports is treated as absent, so requests for it fall through to the
        // SPA fallback and the browser silently downloads index.html renamed
        // to Inwire-Agent-Setup.exe - a ~1 KB "corrupted installer" with no
        // error anywhere to explain it. One page reload when a new installer
        // is copied in is the cheaper failure.
        ignored: ['**/local-agent/**'],
      },
    },
  };
});
