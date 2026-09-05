import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
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
