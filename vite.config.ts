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
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâfile watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {
        // local-agent/ holds the Python source + PyInstaller build output for
        // the local capture agent, and public/downloads/ holds its compiled
        // installers - neither is part of the web app itself. Without this,
        // rebuilding the agent (or copying a new installer into downloads/)
        // triggers a full page reload, which tears down and reopens the
        // live WebSocket to the agent and reads as a connect/disconnect loop.
        ignored: ['**/local-agent/**', '**/public/downloads/**'],
      },
    },
  };
});
