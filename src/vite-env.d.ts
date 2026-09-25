/// <reference types="vite/client" />

/**
 * `package.json`'s version, substituted by Vite's `define` at build time.
 *
 * Declared rather than imported because it is not a module: it is a bare
 * identifier that exists only in a Vite build. Read it through
 * `src/lib/appVersion.ts`, which is what makes it safe under plain `tsx`.
 */
declare const __INWIRE_VERSION__: string;
