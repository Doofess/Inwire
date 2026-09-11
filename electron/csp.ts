/**
 * The Content-Security-Policy, and the list of endpoints it has to cover.
 *
 * The app has never had a CSP - it was served by a four-line Express server
 * with no headers at all. It gets one here because a desktop app that parses
 * hostile bytes and renders strings taken off the wire should not also be a
 * page that can be talked into loading code.
 *
 * ## Why the endpoint list is exported separately
 *
 * `scripts/electron/csp.ts` greps `src/` for every `fetch(`, `new WebSocket(`
 * and style-URL literal and checks each one appears in `OUTBOUND_HOSTS`. That
 * is the part worth the effort: a CSP is a list that goes stale silently, and
 * the failure mode is a feature that quietly stops working in the packaged
 * build only - which is the build nobody runs while developing.
 *
 * ## Two policies, not one
 *
 * `@vitejs/plugin-react` injects an **inline** react-refresh preamble into the
 * dev HTML, so a production `script-src 'self'` kills `npm run dev` outright.
 * The dev policy is therefore separate and looser, and only the production one
 * is asserted to be strict.
 */

/**
 * Every host the renderer talks to, with what needs it.
 *
 * All four are behind consent switches or are the map's own tiles; none is
 * contacted on a cold start with default settings.
 */
export const OUTBOUND_HOSTS = {
  /** `services/geoIpService.ts` - endpoint locations, behind `nameResolution.geoIp`. */
  geo: 'https://get.geojs.io',
  /** `services/geoIpService.ts` - reverse DNS, behind `nameResolution.reverseDns`. */
  doh: 'https://cloudflare-dns.com',
  /** `components/network/PublicIdentity.tsx` - the public-identity section. */
  publicIdentity: 'https://ipapi.co',
  /** `components/analytics/GeoMap.tsx` - the map style and its vector tiles. */
  tiles: 'https://tiles.openfreemap.org',
} as const;

// Deliberately absent: unpkg. maplibre's right-to-left text shaper used to be
// fetched from there at runtime; `vite.config.ts` now ships it, so the CSP does
// not have to allow a CDN to serve this app executable code.

// Also deliberately absent: `ws://localhost:8999`. The agent was reached over
// a WebSocket and the policy had to allow it; it is reached over a named pipe
// now, which no policy governs because no page can open one. A `connect-src`
// entry for a port nothing dials is a hole with no user.

function join(parts: readonly string[]): string {
  return parts.join('; ') + ';';
}

/**
 * The packaged policy.
 *
 * `'unsafe-inline'` survives in two places and neither is negotiable today:
 * `next-themes` renders a pre-hydration inline script (which is the mechanism
 * that stops a flash of the wrong theme), and Tailwind v4 injects styles at
 * runtime. `'unsafe-eval'` is **not** here, which is the line worth asserting -
 * pdfjs will ask for it and is told no (`isEvalSupported: false`).
 */
export function productionCsp(): string {
  const hosts = Object.values(OUTBOUND_HOSTS);
  return join([
    "default-src 'none'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${OUTBOUND_HOSTS.tiles}`,
    "font-src 'self' data:",
    // `blob:` is maplibre's own worker construction, which it does from a blob
    // when it cannot resolve a URL. `'self'` covers the two module workers.
    "worker-src 'self' blob:",
    `connect-src 'self' data: blob: ${hosts.join(' ')}`,
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ]);
}

/**
 * The development policy: the production one plus what Vite needs.
 *
 * `'unsafe-eval'` for the dev bundle's module runtime, `ws://localhost:3000`
 * for HMR, and the dev server itself as a source.
 */
export function developmentCsp(devOrigin: string): string {
  const hosts = Object.values(OUTBOUND_HOSTS);
  const ws = devOrigin.replace(/^http/, 'ws');
  return join([
    "default-src 'none'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' ${devOrigin}`,
    `style-src 'self' 'unsafe-inline' ${devOrigin}`,
    `img-src 'self' data: blob: ${devOrigin} ${OUTBOUND_HOSTS.tiles}`,
    `font-src 'self' data: ${devOrigin}`,
    "worker-src 'self' blob:",
    `connect-src 'self' data: blob: ${devOrigin} ${ws} ${hosts.join(' ')}`,
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ]);
}
