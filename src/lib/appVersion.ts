/**
 * The product's name and version, for anything the app writes about itself.
 *
 * The version is `package.json`'s, substituted by Vite's `define`, and never a
 * literal here: `scripts/agent/version.ts` holds Inwire to one version number
 * authored in one place, and a second copy in the renderer would be the kind
 * of stamp that goes stale without anything noticing.
 *
 * Under plain `tsx` no `define` runs and the identifier does not exist at all,
 * so `typeof` rather than a read - a read would throw a ReferenceError. `'dev'`
 * says honestly that no build stamped it, which a guessed number would not.
 */
export const APP_NAME = 'Inwire';

export function appVersion(): string {
  return typeof __INWIRE_VERSION__ === 'string' && __INWIRE_VERSION__ ? __INWIRE_VERSION__ : 'dev';
}
