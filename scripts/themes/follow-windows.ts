/**
 * "System" follows Windows, including Windows' own High Contrast (ADR 0056).
 *
 *   npx tsx scripts/themes/follow-windows.ts
 *
 * The rule is a pure function so it can be held here; the hook that feeds it
 * the media queries is not reachable from `tsx`, so its source is read for the
 * two queries the rule depends on.
 */
import { readFileSync } from 'node:fs';
import { systemThemeFor } from '../../src/lib/themeOptions';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

for (const prefersDark of [false, true]) {
  for (const prefersMoreContrast of [false, true]) {
    for (const forcedColors of [false, true]) {
      const got = systemThemeFor({ prefersDark, prefersMoreContrast, forcedColors });
      const want = prefersMoreContrast || forcedColors ? 'contrast' : prefersDark ? 'dark' : 'light';
      check(`dark=${prefersDark} more-contrast=${prefersMoreContrast} forced-colors=${forcedColors} -> ${want}`,
        got === want, `got ${got}`);
    }
  }
}

const hook = readFileSync('src/lib/useSystemTheme.ts', 'utf8');
check('the hook asks Windows for more contrast', hook.includes("'(prefers-contrast: more)'"));
check('...and for forced colours, which is what Windows High Contrast sets', hook.includes("'(forced-colors: active)'"));
check('...and chooses through systemThemeFor, not a second copy of the rule', /systemThemeFor\(/.test(hook));

// Windows' contrast themes turn on forced colours, and Chromium then repaints
// the page in the system's colours - while the canvases, the map and the
// window ground keep reading .contrast's own. Under a light contrast theme
// that was a light page over a black ground. The theme Following Windows lands
// on is the audited one, so it opts out (ADR 0056).
const css = readFileSync('src/index.css', 'utf8');
check('High Contrast opts out of forced colours, so its own palette is what shows',
  /\n\.contrast \{[^}]*forced-color-adjust:\s*none;/.test(css));

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All follow-Windows checks passed.');
