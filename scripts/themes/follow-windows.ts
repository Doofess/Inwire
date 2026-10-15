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

if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All follow-Windows checks passed.');
