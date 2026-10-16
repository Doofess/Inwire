/**
 * Prints the accent-swatch block, ready to paste into index.css between the
 * `accent-css:begin` and `accent-css:end` markers.
 *
 *   npx tsx scripts/themes/accent-css.ts
 *
 * The stylesheet holds the values because they have to be right before first
 * paint; `src/lib/accents.ts` is where they are authored, and
 * `scripts/themes/accents.ts` fails if the pasted block is not exactly this.
 *
 * Blue gets no rule, being the theme blocks' own values. Every other swatch
 * gets the light rule FIRST, selected by `:root` as well as `.light` like the
 * light block itself, and then one per dark theme. They are all 0,2,0, so on a
 * dark <html> - which `:root[...]` also matches - the dark rule wins by coming
 * later. The theme tiles carry the theme's class and the attribute on their own
 * wrapper, so each tile resolves its own rule.
 */
import { ACCENTS, DEFAULT_ACCENT } from '../../src/lib/accents';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';
import { THEME_NAMES } from '../../src/lib/themeOptions';

export function accentCss(): string {
  const rules: string[] = [];
  for (const a of ACCENTS) {
    if (a.id === DEFAULT_ACCENT) continue;
    for (const theme of THEME_NAMES) {
      const attr = `[data-accent-color="${a.id}"]`;
      const selector = theme === 'light' ? `:root${attr},\n.light${attr}` : `.${theme}${attr}`;
      const lines = [
        `  --primary: ${a.primary[theme]};`,
        `  --primary-foreground: ${a.primaryForeground[theme]};`,
        `  --ring: ${a.ring[theme]};`,
        `  --speed-download: ${a.primary[theme]};`,
      ];
      if (a.uploadHue) lines.push(`  --speed-upload: ${PALETTE_BY_THEME[theme].hues[a.uploadHue]};`);
      rules.push(`${selector} {\n${lines.join('\n')}\n}`);
    }
  }
  return rules.join('\n');
}

if (process.argv[1]?.replace(/\\/g, '/').endsWith('scripts/themes/accent-css.ts')) {
  console.log(accentCss());
}
