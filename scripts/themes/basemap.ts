/**
 * Assertion tests for the basemap tint.
 *
 *   npx tsx scripts/themes/basemap.ts
 *
 * This exists because of a bug that shipped: water was tinted from `--muted`
 * over `--background`, which are `#f1f5f9` and `#f4f7f9` on the Light theme -
 * three RGB steps apart. On dark themes the same expression gives a real
 * difference, so it looked correct in development and drew Light as a single
 * flat sheet with no coastline at all.
 *
 * The lesson is worth stating rather than just fixing: **chrome tokens describe
 * a surface hierarchy, and that hierarchy is deliberately subtle on light
 * themes.** Land against sea is not a hierarchy, it is a categorical
 * distinction, and those come from the theme palettes. This file is the guard
 * that the distinction stays visible in every theme rather than in the ones
 * that happen to have a dark ground.
 */
import { waterColorFor } from '../../src/components/analytics/mapTheme';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';
import { THEME_OPTIONS } from '../../src/lib/themeOptions';
import { contrastRatio } from '../../src/lib/colorMix';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}

/** Matches MIN_WATER_CONTRAST in mapTheme.ts. */
const MIN_WATER_CONTRAST = 1.35;

for (const { value: theme } of THEME_OPTIONS) {
  const palette = PALETTE_BY_THEME[theme];
  if (!palette) {
    check(`${theme}: has a palette`, false, true);
    continue;
  }
  const land = palette.surface.background;
  const water = waterColorFor(land, palette.hues.blue);
  const ratio = contrastRatio(water, land);

  checkTrue(
    `${theme}: the coastline is visible - water ${water} vs land ${land} (${ratio.toFixed(2)}:1)`,
    ratio >= MIN_WATER_CONTRAST,
  );
}

// The exact case that shipped broken, pinned so it cannot come back: two
// near-identical near-whites must NOT be accepted as land and sea.
{
  const ratio = contrastRatio('#f1f5f9', '#f4f7f9');
  checkTrue(
    `the original Light water/land pair is correctly rejected (${ratio.toFixed(3)}:1)`,
    ratio < MIN_WATER_CONTRAST,
  );
}

// And the fix for that same case clears the bar comfortably.
{
  const water = waterColorFor('#f4f7f9', PALETTE_BY_THEME.light.hues.blue);
  const ratio = contrastRatio(water, '#f4f7f9');
  checkTrue(`Light's water is now clearly water (${water}, ${ratio.toFixed(2)}:1)`,
    ratio >= MIN_WATER_CONTRAST);
}

// Water must stay a backdrop as well as being visible. Anything approaching
// text contrast against the land would fight the connection lines drawn over
// it, which are the actual content of the panel.
for (const { value: theme } of THEME_OPTIONS) {
  const palette = PALETTE_BY_THEME[theme];
  if (!palette) continue;
  const land = palette.surface.background;
  const ratio = contrastRatio(waterColorFor(land, palette.hues.blue), land);
  checkTrue(`${theme}: water stays a backdrop, not a foreground (${ratio.toFixed(2)}:1)`,
    ratio <= 4.5);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All basemap checks passed.');
