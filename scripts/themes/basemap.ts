/**
 * Assertion tests for the basemap palette.
 *
 *   npx tsx scripts/themes/basemap.ts
 *
 * This file used to guard a bug that shipped: water was tinted from `--muted`
 * over `--background`, which are `#f1f5f9` and `#f4f7f9` on the Light theme -
 * three RGB steps apart. On dark themes the same expression gave a real
 * difference, so it looked correct in development and drew Light as a single
 * flat sheet with no coastline at all.
 *
 * The DEFAULT skin's colours are no longer derived from the theme at all, which
 * retires that whole class of bug for the map most people see rather than
 * guarding against it: there is no expression, no ground to be too close to,
 * and no fourth theme to be the one that breaks. Most of this file checks that
 * the fixed palette is actually legible - a smaller question, but not an empty
 * one, because a hand-picked palette is exactly the kind of thing that gets
 * nudged one hex digit at a time until the coastline stops reading.
 *
 * The theme-synced skin is back as a CHOICE, though, so the original lesson is
 * not merely historical and section 8 enforces it directly: **chrome tokens
 * describe a surface hierarchy, and that hierarchy is deliberately subtle on
 * light themes.** Land against sea is not a hierarchy, it is a categorical
 * distinction. `waterColorFor` is what rebuilds it out of `--background`
 * safely - by searching for a tint that clears a contrast floor rather than
 * assuming one constant serves a near-white ground and a near-black one - and
 * the whole reason the bug shipped is that nothing could check it without a
 * browser. Everything the muted skin needs comes from `themePalettes`, so now
 * something can.
 */
import {
  BASEMAP_PALETTE,
  LAND_LIFT,
  LIGHT_FROM_UPPER_LEFT,
  basemapTokensFor,
  skyFor,
  spaceColorFor,
  wallTonesFor,
  waterColorFor,
} from '../../src/components/analytics/mapTheme';
import { PALETTE_BY_THEME } from '../../src/services/themePalettes';
import { THEME_OPTIONS, isDarkTheme } from '../../src/lib/themeOptions';
import { contrastRatio, isDarkColor, toRgb } from '../../src/lib/colorMix';
import { AMBIENT_INTENSITY, gamutSafe } from '../../src/components/analytics/pinLayer';
import fs from 'node:fs';
import path from 'node:path';

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

const { land, sea, wallUpper, wallLower, boundary, label, labelHalo } = BASEMAP_PALETTE;

// --- 1. Land and sea are unmistakably different ------------------------------
//
// The bar the old theme-derived water had to clear, kept at the same number so
// the fixed palette is held to the standard the derived one was.
{
  const ratio = contrastRatio(land, sea);
  checkTrue(`land ${land} and sea ${sea} are clearly different (${ratio.toFixed(2)}:1)`, ratio >= 2.0);
  // Still a backdrop. Anything approaching text contrast would fight the
  // connection arcs drawn over it, which are the content of the panel.
  checkTrue(`land and sea stay a backdrop (${ratio.toFixed(2)}:1)`, ratio <= 4.5);
}

// --- 2. The wall is a face turning away from the light -----------------------
//
// Land, then the upper wall, then the lower wall at the waterline: strictly
// darker at every step. Any pair swapped and the slab lights from underneath,
// which still looks deliberate and is the reason this is pinned rather than
// left to the eye.
{
  const lLand = relativeLuminance(land);
  const lUpper = relativeLuminance(wallUpper);
  const lLower = relativeLuminance(wallLower);
  checkTrue('the upper wall is darker than the land it drops from', lUpper < lLand);
  checkTrue('the lower wall is darker than the upper', lLower < lUpper);

  // Each step perceptible, and the whole drop unmistakable. Two separate
  // floors, because a wall can pass the total and still have one of its tones
  // sitting invisibly on top of the other.
  const topStep = contrastRatio(wallUpper, land);
  const faceStep = contrastRatio(wallLower, wallUpper);
  const wholeDrop = contrastRatio(wallLower, land);
  checkTrue(`the wall separates from the land (${topStep.toFixed(2)}:1)`, topStep >= 1.25);
  checkTrue(`the wall's two tones separate (${faceStep.toFixed(2)}:1)`, faceStep >= 1.25);
  checkTrue(`the whole drop reads as a drop (${wholeDrop.toFixed(2)}:1)`, wholeDrop >= 1.6);

  // The wall meets the sea along every lit coast, so the two must not be
  // confusable - but the thing keeping them apart is HUE, not value. The sea is
  // the darkest thing on the map and the wall is the land in shadow, so their
  // luminances necessarily converge; asserting a contrast ratio there would
  // either fail on a perfectly legible palette or force the wall back up into
  // the land. What actually has to hold is that the wall stays in the land's
  // hue family and nowhere near the sea's.
  const dHue = (a: string, b: string) => {
    const d = Math.abs(hue(a) - hue(b));
    return Math.min(d, 360 - d);
  };
  checkTrue(`the wall keeps the land's hue (${dHue(wallLower, land).toFixed(0)} deg apart)`,
    dHue(wallLower, land) <= 15);
  checkTrue(`the wall is nowhere near the sea's hue (${dHue(wallLower, sea).toFixed(0)} deg apart)`,
    dHue(wallLower, sea) >= 90);
  // Note what is deliberately NOT asserted: that the wall is lighter than the
  // sea. It is not, and it should not be - a cliff face in its own shadow is
  // darker than open water, which is exactly what the reference globe shows.
  // An earlier version of this file required it and the effect it forced was a
  // wall too pale to see.
  checkTrue('the wall is darker than the land, which is the only ordering that matters',
    lLower < lUpper && lUpper < lLand);
}

// --- 3. The slab is lit from one side, and it is the same side every time ----
//
// This is the whole difference between a slab and an outline. Every
// displacement has to point the same way; one sign flipped and that landmass
// grows a wall on the lit side while its neighbours keep theirs on the shaded
// one, which does not read as a mistake, it reads as noise.
{
  /**
   * Every [x, y] pair out of `['interpolate', ..., z0, v0, z1, v1, ...]`.
   *
   * Each `v` is `['literal', [x, y]]`, and unwrapping it here rather than
   * accepting either shape is deliberate: a bare array is not a valid
   * interpolate output, and MapLibre declines the layer over an `error` event
   * instead of throwing - so the wall silently does not exist. This asserts the
   * wrapper is present as much as it reads the numbers through it.
   */
  const offsets = (paint: unknown): number[][] => {
    const expr = paint as unknown[];
    return expr.slice(4).filter((_, i) => i % 2 === 0).map(stop => {
      const literal = stop as unknown[];
      if (literal[0] !== 'literal') throw new Error(`stop is not wrapped in 'literal': ${JSON.stringify(stop)}`);
      return literal[1] as number[];
    });
  };
  const all = LAND_LIFT.flatMap(step => offsets(step.translate));

  checkTrue('there is a wall to draw', all.length > 0);
  checkTrue('every displacement is up and to the left',
    LIGHT_FROM_UPPER_LEFT && all.every(([x, y]) => x < 0 && y < 0));
  // Diagonal, not axis-aligned: a wall on only one axis reads as a shadow
  // dropped straight down rather than as a face.
  checkTrue('every displacement is diagonal', all.every(([x, y]) => x === y));

  // The upper wall reaches further than the lower one at every zoom. Reversed,
  // the darker tone would cover the lighter one entirely and the face would
  // flatten back to a single band - an outline again.
  const upper = offsets(LAND_LIFT[0].translate);
  const lower = offsets(LAND_LIFT[1].translate);
  checkTrue('the two steps have matching zoom stops', upper.length === lower.length);
  checkTrue('the upper wall reaches further inland at every zoom',
    upper.every(([x], i) => Math.abs(x) > Math.abs(lower[i][0])));
  // Ordered longest first, because each is inserted directly under the water
  // fill - so the last one added ends up on top. Reverse the array and the
  // darkest tone hides behind the lightest.
  checkTrue('LAND_LIFT is ordered longest displacement first',
    relativeLuminance(LAND_LIFT[0].color) > relativeLuminance(LAND_LIFT[1].color));
}

// --- 4. Labels read on both grounds ------------------------------------------
//
// Place names sit on land, but sea names and the odd coastal label sit on
// water, and a label is the one thing on this map that must not recede.
{
  const onLand = contrastRatio(label, land);
  const onSea = contrastRatio(label, sea);
  const onHalo = contrastRatio(label, labelHalo);
  checkTrue(`labels read on land (${onLand.toFixed(2)}:1)`, onLand >= 4.5);
  checkTrue(`labels read on the halo they carry (${onHalo.toFixed(2)}:1)`, onHalo >= 4.5);
  // The halo is what carries them over water, so the halo has to be visible
  // there even where the text alone would not be.
  checkTrue(`the halo separates a label from the sea (${contrastRatio(labelHalo, sea).toFixed(2)}:1)`,
    contrastRatio(labelHalo, sea) >= 2.5);
  checkTrue(`labels are legible over water (${onSea.toFixed(2)}:1)`, onSea >= 2.0);
}

// --- 5. Borders are context, not content -------------------------------------
{
  const ratio = contrastRatio(boundary, land);
  checkTrue(`country borders are visible on land (${ratio.toFixed(2)}:1)`, ratio >= 1.15);
  checkTrue(`country borders do not shout (${ratio.toFixed(2)}:1)`, ratio <= 2.5);
}

// --- 6. Two skies, and they are actually two ---------------------------------
//
// The only part of the map the app's theme still touches.
{
  const day = skyFor(false);
  const night = skyFor(true);
  checkTrue('the day sky is light', !isDarkColor(String(day['sky-color'])));
  checkTrue('the night sky is dark', isDarkColor(String(night['sky-color'])));
  checkTrue('day and night are not the same sky',
    JSON.stringify(day) !== JSON.stringify(night));
  // `fog-color` is what carries the sky onto the globe's limb. If it did not
  // follow, a daylit sky would sit behind a night-lit Earth.
  checkTrue('the fog follows the sky into day',
    relativeLuminance(String(day['fog-color'])) > relativeLuminance(String(night['fog-color'])));

  // The backdrop is a separate mechanism - a CSS background on the container,
  // because MapLibre leaves everything past the atmosphere transparent - and it
  // has to agree with the sky it continues, or the limb reads as a ring drawn
  // around the planet rather than as the edge of an atmosphere.
  checkTrue('the daytime backdrop is light', !isDarkColor(spaceColorFor(false)));
  checkTrue('the night backdrop is dark', isDarkColor(spaceColorFor(true)));
  checkTrue('the backdrop sits on the same side of the sky it continues, by day',
    relativeLuminance(spaceColorFor(false)) > relativeLuminance(String(day['sky-color'])) - 0.3);
  checkTrue('and by night',
    Math.abs(relativeLuminance(spaceColorFor(true)) - relativeLuminance(String(night['sky-color']))) < 0.05);
}

// --- 7. The palette is not derived from anything -----------------------------
//
// The point of the whole change. A hex literal cannot drift with a theme.
{
  const values = Object.values(BASEMAP_PALETTE);
  checkTrue('every basemap colour is a plain hex literal',
    values.every(v => /^#[0-9a-f]{6}$/i.test(v)));
  checkTrue('no two roles share a colour', new Set(values).size === values.length);
}

// --- 8. The theme-synced skin, on all four themes ----------------------------
//
// The section the original bug needed and did not have. Every colour in this
// skin is an expression over the theme's tokens, so it can be - and once was -
// correct on three themes and a single flat sheet on the fourth.
{
  const THEMES = THEME_OPTIONS.map((t) => t.value);

  // The muted skin reads `--muted-foreground` out of the palette's `neutral`
  // rather than off the document, which is what lets this file check it at all.
  // Asserted against index.css so the two copies cannot drift apart the way the
  // palette surfaces could before packet-themes.ts started comparing those.
  const css = fs.readFileSync(path.join(process.cwd(), 'src/index.css'), 'utf8');
  const cssToken = (theme: string, token: string): string | undefined => {
    const selector = theme === 'light' ? ':root' : `.${theme}`;
    const start = css.indexOf(`${selector} {`);
    if (start === -1) return undefined;
    const body = css.slice(start, css.indexOf('\n}', start));
    return new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(body)?.[1];
  };
  const neutralDrift = THEMES.filter(
    (t) => cssToken(t, '--muted-foreground')?.toLowerCase() !== PALETTE_BY_THEME[t]?.hues.neutral.toLowerCase(),
  );
  check("the palette's neutral is each theme's --muted-foreground", neutralDrift, []);

  for (const theme of THEMES) {
    // The accent is the one token with no palette counterpart, so it is passed
    // in at runtime. Read from index.css here for the same reason.
    const primary = cssToken(theme, '--primary');
    checkTrue(`${theme}: has a --primary to paint the coastline with`, Boolean(primary));
    const tokens = basemapTokensFor(theme, primary ?? '#000000');
    const land = tokens.background;
    const sea = waterColorFor(land, tokens.mutedForeground);

    // The bug itself, in one line. `#f1f5f9` over `#f4f7f9` cleared no floor at
    // all, and Day rendered with no coastline on it.
    const ratio = contrastRatio(sea, land);
    checkTrue(`${theme}: muted sea and land are clearly different (${ratio.toFixed(2)}:1)`,
      ratio >= 2.0);
    // Same ceiling the fixed palette is held to. A basemap that reaches text
    // contrast is competing with the arcs drawn over it, which are the content.
    checkTrue(`${theme}: the muted basemap stays a backdrop (${ratio.toFixed(2)}:1)`,
      ratio <= 4.5);

    // The coastline is the one saturated stroke, and it has to be visible
    // against BOTH halves of the neutral ramp it separates.
    checkTrue(`${theme}: the coastline reads against the sea (${contrastRatio(tokens.accent, sea).toFixed(2)}:1)`,
      contrastRatio(tokens.accent, sea) >= 1.35);
    checkTrue(`${theme}: the coastline reads against the land (${contrastRatio(tokens.accent, land).toFixed(2)}:1)`,
      contrastRatio(tokens.accent, land) >= 1.35);

    // Labels take `--muted-foreground` itself, haloed in the ground. That is
    // the theme's own body-adjacent text on the theme's own background, so it
    // is legible by construction - but "by construction" is what the water was
    // supposed to be too.
    checkTrue(`${theme}: muted labels read on land (${contrastRatio(tokens.mutedForeground, land).toFixed(2)}:1)`,
      contrastRatio(tokens.mutedForeground, land) >= 4.5);

    // The wall, which cannot use the colourful skin's always-darker rule - see
    // wallTonesFor. What has to hold instead is that the two steps move
    // monotonically from the land toward the sea, and that each step is
    // perceptible rather than sitting invisibly on the one before it.
    const { upper, lower } = wallTonesFor('muted', tokens);
    const towardSea = (c: string) => contrastRatio(c, land);
    checkTrue(`${theme}: the muted wall steps away from the land (${towardSea(upper).toFixed(2)}:1)`,
      towardSea(upper) >= 1.1);
    checkTrue(`${theme}: the muted wall's second step goes further (${towardSea(lower).toFixed(2)} > ${towardSea(upper).toFixed(2)})`,
      towardSea(lower) > towardSea(upper));
    checkTrue(`${theme}: the muted wall's two tones separate (${contrastRatio(lower, upper).toFixed(2)}:1)`,
      contrastRatio(lower, upper) >= 1.1);
    // And it must not reach the water, or the slab has no top face left.
    checkTrue(`${theme}: the muted wall stays short of the sea (${contrastRatio(lower, sea).toFixed(2)}:1)`,
      contrastRatio(lower, sea) >= 1.1);
  }

  // The two skins have to actually be two. A toggle whose ends look alike is
  // worse than no toggle, and the muted skin is only interesting where it
  // differs from the fixed one.
  const colorfulWall = wallTonesFor('colorful', basemapTokensFor('dark', '#f97316'));
  check('the colourful skin ignores the tokens it is handed',
    colorfulWall, { upper: BASEMAP_PALETTE.wallUpper, lower: BASEMAP_PALETTE.wallLower });
  const differs = THEMES.filter((t) => {
    const tokens = basemapTokensFor(t, cssToken(t, '--primary') ?? '#000000');
    return waterColorFor(tokens.background, tokens.mutedForeground) === BASEMAP_PALETTE.sea;
  });
  check('no theme accidentally reproduces the fixed sea', differs, []);

  // --- Pin heads ------------------------------------------------------------
  //
  // The heads are a Lambert material, so their output is roughly
  // `base x incident`, and the ambient light alone is 1.6 before either
  // directional reaches them. An accent whose peak channel survives that
  // multiplication intact is the whole bug: every part of the sphere clips,
  // including the side facing away from both lights, and a pin with no shaded
  // side reads as a glare rather than as an object.
  //
  // This regresses silently - someone raises a light or picks a brighter
  // accent and nothing fails - so it is checked rather than trusted.
  for (const theme of THEMES) {
    if (!isDarkTheme(theme)) continue;
    const accent = cssToken(theme, '--primary') ?? '#000000';
    const green = PALETTE_BY_THEME[theme]?.hues.green ?? '#000000';
    for (const [role, base] of [['host', accent], ['home', green]] as [string, string][]) {
      const ambient = toRgb(gamutSafe(base)).map((c) => c * AMBIENT_INTENSITY);
      checkTrue(
        `${theme}: the ${role} pin keeps a shaded side under ambient alone `
        + `(peak ${Math.round(Math.max(...ambient))}/255)`,
        Math.max(...ambient) <= 255);
    }
  }
}

/** HSL hue in degrees, for the "is this green or is it blue" checks. */
function hue(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const r = ((n >> 16) & 255) / 255, g = ((n >> 8) & 255) / 255, b = (n & 255) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b), c = max - min;
  if (c === 0) return 0;
  const h = max === r ? ((g - b) / c) % 6 : max === g ? (b - r) / c + 2 : (r - g) / c + 4;
  return (h * 60 + 360) % 360;
}

/** WCAG relative luminance, for the "is this darker than that" checks. */
function relativeLuminance(hex: string): number {
  const channel = (value: number) => {
    const c = value / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const n = parseInt(hex.replace('#', ''), 16);
  return 0.2126 * channel((n >> 16) & 255)
    + 0.7152 * channel((n >> 8) & 255)
    + 0.0722 * channel(n & 255);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All basemap checks passed.');
process.exit(0);
