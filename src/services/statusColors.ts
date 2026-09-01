import { themePalette } from './themePalettes';
import { contrastRatio, isDarkColor, labToHex, legibleOn, toLabColor } from '../lib/colorMix';

/**
 * The colours that mean "fine", "check this" and "wrong".
 *
 * Three controls carried these hardcoded: the Interfaces button (red with no
 * adapter, amber with none chosen, green once one is), the Start/Stop capture
 * button, and the anomaly panel. All three used raw Tailwind shades -
 * `emerald-500`, `amber-500`, `rose-500`, `rose-700` - so they rendered
 * identically under every theme, so on a warm theme the one control you look
 * at most was lit from a different palette than everything around it.
 *
 * They cannot simply become `--primary` either. A theme's accent is one colour
 * and these are a scale: "capture is running" and "no adapter found" have to be
 * told apart at a glance, from across a desk, without reading the label. That
 * is a categorical distinction, which is what the theme PALETTES are for -
 * every theme already declares its own green, orange and red, drawn from the
 * palette it is named after.
 *
 * So each theme's status colours are derived from its own hues, and written
 * into index.css as real tokens. Static CSS rather than variables injected at
 * runtime, because next-themes settles the theme class before first paint and
 * JS-set variables would not: every solid button would flash the wrong colour,
 * or no colour, on each load.
 *
 * `scripts/themes/status.ts` re-derives all of it and fails if index.css has
 * drifted, so the copy in the stylesheet cannot rot.
 */

export type StatusName = 'success' | 'warning' | 'danger';

export interface StatusColors {
  /** The solid fill: a button, a status dot. */
  success: string;
  warning: string;
  danger: string;
  /** Text and icons sitting ON that fill. Black or white, whichever is legible. */
  successForeground: string;
  warningForeground: string;
  dangerForeground: string;
  /** The same hue as text on a card - a heading, a line of body copy. */
  successMuted: string;
  warningMuted: string;
  dangerMuted: string;
  /**
   * A deeper red, for Stop Capture only.
   *
   * Not a shade for its own sake. Stop sits directly beside the Interfaces
   * button, which is green whenever an adapter is chosen - which is exactly
   * when Stop is on screen. At equal weight the pair read as an alarm rather
   * than as the ordinary way to end a capture, so the red that means "press
   * this" is deliberately calmer than the red that means "something is wrong".
   */
  dangerStrong: string;
  dangerStrongForeground: string;
}

/**
 * How far every status fill is pulled back from its palette hue.
 *
 * The first version used each palette's hues at full strength, and the result
 * was three saturated blocks in the top-left corner of the window - the two
 * biggest buttons in the app plus a panel - shouting at roughly the volume of
 * an emergency, permanently. Chrome is not data: the packet list gets to be
 * vivid because colour there IS the content, while these are controls that have
 * to be identifiable at a glance and then ignored for the rest of the session.
 *
 * Two separate knobs, because "less bright" is two things:
 *
 *   - **Lightness** comes down, which is what actually stops a fill glaring.
 *     Applied uniformly, so it costs nothing in separation: shifting two
 *     colours by the same amount on L leaves the distance between them
 *     unchanged.
 *   - **Chroma** comes down more gently. This is the knob that does cost
 *     separation - scaling a and b scales the distance between hues by the same
 *     factor - so it is the one held back, and the trim is set at the point
 *     where the tightest real pair in any of the palettes still clears the
 *     floor in scripts/themes/status.ts.
 */
const LIGHTNESS_TRIM = 9;
const CHROMA_TRIM = 0.86;

function softenBy(hex: string, lightnessTrim: number): string {
  const [L, a, b] = toLabColor(hex);
  return labToHex([
    Math.max(12, Math.min(96, L - lightnessTrim)),
    a * CHROMA_TRIM,
    b * CHROMA_TRIM,
  ]);
}

/**
 * Darkens a fill until white text on it clears AA.
 *
 * Only lightness moves, so the fill keeps the hue it was derived from - what
 * changes is how deep it sits, which is the only thing white text cares about.
 */
function deepenUntilWhiteWorks(hex: string): string {
  if (contrastRatio(hex, '#ffffff') >= AA) return hex;
  const [L, a, b] = toLabColor(hex);
  for (let step = 2; step <= 100; step += 2) {
    const candidate = labToHex([Math.max(2, L - step), a, b]);
    if (contrastRatio(candidate, '#ffffff') >= AA) return candidate;
  }
  return '#000000';
}

/**
 * One status fill, finished for the ground it will sit on.
 *
 * The two grounds get opposite treatments, and that is deliberate rather than
 * an inconsistency:
 *
 * **Light themes take white text**, so the fill is deepened until white clears
 * AA on it. This is the conventional pairing - a saturated button carrying
 * white - and it is what the app looked like before any of this was derived.
 * Letting the foreground be chosen per fill produced the opposite on the two
 * lighter hues: green and amber came out light enough that near-black won on
 * contrast, so the header ended up with dark text on two buttons and white on
 * the third, which reads as three unrelated controls rather than one row.
 *
 * **Dark themes keep the black-or-white choice.** Their palette hues are
 * already bright by design - Dracula's green is `#50fa7b` - and deepening those
 * far enough to carry white would throw away the exact quality that makes them
 * that theme's green. Dark text on a bright fill is the right pairing there,
 * and it is what those themes' own buttons already do.
 *
 * On a dark theme the trim also backs off a step at a time where the full
 * amount would drop the fill under AA - a colour ending up a shade brighter is
 * a smaller failure than a label nobody can read.
 */
function statusFill(base: string, whiteText: boolean): string {
  if (whiteText) return deepenUntilWhiteWorks(softenBy(base, LIGHTNESS_TRIM));

  for (let trim = LIGHTNESS_TRIM; trim > 0; trim -= 1) {
    const candidate = softenBy(base, trim);
    if (contrastRatio(candidate, foregroundOn(candidate)) >= AA) return candidate;
  }
  return softenBy(base, 0);
}

/**
 * Themes whose status hues are not simply their palette's green/orange/red.
 *
 * Two, both for stated reasons rather than taste:
 *
 * **light** is pinned to the exact Tailwind shades all three controls used
 * before any of this existed. The light theme is the reference the others are
 * matched against, so it starts from the look it already had. These are the
 * hues BEFORE `soften`, so light is toned down along with everything else -
 * what is pinned is which colour each status is, not how loud it is.
 *
 * The other two entries exist because those themes accent on the warm side of
 * the wheel - see the comment on the table itself.
 */
const OVERRIDES: Record<string, Partial<Pick<StatusColors,
  'success' | 'warning' | 'danger' | 'dangerStrong'>>> = {
  light: {
    success: '#10b981', // emerald-500
    warning: '#f59e0b', // amber-500
    danger: '#f43f5e',  // rose-500
    dangerStrong: '#be123c', // rose-700
  },
  // Two themes accent on the warm side of the wheel, and `warning` is derived
  // from `hues.orange` everywhere. Left alone, "check this" would be the same
  // colour as every ordinary button, badge and link in those themes - a status
  // that is indistinguishable from chrome is not a status. The caution
  // convention has two halves and the other one is unclaimed in both.
  dark: {
    warning: '#facc15', // yellow-400, against Graphite's orange accent
  },
  paper: {
    warning: '#8a6d09', // Paper's own yellow, against its rust accent
  },
};

/** How far `dangerStrong` sits from `danger` in lightness, when not pinned. */
const STRONG_LIGHTNESS_STEP = 16;

/** WCAG AA for normal text, the bar the `-muted` variants must clear. */
const AA = 4.5;

/**
 * Black or white, whichever can be read on this fill.
 *
 * Only those two: this is text sitting on a saturated button, where the job is
 * to disappear into legibility rather than to carry any colour of its own.
 * Near-black rather than pure black, matching how the themes write their own
 * foregrounds - #000 on a saturated fill reads as a hole punched in it.
 */
function foregroundOn(fill: string): string {
  return contrastRatio('#ffffff', fill) >= contrastRatio('#0b0f14', fill)
    ? '#ffffff'
    : '#0b0f14';
}

/** A deeper version of a hue, keeping its a/b and moving only lightness. */
function deepen(hex: string, step: number): string {
  const [L, a, b] = toLabColor(hex);
  return labToHex([Math.max(12, Math.min(96, L - step)), a, b]);
}

export function statusColors(resolvedTheme: string | undefined): StatusColors {
  const palette = themePalette(resolvedTheme);
  const override = (resolvedTheme && OVERRIDES[resolvedTheme]) || {};

  // Every light-ground theme carries white on its status buttons; every dark
  // one picks per fill. See statusFill.
  const whiteText = !isDarkColor(palette.surface.background);

  // Finished after the palette is read and after any override, so every theme
  // is toned back by the same amount and none of them can opt out by pinning a
  // hue.
  const success = statusFill(override.success ?? palette.hues.green, whiteText);
  const warning = statusFill(override.warning ?? palette.hues.orange, whiteText);
  const danger = statusFill(override.danger ?? palette.hues.red, whiteText);
  const strongBase = override.dangerStrong
    ? statusFill(override.dangerStrong, whiteText)
    : deepen(danger, STRONG_LIGHTNESS_STEP);
  const dangerStrong = strongBase;

  const card = palette.surface.card;

  return {
    success,
    warning,
    danger,
    dangerStrong,
    successForeground: whiteText ? '#ffffff' : foregroundOn(success),
    warningForeground: whiteText ? '#ffffff' : foregroundOn(warning),
    dangerForeground: whiteText ? '#ffffff' : foregroundOn(danger),
    dangerStrongForeground: whiteText ? '#ffffff' : foregroundOn(dangerStrong),
    successMuted: legibleOn(success, card, AA),
    warningMuted: legibleOn(warning, card, AA),
    dangerMuted: legibleOn(danger, card, AA),
  };
}

/**
 * The hue each status starts from, before `soften`.
 *
 * Exported so the test can assert that the light theme still begins at the
 * shades the app shipped with - once everything is toned down, that is no
 * longer readable off the finished values.
 */
export function statusBaseHues(resolvedTheme: string | undefined) {
  const palette = themePalette(resolvedTheme);
  const override = (resolvedTheme && OVERRIDES[resolvedTheme]) || {};
  return {
    success: override.success ?? palette.hues.green,
    warning: override.warning ?? palette.hues.orange,
    danger: override.danger ?? palette.hues.red,
    dangerStrong: override.dangerStrong ?? null,
  };
}

/** The CSS custom property each field is written to in index.css. */
export const STATUS_TOKENS: Record<keyof StatusColors, string> = {
  success: '--success',
  warning: '--warning',
  danger: '--danger',
  dangerStrong: '--danger-strong',
  successForeground: '--success-foreground',
  warningForeground: '--warning-foreground',
  dangerForeground: '--danger-foreground',
  dangerStrongForeground: '--danger-strong-foreground',
  successMuted: '--success-muted',
  warningMuted: '--warning-muted',
  dangerMuted: '--danger-muted',
};
