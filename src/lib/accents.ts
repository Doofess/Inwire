import type { Hue } from '../services/themePalettes';

/**
 * The accent swatches (ADR 0056).
 *
 * Seven presets rather than a free colour picker, because every swatch has to
 * be checked in every theme: an accent is the selected row's text, the rail's
 * active fill, the focus ring and the download trace, and a colour nobody
 * checked fails one of those on one theme without saying so.
 * `scripts/themes/registry.ts` loops this table against all four.
 *
 * The setting is `accentColor` and lands on <html> as `data-accent-color`. Not
 * "accent": shadcn's `--accent` is already the hover fill, and an accent rule
 * never touches it. A swatch overrides `--primary`, `--primary-foreground`,
 * `--ring` and `--speed-download`, and nothing else - except Violet, which
 * would be upload's own purple, so it moves upload to the theme's orange.
 *
 * Blue is the theme blocks' own values, so it needs no rule and the stylesheet
 * is right before this module has run. The rules are printed by
 * `scripts/themes/accent-css.ts` and pasted into index.css, and
 * `scripts/themes/accents.ts` fails if the two copies drift.
 *
 * The brand mark does not follow the accent. It is identity, and one ramp
 * draws the icon, the PDF and the workbook (`brandMark.ts`).
 */

export type AccentId = 'blue' | 'teal' | 'green' | 'violet' | 'rose' | 'amber' | 'graphite';

type PerTheme = Readonly<Record<string, string>>;

export interface Accent {
  id: AccentId;
  label: string;
  primary: PerTheme;
  primaryForeground: PerTheme;
  ring: PerTheme;
  /** Set when the accent would be upload's own colour, so upload moves. */
  uploadHue?: Hue;
}

/** White text on the light theme's fill, black on the three dark ones. */
const FOREGROUND: PerTheme = { light: '#ffffff', dark: '#000000', dim: '#000000', contrast: '#000000' };

function swatch(id: AccentId, label: string, primary: PerTheme, extra: Partial<Accent> = {}): Accent {
  return { id, label, primary, primaryForeground: FOREGROUND, ring: primary, ...extra };
}

export const ACCENTS: readonly Accent[] = [
  swatch('blue', 'Blue',
    { light: '#0b6bcb', dark: '#38bdf8', dim: '#4a9ee8', contrast: '#4db2ff' },
    // Today's rings, which are a step lighter than the fill on the dark themes.
    { ring: { light: '#0b6bcb', dark: '#7dd3fc', dim: '#7ab8f0', contrast: '#8ccbff' } }),
  swatch('teal', 'Teal',
    { light: '#0f766e', dark: '#2dd4bf', dim: '#3fb8a8', contrast: '#5eead4' }),
  swatch('green', 'Green',
    { light: '#16763a', dark: '#4ade80', dim: '#57b06f', contrast: '#86efac' }),
  swatch('violet', 'Violet',
    { light: '#6d28d9', dark: '#a78bfa', dim: '#9b87e8', contrast: '#c4b5fd' },
    { uploadHue: 'orange' }),
  swatch('rose', 'Rose',
    { light: '#be185d', dark: '#f472b6', dim: '#e07aa8', contrast: '#f9a8d4' }),
  swatch('amber', 'Amber',
    { light: '#a54d07', dark: '#fbbf24', dim: '#e0a640', contrast: '#fcd34d' }),
  swatch('graphite', 'Graphite',
    { light: '#475569', dark: '#cbd5e1', dim: '#aab4c0', contrast: '#e2e8f0' }),
];

export const DEFAULT_ACCENT: AccentId = 'blue';

const IDS = new Set<string>(ACCENTS.map((a) => a.id));

/** A stored value, or null when it is not one of the swatches. */
export function normalizeAccent(raw: unknown): AccentId | null {
  return typeof raw === 'string' && IDS.has(raw) ? (raw as AccentId) : null;
}
