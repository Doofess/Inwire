import type React from 'react';
import { contrastRatio } from './colorMix';

/**
 * Retints a whole surface to one packet's colour.
 *
 * The packet inspection pane, the hex pane and the detail window all describe a
 * frame they did not draw, and every accent in them - the tree's layer
 * headings, the selected byte, the layer rail's bars, the protocol chip, the
 * cross-reference links, the focus ring - was the app's own `--primary`. That
 * said the same thing on every frame, which is to say it said nothing.
 *
 * This overrides `--primary` for one subtree rather than restyling the elements
 * inside it. Two reasons, and the second is the important one:
 *
 *   - Every `bg-primary`, `text-primary`, `border-primary`, `ring-primary` and
 *     every opacity variant (`bg-primary/15`, which compiles to a `color-mix`
 *     over the same variable) reads one custom property. Setting it on an
 *     ancestor reaches all 24 of them at once.
 *   - Anything accent-coloured added to these panes later is tinted too, with
 *     no new wiring. The alternative - threading a colour prop into eight
 *     components and hand-converting each utility to an inline style - would
 *     have to be redone by whoever adds the next one, and would silently not be.
 *
 * `--primary-foreground` moves with it, because it is not decoration: the hex
 * dump paints the selected byte `bg-primary text-primary-foreground`, and a
 * theme's fixed white-on-accent stops being legible the moment the accent
 * becomes a pale yellow.
 */
export function packetAccentStyle(
  accent: string | null | undefined,
): React.CSSProperties | undefined {
  if (!accent) return undefined;
  const foreground = readableTextOn(accent);
  return {
    // `--color-primary` is the one the utilities actually read, and it is the
    // one that has to be set here. Overriding only `--primary` looks right and
    // does nothing: index.css declares `--color-primary: var(--primary)` inside
    // `@theme`, i.e. on `:root`, and a custom property is substituted at the
    // element it is DECLARED on. So `--color-primary` resolves to the theme's
    // blue once at the root and descendants inherit that literal - a
    // `--primary` set further down is never consulted again. Verified in the
    // running app: the subtree reported `--primary: #db2777` and
    // `--color-primary: #0284c7` at the same time.
    '--color-primary': accent,
    '--color-primary-foreground': foreground,
    // Set as well, for the handful of places that read the raw token directly
    // rather than through a Tailwind utility.
    '--primary': accent,
    '--primary-foreground': foreground,
  } as React.CSSProperties;
}

/**
 * Black or white, whichever can actually be read on this colour.
 *
 * Deliberately only those two. This is for text sitting ON the accent - a
 * selected byte, a filled chip - where the job is to disappear into legibility
 * rather than to carry any colour of its own; a third option would be a
 * second hue competing with the one the surface is already tinted to.
 *
 * Near-black rather than #000, matching how the themes write their own
 * foregrounds: pure black against a saturated fill reads as a hole punched in
 * it.
 */
export function readableTextOn(background: string): string {
  return contrastRatio('#ffffff', background) >= contrastRatio('#0b0f14', background)
    ? '#ffffff'
    : '#0b0f14';
}
