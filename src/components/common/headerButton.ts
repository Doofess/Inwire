/**
 * The one button style the header bar uses, in a module of its own.
 *
 * It lives here rather than in `Header.tsx` because the menu trigger is inside
 * `AppMenu`, which `Header` imports - so a constant exported from `Header`
 * would be a cycle. Three controls in a strip 64px tall, drawn by two
 * components, is exactly the arrangement in which two treatments quietly drift
 * apart, and the menu button had already: a different fill token, a border the
 * others did not have, a wider radius, no shadow, no press response, and four
 * pixels more height than the two buttons beside it.
 *
 * They used to be three colours - amber or green or red for the adapter, green
 * for Start, red for Stop, the accent for Clear Cache - which is four hues
 * competing for attention, none of them meaning anything a label does not
 * already say.
 *
 * They SINK INTO the bar rather than sitting on it: the fill is
 * `--chrome-sunken`, the bar's own colour deepened, with the bar's foreground
 * carrying the label. On the two dark themes that is `--secondary` with the
 * accent on top, which is what they already did; the light themes used to put a
 * pure white slab on a saturated bar instead, and white on full-strength accent
 * was the loudest thing in the window - louder than the packet list it was
 * supposed to be chrome around.
 *
 * The accent is deliberately NOT the fill. On both light themes `--primary` and
 * `--chrome` are the same value, so an accent-filled button would be the bar
 * colour on the bar colour - a shadow and nothing else.
 *
 * The adapter button's STATE is carried by its label and its tooltip alone -
 * "Install Drivers", "No interfaces detected" - which is where the detail
 * always was; the colour was a second, coarser copy of it.
 */
const headerButtonBase =
  // The hover lightens by letting the bar through, rather than by naming a
  // second colour - one fewer value per theme to keep in step.
  'bg-chrome-sunken text-chrome-foreground hover:bg-chrome-sunken/80 ' +
  // The dark themes keep the accent on the label. Their fill is already
  // `--chrome-sunken` (it resolves to `--secondary` there), so this is a text
  // colour and a hover, not a different treatment.
  'dark:text-primary dark:hover:bg-accent ' +
  'rounded shadow-md transition-all flex items-center';

/**
 * A labelled control: the adapter picker and the capture button.
 *
 * `py-2` on a 16px line box is what sets the 32px height the icon-only variant
 * below hard-codes. Change one and the other has to move with it.
 */
export const headerButtonClass =
  `${headerButtonBase} gap-1.5 text-xs px-3.5 sm:px-4 py-2 font-bold uppercase tracking-wider`;

/**
 * An icon-only control: the menu trigger.
 *
 * Square, and the same 32px tall as the labelled pair, so the three sit on one
 * line rather than one of them standing four pixels proud of the others.
 */
export const headerIconButtonClass =
  `${headerButtonBase} justify-center w-8 h-8 shrink-0`;
