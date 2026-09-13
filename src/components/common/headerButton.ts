/**
 * The button style for controls that sit on the app's own chrome.
 *
 * It lives in a module of its own because two components draw it - the command
 * palette's trigger is inside `AppMenu`, the schedule picker's is in
 * `FilterRow` - and a constant exported from either would be a cycle or a
 * coincidence. Controls in one strip drawn by two components is exactly the
 * arrangement in which two treatments quietly drift apart, and the menu button
 * had already: a different fill, a border the others lacked, a wider radius and
 * four pixels more height.
 *
 * ## It used to be the accent bar's, and is not any more
 *
 * These were `--chrome-sunken` with `--chrome-foreground` on top: the old 64px
 * header was a saturated accent band, and a button on it had to be that band
 * deepened. The header is gone. The palette trigger now sits in a `--card`
 * title row and the schedule picker on the app's own `--background`, so the same
 * classes would have painted a deep blue slab with white text onto a near-white
 * ground in Day - loud, and in the one place the window is supposed to be quiet.
 *
 * So the fill is `--secondary` and the label is `--foreground`: the same
 * treatment every other secondary control in the app already uses, which is
 * what makes these read as part of it rather than as a leftover from the bar
 * they came off. The accent is deliberately not the fill - an accent-filled
 * button in a title row is the decoration this redesign exists to remove.
 *
 * One thing kept from the old note, because it is still true: the adapter
 * control's STATE is carried by its icon, its badge and its accessible name, not
 * by the button's colour. A coloured fill was always a second, coarser copy of
 * what the label said.
 */
const chromeButtonBase =
  // Hover lightens to `--accent`, which is what every list row and menu item in
  // the app already does on hover - one fewer treatment to keep in step.
  'bg-secondary text-foreground hover:bg-accent '
  + 'rounded shadow-sm transition-all flex items-center '
  + 'focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring';

/**
 * A labelled control: the schedule picker.
 *
 * `py-1.5` on a 16px line box sets a 28px height, which is what fits the 44px
 * filter row with its padding. The icon-only variant below hard-codes the same
 * height; change one and the other has to move.
 */
export const headerButtonClass =
  `${chromeButtonBase} gap-1.5 text-xs px-3 py-1.5 font-bold uppercase tracking-wider`;

/**
 * An icon-only control: the palette trigger in the title row.
 *
 * 28px square, and deliberately smaller than the rail's 36px targets - the title
 * row is 40px tall, so a 36px button would leave two pixels of air above and
 * below and read as filling the strip.
 */
export const headerIconButtonClass =
  `${chromeButtonBase} justify-center w-7 h-7 shrink-0`;
