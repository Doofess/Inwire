// Shared enter/exit animation for every full-screen modal (Statistics,
// Export/Import, Custom Dissectors, Color Rules, ISP Stats). Kept in one
// place so all of them animate identically - both for their own
// direct-open path (Header buttons) and so their entrance overlaps in
// time with the Command Palette's exit when opened from there, reading as
// one continuous handoff rather than two separate animations.

export const modalBackdropMotion = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit: { opacity: 0 },
  transition: { duration: 0.15 },
};

export const modalPanelMotion = {
  initial: { opacity: 0, scale: 0.96, y: 8 },
  animate: { opacity: 1, scale: 1, y: 0 },
  exit: { opacity: 0, scale: 0.96, y: 8 },
  transition: { duration: 0.18, ease: 'easeOut' as const },
};

/**
 * For a panel that grows out of the control that opened it.
 *
 * Same family as `modalPanelMotion`, three deliberate differences:
 *
 *   - **No `y`.** The panel is scaling from a point somewhere off to the side,
 *     so a vertical offset pulls it away from that point and the motion stops
 *     reading as "out of there" and starts reading as "down a bit as well".
 *   - **A much deeper scale.** 0.96 is a modal settling; growing out of a 32px
 *     icon needs to start small enough that the eye follows it back.
 *   - **The menu's curve and timings**, not the modal's - 150ms out on
 *     `cubic-bezier(0.16, 1, 0.3, 1)` and 110ms back, which is exactly what
 *     `nv-menu-in` and `nv-menu-out` in index.css give the Interfaces menu and
 *     the dashboard's popout bubbles. Every surface in the app that pops out of
 *     something is then timed alike, whether its motion comes from CSS or from
 *     here.
 *
 * The origin itself is not here, because it is a measurement rather than a
 * constant: see `WidgetOverlay`, which writes `transform-origin` from the
 * trigger's position before the first paint.
 */
export const popoutPanelMotion = {
  initial: { opacity: 0, scale: 0.7 },
  animate: { opacity: 1, scale: 1, transition: { duration: 0.15, ease: [0.16, 1, 0.3, 1] as const } },
  exit: { opacity: 0, scale: 0.7, transition: { duration: 0.11, ease: 'easeIn' as const } },
};
