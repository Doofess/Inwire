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
