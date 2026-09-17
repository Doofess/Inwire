// Shared enter/exit animation for every full-screen modal, kept in one place
// so all of them animate identically rather than each drifting.
//
// There are three left, and the shrinking list is the point: Settings
// (`SettingsModal`), Export/Import (`ExportImportModal`) and the import error
// dialog. Statistics and the Routing Map became VIEWS, and Custom Dissectors,
// Color Rules and Network became Settings TABS - so what used to be five
// modals reachable from a header bar is now three surfaces that genuinely
// interrupt. `PacketDetailPane` was the most recent to leave; it fills a view
// slot and animates with neither of these.

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

// There was a third export, `popoutPanelMotion`, for a panel growing out of the
// control that opened it. Its only consumer was `WidgetOverlay`, which wrote
// `transform-origin` from the trigger's position before the first paint; the
// dock and every widget in it are deleted, so it went with them. The timings it
// matched are still the shared ones: `nv-menu-in` and `nv-menu-out` in
// index.css, 150ms out on cubic-bezier(0.16, 1, 0.3, 1) and 110ms back.
