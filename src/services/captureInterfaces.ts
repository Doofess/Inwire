/**
 * Presentation rules for the agent's capture interface list - which adapters
 * are worth offering, and how to name them in a control narrow enough that
 * the full label never fits.
 *
 * Kept dependency-free and pure so it's testable without React or a socket
 * (see scripts/capture-interfaces/).
 */

export interface CaptureInterface {
  name: string;
  label: string;
}

/**
 * The agent's device path for the software loopback adapter. Unlike every
 * other entry it is a fixed string rather than a per-machine GUID, so it can
 * be matched exactly instead of by label - which matters, because the labels
 * are localized (this machine reports several in Hebrew).
 */
export const LOOPBACK_DEVICE = '\\Device\\NPF_Loopback';

/**
 * Drops loopback from the offered adapters.
 *
 * It is excluded for being the wrong kind of traffic, not for being quiet -
 * it is in fact the busiest device on a typical machine (measured at roughly
 * 1200 packets/sec here against ~50/sec on the live Ethernet adapter), and
 * capturing it floods the packet buffer with process-to-process chatter that
 * never touches the network. That volume is also enough to saturate the
 * browser's render loop, which is how it was found.
 */
export function filterCapturableInterfaces(interfaces: CaptureInterface[]): CaptureInterface[] {
  return interfaces.filter((iface) => iface.name !== LOOPBACK_DEVICE);
}

/**
 * "Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)" -> "Ethernet 2".
 *
 * The agent builds labels as "<adapter name> (<driver description>)". The
 * description is the half that makes these unreadable at menu or button
 * width, and it is the half that repeats: three entries here differ only
 * inside their parentheses. Callers keep the full label as a tooltip.
 *
 * Splits on the FIRST " (" rather than the last, since descriptions contain
 * their own nested parentheses. A label with no parenthesised description is
 * already short and comes back unchanged.
 */
export function shortInterfaceLabel(label: string): string {
  const index = label.indexOf(' (');
  const short = index === -1 ? label : label.slice(0, index);
  // Falls back to the full label rather than returning an empty string: a
  // label that somehow begins with " (" would otherwise render as a blank
  // menu row with nothing to click on.
  return short.trim() || label.trim();
}

/**
 * What a SELECTION of adapters is called, in the few characters the rail and
 * the window title have: `Ethernet`, `Ethernet + Wi-Fi`, `3 adapters`.
 *
 * Capture takes several adapters again (it was narrowed to one on 2026-08-26,
 * and the reason was never the several - it was that every adapter came
 * pre-selected, so Start could begin a capture nobody had pointed anywhere;
 * nothing is pre-selected now either). Both callers used to read
 * `selectedInterfaces[0]`, which would name one adapter of a two-adapter
 * capture as if it were the whole of it.
 *
 * In the agent's list order rather than click order, so the name does not
 * change with the order somebody happened to tick the boxes. Names the agent
 * does not list are skipped: a selection restored from a session can outlive
 * an unplugged adapter. Null when nothing listed is selected.
 */
export function selectionLabel(
  interfaces: readonly { name: string; label: string }[],
  selected: readonly string[],
): string | null {
  const chosen = interfaces.filter((i) => selected.includes(i.name));
  if (chosen.length === 0) return null;
  if (chosen.length === 1) return shortInterfaceLabel(chosen[0].label);
  if (chosen.length === 2) return chosen.map((i) => shortInterfaceLabel(i.label)).join(' + ');
  return `${chosen.length} adapters`;
}

/** Adds an adapter to a selection, or takes it out - keeping the agent's order. */
export function toggleInterface(
  interfaces: readonly { name: string }[],
  selected: readonly string[],
  name: string,
): string[] {
  const next = selected.includes(name) ? selected.filter((n) => n !== name) : [...selected, name];
  const order = new Map(interfaces.map((i, index) => [i.name, index]));
  return [...next].sort((a, b) => (order.get(a) ?? Infinity) - (order.get(b) ?? Infinity));
}
