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
