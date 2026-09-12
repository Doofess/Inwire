/**
 * What the renderer knows about the link this capture is being taken over.
 *
 * The Network Information API, and it is worth exactly one thing: **it fires an
 * event when the network changes.** The numbers it carries are estimates
 * Chromium derives from its own recent requests - useful as context, never as
 * measurement, and never to be shown beside the capture's own timings as though
 * they were the same kind of number. The capture measures; this reports what
 * the engine believes.
 *
 * The event is the valuable half because a network transition is the thing that
 * explains what a capture otherwise cannot: a gap with no frames in it, a sudden
 * burst of ARP and DHCP, a new IPv6 prefix appearing mid-session, a TCP stream
 * that stops dead and never recovers. Those all look like faults and are all
 * just the machine changing networks.
 *
 * This used to carry a "Chromium only, and Firefox and Safari report nothing"
 * caveat. The renderer is always Chromium now, so the API is always there - but
 * the absence handling below stays, because a field within it is still optional
 * per platform (`type` is absent on desktop Chromium, which is most of the
 * time) and an absent field must read as "not said" rather than as zero.
 *
 * There is a better answer available and it is not built: the agent runs on the
 * machine and could report the adapter's negotiated link speed, which is a
 * measurement rather than an inference. `adapter_config` is where it would go.
 */

/** A link as the engine describes it. Every field may be absent. */
export interface LinkContext {
  /** 'wifi' | 'ethernet' | 'cellular' | ... Only some platforms report it. */
  type?: string;
  /** Chromium's bucket: 'slow-2g' | '2g' | '3g' | '4g'. */
  effectiveType?: string;
  /** Estimated Mbit/s, rounded by the engine to resist fingerprinting. */
  downlinkMbps?: number;
  /** Estimated round trip in ms, rounded to 25ms for the same reason. */
  rttMs?: number;
  /** Whether the user has asked sites to use less data. */
  saveData?: boolean;
}

/** One observed change of network, for marking on a timeline. */
export interface LinkChange {
  /** Epoch microseconds, to sit on the same axis as `Packet.tsUs`. */
  atUs: number;
  before: LinkContext;
  after: LinkContext;
}

interface NetworkInformationLike extends EventTarget {
  type?: string;
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
}

function connection(): NetworkInformationLike | null {
  if (typeof navigator === 'undefined') return null;
  const nav = navigator as Navigator & {
    connection?: NetworkInformationLike;
    mozConnection?: NetworkInformationLike;
    webkitConnection?: NetworkInformationLike;
  };
  return nav.connection ?? nav.mozConnection ?? nav.webkitConnection ?? null;
}

/** True when this browser reports anything at all about the link. */
export function linkContextAvailable(): boolean {
  return connection() !== null;
}

/**
 * The link right now, or null where the browser does not say.
 *
 * Absent keys rather than zeroes: a `downlink` of 0 is a claim about the
 * network and an absent one is a claim about the browser, and the two must not
 * render the same.
 */
export function readLinkContext(): LinkContext | null {
  const link = connection();
  if (!link) return null;
  const out: LinkContext = {};
  if (typeof link.type === 'string' && link.type) out.type = link.type;
  if (typeof link.effectiveType === 'string' && link.effectiveType) out.effectiveType = link.effectiveType;
  if (typeof link.downlink === 'number') out.downlinkMbps = link.downlink;
  if (typeof link.rtt === 'number') out.rttMs = link.rtt;
  if (typeof link.saveData === 'boolean') out.saveData = link.saveData;
  return out;
}

/** True when two readings differ in any way worth marking. */
export function linkChanged(a: LinkContext, b: LinkContext): boolean {
  return a.type !== b.type
    || a.effectiveType !== b.effectiveType
    || a.downlinkMbps !== b.downlinkMbps
    || a.rttMs !== b.rttMs
    || a.saveData !== b.saveData;
}

/**
 * A one-line description of a link, for a marker's label.
 *
 * Returns '' when nothing is known, so a caller can test the string instead of
 * assembling the same emptiness check at every call site.
 */
export function describeLink(link: LinkContext | null): string {
  if (!link) return '';
  const parts: string[] = [];
  if (link.type) parts.push(link.type);
  // "-class", because `effectiveType` is not the technology. The spec defines
  // it as the bucket whose typical performance the link RESEMBLES, derived
  // from recently observed round trips - so a gigabit Ethernet link reports
  // "4g", and printing that bare on a wired machine is the API's own wording
  // repeated as though it were a finding.
  if (link.effectiveType) parts.push(`${link.effectiveType}-class`);
  if (link.downlinkMbps !== undefined) parts.push(`~${link.downlinkMbps} Mbit/s`);
  if (link.rttMs !== undefined) parts.push(`~${link.rttMs} ms`);
  if (link.saveData) parts.push('data saver');
  return parts.join(', ');
}

/**
 * Calls back whenever the link changes, and returns an unsubscribe.
 *
 * A no-op returning a no-op where the API does not exist, so a caller never has
 * to branch on the browser.
 *
 * The first reading is taken at subscription and is NOT reported as a change:
 * a capture starting on Wi-Fi has not just moved to Wi-Fi, and a marker at
 * t=0 on every capture would train people to ignore the ones that mean
 * something.
 */
export function watchLinkChanges(onChange: (change: LinkChange) => void): () => void {
  const link = connection();
  if (!link) return () => {};

  let previous = readLinkContext() ?? {};
  const handler = () => {
    const next = readLinkContext() ?? {};
    if (!linkChanged(previous, next)) return;
    const change: LinkChange = { atUs: Date.now() * 1000, before: previous, after: next };
    previous = next;
    onChange(change);
  };

  link.addEventListener('change', handler);
  return () => link.removeEventListener('change', handler);
}
