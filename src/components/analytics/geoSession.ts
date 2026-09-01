import type { GeoLocation } from '../../services/geoIpService';
import type { GeoPlace } from './GeoLocationCounter';

/**
 * What the geo map has learned this session, held outside the component.
 *
 * The map is now unmounted whenever the dashboard is minimized or the widget is
 * switched off, and everything it had accumulated used to go with it: the set
 * of places seen, which addresses had already been asked about, and how far
 * into the packet buffer the scan had got.
 *
 * That was wrong in two separate ways.
 *
 * The first is a correctness problem. `places` answers "which places have
 * talked to this machine THIS SESSION" and is deliberately monotonic - the
 * counter it feeds is not supposed to fall when old traffic ages out of the
 * buffer. Rebuilding it on every remount quietly redefines "this session" as
 * "since you last expanded the dashboard", which is a different question with a
 * smaller answer, and nothing on screen would say so.
 *
 * The second is cost. With the scan cursor reset, the next render re-scans the
 * whole buffer - at the 50,000-packet cap that is a full array copy plus two
 * `isLocatable` calls per packet, tens of milliseconds of synchronous work on
 * the frame the map comes back. Resetting `seenIps` on top of that would ask
 * about every address again; the answers are cached in `geoIpService`, so no
 * requests would go out, but the work of asking still would.
 *
 * So it lives here instead, at module scope, exactly as `geoIpService` already
 * holds its own caches. The component reads and writes it; unmounting simply
 * stops it changing.
 *
 * The camera is kept for the same reason at a human scale: someone who flew the
 * map to a city and then collapsed the dashboard should not find themselves
 * back at the world view.
 */

export interface GeoSession {
  /** Distinct places seen, keyed by rounded coordinate. Only ever grows. */
  places: Map<string, GeoPlace>;
  /** Addresses that resolved to nothing, so the count can report them. */
  unresolved: Set<string>;
  /** Addresses already asked about, so each is asked once. */
  seenIps: Set<string>;
  /** City-level locations, which is what markers and routes are built from. */
  locations: Map<string, GeoLocation>;
  hostnames: Map<string, string | null>;
  /** How far into the buffer the scan has looked, and what it was looking at. */
  scan: { firstPacketId: number; scannedCount: number };
  /** Where the map was pointing, so a remount does not snap back to the world. */
  camera: { center: [number, number]; zoom: number } | null;
}

function emptySession(): GeoSession {
  return {
    places: new Map(),
    unresolved: new Set(),
    seenIps: new Set(),
    locations: new Map(),
    hostnames: new Map(),
    scan: { firstPacketId: -1, scannedCount: 0 },
    camera: null,
  };
}

let session = emptySession();

export function geoSession(): GeoSession {
  return session;
}

/**
 * Forgets everything learned about this capture.
 *
 * Called when the packet buffer is cleared, because at that point the places
 * are describing traffic that no longer exists - the one case where the
 * monotonic count SHOULD go back to zero.
 *
 * The camera is deliberately kept: clearing the buffer is a statement about
 * packets, not about where the user was looking.
 */
export function resetGeoSession(): void {
  const { camera } = session;
  session = emptySession();
  session.camera = camera;
}
