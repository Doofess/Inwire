/**
 * Whether a frame was sent by this machine, received by it, or overheard.
 *
 * This is the fact a capture taken *on an endpoint* has and a capture taken
 * anywhere else does not. Wireshark cannot answer it at all - it has no way to
 * know which of the two MACs in a frame belongs to the machine you are sitting
 * at - and every consequence of not knowing shows up somewhere in this app:
 * the conversations table splits A->B and B->A by whoever spoke first rather
 * than by which end is us, Follow Stream guesses the client from port numbers,
 * and there has never been a way to ask "what did this machine send".
 *
 * It comes from the same seam as process attribution
 * (`docs/decisions/0009-off-wire-enrichment.md`): the host's identity is
 * learned from the machine the capture was taken on - the agent's
 * `adapter_config`, or its socket table - never from a third party. For an
 * imported capture there is no machine to ask, so the identity is *inferred*
 * from the frames themselves (`services/hostIdentity.ts`), and the difference
 * between knowing and inferring is carried on every frame rather than being
 * forgotten at the door.
 *
 * ## One number, three facts
 *
 * `Packet.direction` packs the direction, the signal that decided it, and
 * whether the frame is a duplicate of one already seen on another adapter.
 * That is not a micro-optimisation looking for a justification - the tooltip
 * has to name which signal decided, so the signal has to be stored either way,
 * and this is the same shape `colorSlot` already uses for the same reason
 * (`types/packet.ts`, `docs/decisions/0015`).
 *
 * Two alternatives were rejected on facts rather than taste. A `Packet.fields`
 * entry costs ~30 B a frame against ~8 - 21 MB at a full buffer, immediately
 * after the work that took a frame from 2,342 B to 663. And a **dense column**
 * is ruled out outright by `POST_DISSECTION_KEYS`
 * (`dissect/denseFields.ts`): `FieldBlockWriter.absorb` fills a row once and
 * never again, while a host override has to re-derive direction for frames
 * already in the buffer. A plain property can simply be reassigned.
 *
 * Nothing outside this module reads the bits.
 */

/** Which way the frame went, relative to the capturing host. */
export const enum Direction {
  /** Nothing decided. Not a guess that failed - a question not yet answered. */
  Unknown = 0,
  /** This machine sent it. */
  Out = 1,
  /** This machine received it, including as part of a group. */
  In = 2,
  /** Neither end is this machine: promiscuous mode, a mirror port, a hub. */
  Transit = 3,
}

/**
 * What decided the direction, so the answer can be defended.
 *
 * Shown in the column's tooltip. A user looking at an arrow they did not
 * expect is owed the reason, and "the interface MAC said so" and "the frame
 * was too big to have arrived over Ethernet" are very different degrees of
 * confidence to have in the same glyph.
 */
export const enum DirectionSignal {
  None = 0,
  /** The capture interface's own MAC, from the agent. The strong case. */
  InterfaceMac = 1,
  /** The capture interface's own addresses, for links with no MACs at all. */
  InterfaceAddress = 2,
  /** The socket table: this address is one this machine holds a socket on. */
  SocketTable = 3,
  /** A host identity inferred from the capture itself, not read from an OS. */
  InferredHost = 4,
  /** Transmit-side offload: a frame larger than the link can carry. */
  Offload = 5,
  /** Transmit-side offload: a checksum the NIC had not filled in yet. */
  ChecksumOffload = 6,
}

const DIRECTION_BITS = 0b11;
const SIGNAL_SHIFT = 2;
const SIGNAL_BITS = 0b111;
const DUPLICATE_BIT = 1 << 5;

/** Packs a decision into the number a `Packet` carries. */
export function packDirection(
  direction: Direction,
  signal: DirectionSignal = DirectionSignal.None,
): number {
  return direction | (signal << SIGNAL_SHIFT);
}

export function directionOf(slot: number | undefined): Direction {
  return ((slot ?? 0) & DIRECTION_BITS) as Direction;
}

export function signalOf(slot: number | undefined): DirectionSignal {
  return (((slot ?? 0) >> SIGNAL_SHIFT) & SIGNAL_BITS) as DirectionSignal;
}

export function isDuplicate(slot: number | undefined): boolean {
  return ((slot ?? 0) & DUPLICATE_BIT) !== 0;
}

/** Marks a frame as a duplicate without disturbing what it already decided. */
export function withDuplicate(slot: number | undefined): number {
  return (slot ?? 0) | DUPLICATE_BIT;
}

/**
 * The names a filter matches, per direction.
 *
 * Two spellings each, and the aliasing costs nothing to implement: the filter
 * engine already lets a reader return several values so that `proto == tls`
 * and `proto == tlsv1.2` both match one frame (`filter/fields.ts`). `sent` and
 * `received` are what a person types; `out` and `in` are what the column and
 * the export mean. Both are true of the same frame, so both should match it.
 */
export const DIRECTION_NAMES: Record<Direction, string[]> = {
  [Direction.Unknown]: ['unknown'],
  [Direction.Out]: ['out', 'sent'],
  [Direction.In]: ['in', 'received'],
  [Direction.Transit]: ['transit'],
};

/** The single word for a direction, for a tooltip or a table. */
export const DIRECTION_LABEL: Record<Direction, string> = {
  [Direction.Unknown]: 'Unknown',
  [Direction.Out]: 'Sent',
  [Direction.In]: 'Received',
  [Direction.Transit]: 'Transit',
};

/** The glyph the packet list draws. Deliberately not a colour: see below. */
export const DIRECTION_GLYPH: Record<Direction, string> = {
  [Direction.Unknown]: '·',
  [Direction.Out]: '↑',
  [Direction.In]: '↓',
  [Direction.Transit]: '↔',
};

export const SIGNAL_LABEL: Record<DirectionSignal, string> = {
  [DirectionSignal.None]: 'not determined',
  [DirectionSignal.InterfaceMac]: "the capture adapter's MAC address",
  [DirectionSignal.InterfaceAddress]: "the capture adapter's IP address",
  [DirectionSignal.SocketTable]: 'a local socket on this address',
  [DirectionSignal.InferredHost]: 'a host inferred from the capture',
  [DirectionSignal.Offload]: 'segmentation offload (frame exceeds the MTU)',
  [DirectionSignal.ChecksumOffload]: 'checksum offload (checksum not yet filled in)',
};

/**
 * Who this machine is, as far as one capture is concerned.
 *
 * Filled from `adapter_config` for a live capture and from
 * `services/hostIdentity.ts` for an imported one. `inferred` is what keeps the
 * two apart on screen: an inferred identity can be wrong, and a column that
 * rendered a guess identically to a known answer would be the kind of quiet
 * confidence this codebase avoids elsewhere (Follow Stream discloses its
 * first-speaker guess; a replay that could not start at the beginning says so).
 */
export interface HostIdentity {
  /** Lowercase, colon-separated. */
  macs: ReadonlySet<string>;
  addresses: ReadonlySet<string>;
  /** Whether this came from the machine, or was worked out from the frames. */
  inferred: boolean;
  /** 0..1. Always 1 when it came from an adapter. */
  confidence: number;
  /** Short prose for the disclosure banner: what the inference went on. */
  basis?: string;
}

export const NO_HOST: HostIdentity = {
  macs: new Set(), addresses: new Set(), inferred: false, confidence: 0,
};

const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff';

/**
 * Group traffic - broadcast, and IPv4/IPv6 multicast.
 *
 * The low bit of the first octet is the I/G bit, and it is set for every
 * multicast destination including the `01:00:5e` and `33:33` prefixes the IP
 * stacks map group addresses onto. A frame *to* a group did not single this
 * machine out, but this machine did receive it, which is what `in` means here.
 */
function isGroupMac(mac: string): boolean {
  if (mac === BROADCAST_MAC) return true;
  const firstOctet = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(firstOctet) && (firstOctet & 0x01) === 1;
}

/**
 * The direction of a frame, from its MACs.
 *
 * The first and strongest signal, and the one that needs no addresses: a frame
 * whose source MAC is the adapter's left this machine, whatever it contains.
 * That includes the broadcasts and multicasts this machine sends, which is why
 * the source is tested before the destination - a DHCP Discover goes to
 * `ff:ff:ff:ff:ff:ff` *from* us, and reading the destination first would call
 * it inbound.
 */
export function directionFromMacs(
  srcMac: string | undefined,
  dstMac: string | undefined,
  host: HostIdentity,
): number {
  if (host.macs.size === 0 || !srcMac || !dstMac) return 0;
  const signal = host.inferred ? DirectionSignal.InferredHost : DirectionSignal.InterfaceMac;
  if (host.macs.has(srcMac)) return packDirection(Direction.Out, signal);
  if (host.macs.has(dstMac) || isGroupMac(dstMac)) return packDirection(Direction.In, signal);
  // Both MACs are real and neither is ours: somebody else's conversation,
  // reaching us through promiscuous mode, a mirror port or a hub.
  return packDirection(Direction.Transit, signal);
}

/**
 * The direction of a frame, from its addresses.
 *
 * Second, and for two different cases. A TUN-style VPN adapter has no Ethernet
 * header at all, so there are no MACs to compare and this is the only signal
 * that can fire. And on a normal link it answers for frames whose MACs were
 * inconclusive - a host identity that knows an address but not a MAC, which is
 * what the socket table alone provides.
 *
 * `socketLocal` is consulted after the host's own addresses because it is the
 * weaker claim: the socket table says this machine holds a socket on an
 * address, which is true of `0.0.0.0` and of every address on a machine with
 * several adapters.
 */
export function directionFromAddresses(
  source: string,
  destination: string,
  host: HostIdentity,
  socketLocal?: (address: string) => boolean,
): number {
  if (host.addresses.size > 0) {
    const signal = host.inferred ? DirectionSignal.InferredHost : DirectionSignal.InterfaceAddress;
    if (host.addresses.has(source)) return packDirection(Direction.Out, signal);
    if (host.addresses.has(destination)) return packDirection(Direction.In, signal);
  }
  if (socketLocal) {
    const fromHere = socketLocal(source);
    const toHere = socketLocal(destination);
    // Only when exactly one end is local. Both ends local is loopback or a
    // second adapter, and neither direction is more true than the other.
    if (fromHere && !toHere) return packDirection(Direction.Out, DirectionSignal.SocketTable);
    if (toHere && !fromHere) return packDirection(Direction.In, DirectionSignal.SocketTable);
  }
  return 0;
}

/** The largest frame that can arrive over standard Ethernet, without an FCS. */
const ETHERNET_MAX_FRAME = 1514;

/**
 * The last resort: artefacts only a transmitting NIC leaves.
 *
 * A frame longer than the link's maximum was never on the wire at that size -
 * the capture point is above segmentation offload, so the driver handed the
 * sniffer one large buffer that the NIC will cut up on its way out. Likewise a
 * zero checksum on a protocol that requires one is not a corrupt frame, it is
 * a checksum the NIC has not computed yet. Both are only ever true of frames
 * leaving the machine.
 *
 * Deliberately last, and deliberately narrow. Neither can say a frame is
 * *inbound* - their absence means nothing - so this only ever answers `out`
 * or nothing at all.
 */
export function directionFromOffload(
  frameLength: number,
  hasEthernetHeader: boolean,
  checksumUnfilled: boolean,
): number {
  if (hasEthernetHeader && frameLength > ETHERNET_MAX_FRAME) {
    return packDirection(Direction.Out, DirectionSignal.Offload);
  }
  if (checksumUnfilled) return packDirection(Direction.Out, DirectionSignal.ChecksumOffload);
  return 0;
}
