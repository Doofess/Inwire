/**
 * Conversations, endpoints and the protocol hierarchy.
 *
 * Pure aggregation over the packet buffer, in `services` rather than inside
 * the dialog, because these three answers are the ones a capture is opened to
 * get and they need to be assertable: "who talked to whom, how much, and for
 * how long" is a question with one right answer, and a table that quietly
 * counts a retransmission twice or attributes a flow to the wrong direction
 * looks exactly like a table that does not.
 *
 * ## Direction, and why A and B are ordered
 *
 * A conversation is one row, not two. Which end is "A" therefore has to be
 * decided by something stable, or the same pair would produce a different row
 * depending on which frame happened to arrive first. Wireshark uses the first
 * frame seen: whoever sent it is A. That is kept here, because it is also the
 * useful answer - the first frame of a TCP conversation is the SYN, so A is
 * the side that opened the connection.
 *
 * ## Protocol hierarchy
 *
 * Built from `frameProtocols`, which is the dissected layer stack in the order
 * the layers actually nest (`eth:ip:tcp:tls`), so the tree is the real
 * containment relationship rather than a flat count keyed on the top-most
 * name. A frame counts once at every level it passed through, which is what
 * makes the percentages read the way Wireshark's do: `eth` is 100 %, and the
 * children of a node sum to at most the node itself.
 */

import { Packet } from '../types/packet';
import { fieldValue } from './dissect/fieldAccess';

export type ConversationKind = 'eth' | 'ipv4' | 'ipv6' | 'tcp' | 'udp';

export interface Endpoint {
  address: string;
  packets: number;
  bytes: number;
  packetsTx: number;
  bytesTx: number;
  packetsRx: number;
  bytesRx: number;
  /** Port, for the transport tabs. */
  port?: number;
}

export interface Conversation {
  /** Stable identity, and the React key. */
  key: string;
  addressA: string;
  addressB: string;
  portA?: number;
  portB?: number;
  packetsAtoB: number;
  bytesAtoB: number;
  packetsBtoA: number;
  bytesBtoA: number;
  packets: number;
  bytes: number;
  /** Seconds since the capture started, from the first frame of this pair. */
  startRel: number;
  duration: number;
  /** The TCP/UDP stream this pair is, when the tracker assigned one. */
  streamId?: number;
  /** The most specific protocol label seen on the pair, for the list. */
  protocol: string;
  /** Frame number of the first packet, so a row can jump to it. */
  firstFrame: number;
}

export interface HierarchyNode {
  /** The `frameProtocols` token: `tcp`, `tls`. */
  token: string;
  packets: number;
  bytes: number;
  children: HierarchyNode[];
}

/** The addresses a frame has at the level being counted, or null if it has none. */
function addressesFor(packet: Packet, kind: ConversationKind): { a: string; b: string; pa?: number; pb?: number } | null {
  switch (kind) {
    case 'eth': {
      const src = fieldValue(packet, 'eth.src');
      const dst = fieldValue(packet, 'eth.dst');
      return typeof src === 'string' && typeof dst === 'string' ? { a: src, b: dst } : null;
    }
    case 'ipv4': {
      const src = fieldValue(packet, 'ip.src');
      const dst = fieldValue(packet, 'ip.dst');
      return typeof src === 'string' && typeof dst === 'string' ? { a: src, b: dst } : null;
    }
    case 'ipv6': {
      const src = fieldValue(packet, 'ipv6.src');
      const dst = fieldValue(packet, 'ipv6.dst');
      return typeof src === 'string' && typeof dst === 'string' ? { a: src, b: dst } : null;
    }
    case 'tcp':
    case 'udp': {
      const sp = fieldValue(packet, `${kind}.srcport`);
      const dp = fieldValue(packet, `${kind}.dstport`);
      if (typeof sp !== 'number' || typeof dp !== 'number') return null;
      return { a: packet.source, b: packet.destination, pa: sp, pb: dp };
    }
  }
}

/**
 * The frames that belong on one tab.
 *
 * A TLS frame is a TCP frame and belongs on the TCP tab; the layer list is
 * what decides, not the top-most protocol name - which is the same rule the
 * filter engine's barewords follow, and for the same reason.
 */
function frameHasLayer(packet: Packet, kind: ConversationKind): boolean {
  const layers = packet.frameProtocols;
  if (!layers || layers.length === 0) return false;
  return layers.includes(kind === 'ipv4' ? 'ip' : kind);
}

export function conversations(packets: readonly Packet[], kind: ConversationKind): Conversation[] {
  const byKey = new Map<string, Conversation>();

  for (const packet of packets) {
    if (!frameHasLayer(packet, kind)) continue;
    const ends = addressesFor(packet, kind);
    if (!ends) continue;

    // Both orderings map to the same row; the first frame seen fixes which
    // end is A, so a TCP conversation's A is the side that sent the SYN.
    const forwardKey = `${ends.a}|${ends.pa ?? ''}|${ends.b}|${ends.pb ?? ''}`;
    const reverseKey = `${ends.b}|${ends.pb ?? ''}|${ends.a}|${ends.pa ?? ''}`;
    const existing = byKey.get(forwardKey) ?? byKey.get(reverseKey);

    if (!existing) {
      byKey.set(forwardKey, {
        key: forwardKey,
        addressA: ends.a, addressB: ends.b, portA: ends.pa, portB: ends.pb,
        packetsAtoB: 1, bytesAtoB: packet.length,
        packetsBtoA: 0, bytesBtoA: 0,
        packets: 1, bytes: packet.length,
        startRel: packet.relativeTime,
        duration: 0,
        streamId: packet.streamId,
        protocol: packet.protocolLabel ?? packet.protocol,
        firstFrame: packet.id,
      });
      continue;
    }

    const isAtoB = existing.addressA === ends.a && existing.portA === ends.pa;
    if (isAtoB) {
      existing.packetsAtoB++;
      existing.bytesAtoB += packet.length;
    } else {
      existing.packetsBtoA++;
      existing.bytesBtoA += packet.length;
    }
    existing.packets++;
    existing.bytes += packet.length;
    // Frames arrive in capture order on every path that feeds this, so the
    // last one seen is the latest; `Math.max` rather than assignment anyway,
    // because a sorted view could hand them over in any order.
    existing.duration = Math.max(existing.duration, packet.relativeTime - existing.startRel);
    if (existing.streamId === undefined) existing.streamId = packet.streamId;
    // A pair's protocol is the most specific label it ever carried: a TCP
    // conversation that turns into TLS reads better as TLS, and the plain
    // ACKs that outnumber the TLS records should not decide the label.
    const label = packet.protocolLabel ?? packet.protocol;
    if (label !== 'TCP' && label !== 'UDP') existing.protocol = label;
  }

  return [...byKey.values()];
}

export function endpoints(packets: readonly Packet[], kind: ConversationKind): Endpoint[] {
  const byKey = new Map<string, Endpoint>();

  const bump = (address: string, port: number | undefined, bytes: number, sending: boolean) => {
    const key = port === undefined ? address : `${address}|${port}`;
    let e = byKey.get(key);
    if (!e) {
      e = { address, port, packets: 0, bytes: 0, packetsTx: 0, bytesTx: 0, packetsRx: 0, bytesRx: 0 };
      byKey.set(key, e);
    }
    e.packets++;
    e.bytes += bytes;
    if (sending) { e.packetsTx++; e.bytesTx += bytes; }
    else { e.packetsRx++; e.bytesRx += bytes; }
  };

  for (const packet of packets) {
    if (!frameHasLayer(packet, kind)) continue;
    const ends = addressesFor(packet, kind);
    if (!ends) continue;
    bump(ends.a, ends.pa, packet.length, true);
    bump(ends.b, ends.pb, packet.length, false);
  }

  return [...byKey.values()];
}

/**
 * The layer tree, counted the way Wireshark counts it.
 *
 * Every frame walks its own `frameProtocols` chain, adding itself to each node
 * on the way down, so a TLS-over-TCP frame is one packet at `eth`, at `ip`, at
 * `tcp` and at `tls`. This depends on that chain being in nesting order, which
 * is why the dissector inserts a QUIC or SSDP token beside its transport layer
 * rather than appending it - appended, `quic` landed under `tls` on the 68
 * frames that carry both, which is the inverse of what contains what.
 */
export function protocolHierarchy(packets: readonly Packet[]): { roots: HierarchyNode[]; packets: number; bytes: number } {
  const roots: HierarchyNode[] = [];
  let totalPackets = 0;
  let totalBytes = 0;

  for (const packet of packets) {
    const chain = packet.frameProtocols;
    if (!chain || chain.length === 0) continue;
    totalPackets++;
    totalBytes += packet.length;

    let level = roots;
    for (const token of chain) {
      let node = level.find((n) => n.token === token);
      if (!node) {
        node = { token, packets: 0, bytes: 0, children: [] };
        level.push(node);
      }
      node.packets++;
      node.bytes += packet.length;
      level = node.children;
    }
  }

  const sortTree = (nodes: HierarchyNode[]) => {
    nodes.sort((a, b) => b.packets - a.packets);
    for (const n of nodes) sortTree(n.children);
  };
  sortTree(roots);

  return { roots, packets: totalPackets, bytes: totalBytes };
}

/**
 * One machine on the segment, as the capture saw it.
 *
 * Keyed on the MAC rather than on an address, because that is what a machine
 * has one of: a laptop on a dual-stack network shows up as an IPv4 address, a
 * stable IPv6 address and however many temporary ones its privacy extensions
 * have rotated through, and listing those as five devices would be an
 * inventory that miscounts the thing it exists to count.
 *
 * Only frames that recorded an Ethernet header contribute, so this is an
 * inventory of the local segment - a remote server reached through a router
 * appears under the router's MAC and is deliberately not listed as a device,
 * because it is not one that was ever here.
 */
export interface Device {
  mac: string;
  /** Every network address seen sending from this MAC, first seen first. */
  addresses: string[];
  packets: number;
  bytes: number;
  firstFrame: number;
  firstSeen: number;
  lastSeen: number;
}

/** Addresses that say nothing about a device: unset, broadcast, multicast. */
function isRealSender(mac: string): boolean {
  if (mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff') return false;
  // The multicast bit of the first octet. A frame is never SENT from a group
  // address, so one here means the frame is not what it claims to be.
  const first = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 1) === 0;
}

export function devices(packets: readonly Packet[]): Device[] {
  const byMac = new Map<string, Device>();

  for (const packet of packets) {
    const mac = fieldValue(packet, 'eth.src');
    if (typeof mac !== 'string' || !isRealSender(mac)) continue;

    let device = byMac.get(mac);
    if (!device) {
      device = {
        mac, addresses: [], packets: 0, bytes: 0,
        firstFrame: packet.id, firstSeen: packet.relativeTime, lastSeen: packet.relativeTime,
      };
      byMac.set(mac, device);
    }
    device.packets++;
    device.bytes += packet.length;
    device.lastSeen = Math.max(device.lastSeen, packet.relativeTime);

    // The sender's network address, from the layer that has one. `source` on
    // the packet is the MAC itself for a frame with no network layer, which
    // would otherwise list every ARP sender's MAC as its own address.
    const ip = fieldValue(packet, 'ip.src') ?? fieldValue(packet, 'ipv6.src') ?? fieldValue(packet, 'arp.src.proto_ipv4');
    if (typeof ip === 'string' && ip !== '0.0.0.0' && !device.addresses.includes(ip)) {
      // A privacy-extension address rotates hourly; a device that has held
      // twenty of them is still one device, but the list is for reading.
      if (device.addresses.length < 16) device.addresses.push(ip);
    }
  }

  return [...byMac.values()];
}

/**
 * One program on this machine, and the traffic attributed to it.
 *
 * The grouping no other analyzer can offer, because it needs the operating
 * system of the captured machine rather than the capture (see
 * `services/flowAnnotations.ts`). It answers "what is talking to the network",
 * which is the question a packet list makes hardest to answer and the one
 * people most often open a capture to ask.
 */
export interface ProcessGroup {
  name: string;
  pid: number;
  /** Full path, or '' when the OS named the process but refused its path. */
  exe: string;
  /** Remote addresses this process talked to, first seen first. */
  peers: string[];
  packets: number;
  bytes: number;
  firstFrame: number;
  firstSeen: number;
  lastSeen: number;
}

/**
 * Grouped by **pid**, not by name.
 *
 * Two processes with one name are two programs: a browser runs a dozen renderer
 * children and folding them into one row would hide which of them is the one
 * talking. The name is on the row; the pid is what makes the row a thing.
 *
 * Frames with no attribution are simply absent - not gathered into an
 * "unknown" row. There is no single thing they belong to, and inventing one
 * would put a number next to a name that does not exist.
 */
export function processes(packets: readonly Packet[], isLocal?: (address: string) => boolean): ProcessGroup[] {
  const byPid = new Map<number, ProcessGroup>();

  for (const packet of packets) {
    const name = fieldValue(packet, 'inwire.process.name');
    const pid = fieldValue(packet, 'inwire.process.pid');
    if (typeof name !== 'string' || typeof pid !== 'number') continue;

    let group = byPid.get(pid);
    if (!group) {
      group = {
        name, pid,
        exe: String(fieldValue(packet, 'inwire.process.path') ?? ''),
        peers: [], packets: 0, bytes: 0,
        firstFrame: packet.id, firstSeen: packet.relativeTime, lastSeen: packet.relativeTime,
      };
      byPid.set(pid, group);
    }
    group.packets++;
    group.bytes += packet.length;
    group.lastSeen = Math.max(group.lastSeen, packet.relativeTime);

    // The far end, which is whichever of the two is not this machine. Without
    // the local set to compare against there is no way to tell, so the column
    // stays empty rather than listing this machine as its own peer.
    if (isLocal) {
      const peer = isLocal(packet.source) ? packet.destination
        : isLocal(packet.destination) ? packet.source
          : null;
      if (peer && !group.peers.includes(peer) && group.peers.length < 16) {
        group.peers.push(peer);
      }
    }
  }

  return [...byPid.values()];
}

/**
 * The display filter that selects one process's frames.
 *
 * On the pid, because that is what the row is. Filtering on the name would
 * select every renderer a browser has, which is not the row that was clicked.
 */
export function processFilter(group: ProcessGroup): string {
  return `inwire.process.pid == ${group.pid}`;
}

/** The display filter that selects everything one device sent or received. */
export function deviceFilter(device: Device): string {
  return `eth.addr == "${device.mac}"`;
}

/**
 * The display filter that selects one conversation.
 *
 * Built from the registry names rather than the summary columns, so it means
 * the same thing the table meant - `ip.addr == a && ip.addr == b` is
 * Wireshark's own idiom for "between these two", and it works because a
 * multi-occurrence field matches when any occurrence does.
 */
export function conversationFilter(c: Conversation, kind: ConversationKind): string {
  const quote = (v: string) => `"${v}"`;
  switch (kind) {
    case 'eth':
      return `eth.addr == ${quote(c.addressA)} && eth.addr == ${quote(c.addressB)}`;
    case 'ipv4':
      return `ip.addr == ${quote(c.addressA)} && ip.addr == ${quote(c.addressB)}`;
    case 'ipv6':
      return `ipv6.addr == ${quote(c.addressA)} && ipv6.addr == ${quote(c.addressB)}`;
    case 'tcp':
    case 'udp':
      return `addr == ${quote(c.addressA)} && ${kind}.port == ${c.portA}`
        + ` && addr == ${quote(c.addressB)} && ${kind}.port == ${c.portB}`;
  }
}

/** The display filter that selects everything to or from one endpoint. */
export function endpointFilter(e: Endpoint, kind: ConversationKind): string {
  const quote = (v: string) => `"${v}"`;
  switch (kind) {
    case 'eth': return `eth.addr == ${quote(e.address)}`;
    case 'ipv4': return `ip.addr == ${quote(e.address)}`;
    case 'ipv6': return `ipv6.addr == ${quote(e.address)}`;
    case 'tcp':
    case 'udp':
      return e.port === undefined
        ? `addr == ${quote(e.address)}`
        : `addr == ${quote(e.address)} && ${kind}.port == ${e.port}`;
  }
}
