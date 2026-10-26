/**
 * A DHCPv4 exchange, folded from rows by its transaction id (ADR 0055, stage 3).
 *
 * Beside the UDP summaries and never inside them: a DHCP row also counts in its
 * UDP flow, and this is the exchange read across flows. A discover from
 * 0.0.0.0:68 and the server's offer to the client's new address are two UDP
 * flows and one exchange. Pure steps over a summary and a row; `StreamDigest`
 * owns the map and the version.
 *
 * A side comes from the message type, not from ports or addresses (ruling
 * S3-7), so a relay (67 to 67) and a unicast renewal read right. DHCPv6 rows
 * carry no message type or transaction id and stay UDP flows (ruling S3-6).
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import type { Endpoint } from './clientSide';
import type { Side } from './tcpStates';
import type { DirectionTotals } from './streamDigest';

export type DhcpMessage = 'Discover' | 'Offer' | 'Request' | 'Decline' | 'ACK' | 'NAK' | 'Release' | 'Inform';
export type DhcpOutcome = 'acked' | 'NAK' | 'declined' | 'released' | 'offer not taken' | 'no reply' | 'no offer';

export interface DhcpPhaseStep { message: DhcpMessage; side: Side; frameId: number; time: number }

export interface DhcpSummary {
  kind: 'dhcp';
  /** `dhcp.id`, unsigned. */
  key: number;
  client: Endpoint;
  server: Endpoint;
  /** `dhcp.option.hostname`, the first one a row carried. */
  hostname: string | null;
  /** `dhcp.ip.your`, the newest one a row carried. */
  offered: string | null;
  toServer: DirectionTotals;
  toClient: DirectionTotals;
  firstId: number;
  lastId: number;
  start: number;
  end: number;
  /** The first of each message. */
  phases: DhcpPhaseStep[];
  outcome: DhcpOutcome;
  /** The digest's version when this summary last changed. */
  version: number;
}

/** Option 53's values, by number (RFC 2132), and the side that sends each (ruling S3-7). */
const MESSAGES: readonly (readonly [DhcpMessage, Side] | undefined)[] = [
  undefined,
  ['Discover', 'client'], ['Offer', 'server'], ['Request', 'client'], ['Decline', 'client'],
  ['ACK', 'server'], ['NAK', 'server'], ['Release', 'client'], ['Inform', 'client'],
];

const emptyTotals = (): DirectionTotals => ({ packets: 0, bytes: 0, first: null, last: null });

function num(row: Packet, abbrev: string): number | undefined {
  const v = fieldValue(row, abbrev);
  return typeof v === 'number' ? v : undefined;
}

function text(row: Packet, abbrev: string): string | undefined {
  const v = fieldValue(row, abbrev);
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function messageOf(row: Packet): number | undefined {
  const type = num(row, 'dhcp.option.dhcp');
  return type !== undefined && type >= 1 && type <= 8 && Number.isInteger(type) ? type : undefined;
}

/**
 * The exchange a row counts in, or null: its `dhcp.id` as an unsigned 32-bit
 * number. A DHCPv4 row with a transaction id and a known message type only.
 */
export function dhcpKeyOf(row: Packet): number | null {
  const protocols = row.frameProtocols;
  if (protocols === undefined || !protocols.includes('dhcp')) return null;
  const id = num(row, 'dhcp.id');
  if (id === undefined || messageOf(row) === undefined) return null;
  return id >>> 0;
}

/** Whether the row's message type is one a client sends (ruling S3-7). */
export function dhcpFromClient(row: Packet): boolean {
  const type = messageOf(row);
  return type !== undefined && MESSAGES[type]![1] === 'client';
}

export function openDhcp(row: Packet, key: number): DhcpSummary {
  const type = messageOf(row);
  const fromServer = type !== undefined && MESSAGES[type]![1] === 'server';
  return {
    kind: 'dhcp', key,
    client: { address: text(row, 'dhcp.hw.mac_addr') ?? '', port: 68 },
    server: { address: text(row, 'dhcp.option.dhcp_server_id') ?? (fromServer ? row.source : ''), port: 67 },
    hostname: null, offered: null,
    toServer: emptyTotals(), toClient: emptyTotals(),
    firstId: row.id, lastId: row.id, start: row.relativeTime, end: row.relativeTime,
    phases: [], outcome: 'no offer', version: 0,
  };
}

/** Folds a row of the exchange into its summary. The caller has checked `dhcpKeyOf`. */
export function foldDhcp(s: DhcpSummary, row: Packet): void {
  const [message, side] = MESSAGES[messageOf(row)!]!;
  const totals = side === 'client' ? s.toServer : s.toClient;
  totals.packets++;
  totals.bytes += row.length;
  totals.first = Math.min(totals.first ?? row.relativeTime, row.relativeTime);
  totals.last = Math.max(totals.last ?? row.relativeTime, row.relativeTime);
  s.lastId = row.id;
  s.start = Math.min(s.start, row.relativeTime);
  s.end = Math.max(s.end, row.relativeTime);

  if (s.client.address === '') s.client = { address: text(row, 'dhcp.hw.mac_addr') ?? '', port: 68 };
  // The server identifier names the server whoever sent the row; the first
  // server message's source stands in until one does, and before that a client
  // message sent to an address rather than broadcast: a renewal, a release or an
  // inform goes to the server it names.
  const serverId = text(row, 'dhcp.option.dhcp_server_id');
  if (serverId !== undefined) s.server = { address: serverId, port: 67 };
  else if (s.server.address === '' && side === 'server') s.server = { address: row.source, port: 67 };
  else if (s.server.address === '' && row.destination !== '' && row.destination !== '255.255.255.255') {
    s.server = { address: row.destination, port: 67 };
  }
  if (s.hostname === null) s.hostname = text(row, 'dhcp.option.hostname') ?? null;
  s.offered = text(row, 'dhcp.ip.your') ?? s.offered;

  if (!s.phases.some((p) => p.message === message)) {
    s.phases.push({ message, side, frameId: row.id, time: row.relativeTime });
  }
  s.outcome = nextOutcome(s.outcome, message);
}

/**
 * Ruling S3-8, one message at a time: the last of ACK or NAK decides; a Decline
 * after an ACK is declined; a Release is released; otherwise an Offer is an
 * offer not taken, a Request or Inform no reply, and anything else no offer.
 * A Request after the Offer took it, so the exchange waits on the server: no reply.
 */
function nextOutcome(outcome: DhcpOutcome, message: DhcpMessage): DhcpOutcome {
  switch (message) {
    case 'ACK': return 'acked';
    case 'NAK': return 'NAK';
    case 'Release': return 'released';
    case 'Decline': return outcome === 'acked' ? 'declined' : outcome;
    case 'Offer': return outcome === 'no offer' || outcome === 'no reply' ? 'offer not taken' : outcome;
    case 'Request':
    case 'Inform': return outcome === 'no offer' || outcome === 'offer not taken' ? 'no reply' : outcome;
    default: return outcome;
  }
}
