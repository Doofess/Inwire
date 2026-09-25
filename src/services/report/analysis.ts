/**
 * Everything the report says about a capture, computed in one pass.
 *
 * An export reads the capture off disk in pages and never holds it whole, so
 * this is a fold like every piece it is built from: `add` or `addPage` as the
 * frames arrive, `finish` once at the end. Nothing here may depend on page
 * boundaries - `scripts/report/analysis.ts` folds both real captures at several
 * page sizes and requires the answers to be identical to one pass over the
 * whole array, JSON for JSON.
 *
 * ## What it is made of
 *
 * The folds the app's own panes already use, so the report and the Statistics
 * pane cannot disagree about one capture: `ConversationTable`, `EndpointTable`,
 * `HierarchyFold` and `ProcessTable` from `statistics.ts`, `TimelineFold` and
 * `SizeFold`, `ExpertLog`, and the passive `NameResolutionMap`. What is new
 * here is only what no pane shows: the signals below, and the ranking.
 *
 * ## Caller packets are not touched
 *
 * Colour rules are counted with an engine of this analyser's own, run against a
 * shallow copy of each frame with its `colorSlot` cleared. The engine caches its
 * answer on the object it is handed, so handing it the caller's frames would
 * write this engine's generation into packets the packet list is painting from.
 *
 * ## Deterministic by construction
 *
 * Every list is sorted with an explicit, total tie-break - bytes, then frames,
 * then the key as a plain string comparison (never `localeCompare`, whose
 * answer is the machine's locale). Two runs over one capture produce the same
 * report, and so does the same capture read in different pages.
 */
import type { ExpertCategory, Packet } from '../../types/packet';
import {
  ConversationTable, EndpointTable, HierarchyFold, ProcessTable,
  type Conversation, type Endpoint, type ProcessGroup, type ProtocolHierarchy,
} from '../statistics';
import { TimelineFold, rebin, type Timeline } from './timeline';
import { SizeFold, type SizeDistribution } from './sizeBuckets';
import { ExpertLog, type ExpertGroupRow } from '../expertInfo';
import { NameResolutionMap, type NameSource } from '../nameResolution';
import { ColorRulesEngine, DEFAULT_COLOR_RULES } from '../colorRules';
import { fieldValue } from '../dissect/fieldAccess';
import { Direction, directionOf, isDuplicate } from '../direction';

export interface Ranked<T> {
  /** The top rows, largest first. */
  rows: T[];
  /** How many there were in all, before the cut. */
  distinct: number;
}

export interface InterfaceShare { name: string; frames: number; bytes: number }

export interface RuleCount { id: string; name: string; frames: number }

/** A host the capture itself named, with how much traffic it carried. */
export interface NamedHost {
  address: string;
  name: string;
  source: NameSource;
  /** The frame that taught the name. */
  frame: number;
  frames: number;
  bytes: number;
}

export interface CleartextUse {
  id: CleartextId;
  label: string;
  frames: number;
  bytes: number;
}

export type CleartextId = 'http' | 'ftp' | 'telnet' | 'smtp' | 'pop3' | 'imap' | 'snmp' | 'tftp';

export interface Signals {
  tcp: {
    frames: number;
    bytes: number;
    /** Frames with the RST flag set. */
    resets: number;
    /**
     * Distinct TCP conversations that saw at least one RST, keyed exactly as
     * `ConversationTable` keys them (the unordered pair of address and port),
     * so this can never exceed `conversations.tcp.distinct`.
     */
    resetConversations: number;
    /** Frames flagged retransmission, fast retransmission or spurious retransmission. */
    retransmissions: number;
    fastRetransmissions: number;
    spuriousRetransmissions: number;
    duplicateAcks: number;
    outOfOrder: number;
    zeroWindow: number;
  };
  dns: {
    queries: number;
    responses: number;
    /** Responses whose reply code is not NOERROR. */
    errors: number;
    /** Error responses by reply code, ascending code. */
    byRcode: { rcode: number; count: number }[];
    /** Plain DNS on port 53 - readable by anyone on the path. */
    port53Frames: number;
  };
  /**
   * Each frame counts once. QUIC carries its TLS handshake inside CRYPTO
   * frames, so a QUIC Initial dissects as both; it is counted as QUIC, and
   * `tls*` is TLS over TCP alone. Counting it twice made the two shares add
   * up to more than the frames that carried them.
   */
  encrypted: {
    tlsFrames: number;
    tlsBytes: number;
    quicFrames: number;
    quicBytes: number;
    /** DNS over TLS, port 853. */
    dotFrames: number;
    /** Well-known DNS-over-HTTPS resolvers named in a TLS or QUIC SNI, sorted. */
    dohResolvers: string[];
  };
  /** Protocols that carry their payload readable on the wire, in a fixed order; only those seen. */
  cleartext: CleartextUse[];
  broadcastFrames: number;
  multicastFrames: number;
  /** The same frame captured on a second interface. */
  duplicateFrames: number;
  /** Frames by direction relative to the capturing machine. */
  direction: { out: number; in: number; transit: number; unknown: number };
}

export interface CaptureAnalysis {
  frames: number;
  bytes: number;
  /** First and last capture time by TIME, not by arrival; epoch µs. Null when empty. */
  firstUs: number | null;
  lastUs: number | null;
  durationSeconds: number;
  rates: {
    avgFramesPerSecond: number;
    avgBitsPerSecond: number;
    /** From the one-second cells, so a burst is measured over a second rather than a frame pair. */
    peakFramesPerSecond: number;
    peakBitsPerSecond: number;
    /** The second the peak happened in, relative to the capture's start. Null when empty. */
    peakFramesAt: number | null;
    peakBitsAt: number | null;
  };
  /** `end` is the second after the last one with a frame, so the last bar's real width is known. */
  timeline: Timeline & { end: number };
  /** The longest run of whole seconds with no frame at all, inside the capture's span. */
  silence: { from: number; seconds: number } | null;
  sizes: SizeDistribution & { min: number; max: number; mean: number };
  hierarchy: ProtocolHierarchy;
  /** Frames and bytes carried over IPv4 or IPv6 - the denominator of a host's share. */
  ip: { frames: number; bytes: number };
  endpoints: { ipv4: Ranked<Endpoint>; ipv6: Ranked<Endpoint> };
  conversations: {
    ipv4: Ranked<Conversation>;
    ipv6: Ranked<Conversation>;
    tcp: Ranked<Conversation>;
    udp: Ranked<Conversation>;
  };
  /** Distinct IPv4 and IPv6 addresses seen. */
  hosts: number;
  /** Addresses this machine sent from, as the direction column decided; sorted. */
  localAddresses: string[];
  /**
   * The endpoint with the most bytes that is neither this machine nor a group
   * address, over the whole endpoint tables rather than the top rows.
   *
   * Decided here, on the real addresses, and not by whoever reads the
   * analysis: after anonymising, Crypto-PAn can map a unicast address into a
   * multicast range, and a reader classifying the pseudonym would skip the
   * real busiest host for it.
   */
  topRemote: (Endpoint & { family: 'ipv4' | 'ipv6' }) | null;
  /** How many rows each ranked table keeps. */
  top: number;
  expert: {
    /** Findings, not frames: a frame may carry several. */
    total: number;
    counts: Record<ExpertCategory, number>;
    groups: ExpertGroupRow[];
  };
  /** Hosts the capture named, busiest first. */
  names: NamedHost[];
  processes: ProcessGroup[];
  interfaces: InterfaceShare[];
  /** Frames per colour rule, in chain order, rules that matched nothing omitted. */
  colorRules: RuleCount[];
  /** Frames no colour rule matched. */
  uncoloured: number;
  signals: Signals;
}

export interface AnalyzerOptions {
  /** How many rows each ranked table keeps. */
  top?: number;
  /** How many bars the timeline may have. */
  maxBars?: number;
}

/** How many frame numbers a group row keeps - the report prints a few, not two hundred. */
const GROUP_FRAMES = 8;
/** How many local addresses are remembered. A host with more is not one host. */
const MAX_LOCAL = 64;

const RCODE_ERR = 0;

/**
 * Resolvers that answer DNS over HTTPS, by the name a client asks for.
 *
 * DoH is ordinary HTTPS on 443, so the one thing that gives it away on the
 * wire is the server name. The list is the public resolvers browsers and
 * operating systems ship with; a private resolver is invisible to it, which is
 * why the report says "seen" rather than "absent".
 */
const DOH_RESOLVERS: ReadonlySet<string> = new Set([
  'dns.google', 'dns.google.com', 'dns64.dns.google',
  'cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'chrome.cloudflare-dns.com',
  'one.one.one.one', '1dot1dot1dot1.cloudflare-dns.com', 'security.cloudflare-dns.com',
  'family.cloudflare-dns.com',
  'dns.quad9.net', 'dns9.quad9.net', 'dns10.quad9.net', 'dns11.quad9.net',
  'doh.opendns.com', 'doh.familyshield.opendns.com',
  'dns.nextdns.io', 'doh.cleanbrowsing.org', 'dns.adguard-dns.com', 'dns.adguard.com',
  'doh.mullvad.net', 'dns.mullvad.net', 'freedns.controld.com',
]);

/**
 * Cleartext protocols this build has no dissector for, found by their port.
 *
 * Only frames carrying data count: a SYN to port 23 that was refused is a
 * connection attempt, not Telnet, and a report that listed it as cleartext use
 * would be accusing a host of something it never did.
 */
const CLEARTEXT_PORTS: readonly { id: CleartextId; port: number }[] = [
  { id: 'ftp', port: 21 },
  { id: 'telnet', port: 23 },
  { id: 'smtp', port: 25 },
  { id: 'pop3', port: 110 },
  { id: 'imap', port: 143 },
];

export const CLEARTEXT_LABELS: Record<CleartextId, string> = {
  http: 'HTTP',
  ftp: 'FTP',
  telnet: 'Telnet',
  smtp: 'SMTP',
  pop3: 'POP3',
  imap: 'IMAP',
  snmp: 'SNMP v1/v2c',
  tftp: 'TFTP',
};

const CLEARTEXT_ORDER: readonly CleartextId[] = ['http', 'ftp', 'telnet', 'smtp', 'pop3', 'imap', 'snmp', 'tftp'];

function num(packet: Packet, abbrev: string): number | undefined {
  const v = fieldValue(packet, abbrev);
  return typeof v === 'number' ? v : undefined;
}

function str(packet: Packet, abbrev: string): string | undefined {
  const v = fieldValue(packet, abbrev);
  return typeof v === 'string' ? v : undefined;
}

/** A plain code-unit comparison, so an order never depends on the machine's locale. */
function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function rankEndpoints(rows: Endpoint[], top: number): Ranked<Endpoint> {
  rows.sort((a, b) => b.bytes - a.bytes || b.packets - a.packets || cmp(a.address, b.address));
  return { rows: rows.slice(0, top), distinct: rows.length };
}

function rankConversations(rows: Conversation[], top: number): Ranked<Conversation> {
  rows.sort((a, b) => b.bytes - a.bytes || b.packets - a.packets || cmp(a.key, b.key));
  return { rows: rows.slice(0, top), distinct: rows.length };
}

/** A broadcast or multicast IP address: nobody's, so never "the busiest host". */
export function isGroupAddress(address: string): boolean {
  if (address.includes(':')) return address.toLowerCase().startsWith('ff');
  const first = Number(address.split('.')[0]);
  return address === '255.255.255.255' || (first >= 224 && first <= 239);
}

/** Is a destination MAC broadcast, multicast, or neither. */
function macScope(mac: string): 'broadcast' | 'multicast' | null {
  if (mac === 'ff:ff:ff:ff:ff:ff') return 'broadcast';
  const first = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 1) === 1 ? 'multicast' : null;
}

/** The same question for a frame with no Ethernet header, from its IP destination. */
function ipScope(packet: Packet): 'broadcast' | 'multicast' | null {
  const v4 = str(packet, 'ip.dst');
  if (v4 !== undefined) {
    if (v4 === '255.255.255.255') return 'broadcast';
    const first = Number(v4.split('.')[0]);
    return first >= 224 && first <= 239 ? 'multicast' : null;
  }
  const v6 = str(packet, 'ipv6.dst');
  return v6 !== undefined && v6.toLowerCase().startsWith('ff') ? 'multicast' : null;
}

export class CaptureAnalyzer {
  private readonly top: number;
  private readonly maxBars: number;

  private frames = 0;
  private bytes = 0;
  private firstUs = Number.POSITIVE_INFINITY;
  private lastUs = Number.NEGATIVE_INFINITY;
  private minLength = Number.POSITIVE_INFINITY;
  private maxLength = 0;

  private readonly timeline = new TimelineFold();
  private readonly sizes = new SizeFold();
  private readonly hierarchy = new HierarchyFold();
  private readonly endpointsV4 = new EndpointTable('ipv4');
  private readonly endpointsV6 = new EndpointTable('ipv6');
  private readonly convV4 = new ConversationTable('ipv4');
  private readonly convV6 = new ConversationTable('ipv6');
  private readonly convTcp = new ConversationTable('tcp');
  private readonly convUdp = new ConversationTable('udp');
  private readonly processes = new ProcessTable();
  // No per-frame state: a report over a whole capture needs the groups and the
  // counts, and one Map entry per flagged frame is what would run out first.
  private readonly expert = new ExpertLog(false);
  private readonly names = new NameResolutionMap();
  private readonly colors = new ColorRulesEngine();
  private readonly ruleFrames = new Map<string, number>();
  private uncoloured = 0;
  private readonly interfaces = new Map<string, InterfaceShare>();
  private readonly local = new Set<string>();

  private ipFrames = 0;
  private ipBytes = 0;

  private readonly tcp = {
    frames: 0, bytes: 0, resets: 0, retransmissions: 0, fastRetransmissions: 0,
    spuriousRetransmissions: 0, duplicateAcks: 0, outOfOrder: 0, zeroWindow: 0,
  };
  private readonly resetKeys = new Set<string>();
  private readonly dns = { queries: 0, responses: 0, errors: 0, port53Frames: 0 };
  private readonly rcodes = new Map<number, number>();
  private readonly enc = { tlsFrames: 0, tlsBytes: 0, quicFrames: 0, quicBytes: 0, dotFrames: 0 };
  private readonly doh = new Set<string>();
  private readonly cleartext = new Map<CleartextId, { frames: number; bytes: number }>();
  private broadcastFrames = 0;
  private multicastFrames = 0;
  private duplicateFrames = 0;
  private readonly direction = { out: 0, in: 0, transit: 0, unknown: 0 };

  constructor(options: AnalyzerOptions = {}) {
    this.top = Math.max(1, Math.floor(options.top ?? 10));
    this.maxBars = options.maxBars ?? 120;
  }

  addPage(page: readonly Packet[]): void {
    for (const packet of page) this.add(packet);
  }

  add(packet: Packet): void {
    const length = packet.length;
    this.frames += 1;
    this.bytes += length;
    if (packet.tsUs < this.firstUs) this.firstUs = packet.tsUs;
    if (packet.tsUs > this.lastUs) this.lastUs = packet.tsUs;
    if (length < this.minLength) this.minLength = length;
    if (length > this.maxLength) this.maxLength = length;

    this.timeline.add(packet);
    this.sizes.add(packet);
    this.hierarchy.add(packet);
    this.endpointsV4.add(packet);
    this.endpointsV6.add(packet);
    this.convV4.add(packet);
    this.convV6.add(packet);
    this.convTcp.add(packet);
    this.convUdp.add(packet);
    this.processes.add(packet);
    this.expert.add(packet);
    this.names.learnFromPacket(packet);

    // A copy with no cache, so the engine writes its answer there and not on
    // the frame the caller still holds.
    const copy: Packet = { ...packet, colorSlot: undefined };
    this.colors.resolve(copy);
    const rule = this.colors.matchedRuleIfKnown(copy);
    if (rule) this.ruleFrames.set(rule.id, (this.ruleFrames.get(rule.id) ?? 0) + 1);
    else this.uncoloured += 1;

    const iface = packet.interfaceName || 'unknown';
    let share = this.interfaces.get(iface);
    if (!share) {
      share = { name: iface, frames: 0, bytes: 0 };
      this.interfaces.set(iface, share);
    }
    share.frames += 1;
    share.bytes += length;

    const layers = packet.frameProtocols ?? [];
    const has = (token: string) => layers.includes(token);
    const isIp = has('ip') || has('ipv6');
    if (isIp) {
      this.ipFrames += 1;
      this.ipBytes += length;
    }

    switch (directionOf(packet.direction)) {
      case Direction.Out:
        this.direction.out += 1;
        if (isIp && this.local.size < MAX_LOCAL && packet.source) this.local.add(packet.source);
        break;
      case Direction.In: this.direction.in += 1; break;
      case Direction.Transit: this.direction.transit += 1; break;
      default: this.direction.unknown += 1;
    }
    if (isDuplicate(packet.direction)) this.duplicateFrames += 1;

    const ethDst = str(packet, 'eth.dst');
    const scope = ethDst !== undefined ? macScope(ethDst) : ipScope(packet);
    if (scope === 'broadcast') this.broadcastFrames += 1;
    else if (scope === 'multicast') this.multicastFrames += 1;

    if (has('tcp')) this.addTcp(packet, length);
    if (has('dns')) this.addDns(packet);
    if (has('quic')) {
      this.enc.quicFrames += 1;
      this.enc.quicBytes += length;
    } else if (has('tls')) {
      this.enc.tlsFrames += 1;
      this.enc.tlsBytes += length;
    }
    const sni = str(packet, 'tls.handshake.extensions_server_name');
    if (sni !== undefined && DOH_RESOLVERS.has(sni.toLowerCase())) this.doh.add(sni.toLowerCase());

    if (has('http')) this.bumpCleartext('http', length);
    if (has('tftp')) this.bumpCleartext('tftp', length);
    if (has('snmp')) {
      // 0 is v1 and 1 is v2c; both carry the community string in the clear.
      // v3 (3) authenticates and may encrypt, so it is not listed.
      const version = num(packet, 'snmp.version');
      if (version === 0 || version === 1) this.bumpCleartext('snmp', length);
    }
  }

  private bumpCleartext(id: CleartextId, length: number): void {
    const use = this.cleartext.get(id) ?? { frames: 0, bytes: 0 };
    use.frames += 1;
    use.bytes += length;
    this.cleartext.set(id, use);
  }

  private addTcp(packet: Packet, length: number): void {
    const t = this.tcp;
    t.frames += 1;
    t.bytes += length;

    const sp = num(packet, 'tcp.srcport');
    const dp = num(packet, 'tcp.dstport');

    if (num(packet, 'tcp.flags.reset') === 1) {
      t.resets += 1;
      // The unordered pair of ends, which is the conversation table's own
      // identity - one conversation is one key whichever side reset it.
      const a = `${packet.source}|${sp ?? ''}`;
      const b = `${packet.destination}|${dp ?? ''}`;
      this.resetKeys.add(a < b ? `${a}|${b}` : `${b}|${a}`);
    }

    const flags = packet.analysisFlags;
    if (flags && flags.length > 0) {
      const retrans = flags.includes('retransmission');
      const fast = flags.includes('fast_retransmission');
      const spurious = flags.includes('spurious_retransmission');
      if (retrans || fast || spurious) t.retransmissions += 1;
      if (fast) t.fastRetransmissions += 1;
      if (spurious) t.spuriousRetransmissions += 1;
      if (flags.includes('duplicate_ack')) t.duplicateAcks += 1;
      if (flags.includes('out_of_order')) t.outOfOrder += 1;
      if (flags.includes('zero_window')) t.zeroWindow += 1;
    }

    if (sp === 853 || dp === 853) this.enc.dotFrames += 1;

    const payload = num(packet, 'tcp.len') ?? 0;
    if (payload > 0) {
      for (const { id, port } of CLEARTEXT_PORTS) {
        if (sp === port || dp === port) {
          this.bumpCleartext(id, length);
          break;
        }
      }
    }
  }

  private addDns(packet: Packet): void {
    const response = num(packet, 'dns.flags.response');
    if (response === 1) {
      this.dns.responses += 1;
      const rcode = num(packet, 'dns.flags.rcode');
      if (rcode !== undefined && rcode !== RCODE_ERR) {
        this.dns.errors += 1;
        this.rcodes.set(rcode, (this.rcodes.get(rcode) ?? 0) + 1);
      }
    } else if (response === 0) {
      this.dns.queries += 1;
    }
    const ports = [num(packet, 'udp.srcport'), num(packet, 'udp.dstport'), num(packet, 'tcp.srcport'), num(packet, 'tcp.dstport')];
    if (ports.includes(53)) this.dns.port53Frames += 1;
  }

  finish(): CaptureAnalysis {
    const empty = this.frames === 0;
    const firstUs = empty ? null : this.firstUs;
    const lastUs = empty ? null : this.lastUs;
    const durationSeconds = empty ? 0 : (this.lastUs - this.firstUs) / 1e6;

    // Peak and silence from the one-second cells. Keys are sorted so a tie
    // resolves to the earliest second, whatever order the pages came in.
    const seconds = [...this.timeline.seconds.keys()].sort((a, b) => a - b);
    let peakFrames = 0; let peakFramesAt: number | null = null;
    let peakBytes = 0; let peakBytesAt: number | null = null;
    let silence: { from: number; seconds: number } | null = null;
    for (let i = 0; i < seconds.length; i++) {
      const cell = this.timeline.seconds.get(seconds[i])!;
      if (cell.frames > peakFrames) { peakFrames = cell.frames; peakFramesAt = seconds[i]; }
      if (cell.bytes > peakBytes) { peakBytes = cell.bytes; peakBytesAt = seconds[i]; }
      if (i > 0) {
        const gap = seconds[i] - seconds[i - 1] - 1;
        if (gap > 0 && (silence === null || gap > silence.seconds)) silence = { from: seconds[i - 1] + 1, seconds: gap };
      }
    }
    // Averages over the span the capture covers. A capture of one frame, or of
    // frames all stamped in the same microsecond, has no span to divide by and
    // reports its totals as its rate rather than infinity.
    const span = durationSeconds > 0 ? durationSeconds : 1;

    const endpointsV4 = this.endpointsV4.result();
    const endpointsV6 = this.endpointsV6.result();
    const traffic = new Map<string, Endpoint>();
    for (const e of endpointsV4) traffic.set(e.address, e);
    for (const e of endpointsV6) traffic.set(e.address, e);

    // Only names for addresses: a MAC-keyed name belongs to the device
    // inventory, and the report's hosts are the ones the tables list.
    const names: NamedHost[] = this.names.entries()
      .filter((h) => traffic.has(h.address))
      .map((h) => {
        const e = traffic.get(h.address)!;
        return { address: h.address, name: h.name, source: h.source, frame: h.frame, frames: e.packets, bytes: e.bytes };
      })
      .sort((a, b) => b.bytes - a.bytes || b.frames - a.frames || cmp(a.address, b.address));

    const expertCounts = this.expert.counts();
    let expertTotal = 0;
    for (const c of Object.values(expertCounts)) expertTotal += c;
    const groups = this.expert.groups().map((g) => ({ ...g, frames: g.frames.slice(0, GROUP_FRAMES) }));

    const colorRules: RuleCount[] = [];
    for (const rule of DEFAULT_COLOR_RULES) {
      const frames = this.ruleFrames.get(rule.id);
      if (frames) colorRules.push({ id: rule.id, name: rule.name, frames });
    }

    const processes = this.processes.result()
      .sort((a, b) => b.bytes - a.bytes || b.packets - a.packets || a.pid - b.pid);

    const interfaces = [...this.interfaces.values()]
      .map((i) => ({ ...i }))
      .sort((a, b) => b.frames - a.frames || cmp(a.name, b.name));

    const sizes = this.sizes.result();

    const local = this.local;
    let topRemote: CaptureAnalysis['topRemote'] = null;
    for (const [family, rows] of [['ipv4', endpointsV4], ['ipv6', endpointsV6]] as const) {
      for (const e of rows) {
        if (local.has(e.address) || isGroupAddress(e.address)) continue;
        if (topRemote === null || e.bytes > topRemote.bytes
          || (e.bytes === topRemote.bytes && (e.packets > topRemote.packets
            || (e.packets === topRemote.packets && cmp(e.address, topRemote.address) < 0)))) {
          topRemote = { ...e, family };
        }
      }
    }

    return {
      frames: this.frames,
      bytes: this.bytes,
      firstUs,
      lastUs,
      durationSeconds,
      rates: {
        avgFramesPerSecond: this.frames / span,
        avgBitsPerSecond: (this.bytes * 8) / span,
        peakFramesPerSecond: peakFrames,
        peakBitsPerSecond: peakBytes * 8,
        peakFramesAt,
        peakBitsAt: peakBytesAt,
      },
      timeline: { ...rebin(this.timeline, this.maxBars), end: seconds.length > 0 ? seconds[seconds.length - 1] + 1 : 0 },
      silence,
      sizes: {
        ...sizes,
        min: empty ? 0 : this.minLength,
        max: this.maxLength,
        mean: empty ? 0 : this.bytes / this.frames,
      },
      hierarchy: this.hierarchy.result(),
      ip: { frames: this.ipFrames, bytes: this.ipBytes },
      endpoints: {
        ipv4: rankEndpoints(endpointsV4, this.top),
        ipv6: rankEndpoints(endpointsV6, this.top),
      },
      conversations: {
        ipv4: rankConversations(this.convV4.result(), this.top),
        ipv6: rankConversations(this.convV6.result(), this.top),
        tcp: rankConversations(this.convTcp.result(), this.top),
        udp: rankConversations(this.convUdp.result(), this.top),
      },
      hosts: endpointsV4.length + endpointsV6.length,
      localAddresses: [...this.local].sort(cmp),
      topRemote,
      top: this.top,
      expert: { total: expertTotal, counts: expertCounts, groups },
      names,
      processes,
      interfaces,
      colorRules,
      uncoloured: this.uncoloured,
      signals: {
        tcp: { ...this.tcp, resetConversations: this.resetKeys.size },
        dns: {
          ...this.dns,
          byRcode: [...this.rcodes].sort((a, b) => a[0] - b[0]).map(([rcode, count]) => ({ rcode, count })),
        },
        encrypted: { ...this.enc, dohResolvers: [...this.doh].sort(cmp) },
        cleartext: CLEARTEXT_ORDER
          .filter((id) => this.cleartext.has(id))
          .map((id) => ({ id, label: CLEARTEXT_LABELS[id], ...this.cleartext.get(id)! })),
        broadcastFrames: this.broadcastFrames,
        multicastFrames: this.multicastFrames,
        duplicateFrames: this.duplicateFrames,
        direction: { ...this.direction },
      },
    };
  }
}

/** One pass over an array, for a caller that has one. */
export function analyseCapture(packets: readonly Packet[], options?: AnalyzerOptions): CaptureAnalysis {
  const analyzer = new CaptureAnalyzer(options);
  analyzer.addPage(packets);
  return analyzer.finish();
}
