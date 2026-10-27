import React, { useMemo, useState } from 'react';
import { ChartColumn, ChevronDown, ChevronRight, Filter } from 'lucide-react';

import { Packet } from '../../types/packet';
import {
  conversations, endpoints, protocolHierarchy, devices, processes, processFilter,
  conversationFilter, endpointFilter, deviceFilter,
  type Conversation, type ConversationKind, type Device, type Endpoint, type HierarchyNode,
  type ProcessGroup,
} from '../../services/statistics';
import { flowAnnotations } from '../../services/flowAnnotations';
import { resolveMacVendor } from '../../services/macVendors';
import type { StreamTarget } from '../../services/followStream';
import { conversationRows, digestScopeNote, outcomeText, type DigestConversation } from '../../services/conversation/digestRows';
import type { StreamSummary } from '../../services/conversation/streamDigest';
import type { QuicSummary, UdpSummary } from '../../services/conversation/flowSummary';
import type { TlsSummary } from '../../services/conversation/tlsSummary';
import type { DhcpSummary } from '../../services/conversation/dhcpSummary';
import { NameLookup, SOURCE_LABELS } from '../../services/nameResolution';
import {
  CATEGORY_HINTS, CATEGORY_LABELS, CATEGORY_ORDER, CATEGORY_TEXT,
  type ExpertGroupRow, type ExpertLookup,
} from '../../services/expertInfo';
import { portLabel } from '../../services/portServices';
import { copyText } from '../ui/CopyButton';
import { StatTable, bitrate, bytes, count, seconds, type StatColumn } from './StatTable';
import { MICRO_LABEL } from '../common/typography';
import { GraphsTab } from './GraphsTab';
import {
  ContextMenu, ContextMenuTrigger, ContextMenuContent,
  ContextMenuLabel, ContextMenuItem, ContextMenuSeparator,
} from '../ui/context-menu';

/**
 * Conversations, endpoints, the protocol hierarchy and the passive name map.
 *
 * The four answers a capture is opened to get, on four tabs. The aggregation
 * itself is in `services/statistics.ts` and `services/nameResolution.ts` so it
 * can be asserted; this file is the presentation and nothing else.
 *
 * Every row leads to its frames - clicking one applies the display filter that
 * selects exactly them, which is the shortest path there is from "this pair
 * moved 7 MB" to looking at the frames that did it. The filters come from the
 * statistics module rather than being spelled out here, so the row and the
 * filter can never disagree about what the row meant.
 *
 * A TCP or UDP conversation row is one stream, so its click opens that stream
 * on the ladder instead, and the filter moves to a button on the row. The TCP
 * level is the one table that does not count the buffer: it reads the store's
 * stream digest, the whole capture with each stream's outcome (ADR 0055).
 */

/** The empty digest, one identity, so a pane without one memoizes. */
const NO_DIGEST = {
  summaries: new Map<number, StreamSummary>() as ReadonlyMap<number, StreamSummary>,
  udp: new Map<number, UdpSummary>() as ReadonlyMap<number, UdpSummary>,
  quic: new Map<number, QuicSummary>() as ReadonlyMap<number, QuicSummary>,
  tls: new Map<number, TlsSummary>() as ReadonlyMap<number, TlsSummary>,
  dhcp: new Map<number, DhcpSummary>() as ReadonlyMap<number, DhcpSummary>,
  captureEnd: 0,
  finished: false,
  rebuilding: null as { done: number; total: number } | null,
  partial: false,
};

type Tab = 'hierarchy' | 'conversations' | 'endpoints' | 'devices' | 'processes'
  | 'graphs' | 'expert' | 'names';

const CONVERSATION_TABS: { id: ConversationKind; label: string }[] = [
  { id: 'eth', label: 'Ethernet' },
  { id: 'ipv4', label: 'IPv4' },
  { id: 'ipv6', label: 'IPv6' },
  { id: 'tcp', label: 'TCP' },
  { id: 'udp', label: 'UDP' },
  { id: 'quic', label: 'QUIC' },
  { id: 'dhcp', label: 'DHCP' },
];

interface StatisticsPaneProps {
  /** The whole buffer. The tables count the capture, not the filtered view. */
  packets: Packet[];
  /** What the capture says its addresses are called. */
  names: NameLookup;
  resolveNames: boolean;
  resolvePorts: boolean;
  /** Applies a display filter in the packet list. Pairs with the return below. */
  onApplyFilter: (expression: string) => void;
  /** Opens the stream follower on a TCP or UDP conversation. */
  onFollowStream?: (target: StreamTarget, view?: 'dialogue' | 'ladder') => void;
  /**
   * The store's stream digest (ADR 0055), which answers the TCP, UDP, QUIC and
   * DHCP levels for the whole capture where the buffer can only count what it still
   * holds - and knows how each flow ended, which a pair count cannot.
   */
  digest?: {
    summaries: ReadonlyMap<number, StreamSummary>;
    udp: ReadonlyMap<number, UdpSummary>;
    quic: ReadonlyMap<number, QuicSummary>;
    tls: ReadonlyMap<number, TlsSummary>;
    dhcp: ReadonlyMap<number, DhcpSummary>;
    /** The latest frame time folded, which "went quiet" is measured against. */
    captureEnd: number;
    /** No capture is running, so no answer can still arrive: a DNS query still open is unanswered. */
    finished: boolean;
    rebuilding: { done: number; total: number } | null;
    /** A rebuild dropped rows, so these levels are not the whole capture. */
    partial?: boolean;
  };
  /** Everything the dissectors and the anomaly detector found. */
  expert: ExpertLookup;
  /** Selects a frame in the main window. */
  onSelectFrame?: (frameNumber: number) => void;
  /**
   * Frames the buffer has dropped since this capture began, or 0.
   *
   * These tables count the buffer and are titled "Capture Statistics", and
   * those are the same thing right up until the buffer fills. Past that they
   * are not, and the difference is invisible: a conversation table answering
   * for the most recent 100,000 frames of a two-million-frame capture is the
   * same table with different numbers. The header says so when this is
   * non-zero.
   */
  droppedBuffer?: number;
  /**
   * Leaves for the packet list.
   *
   * Named for what it does rather than `onClose`, which is what it was called
   * while this was a dialog. Every row here is a filter, and applying one means
   * going to look at the frames it selects - so this is not a dismissal, it is
   * the second half of the action. Calling it `onClose` on a pane would also
   * invite somebody to put a close button back on a surface that has no dialog
   * to close.
   */
  onReturnToPackets: () => void;
  /**
   * Passed through to the Graphs tab, which is the only thing in this pane that
   * draws rather than tabulates.
   *
   * `themeKey` is not used for styling. The timeline's D3 draw is imperative, so
   * it needs something in its dependency list that changes on a theme switch -
   * and `isDark` alone cannot do it if two themes of the same polarity are ever
   * added back, which they have been before.
   */
  isDark: boolean;
  themeKey?: string;
}

export const StatisticsPane: React.FC<StatisticsPaneProps> = ({
  packets,
  names,
  resolveNames,
  resolvePorts,
  expert,
  onApplyFilter,
  onFollowStream,
  digest,
  onSelectFrame,
  droppedBuffer = 0,
  onReturnToPackets,
  isDark,
  themeKey,
}) => {
  const [tab, setTab] = useState<Tab>('hierarchy');
  const [kind, setKind] = useState<ConversationKind>('ipv4');
  const [menuRow, setMenuRow] = useState<{
    filter: string;
    title: string;
    stream?: StreamTarget;
    frame?: number;
  } | null>(null);

  const hierarchy = useMemo(() => protocolHierarchy(packets), [packets]);
  const held = digest ?? NO_DIGEST;
  // The digest's rows where it answers the level, the buffer's count elsewhere.
  const digestRows = useMemo(
    () => conversationRows(kind, held),
    [kind, held.summaries, held.udp, held.quic, held.tls, held.dhcp],
  );
  const bufferRows = useMemo(
    () => (digestRows === null ? conversations(packets, kind) : []),
    [packets, kind, digestRows],
  );
  const convRows: Conversation[] = digestRows ?? bufferRows;
  const scopeNote = tab === 'conversations'
    ? digestScopeNote(kind, held, held.rebuilding, held.partial ?? false)
    : null;
  const transport = kind === 'tcp' || kind === 'udp' || kind === 'quic' || kind === 'dhcp';
  /** A TCP, UDP, QUIC or DHCP row is one stream; an address row is many, with no single one to open. */
  const streamOf = (r: Conversation): StreamTarget | undefined =>
    (kind === 'tcp' || kind === 'udp' || kind === 'quic' || kind === 'dhcp') && r.portA !== undefined && r.portB !== undefined
      ? { kind, addressA: r.addressA, portA: r.portA, addressB: r.addressB, portB: r.portB, streamId: r.streamId }
      : undefined;
  const endpointRows = useMemo(() => endpoints(packets, kind), [packets, kind]);
  const nameRows = useMemo(
    () => names.entries().sort((a, b) => a.name.localeCompare(b.name)),
    [names],
  );
  const deviceRows = useMemo(() => devices(packets), [packets]);
  // The peer column needs to know which end of a frame is this machine, and
  // the annotation store is the only thing that knows - it learned the local
  // addresses from the socket table itself.
  const processRows = useMemo(
    () => processes(packets, (address) => flowAnnotations.isLocalAddress(address)),
    [packets],
  );
  const deviceName = (d: Device): string | undefined =>
    names.macName(d.mac) ?? (d.addresses.length === 1 ? names.hostName(d.addresses[0]) : undefined);
  const expertRows = useMemo(() => expert.groups(), [expert]);
  const expertCounts = useMemo(() => expert.counts(), [expert]);

  /** An address as the tables should read it, with the address kept as a title. */
  const addr = (value: string) => {
    const name = resolveNames ? names.hostName(value) ?? names.macName(value) : undefined;
    return <span title={value}>{name ?? value}</span>;
  };
  const port = (value: number | undefined) =>
    value === undefined ? '' : portLabel(value, kind === 'udp' || kind === 'quic' || kind === 'dhcp' ? 'udp' : 'tcp', resolvePorts);

  const apply = (expression: string) => {
    onApplyFilter(expression);
    onReturnToPackets();
  };

  /**
   * When a direction was active, as one cell.
   *
   * A single instant reads as itself rather than as a zero-length range: a
   * conversation with one frame each way is common, and "0.100 s - 0.100 s"
   * is noise where "0.100 s" is a fact.
   */
  const span = (first: number | null, last: number | null) => {
    if (first === null || last === null) return '—';
    return first === last
      ? `${first.toFixed(3)} s`
      : `${first.toFixed(3)} – ${last.toFixed(3)} s`;
  };

  const conversationColumns: StatColumn<Conversation>[] = [
    { key: 'a', label: 'Address A', render: (r) => addr(r.addressA), sortValue: (r) => r.addressA, className: 'max-w-[15rem]' },
    ...(transport
      ? [{ key: 'pa', label: 'Port A', align: 'right' as const, render: (r: Conversation) => port(r.portA), sortValue: (r: Conversation) => r.portA ?? 0 }]
      : []),
    { key: 'b', label: 'Address B', render: (r) => addr(r.addressB), sortValue: (r) => r.addressB, className: 'max-w-[15rem]' },
    ...(transport
      ? [{ key: 'pb', label: 'Port B', align: 'right' as const, render: (r: Conversation) => port(r.portB), sortValue: (r: Conversation) => r.portB ?? 0 }]
      : []),
    { key: 'proto', label: 'Protocol', render: (r) => r.protocol, sortValue: (r) => r.protocol },
    // How the stream ended, which only the digest knows. A stream still open
    // is the ordinary case and is set back, so the endings that need
    // explaining - a reset, a half close - are what the eye lands on.
    ...(digestRows !== null
      ? [{
        key: 'outcome', label: 'Outcome',
        render: (r: Conversation) => {
          const d = r as DigestConversation;
          return (
            <span className={d.kind === 'tcp' && d.outcome === 'open' ? 'text-muted-foreground' : undefined}>
              {outcomeText(d, held.captureEnd, held.finished)}
            </span>
          );
        },
        // The text the cell shows, so the order matches what is read: the bare
        // outcome has no tally, no "went quiet" and no TLS note.
        sortValue: (r: Conversation) => outcomeText(r as DigestConversation, held.captureEnd, held.finished),
      }]
      : []),
    { key: 'packets', label: 'Packets', align: 'right', render: (r) => count(r.packets), sortValue: (r) => r.packets },
    { key: 'bytes', label: 'Bytes', align: 'right', render: (r) => bytes(r.bytes), sortValue: (r) => r.bytes },
    { key: 'ab', label: 'A → B', align: 'right', render: (r) => count(r.packetsAtoB), sortValue: (r) => r.packetsAtoB },
    { key: 'abBytes', label: 'A → B bytes', align: 'right', render: (r) => bytes(r.bytesAtoB), sortValue: (r) => r.bytesAtoB },
    { key: 'ba', label: 'B → A', align: 'right', render: (r) => count(r.packetsBtoA), sortValue: (r) => r.packetsBtoA },
    { key: 'baBytes', label: 'B → A bytes', align: 'right', render: (r) => bytes(r.bytesBtoA), sortValue: (r) => r.bytesBtoA },
    // Per direction, because one Start and one Duration describe the pair and
    // hide what is usually the question: a request at 0.1s answered at 4.2s,
    // or one side that went quiet a minute before the other did, both read as
    // a healthy conversation when there is only one span for the two of them.
    // An em dash for a direction that never spoke - which is itself a finding,
    // and is not the same as a duration of zero.
    { key: 'abSpan', label: 'A → B span', align: 'right',
      render: (r) => span(r.firstAtoB, r.lastAtoB), sortValue: (r) => r.firstAtoB ?? Infinity },
    { key: 'baSpan', label: 'B → A span', align: 'right',
      render: (r) => span(r.firstBtoA, r.lastBtoA), sortValue: (r) => r.firstBtoA ?? Infinity },
    { key: 'start', label: 'Start', align: 'right', render: (r) => `${r.startRel.toFixed(3)} s`, sortValue: (r) => r.startRel },
    { key: 'dur', label: 'Duration', align: 'right', render: (r) => seconds(r.duration), sortValue: (r) => r.duration },
    { key: 'rate', label: 'Bits/s', align: 'right', render: (r) => bitrate(r.bytes, r.duration), sortValue: (r) => (r.duration > 0 ? r.bytes / r.duration : 0) },
    // A transport row's click opens its stream, so filtering - what the click
    // did before, and still does on the address levels - keeps a control of
    // its own on the row rather than living only in the context menu.
    ...(transport
      ? [{
        key: 'filter', label: '',
        render: (r: Conversation) => (
          <button
            type="button"
            aria-label="Filter to this conversation"
            title="Filter to this conversation"
            onClick={(event) => { event.stopPropagation(); apply(conversationFilter(r, kind)); }}
            className="p-1 -my-1 rounded text-muted-foreground hover:text-foreground hover:bg-accent"
          >
            <Filter className="w-3 h-3" />
          </button>
        ),
      }]
      : []),
  ];

  const endpointColumns: StatColumn<Endpoint>[] = [
    { key: 'addr', label: 'Address', render: (r) => addr(r.address), sortValue: (r) => r.address, className: 'max-w-[18rem]' },
    ...(kind === 'tcp' || kind === 'udp'
      ? [{ key: 'port', label: 'Port', align: 'right' as const, render: (r: Endpoint) => port(r.port), sortValue: (r: Endpoint) => r.port ?? 0 }]
      : []),
    { key: 'packets', label: 'Packets', align: 'right', render: (r) => count(r.packets), sortValue: (r) => r.packets },
    { key: 'bytes', label: 'Bytes', align: 'right', render: (r) => bytes(r.bytes), sortValue: (r) => r.bytes },
    { key: 'tx', label: 'Tx packets', align: 'right', render: (r) => count(r.packetsTx), sortValue: (r) => r.packetsTx },
    { key: 'txb', label: 'Tx bytes', align: 'right', render: (r) => bytes(r.bytesTx), sortValue: (r) => r.bytesTx },
    { key: 'rx', label: 'Rx packets', align: 'right', render: (r) => count(r.packetsRx), sortValue: (r) => r.packetsRx },
    { key: 'rxb', label: 'Rx bytes', align: 'right', render: (r) => bytes(r.bytesRx), sortValue: (r) => r.bytesRx },
  ];

  const tabClass = (id: Tab) =>
    `px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors ${
      tab === id
        ? 'bg-primary text-primary-foreground shadow-sm'
        : 'text-muted-foreground hover:text-foreground hover:bg-accent'
    }`;

  const kindClass = (id: ConversationKind) =>
    `px-2 py-0.5 rounded text-[11px] transition-colors cursor-pointer ${
      kind === id ? 'bg-accent text-primary font-bold' : 'text-muted-foreground hover:text-foreground'
    }`;

  /*
   * A pane, not a dialog.
   *
   * What went when it stopped being one: the `fixed inset-0` scrim that darkened
   * the packet list it describes, the centred 85vh panel, the rounded border and
   * the shadow that said "floating", the entrance animation, and the close
   * button. What stayed is everything that was actually the statistics.
   *
   * `min-h-0` on a flex child is load-bearing - without it the tables below grow
   * the pane instead of scrolling inside it, which in a dialog was bounded by the
   * 85vh and here would push the window's own chrome off screen.
   */
  return (
    <div className="flex-1 min-w-0 flex flex-col overflow-hidden bg-card text-card-foreground">
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <ChartColumn className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Capture Statistics</div>
              <p className="text-xs text-muted-foreground">
                {count(packets.length)} frames · {bytes(hierarchy.bytes)} · click a row to see its frames
              </p>
              {/* Named as a range rather than a count, because "counted
                  1,900,000 of 2,000,000" still invites the reader to treat the
                  tables as the capture. Frame numbers are what the rest of the
                  app addresses frames by, so they are what says which part of
                  it this is. */}
              {/* The TCP level answers from the digest, so the buffer's
                  limits are not its limits: it says its own scope instead. */}
              {scopeNote !== null && (
                <p className="mt-0.5 text-[11px] text-muted-foreground">{scopeNote}</p>
              )}
              {scopeNote === null && droppedBuffer > 0 && packets.length > 0 && (
                <p className="mt-0.5 text-[11px] text-amber-600 dark:text-amber-400">
                  Frames {packets[0].id.toLocaleString()}–
                  {packets[packets.length - 1].id.toLocaleString()} only:{' '}
                  {count(droppedBuffer)} earlier frames have left the buffer and are
                  not counted here.
                </p>
              )}
            </div>
          </div>
          {/* The close button stood here. A pane is left by choosing another view
              in the rail, or by Escape, which returns to Packets - so a control
              whose only job was dismissing a dialog would now be a second,
              weaker way of doing one of those. */}
        </div>

        <div className="px-5 py-2 border-b border-border flex flex-wrap items-center gap-2 text-xs shrink-0">
          <button onClick={() => setTab('hierarchy')} className={tabClass('hierarchy')}>Protocol Hierarchy</button>
          <button onClick={() => setTab('conversations')} className={tabClass('conversations')}>Conversations</button>
          {/* QUIC and DHCP are conversation levels only: a connection or an exchange is not an endpoint. */}
          <button onClick={() => { setTab('endpoints'); setKind((k) => (k === 'quic' ? 'udp' : k === 'dhcp' ? 'udp' : k)); }} className={tabClass('endpoints')}>Endpoints</button>
          <button onClick={() => setTab('devices')} className={tabClass('devices')}>
            Devices{deviceRows.length > 0 ? ` (${deviceRows.length})` : ''}
          </button>
          <button onClick={() => setTab('processes')} className={tabClass('processes')}>
            Processes{processRows.length > 0 ? ` (${processRows.length})` : ''}
          </button>
          {/* Between the tables and the findings, deliberately. Everything to
              the left of it is an aggregate of the capture and this is the same
              aggregate drawn rather than tabulated; Expert Information and
              Resolved Addresses to the right are lists of things FOUND in the
              capture, which is a different kind of answer. */}
          <button onClick={() => setTab('graphs')} className={tabClass('graphs')}>Graphs</button>
          <button onClick={() => setTab('expert')} className={tabClass('expert')}>
            Expert Information{expert.size > 0 ? ` (${count(expert.size)})` : ''}
          </button>
          <button onClick={() => setTab('names')} className={tabClass('names')}>
            Resolved Addresses{names.size > 0 ? ` (${names.size})` : ''}
          </button>

          {(tab === 'conversations' || tab === 'endpoints') && (
            <div className="ml-auto flex items-center gap-1">
              {CONVERSATION_TABS.filter((t) => (t.id !== 'quic' && t.id !== 'dhcp') || tab === 'conversations').map((t) => (
                <button key={t.id} onClick={() => setKind(t.id)} className={kindClass(t.id)}>
                  {t.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* The Graphs tab owns its own height and must not be inside a
            scroller: `TrafficTimelineChart` measures its container, so a parent
            that grows to fit its child would let the SVG size itself from a box
            it is itself defining. Every other tab is a table and wants exactly
            the opposite. */}
        {tab === 'graphs' ? (
          <GraphsTab packets={packets} isDark={isDark} themeKey={themeKey} />
        ) : (
        <div className="flex-1 overflow-y-auto custom-scrollbar px-5 py-3">
          {tab === 'hierarchy' && (
            <HierarchyTable
              hierarchy={hierarchy}
              onApplyFilter={apply}
            />
          )}

          {tab === 'devices' && (
            <>
              <p className="text-[11px] text-muted-foreground mb-2">
                One row per machine on the local segment, keyed on its MAC — a dual-stack host
                with rotating IPv6 privacy addresses is one device here, not five. Everything
                beyond the router appears under the router's MAC and is deliberately not listed:
                it was never on this segment.
              </p>
              <StatTable
                rows={deviceRows}
                columns={[
                  {
                    key: 'mac', label: 'Hardware address',
                    render: (r: Device) => <span title={r.mac}>{resolveMacVendor(r.mac)}</span>,
                    sortValue: (r: Device) => r.mac,
                    className: 'max-w-[16rem]',
                  },
                  {
                    key: 'name', label: 'Name',
                    // The MAC-keyed name first, because that is the only one
                    // that names the DEVICE - it came from the host naming
                    // itself over DHCP or LLDP. An address-derived name is
                    // only the device's when the device has exactly one
                    // address: a router carries traffic from everything behind
                    // it, so the first named address under a router's MAC is a
                    // remote server, and calling the router by that name would
                    // be confidently wrong.
                    render: (r: Device) => deviceName(r) ?? '—',
                    sortValue: (r: Device) => deviceName(r) ?? '',
                    className: 'max-w-[14rem]',
                  },
                  {
                    key: 'addresses', label: 'Addresses',
                    render: (r: Device) => (
                      <span title={r.addresses.join(', ')}>
                        {r.addresses.length === 0 ? '—' : r.addresses[0]}
                        {r.addresses.length > 1 && (
                          <span className="text-muted-foreground"> +{r.addresses.length - 1}</span>
                        )}
                      </span>
                    ),
                    sortValue: (r: Device) => r.addresses.length,
                    className: 'max-w-[20rem]',
                  },
                  { key: 'packets', label: 'Packets', align: 'right', render: (r: Device) => count(r.packets), sortValue: (r: Device) => r.packets },
                  { key: 'bytes', label: 'Bytes', align: 'right', render: (r: Device) => bytes(r.bytes), sortValue: (r: Device) => r.bytes },
                  { key: 'first', label: 'First seen', align: 'right', render: (r: Device) => `${r.firstSeen.toFixed(3)} s`, sortValue: (r: Device) => r.firstSeen },
                  { key: 'last', label: 'Last seen', align: 'right', render: (r: Device) => `${r.lastSeen.toFixed(3)} s`, sortValue: (r: Device) => r.lastSeen },
                ]}
                rowKey={(r: Device) => r.mac}
                initialSort="bytes"
                onRowClick={(r: Device) => apply(deviceFilter(r))}
                empty="No frames with an Ethernet header yet."
              />
            </>
          )}

          {tab === 'processes' && (
            <>
              <p className="text-[11px] text-muted-foreground mb-2">
                One row per program on this machine, from the operating system's own socket
                table — the one thing a capture cannot contain, and the reason no analyzer
                reading a file alone can show it. Keyed on the process id rather than the
                name, so a browser's dozen renderer children stay the dozen things they are.
                Frames whose socket was opened and closed inside one second, or belonged to
                another machine, are absent rather than guessed at.
              </p>
              <StatTable
                rows={processRows}
                columns={[
                  {
                    key: 'name', label: 'Process',
                    render: (r: ProcessGroup) => <span title={r.exe || r.name}>{r.name}</span>,
                    sortValue: (r: ProcessGroup) => r.name,
                    className: 'max-w-[16rem]',
                  },
                  { key: 'pid', label: 'PID', align: 'right', render: (r: ProcessGroup) => r.pid, sortValue: (r: ProcessGroup) => r.pid },
                  {
                    key: 'peers', label: 'Talking to',
                    render: (r: ProcessGroup) => (
                      <span title={r.peers.join(', ')}>
                        {r.peers.length === 0 ? '—' : r.peers[0]}
                        {r.peers.length > 1 && (
                          <span className="text-muted-foreground"> +{r.peers.length - 1}</span>
                        )}
                      </span>
                    ),
                    sortValue: (r: ProcessGroup) => r.peers.length,
                    className: 'max-w-[20rem]',
                  },
                  { key: 'packets', label: 'Packets', align: 'right', render: (r: ProcessGroup) => count(r.packets), sortValue: (r: ProcessGroup) => r.packets },
                  { key: 'bytes', label: 'Bytes', align: 'right', render: (r: ProcessGroup) => bytes(r.bytes), sortValue: (r: ProcessGroup) => r.bytes },
                  { key: 'first', label: 'First seen', align: 'right', render: (r: ProcessGroup) => `${r.firstSeen.toFixed(3)} s`, sortValue: (r: ProcessGroup) => r.firstSeen },
                  { key: 'last', label: 'Last seen', align: 'right', render: (r: ProcessGroup) => `${r.lastSeen.toFixed(3)} s`, sortValue: (r: ProcessGroup) => r.lastSeen },
                ]}
                rowKey={(r: ProcessGroup) => String(r.pid)}
                initialSort="bytes"
                onRowClick={(r: ProcessGroup) => apply(processFilter(r))}
                empty="No frames attributed to a process yet. Attribution needs the local agent, and only covers this machine's own sockets."
              />
            </>
          )}

          {tab === 'expert' && (
            <>
              {/* Only the categories this capture actually raised. A strip of
                  eight zeroes says less than a strip of the three things that
                  happened. */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mb-3 text-[11px]">
                {CATEGORY_ORDER.filter((c) => expertCounts[c] > 0).map((c) => (
                  <span key={c} className="flex items-center gap-1.5" title={CATEGORY_HINTS[c]}>
                    <span className={`font-semibold ${CATEGORY_TEXT[c]}`}>{CATEGORY_LABELS[c]}</span>
                    <span className="tabular-nums font-bold">{count(expertCounts[c])}</span>
                  </span>
                ))}
              </div>
              <StatTable
                rows={expertRows}
                columns={[
                  // Summary first: it is the only column that says what
                  // happened, and it sat fourth behind a severity that turned
                  // out to be wrong more often than it was right.
                  { key: 'summary', label: 'Summary', render: (r: ExpertGroupRow) => r.summary, sortValue: (r: ExpertGroupRow) => r.summary, className: 'max-w-[32rem]' },
                  {
                    key: 'category', label: 'Category',
                    render: (r: ExpertGroupRow) => (
                      <span className={`font-semibold ${CATEGORY_TEXT[r.category]}`}
                        title={CATEGORY_HINTS[r.category]}>
                        {CATEGORY_LABELS[r.category]}
                      </span>
                    ),
                    // Negated, because the table sorts descending on the first
                    // click and `CATEGORY_ORDER` runs most-consequential-first.
                    sortValue: (r: ExpertGroupRow) => -CATEGORY_ORDER.indexOf(r.category),
                  },
                  { key: 'proto', label: 'Protocol', render: (r: ExpertGroupRow) => r.protocol, sortValue: (r: ExpertGroupRow) => r.protocol },
                  { key: 'count', label: 'Count', align: 'right', render: (r: ExpertGroupRow) => count(r.count), sortValue: (r: ExpertGroupRow) => r.count },
                ]}
                rowKey={(r: ExpertGroupRow) => r.key}
                // Commonest first. With severity gone there is no single
                // "worst" to lead with, and how often a thing happened is the
                // next most useful ordering - the Category column sorts by
                // consequence for whoever wants that.
                initialSort="count"
                // Clicking jumps to the first frame that raised it rather than
                // filtering: an expert finding is a place in the capture, and
                // the filter that would select "frames with this finding" is
                // not expressible - the finding is not a field.
                onRowClick={(r: ExpertGroupRow) => {
                  if (r.frames.length === 0) return;
                  onSelectFrame?.(r.frames[0]);
                  onReturnToPackets();
                }}
                empty="Nothing to report. No dissector raised a finding on this capture."
              />
            </>
          )}

          {(tab === 'conversations' || tab === 'endpoints') && (
            <ContextMenu>
              <ContextMenuTrigger asChild>
                <div>
                  {tab === 'conversations' ? (
                    <StatTable
                      rows={convRows}
                      columns={conversationColumns}
                      rowKey={(r) => r.key}
                      initialSort="bytes"
                      // A transport row opens its stream on the ladder, the
                      // way "Show conversation" does; an address row is many
                      // streams and filters, as every row once did.
                      onRowClick={(r) => {
                        const stream = streamOf(r);
                        if (stream !== undefined && onFollowStream) { onFollowStream?.(stream, 'ladder'); return; }
                        apply(conversationFilter(r, kind));
                      }}
                      onRowContextMenu={(r) => setMenuRow({
                        filter: conversationFilter(r, kind),
                        title: `${r.addressA} ↔ ${r.addressB}`,
                        // Only the transport tabs describe a stream: an IP-tab
                        // row collapses every port pair between two hosts, so
                        // there is no single conversation to follow.
                        stream: streamOf(r),
                        frame: r.firstFrame,
                      })}
                      empty={`No ${CONVERSATION_TABS.find((t) => t.id === kind)?.label} conversations in this capture.`}
                    />
                  ) : (
                    <StatTable
                      rows={endpointRows}
                      columns={endpointColumns}
                      rowKey={(r) => `${r.address}|${r.port ?? ''}`}
                      initialSort="bytes"
                      onRowClick={(r) => apply(endpointFilter(r, kind))}
                      onRowContextMenu={(r) => setMenuRow({
                        filter: endpointFilter(r, kind),
                        title: r.port === undefined ? r.address : `${r.address}:${r.port}`,
                      })}
                      empty={`No ${CONVERSATION_TABS.find((t) => t.id === kind)?.label} endpoints in this capture.`}
                    />
                  )}
                </div>
              </ContextMenuTrigger>
              {menuRow && (
                <ContextMenuContent className="w-60 text-xs">
                  <ContextMenuLabel className="text-[10px] uppercase tracking-wider text-muted-foreground truncate">
                    {menuRow.title}
                  </ContextMenuLabel>
                  <ContextMenuItem onSelect={() => apply(menuRow.filter)}>Apply as Filter</ContextMenuItem>
                  <ContextMenuItem onSelect={() => apply(`!(${menuRow.filter})`)}>Apply as Filter (not)</ContextMenuItem>
                  <ContextMenuItem
                    disabled={menuRow.stream === undefined || !onFollowStream}
                    onSelect={() => {
                      if (menuRow.stream === undefined) return;
                      onFollowStream?.(menuRow.stream);
                    }}
                  >
                    Follow Stream
                  </ContextMenuItem>
                  {/* The same conversation, asked about its shape rather than
                      its content: which side spoke when, how long an answer
                      took, where it went quiet. */}
                  <ContextMenuItem
                    disabled={menuRow.stream === undefined || !onFollowStream}
                    onSelect={() => {
                      if (menuRow.stream === undefined) return;
                      onFollowStream?.(menuRow.stream, 'ladder');
                    }}
                  >
                    Show conversation
                  </ContextMenuItem>
                  <ContextMenuItem
                    disabled={menuRow.frame === undefined || !onSelectFrame}
                    onSelect={() => {
                      if (menuRow.frame === undefined) return;
                      onSelectFrame?.(menuRow.frame);
                      onReturnToPackets();
                    }}
                  >
                    Go to First Frame
                  </ContextMenuItem>
                  <ContextMenuSeparator />
                  <ContextMenuItem onSelect={() => void copyText(menuRow.filter)}>
                    Copy as Filter
                  </ContextMenuItem>
                </ContextMenuContent>
              )}
            </ContextMenu>
          )}

          {tab === 'names' && (
            <>
              <p className="text-[11px] text-muted-foreground mb-2">
                Learned from the capture itself - DNS and mDNS answers, TLS and QUIC server
                names, DHCP and LLDP. Nothing was looked up, so this works on an imported
                file from a network that no longer exists.
              </p>
              <StatTable
                rows={nameRows}
                columns={[
                  { key: 'name', label: 'Name', render: (r) => r.name, sortValue: (r) => r.name, className: 'max-w-[22rem]' },
                  { key: 'address', label: 'Address', render: (r) => r.address, sortValue: (r) => r.address, className: 'max-w-[20rem]' },
                  { key: 'source', label: 'Learned from', render: (r) => SOURCE_LABELS[r.source], sortValue: (r) => r.source },
                  { key: 'frame', label: 'Frame', align: 'right', render: (r) => count(r.frame), sortValue: (r) => r.frame },
                ]}
                rowKey={(r) => `${r.address}|${r.name}`}
                initialSort="name"
                onRowClick={(r) => apply(`addr == "${r.address}"`)}
                empty="Nothing in this capture named an address. A DNS answer, a TLS handshake or a DHCP lease would."
              />
            </>
          )}
        </div>
        )}
    </div>
  );
};

/**
 * The layer tree, as a tree.
 *
 * Wireshark draws this as an indented table with a row per protocol and the
 * percentages relative to the whole capture, which is the only presentation
 * that answers the question it is opened for: "what is all this traffic". The
 * bar behind each row is the same number as the percentage beside it - it is
 * there so the shape can be read without reading any of the digits.
 */
const HierarchyTable: React.FC<{
  hierarchy: { roots: HierarchyNode[]; packets: number; bytes: number };
  onApplyFilter: (expression: string) => void;
}> = ({ hierarchy, onApplyFilter }) => {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  if (hierarchy.packets === 0) {
    return <div className="py-10 text-center text-xs text-muted-foreground italic">No dissected frames yet.</div>;
  }

  const rows: React.ReactNode[] = [];
  const walk = (nodes: HierarchyNode[], depth: number, path: string) => {
    for (const node of nodes) {
      const key = `${path}/${node.token}`;
      const open = !collapsed[key];
      const share = (node.packets / hierarchy.packets) * 100;
      rows.push(
        <tr
          key={key}
          onClick={() => onApplyFilter(node.token)}
          className="border-b border-border/40 hover:bg-accent/60 cursor-pointer"
          title={`Filter on ${node.token}`}
        >
          <td className="px-2 py-1 whitespace-nowrap">
            <span style={{ paddingLeft: `${depth * 1.1}rem` }} className="inline-flex items-center gap-1">
              {node.children.length > 0 ? (
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCollapsed((c) => ({ ...c, [key]: !c[key] })); }}
                  className="shrink-0 text-muted-foreground hover:text-foreground cursor-pointer"
                  aria-label={open ? 'Collapse' : 'Expand'}
                >
                  {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                </button>
              ) : (
                <span className="w-3 shrink-0" />
              )}
              <span className="font-semibold text-foreground">{node.token}</span>
            </span>
          </td>
          <td className="px-2 py-1 text-right tabular-nums">{count(node.packets)}</td>
          <td className="px-2 py-1 text-right tabular-nums">{share.toFixed(2)} %</td>
          <td className="px-2 py-1 text-right tabular-nums">{bytes(node.bytes)}</td>
          <td className="px-2 py-1 w-40">
            <div className="h-1.5 rounded-full bg-muted overflow-hidden">
              <div className="h-full bg-primary" style={{ width: `${share}%` }} />
            </div>
          </td>
        </tr>,
      );
      if (open) walk(node.children, depth + 1, key);
    }
  };
  walk(hierarchy.roots, 0, '');

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse font-mono text-[11px]">
        <thead className="sticky top-0 z-10 bg-card">
          <tr className={`border-b border-border ${MICRO_LABEL}`}>
            <th className="px-2 py-1.5 font-bold">Protocol</th>
            <th className="px-2 py-1.5 font-bold text-right">Packets</th>
            <th className="px-2 py-1.5 font-bold text-right">% of capture</th>
            <th className="px-2 py-1.5 font-bold text-right">Bytes</th>
            <th className="px-2 py-1.5" />
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  );
};
