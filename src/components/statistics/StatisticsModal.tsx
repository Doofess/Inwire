import React, { useMemo, useState } from 'react';
import { motion } from 'motion/react';
import { TbChartBar, TbX, TbChevronDown, TbChevronRight } from 'react-icons/tb';

import { Packet } from '../../types/packet';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import {
  conversations, endpoints, protocolHierarchy, devices, processes, processFilter,
  conversationFilter, endpointFilter, deviceFilter,
  type Conversation, type ConversationKind, type Device, type Endpoint, type HierarchyNode,
  type ProcessGroup,
} from '../../services/statistics';
import { flowAnnotations } from '../../services/flowAnnotations';
import { resolveMacVendor } from '../../services/macVendors';
import type { StreamTarget } from '../../services/followStream';
import { NameLookup, SOURCE_LABELS } from '../../services/nameResolution';
import {
  SEVERITY_DOT, SEVERITY_LABELS, SEVERITY_ORDER, SEVERITY_TEXT,
  type ExpertGroupRow, type ExpertLookup,
} from '../../services/expertInfo';
import { portLabel } from '../../services/portServices';
import { StatTable, bitrate, bytes, count, seconds, type StatColumn } from './StatTable';
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
 * Every row is a filter waiting to happen - clicking one applies the display
 * filter that selects exactly its frames, which is the shortest path there is
 * from "this pair moved 7 MB" to looking at the frames that did it. The
 * filters come from the statistics module rather than being spelled out here,
 * so the row and the filter can never disagree about what the row meant.
 */

type Tab = 'hierarchy' | 'conversations' | 'endpoints' | 'devices' | 'processes' | 'expert' | 'names';

const CONVERSATION_TABS: { id: ConversationKind; label: string }[] = [
  { id: 'eth', label: 'Ethernet' },
  { id: 'ipv4', label: 'IPv4' },
  { id: 'ipv6', label: 'IPv6' },
  { id: 'tcp', label: 'TCP' },
  { id: 'udp', label: 'UDP' },
];

interface StatisticsModalProps {
  /** The whole buffer. The tables count the capture, not the filtered view. */
  packets: Packet[];
  /** What the capture says its addresses are called. */
  names: NameLookup;
  resolveNames: boolean;
  resolvePorts: boolean;
  /** Applies a display filter in the main window and closes this dialog. */
  onApplyFilter: (expression: string) => void;
  /** Opens the stream follower on a TCP or UDP conversation. */
  onFollowStream?: (target: StreamTarget) => void;
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
  onClose: () => void;
}

export const StatisticsModal: React.FC<StatisticsModalProps> = ({
  packets,
  names,
  resolveNames,
  resolvePorts,
  expert,
  onApplyFilter,
  onFollowStream,
  onSelectFrame,
  droppedBuffer = 0,
  onClose,
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
  const convRows = useMemo(() => conversations(packets, kind), [packets, kind]);
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
    value === undefined ? '' : portLabel(value, kind === 'udp' ? 'udp' : 'tcp', resolvePorts);

  const apply = (expression: string) => {
    onApplyFilter(expression);
    onClose();
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
    ...(kind === 'tcp' || kind === 'udp'
      ? [{ key: 'pa', label: 'Port A', align: 'right' as const, render: (r: Conversation) => port(r.portA), sortValue: (r: Conversation) => r.portA ?? 0 }]
      : []),
    { key: 'b', label: 'Address B', render: (r) => addr(r.addressB), sortValue: (r) => r.addressB, className: 'max-w-[15rem]' },
    ...(kind === 'tcp' || kind === 'udp'
      ? [{ key: 'pb', label: 'Port B', align: 'right' as const, render: (r: Conversation) => port(r.portB), sortValue: (r: Conversation) => r.portB ?? 0 }]
      : []),
    { key: 'proto', label: 'Protocol', render: (r) => r.protocol, sortValue: (r) => r.protocol },
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
    `px-3 py-1.5 rounded-md font-medium transition-colors ${
      tab === id
        ? 'bg-primary text-primary-foreground shadow-sm'
        : 'text-muted-foreground hover:text-foreground hover:bg-accent'
    }`;

  const kindClass = (id: ConversationKind) =>
    `px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer ${
      kind === id ? 'bg-accent text-primary font-bold' : 'text-muted-foreground hover:text-foreground'
    }`;

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-6xl h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground"
      >
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <TbChartBar className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Capture Statistics</div>
              <p className="text-xs text-muted-foreground">
                {count(packets.length)} frames · {bytes(hierarchy.bytes)} · every row is a filter
              </p>
              {/* Named as a range rather than a count, because "counted
                  1,900,000 of 2,000,000" still invites the reader to treat the
                  tables as the capture. Frame numbers are what the rest of the
                  app addresses frames by, so they are what says which part of
                  it this is. */}
              {droppedBuffer > 0 && packets.length > 0 && (
                <p className="mt-0.5 text-[11px] text-amber-600 dark:text-amber-400 font-mono">
                  Frames {packets[0].id.toLocaleString()}–
                  {packets[packets.length - 1].id.toLocaleString()} only:{' '}
                  {count(droppedBuffer)} earlier frames have left the buffer and are
                  not counted here.
                </p>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
            aria-label="Close"
          >
            <TbX className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-2 border-b border-border flex items-center gap-2 text-xs shrink-0">
          <button onClick={() => setTab('hierarchy')} className={tabClass('hierarchy')}>Protocol Hierarchy</button>
          <button onClick={() => setTab('conversations')} className={tabClass('conversations')}>Conversations</button>
          <button onClick={() => setTab('endpoints')} className={tabClass('endpoints')}>Endpoints</button>
          <button onClick={() => setTab('devices')} className={tabClass('devices')}>
            Devices{deviceRows.length > 0 ? ` (${deviceRows.length})` : ''}
          </button>
          <button onClick={() => setTab('processes')} className={tabClass('processes')}>
            Processes{processRows.length > 0 ? ` (${processRows.length})` : ''}
          </button>
          <button onClick={() => setTab('expert')} className={tabClass('expert')}>
            Expert Information{expert.size > 0 ? ` (${count(expert.size)})` : ''}
          </button>
          <button onClick={() => setTab('names')} className={tabClass('names')}>
            Resolved Addresses{names.size > 0 ? ` (${names.size})` : ''}
          </button>

          {(tab === 'conversations' || tab === 'endpoints') && (
            <div className="ml-auto flex items-center gap-1">
              {CONVERSATION_TABS.map((t) => (
                <button key={t.id} onClick={() => setKind(t.id)} className={kindClass(t.id)}>
                  {t.label}
                </button>
              ))}
            </div>
          )}
        </div>

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
              <div className="flex items-center gap-4 mb-3 text-[11px] font-mono">
                {SEVERITY_ORDER.map((s) => (
                  <span key={s} className="flex items-center gap-1.5">
                    <span className={`inline-block w-2 h-2 rounded-full ${SEVERITY_DOT[s]}`} />
                    <span className="text-muted-foreground">{SEVERITY_LABELS[s]}</span>
                    <span className="tabular-nums font-bold">{count(expertCounts[s])}</span>
                  </span>
                ))}
              </div>
              <StatTable
                rows={expertRows}
                columns={[
                  {
                    key: 'severity', label: 'Severity',
                    render: (r: ExpertGroupRow) => (
                      <span className={`flex items-center gap-1.5 ${SEVERITY_TEXT[r.severity]}`}>
                        <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[r.severity]}`} />
                        {SEVERITY_LABELS[r.severity]}
                      </span>
                    ),
                    // Negated: the table sorts descending by default and
                    // `SEVERITY_ORDER` runs worst-first, so the raw index would
                    // put Chat at the top of a list whose whole purpose is to
                    // show what is broken.
                    sortValue: (r: ExpertGroupRow) => -SEVERITY_ORDER.indexOf(r.severity),
                  },
                  { key: 'group', label: 'Group', render: (r: ExpertGroupRow) => r.group, sortValue: (r: ExpertGroupRow) => r.group },
                  { key: 'proto', label: 'Protocol', render: (r: ExpertGroupRow) => r.protocol, sortValue: (r: ExpertGroupRow) => r.protocol },
                  { key: 'summary', label: 'Summary', render: (r: ExpertGroupRow) => r.summary, sortValue: (r: ExpertGroupRow) => r.summary, className: 'max-w-[30rem]' },
                  { key: 'count', label: 'Count', align: 'right', render: (r: ExpertGroupRow) => count(r.count), sortValue: (r: ExpertGroupRow) => r.count },
                ]}
                rowKey={(r: ExpertGroupRow) => r.key}
                initialSort="severity"
                // Clicking jumps to the first frame that raised it rather than
                // filtering: an expert finding is a place in the capture, and
                // the filter that would select "frames with this finding" is
                // not expressible - the finding is not a field.
                onRowClick={(r: ExpertGroupRow) => {
                  if (r.frames.length === 0) return;
                  onSelectFrame?.(r.frames[0]);
                  onClose();
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
                      onRowClick={(r) => apply(conversationFilter(r, kind))}
                      onRowContextMenu={(r) => setMenuRow({
                        filter: conversationFilter(r, kind),
                        title: `${r.addressA} ↔ ${r.addressB}`,
                        // Only the transport tabs describe a stream: an IP-tab
                        // row collapses every port pair between two hosts, so
                        // there is no single conversation to follow.
                        stream: (kind === 'tcp' || kind === 'udp') && r.portA !== undefined && r.portB !== undefined
                          ? { kind, addressA: r.addressA, portA: r.portA, addressB: r.addressB, portB: r.portB, streamId: r.streamId }
                          : undefined,
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
                <ContextMenuContent className="w-60 font-mono text-xs">
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
                      onClose();
                    }}
                  >
                    Follow Stream
                  </ContextMenuItem>
                  <ContextMenuItem
                    disabled={menuRow.frame === undefined || !onSelectFrame}
                    onSelect={() => {
                      if (menuRow.frame === undefined) return;
                      onSelectFrame?.(menuRow.frame);
                      onClose();
                    }}
                  >
                    Go to First Frame
                  </ContextMenuItem>
                  <ContextMenuSeparator />
                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(menuRow.filter)}>
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
      </motion.div>
    </motion.div>
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
                  {open ? <TbChevronDown className="w-3 h-3" /> : <TbChevronRight className="w-3 h-3" />}
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
          <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
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
