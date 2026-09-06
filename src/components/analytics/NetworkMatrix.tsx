import React from 'react';
import { Packet } from '../../types/packet';
import { useIncrementalAggregate } from '../../lib/useIncrementalAggregate';
import { categoryOfPacket, isFaultCategory } from '../../services/expertInfo';
import { TbArrowsExchange, TbShieldExclamation } from 'react-icons/tb';

export type TalkersView = 'flows' | 'hosts';

interface NetworkMatrixProps {
  packets: Packet[];
  onFilterHost: (ip: string) => void;
  /**
   * Which list to show, and how much of it.
   *
   * Both were local state with hardcoded constants beside them - `activeTab`
   * and `TOP_ROWS = 5`. They are stored settings now, so the choice survives a
   * reload and two instances of this widget can show flows and hosts side by
   * side, which is the point of a dashboard you build.
   */
  view: TalkersView;
  top: number;
}

interface ConversationPair {
  id: string;
  hostA: string;
  hostB: string;
  packetsCount: number;
  totalBytes: number;
  protocols: Set<string>;
  hasAnomaly: boolean;
}

export const NetworkMatrix: React.FC<NetworkMatrixProps> = ({
  packets,
  onFilterHost,
  view,
  top,
}) => {
  /**
   * Conversation flows, folded one packet at a time.
   *
   * This walked the entire buffer on every dashboard tick, twice a second,
   * and so did the endpoint fold under it. A conversation's packet count and
   * byte total are running sums, so nothing here needed re-reading: a tick
   * now folds in the packets that arrived during that tick and sorts the pair
   * map, which is bounded by how many pairs are talking rather than by how
   * long the capture has been running. See useIncrementalAggregate.
   *
   * Both tabs are folded whether or not they are showing. Adding a packet to
   * a Map costs far less than the render it would otherwise cost to switch
   * tabs and rebuild from zero, and a tab switch should be instant.
   */
  const conversations: ConversationPair[] = useIncrementalAggregate(
    packets,
    () => new Map<string, ConversationPair>(),
    (pairMap, p) => {
      if (!p.source || !p.destination) return;
      // A comparison rather than [a, b].sort(): the sort allocated an array and
      // ran a comparator for every packet, and this runs for every packet.
      // Same canonical ordering, no allocation.
      const first = p.source < p.destination ? p.source : p.destination;
      const second = p.source < p.destination ? p.destination : p.source;
      const key = `${first}<->${second}`;

      let existing = pairMap.get(key);
      if (!existing) {
        existing = {
          id: key,
          hostA: first,
          hostB: second,
          packetsCount: 0,
          totalBytes: 0,
          protocols: new Set<string>(),
          hasAnomaly: false,
        };
        pairMap.set(key, existing);
      }

      existing.packetsCount += 1;
      existing.totalBytes += p.length;
      existing.protocols.add(p.protocol);
      if (isFaultCategory(categoryOfPacket(p))) existing.hasAnomaly = true;
    },
    // Sorted but NOT cut. The row count is a setting now, and listing it in
    // this hook's deps would discard the fold and re-walk every packet in the
    // buffer just to show five more rows. The sort is over distinct pairs
    // rather than over packets, so taking the whole list costs nothing extra
    // and the slice happens below, for free.
    (pairMap) => Array.from(pairMap.values()).sort((a, b) => b.totalBytes - a.totalBytes),
  );

  /** Per-host totals, folded the same way. */
  const endpoints = useIncrementalAggregate(
    packets,
    () => new Map<string, { ip: string; txPkts: number; rxPkts: number; bytes: number; anomalies: number }>(),
    (epMap, p) => {
      const flagged = isFaultCategory(categoryOfPacket(p));

      let srcEp = epMap.get(p.source);
      if (!srcEp) {
        srcEp = { ip: p.source, txPkts: 0, rxPkts: 0, bytes: 0, anomalies: 0 };
        epMap.set(p.source, srcEp);
      }
      srcEp.txPkts += 1;
      srcEp.bytes += p.length;
      if (flagged) srcEp.anomalies++;

      let dstEp = epMap.get(p.destination);
      if (!dstEp) {
        dstEp = { ip: p.destination, txPkts: 0, rxPkts: 0, bytes: 0, anomalies: 0 };
        epMap.set(p.destination, dstEp);
      }
      dstEp.rxPkts += 1;
      dstEp.bytes += p.length;
      if (flagged) dstEp.anomalies++;
    },
    (epMap) => Array.from(epMap.values()).sort((a, b) => b.bytes - a.bytes),
  );

  // The card owns its own height now, so the list fills whatever it is given
  // rather than stopping at the 130px it used to be pinned to - which in the
  // rail's popout bubble left a scroller a third the height of the space
  // around it.
  return (
    <div className="h-full overflow-y-auto space-y-1.5 pr-0.5 custom-scrollbar">
      {view === 'flows'
        ? conversations.slice(0, top).map((conv) => (
            <div
              key={conv.id}
              className={`flex items-center justify-between gap-2 text-xs px-2.5 py-1.5 rounded border transition-colors ${
                conv.hasAnomaly
                  ? 'border-danger/40 bg-danger/10 text-danger-muted'
                  : 'border-border bg-secondary/60 hover:bg-accent/80'
              }`}
            >
              <div className="flex items-center gap-1.5 font-mono text-[10px] min-w-0">
                {conv.hasAnomaly && (
                  <TbShieldExclamation className="w-3.5 h-3.5 text-danger shrink-0 animate-pulse" />
                )}
                <button
                  onClick={() => onFilterHost(conv.hostA)}
                  className="hover:underline hover:text-primary truncate max-w-[85px] cursor-pointer"
                  title={conv.hostA}
                >
                  {conv.hostA}
                </button>
                <TbArrowsExchange className="w-3 h-3 text-muted-foreground shrink-0" />
                <button
                  onClick={() => onFilterHost(conv.hostB)}
                  className="hover:underline hover:text-primary truncate max-w-[85px] cursor-pointer"
                  title={conv.hostB}
                >
                  {conv.hostB}
                </button>
              </div>

              <div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground shrink-0">
                {/* The protocols on this pair. The fold has always collected
                    this set and the row has never shown it, so "which
                    conversation is this" could only be answered by filtering to
                    it. One name when there is one, a count when there are more,
                    because three protocol names and two addresses do not fit in
                    352px. */}
                <span
                  className="uppercase tracking-wide opacity-70"
                  title={Array.from(conv.protocols).join(', ')}
                >
                  {conv.protocols.size === 1
                    ? Array.from(conv.protocols)[0]
                    : `${conv.protocols.size} proto`}
                </span>
                {/* The heading's own colour rather than the app accent. These
                    are the values the heading is about, and painting them the
                    accent made five rows of numbers compete with the one
                    accent-coloured control in the card - the Flows/Hosts
                    toggle - which is the only interactive thing here. Weight
                    carries the hierarchy instead. */}
                <span className="font-bold">
                  {conv.totalBytes >= 1024
                    ? `${(conv.totalBytes / 1024).toFixed(1)}K`
                    : `${conv.totalBytes}B`}
                </span>
              </div>
            </div>
          ))
        : endpoints.slice(0, top).map((ep) => (
            <div
              key={ep.ip}
              className={`flex items-center justify-between gap-2 text-xs px-2.5 py-1.5 rounded border transition-colors ${
                ep.anomalies > 0
                  ? 'border-danger/40 bg-danger/10 text-danger-muted'
                  : 'border-border bg-secondary/60 hover:bg-accent/80'
              }`}
            >
              <div className="flex items-center gap-1.5 font-mono text-[10px] min-w-0">
                {ep.anomalies > 0 && (
                  <TbShieldExclamation className="w-3.5 h-3.5 text-danger shrink-0 animate-pulse" />
                )}
                <button
                  onClick={() => onFilterHost(ep.ip)}
                  className="hover:underline hover:text-primary font-medium truncate cursor-pointer"
                  title={ep.ip}
                >
                  {ep.ip}
                </button>
              </div>

              <div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground shrink-0">
                <span className="opacity-70">{ep.txPkts + ep.rxPkts} pkts</span>
                <span className="font-bold">
                  {ep.bytes >= 1024 ? `${(ep.bytes / 1024).toFixed(1)}K` : `${ep.bytes}B`}
                </span>
              </div>
            </div>
          ))}
    </div>
  );
};
