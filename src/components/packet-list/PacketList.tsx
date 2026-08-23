import React, { useState, useEffect, useRef } from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import { PacketDiffModal } from '../diff/PacketDiffModal';
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ShieldAlert,
  MessageSquare,
  Filter,
  Copy,
  AlertTriangle,
  GitCompare,
  CheckSquare,
  Square,
  ArrowRightLeft,
  X,
  Search,
  Play,
  Repeat,
} from 'lucide-react';

interface PacketListProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  onFollowStream: (streamId: number) => void;
  onQuickFilter: (filter: string) => void;
  onReplayPackets: (packets: Packet[]) => void;
  colorEngine: ColorRulesEngine;
  permissions: UserRolePermissions;
  isDark: boolean;
}

type SortField = 'id' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length' | 'info';
type SortOrder = 'asc' | 'desc';

export const PacketList: React.FC<PacketListProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
  onFollowStream,
  onQuickFilter,
  onReplayPackets,
  colorEngine,
  permissions,
  isDark,
}) => {
  const [sortField, setSortField] = useState<SortField>('id');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; packet: Packet } | null>(null);
  const tableContainerRef = useRef<HTMLDivElement | null>(null);

  // Search State
  const [localSearchText, setLocalSearchText] = useState('');

  // Replay Multi-Select State
  const [isReplaySelectMode, setIsReplaySelectMode] = useState(false);
  const [selectedForReplay, setSelectedForReplay] = useState<Set<number>>(new Set());

  // Diff Mode State
  const [isDiffMode, setIsDiffMode] = useState(false);
  const [diffPacketA, setDiffPacketA] = useState<Packet | null>(null);
  const [diffPacketB, setDiffPacketB] = useState<Packet | null>(null);
  const [showDiffModal, setShowDiffModal] = useState(false);

  // Sorting & Filtering
  const sortedPackets = React.useMemo(() => {
    let processedPackets = packets;

    // Apply local search
    if (localSearchText.trim()) {
      const lowerSearch = localSearchText.toLowerCase();
      processedPackets = processedPackets.filter(
        p =>
          p.protocol.toLowerCase().includes(lowerSearch) ||
          p.source.toLowerCase().includes(lowerSearch) ||
          p.destination.toLowerCase().includes(lowerSearch) ||
          p.info.toLowerCase().includes(lowerSearch) ||
          p.id.toString().includes(lowerSearch)
      );
    }

    if (!sortField) return processedPackets;

    return [...processedPackets].sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];
      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = (valB || '').toLowerCase();
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    });
  }, [packets, sortField, sortOrder, localSearchText]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Auto scroll to bottom
  const shouldAutoScrollRef = useRef(true);
  const handleScroll = () => {
    if (!tableContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = tableContainerRef.current;
    shouldAutoScrollRef.current = scrollHeight - (scrollTop + clientHeight) < 50;
  };

  useEffect(() => {
    if (shouldAutoScrollRef.current && tableContainerRef.current && !isDiffMode) {
      tableContainerRef.current.scrollTop = tableContainerRef.current.scrollHeight;
    }
  }, [packets.length, isDiffMode]);

  // Global Keyboard navigation is now handled in App.tsx
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!selectedPacket || sortedPackets.length === 0) return;
      const currentIndex = sortedPackets.findIndex(p => p.id === selectedPacket.id);
      if (currentIndex === -1) return;

      if (e.key.toLowerCase() === 'd' && !e.ctrlKey && !e.metaKey) {
        // Quick diff with previous packet
        if (currentIndex > 0) {
          setDiffPacketA(sortedPackets[currentIndex - 1]);
          setDiffPacketB(selectedPacket);
          setShowDiffModal(true);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedPacket, sortedPackets, onSelectPacket]);

  // Context Menu handlers
  const handleContextMenu = (e: React.MouseEvent, packet: Packet) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, packet });
  };

  useEffect(() => {
    const closeMenu = () => setContextMenu(null);
    window.addEventListener('click', closeMenu);
    return () => window.removeEventListener('click', closeMenu);
  }, []);

  const handleToggleDiffSelection = (packet: Packet) => {
    if (!diffPacketA) {
      setDiffPacketA(packet);
    } else if (diffPacketA.id === packet.id) {
      setDiffPacketA(null);
    } else if (!diffPacketB) {
      setDiffPacketB(packet);
      setShowDiffModal(true);
    } else if (diffPacketB.id === packet.id) {
      setDiffPacketB(null);
    } else {
      // Replace target
      setDiffPacketB(packet);
      setShowDiffModal(true);
    }
  };

  const handleRowClick = (packet: Packet) => {
    if (isDiffMode) {
      handleToggleDiffSelection(packet);
    } else {
      onSelectPacket(packet);
    }
  };

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) return <ArrowUpDown className="w-3 h-3 text-slate-500 opacity-30 group-hover:opacity-100 transition-opacity" />;
    return sortOrder === 'asc' ? (
      <ArrowUp className="w-3 h-3 text-cyan-400" />
    ) : (
      <ArrowDown className="w-3 h-3 text-cyan-400" />
    );
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden select-none relative">
      {/* Diff Mode Control Bar */}
      <div
        className={`px-4 py-2 border-b flex items-center justify-between transition-colors shrink-0 text-xs font-mono ${
          isDiffMode
            ? 'bg-cyan-950/40 border-cyan-500/40 text-cyan-200'
            : isDark
            ? 'bg-slate-900/60 border-slate-800 text-slate-400'
            : 'bg-slate-100 border-slate-200 text-slate-600'
        }`}
      >
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setIsDiffMode(!isDiffMode);
              if (!isDiffMode && selectedPacket) {
                setDiffPacketA(selectedPacket);
              }
            }}
            className={`px-2.5 py-1 rounded border flex items-center gap-1.5 font-bold transition-all cursor-pointer ${
              isDiffMode
                ? 'bg-cyan-500 text-slate-950 border-cyan-400 shadow-sm shadow-cyan-500/20'
                : 'bg-slate-800 hover:bg-slate-700 text-cyan-400 border-slate-700'
            }`}
            title="Toggle packet comparison mode (Shortcut: Press 'D' on any packet)"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>{isDiffMode ? 'Diff Mode Active' : 'Diff View (Compare)'}</span>
          </button>

          {isDiffMode && (
            <span className="text-[11px] text-slate-300 hidden sm:inline">
              Select two packets to compare header fields and byte hex dumps
            </span>
          )}

          {!isDiffMode && (
            <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md border ${isDark ? 'bg-slate-950 border-slate-700' : 'bg-white border-slate-300'}`}>
              <Search className="w-3.5 h-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Find packet (IP, protocol, info)..."
                value={localSearchText}
                onChange={e => setLocalSearchText(e.target.value)}
                className={`bg-transparent outline-none w-56 text-[11px] font-mono ${isDark ? 'text-slate-200 placeholder-slate-600' : 'text-slate-800 placeholder-slate-400'}`}
              />
              {localSearchText && (
                <button onClick={() => setLocalSearchText('')} className="p-0.5 rounded-full hover:bg-slate-800 text-slate-400">
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          )}

          {!isDiffMode && (
            <button
              onClick={() => {
                setIsReplaySelectMode(!isReplaySelectMode);
                if (isReplaySelectMode) {
                  setSelectedForReplay(new Set());
                }
              }}
              className={`px-2.5 py-1 rounded border flex items-center gap-1.5 font-bold transition-all cursor-pointer ${
                isReplaySelectMode
                  ? 'bg-amber-500 text-slate-950 border-amber-400 shadow-sm shadow-amber-500/20'
                  : 'bg-slate-800 hover:bg-slate-700 text-amber-400 border-slate-700'
              }`}
              title="Toggle Replay Selection Mode"
            >
              <Repeat className="w-3.5 h-3.5" />
              <span>{isReplaySelectMode ? 'Cancel Replay' : 'Select to Replay'}</span>
            </button>
          )}
        </div>

        {/* Selected replay pills */}
        {isReplaySelectMode && (
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-300 hidden sm:inline">
              Select packets via checkboxes to inject back into live feed
            </span>
            <span className="px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/30 text-amber-300 font-bold">
              {selectedForReplay.size} selected
            </span>
            {selectedForReplay.size > 0 && (
              <button
                onClick={() => {
                  const packetsToReplay = packets.filter(p => selectedForReplay.has(p.id));
                  onReplayPackets(packetsToReplay);
                  setIsReplaySelectMode(false);
                  setSelectedForReplay(new Set());
                }}
                className="px-2.5 py-1 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-[11px] flex items-center gap-1 shadow-sm transition-colors cursor-pointer"
              >
                <Play className="w-3 h-3" />
                <span>Replay {selectedForReplay.size} Packets</span>
              </button>
            )}
          </div>
        )}

        {/* Selected diff pills */}
        {isDiffMode && (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 text-[11px]">
              <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 font-bold">
                A: {diffPacketA ? `#${diffPacketA.id}` : 'Select 1st'}
              </span>
              <span className="text-slate-500">vs</span>
              <span className="px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/30 text-amber-300 font-bold">
                B: {diffPacketB ? `#${diffPacketB.id}` : 'Select 2nd'}
              </span>
            </div>

            {diffPacketA && diffPacketB && (
              <button
                onClick={() => setShowDiffModal(true)}
                className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-[11px] flex items-center gap-1 shadow-sm transition-colors cursor-pointer"
              >
                <GitCompare className="w-3 h-3" />
                <span>Open Diff View</span>
              </button>
            )}

            <button
              onClick={() => {
                setDiffPacketA(null);
                setDiffPacketB(null);
                setIsDiffMode(false);
              }}
              className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
              title="Exit Diff Mode"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* Table Container */}
      <div
        ref={tableContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto overflow-x-auto custom-scrollbar"
      >
        <table className="w-full text-left border-collapse font-mono text-xs">
          {/* Table Header */}
          <thead
            className={`sticky top-0 z-20 border-b transition-colors select-none ${
              isDark ? 'bg-slate-900 border-slate-800 text-slate-500' : 'bg-slate-200 border-slate-300 text-slate-700'
            }`}
          >
            <tr className="text-[11px] uppercase tracking-wider divide-x divide-slate-800/40">
              {isDiffMode && (
                <th className="w-10 px-2 py-2.5 text-center text-slate-500 font-bold">
                  Diff
                </th>
              )}

              {isReplaySelectMode && (
                <th className="w-10 px-2 py-2.5 text-center text-slate-500 font-bold">
                  <input
                    type="checkbox"
                    checked={selectedForReplay.size > 0 && selectedForReplay.size === sortedPackets.length}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedForReplay(new Set(sortedPackets.map(p => p.id)));
                      } else {
                        setSelectedForReplay(new Set());
                      }
                    }}
                    className="accent-amber-500 w-3 h-3 cursor-pointer"
                    title="Select All"
                  />
                </th>
              )}

              <th
                onClick={() => handleSort('id')}
                className={`w-16 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>No.</span>
                  {renderSortIcon('id')}
                </div>
              </th>

              <th
                onClick={() => handleSort('relativeTime')}
                className={`w-24 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Time</span>
                  {renderSortIcon('relativeTime')}
                </div>
              </th>

              <th
                onClick={() => handleSort('source')}
                className={`w-36 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Source</span>
                  {renderSortIcon('source')}
                </div>
              </th>

              <th
                onClick={() => handleSort('destination')}
                className={`w-36 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Destination</span>
                  {renderSortIcon('destination')}
                </div>
              </th>

              <th
                onClick={() => handleSort('protocol')}
                className={`w-24 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Protocol</span>
                  {renderSortIcon('protocol')}
                </div>
              </th>

              <th
                onClick={() => handleSort('length')}
                className={`w-20 px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Length</span>
                  {renderSortIcon('length')}
                </div>
              </th>

              <th onClick={() => handleSort('info')} className={`px-4 py-2.5 cursor-pointer group font-bold ${isDark ? "hover:bg-slate-800 text-slate-500" : "hover:bg-slate-300 text-slate-700"}`}><div className="flex items-center gap-1"><span>Info</span>{renderSortIcon('info')}</div></th>
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="divide-y divide-slate-900 font-mono text-[11px]">
            {sortedPackets.length === 0 ? (
              <tr>
                <td colSpan={isDiffMode ? 8 : 7} className="text-center py-16 text-slate-500">
                  <div className="flex flex-col items-center justify-center gap-1">
                    <Filter className="w-6 h-6 text-slate-600 mb-1" />
                    <span>No packets match current display filter or capture is empty.</span>
                    <span className="text-[10px] text-slate-600">Start capture or clear filter to resume telemetry</span>
                  </div>
                </td>
              </tr>
            ) : (
              sortedPackets.map(packet => {
                const isSelected = selectedPacket?.id === packet.id;
                const isPacketA = diffPacketA?.id === packet.id;
                const isPacketB = diffPacketB?.id === packet.id;
                const style = colorEngine.getPacketStyle(packet, isDark);

                return (
                  <tr
                    key={packet.id}
                    onClick={() => handleRowClick(packet)}
                    onContextMenu={e => handleContextMenu(e, packet)}
                    className={`cursor-pointer transition-colors duration-75 ${
                      isPacketA
                        ? '!bg-cyan-950/70 !text-cyan-200 ring-1 ring-inset ring-cyan-400 font-bold'
                        : isPacketB
                        ? '!bg-amber-950/70 !text-amber-200 ring-1 ring-inset ring-amber-400 font-bold'
                        : isSelected
                        ? isDark
                          ? '!bg-slate-800 !text-cyan-200 ring-1 ring-inset ring-cyan-500 font-bold'
                          : '!bg-cyan-100 !text-slate-950 ring-1 ring-inset ring-cyan-500 font-bold'
                        : isDark
                        ? 'hover:bg-slate-900 text-cyan-200/90'
                        : 'hover:bg-slate-100 text-slate-800'
                    }`}
                    style={!isSelected && !isPacketA && !isPacketB && style.background ? { backgroundColor: style.background } : undefined}
                  >
                    {/* Diff Selector Checkbox */}
                    {isDiffMode && (
                      <td className="px-2 py-2 text-center" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => handleToggleDiffSelection(packet)}
                          className="p-0.5 rounded text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
                        >
                          {isPacketA ? (
                            <span className="w-4 h-4 rounded bg-cyan-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                              A
                            </span>
                          ) : isPacketB ? (
                            <span className="w-4 h-4 rounded bg-amber-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                              B
                            </span>
                          ) : (
                            <Square className="w-4 h-4 text-slate-600 hover:text-slate-400" />
                          )}
                        </button>
                      </td>
                    )}

                    {/* Replay Selector Checkbox */}
                    {isReplaySelectMode && (
                      <td className="px-2 py-2 text-center" onClick={e => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedForReplay.has(packet.id)}
                          onChange={(e) => {
                            const newSet = new Set(selectedForReplay);
                            if (e.target.checked) {
                              newSet.add(packet.id);
                            } else {
                              newSet.delete(packet.id);
                            }
                            setSelectedForReplay(newSet);
                          }}
                          className="accent-amber-500 w-3 h-3 cursor-pointer"
                        />
                      </td>
                    )}

                    {/* No. */}
                    <td className="px-4 py-2 font-mono whitespace-nowrap text-slate-600">
                      <div className="flex items-center gap-1.5">
                        {packet.anomaly || packet.status === 'alert' ? (
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-500 shrink-0 animate-pulse" />
                        ) : packet.status === 'warning' ? (
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                        ) : null}
                        <span>{packet.id}</span>
                      </div>
                    </td>

                    {/* Time */}
                    <td className={`px-4 py-2 whitespace-nowrap font-mono ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                      {typeof packet.relativeTime === 'number' ? packet.relativeTime.toFixed(2) : '0.00'}
                    </td>

                    {/* Source */}
                    <td className="px-4 py-2 whitespace-nowrap truncate max-w-[140px]" title={packet.source}>
                      {packet.source}
                      {packet.sourcePort && <span className={isDark ? 'text-slate-500 text-[10px]' : 'text-slate-400 text-[10px]'}>:{packet.sourcePort}</span>}
                    </td>

                    {/* Destination */}
                    <td className="px-4 py-2 whitespace-nowrap truncate max-w-[140px]" title={packet.destination}>
                      {packet.destination}
                      {packet.destPort && <span className={isDark ? 'text-slate-500 text-[10px]' : 'text-slate-400 text-[10px]'}>:{packet.destPort}</span>}
                    </td>

                    {/* Protocol */}
                    <td className="px-4 py-2 whitespace-nowrap font-bold">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] uppercase"
                        style={{ color: style.color || (isDark ? '#22d3ee' : '#0891b2') }}
                      >
                        {packet.protocol}
                      </span>
                    </td>

                    {/* Length */}
                    <td className={`px-4 py-2 whitespace-nowrap ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{packet.length}</td>

                    {/* Info */}
                    <td
                      className={`px-4 py-2 truncate max-w-xl ${
                        packet.anomaly ? (isDark ? 'text-rose-300 font-semibold' : 'text-rose-600 font-semibold') : ''
                      }`}
                      title={packet.info}
                    >
                      {packet.info}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Right Click Context Menu */}
      {contextMenu && (
        <div
          className={`fixed z-50 rounded-lg border p-1 shadow-2xl transition-all ${
            isDark ? 'bg-slate-950 border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800 shadow-md rounded-lg'
          } min-w-[240px] font-sans text-xs`}
          style={{ top: Math.min(contextMenu.y, window.innerHeight - 300), left: Math.min(contextMenu.x, window.innerWidth - 260) }}
        >
          <div className="px-2 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 font-mono">
            Packet #{contextMenu.packet.id} Options
          </div>

          {/* Diff Actions */}
          <button
            onClick={() => {
              setDiffPacketA(contextMenu.packet);
              setIsDiffMode(true);
            }}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <GitCompare className="w-3.5 h-3.5 text-cyan-400" />
            <span>Set as Diff Baseline (Packet A)</span>
          </button>

          {selectedPacket && selectedPacket.id !== contextMenu.packet.id && (
            <button
              onClick={() => {
                setDiffPacketA(selectedPacket);
                setDiffPacketB(contextMenu.packet);
                setShowDiffModal(true);
              }}
              className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
            >
              <ArrowRightLeft className="w-3.5 h-3.5 text-amber-400" />
              <span>Compare with #{selectedPacket.id} (Diff View)</span>
            </button>
          )}

          <div className="my-1 border-t border-slate-800" />

          {contextMenu.packet.streamId !== undefined && (
            <button
              onClick={() => onFollowStream(contextMenu.packet.streamId!)}
              className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
            >
              <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
              <span>Follow Stream (#{contextMenu.packet.streamId})</span>
            </button>
          )}

          <button
            onClick={() => onQuickFilter(`ip.src == "${contextMenu.packet.source}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5" />
            <span>Filter by Source ({contextMenu.packet.source})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`ip.dst == "${contextMenu.packet.destination}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5" />
            <span>Filter by Destination ({contextMenu.packet.destination})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`proto == ${contextMenu.packet.protocol.toLowerCase()}`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5" />
            <span>Filter by Protocol ({contextMenu.packet.protocol})</span>
          </button>

          <div className="my-1 border-t border-slate-800" />

          <button
            onClick={() => {
              navigator.clipboard.writeText(contextMenu.packet.hexDump);
            }}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Copy className="w-3.5 h-3.5 text-emerald-400" />
            <span>Copy Raw Hex Stream</span>
          </button>
        </div>
      )}

      {/* Packet Diff Modal */}
      {showDiffModal && diffPacketA && diffPacketB && (
        <PacketDiffModal
          packetA={diffPacketA}
          packetB={diffPacketB}
          onClose={() => setShowDiffModal(false)}
          onSwapPackets={() => {
            const temp = diffPacketA;
            setDiffPacketA(diffPacketB);
            setDiffPacketB(temp);
          }}
          isDark={isDark}
        />
      )}
    </div>
  );
};
