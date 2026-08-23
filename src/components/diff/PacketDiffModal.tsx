import React, { useState, useMemo } from 'react';
import { Packet, ProtocolLayer, ProtocolField } from '../../types/packet';
import {
  GitCompare,
  ArrowRightLeft,
  X,
  Layers,
  Binary,
  CheckCircle2,
  AlertTriangle,
  Download,
  Copy,
  ChevronRight,
  ChevronDown,
  ShieldAlert,
  SlidersHorizontal,
} from 'lucide-react';

interface PacketDiffModalProps {
  packetA: Packet;
  packetB: Packet;
  onClose: () => void;
  onSwapPackets?: () => void;
  isDark: boolean;
}

export const PacketDiffModal: React.FC<PacketDiffModalProps> = ({
  packetA,
  packetB,
  onClose,
  onSwapPackets,
  isDark,
}) => {
  const [activeTab, setActiveTab] = useState<'headers' | 'hex' | 'summary'>('headers');
  const [showOnlyDifferences, setShowOnlyDifferences] = useState(false);
  const [copiedDiff, setCopiedDiff] = useState(false);

  // Compute byte-level differences
  const hexDiffStats = useMemo(() => {
    const bytesA = packetA.rawBytes;
    const bytesB = packetB.rawBytes;
    const maxLen = Math.max(bytesA.length, bytesB.length);
    let diffCount = 0;

    for (let i = 0; i < maxLen; i++) {
      if (bytesA[i] !== bytesB[i]) {
        diffCount++;
      }
    }

    const similarity = maxLen > 0 ? (((maxLen - diffCount) / maxLen) * 100).toFixed(1) : '100.0';
    return { maxLen, diffCount, similarity };
  }, [packetA, packetB]);

  // Compute protocol layer comparison tree
  const layerDiffs = useMemo(() => {
    const layersA = packetA.layers;
    const layersB = packetB.layers;

    const layerMap = new Map<string, { layerA?: ProtocolLayer; layerB?: ProtocolLayer }>();

    layersA.forEach(l => {
      layerMap.set(l.name, { layerA: l });
    });

    layersB.forEach(l => {
      const existing = layerMap.get(l.name) || {};
      layerMap.set(l.name, { ...existing, layerB: l });
    });

    const results: {
      layerName: string;
      layerA?: ProtocolLayer;
      layerB?: ProtocolLayer;
      fieldDiffs: {
        fieldName: string;
        valA?: string | number | boolean;
        valB?: string | number | boolean;
        isDiff: boolean;
      }[];
      hasDifferences: boolean;
    }[] = [];

    layerMap.forEach((val, layerName) => {
      const fieldMap = new Map<string, { valA?: any; valB?: any }>();

      val.layerA?.fields.forEach(f => {
        fieldMap.set(f.name, { valA: f.value });
      });

      val.layerB?.fields.forEach(f => {
        const existing = fieldMap.get(f.name) || {};
        fieldMap.set(f.name, { ...existing, valB: f.value });
      });

      const fieldDiffs: {
        fieldName: string;
        valA?: any;
        valB?: any;
        isDiff: boolean;
      }[] = [];

      let hasDiff = false;
      fieldMap.forEach((fVal, fieldName) => {
        const isDiff = String(fVal.valA) !== String(fVal.valB);
        if (isDiff) hasDiff = true;
        fieldDiffs.push({
          fieldName,
          valA: fVal.valA,
          valB: fVal.valB,
          isDiff,
        });
      });

      results.push({
        layerName,
        layerA: val.layerA,
        layerB: val.layerB,
        fieldDiffs,
        hasDifferences: hasDiff || !val.layerA || !val.layerB,
      });
    });

    return results;
  }, [packetA, packetB]);

  // Generate Hex lines aligned by 16 bytes
  const hexLinesA = useMemo(() => formatHexRows(packetA.rawBytes), [packetA]);
  const hexLinesB = useMemo(() => formatHexRows(packetB.rawBytes), [packetB]);

  const maxRows = Math.max(hexLinesA.length, hexLinesB.length);

  const handleExportDiffReport = () => {
    const report = {
      title: 'Net View - Packet Comparison & Differential Analysis Report',
      timestamp: new Date().toISOString(),
      similarityScore: `${hexDiffStats.similarity}%`,
      totalByteDifferences: hexDiffStats.diffCount,
      packetA: {
        id: packetA.id,
        time: packetA.relativeTime,
        protocol: packetA.protocol,
        length: packetA.length,
        source: packetA.source,
        destination: packetA.destination,
        info: packetA.info,
      },
      packetB: {
        id: packetB.id,
        time: packetB.relativeTime,
        protocol: packetB.protocol,
        length: packetB.length,
        source: packetB.source,
        destination: packetB.destination,
        info: packetB.info,
      },
      headerDifferences: layerDiffs
        .map(l => ({
          layer: l.layerName,
          fields: l.fieldDiffs.filter(f => f.isDiff),
        }))
        .filter(l => l.fields.length > 0),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netview_diff_${packetA.id}_vs_${packetB.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyDiffSummary = () => {
    const text = `--- NET VIEW PACKET DIFF ---
Packet A: #${packetA.id} (${packetA.protocol}, ${packetA.length}B) [${packetA.source} -> ${packetA.destination}]
Packet B: #${packetB.id} (${packetB.protocol}, ${packetB.length}B) [${packetB.source} -> ${packetB.destination}]
Similarity: ${hexDiffStats.similarity}% | Byte Deltas: ${hexDiffStats.diffCount} bytes
`;
    navigator.clipboard.writeText(text);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm select-none">
      <div
        className={`w-full max-w-6xl h-[90vh] rounded-xl border shadow-2xl flex flex-col overflow-hidden ${
          isDark ? 'bg-slate-900 border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
        }`}
      >
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center">
              <GitCompare className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold tracking-tight">Packet Diff & Comparison Analysis</h2>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {hexDiffStats.similarity}% Match
                </span>
                {hexDiffStats.diffCount > 0 ? (
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {hexDiffStats.diffCount} Byte Deltas
                  </span>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    Identical Payloads
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400">
                Comparing Baseline <b>#{packetA.id}</b> with Target <b>#{packetB.id}</b>
              </p>
            </div>
          </div>

          {/* Actions & Close */}
          <div className="flex items-center gap-2">
            {onSwapPackets && (
              <button
                onClick={onSwapPackets}
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Swap Baseline (A) and Target (B)"
              >
                <ArrowRightLeft className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Swap A ⇄ B</span>
              </button>
            )}

            <button
              onClick={handleCopyDiffSummary}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
              title="Copy Summary"
            >
              {copiedDiff ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>

            <button
              onClick={handleExportDiffReport}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
              title="Export Diff Report JSON"
            >
              <Download className="w-4 h-4 text-cyan-400" />
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Packet Metadata Summary Banner */}
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-800 border-b border-slate-800 bg-slate-950/40 shrink-0 font-mono text-xs">
          {/* Packet A Summary */}
          <div className="p-3 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                Packet A (Baseline #{packetA.id})
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                {packetA.protocol} • {packetA.length} Bytes
              </span>
            </div>
            <div className="text-[11px] text-slate-300 truncate">
              <span className="text-slate-500">Route:</span> {packetA.source} → {packetA.destination}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              <span className="text-slate-500">Info:</span> {packetA.info}
            </div>
          </div>

          {/* Packet B Summary */}
          <div className="p-3 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-amber-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                Packet B (Target #{packetB.id})
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                {packetB.protocol} • {packetB.length} Bytes
              </span>
            </div>
            <div className="text-[11px] text-slate-300 truncate">
              <span className="text-slate-500">Route:</span> {packetB.source} → {packetB.destination}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              <span className="text-slate-500">Info:</span> {packetB.info}
            </div>
          </div>
        </div>

        {/* View Tabs & Filters */}
        <div className="px-5 py-2 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setActiveTab('headers')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'headers'
                  ? 'bg-cyan-500 text-slate-950 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Header Fields Diff</span>
            </button>

            <button
              onClick={() => setActiveTab('hex')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono flex items-center gap-1.5 transition-colors cursor-pointer ${
                activeTab === 'hex'
                  ? 'bg-cyan-500 text-slate-950 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Side-by-Side Hex Diff</span>
            </button>
          </div>

          {activeTab === 'headers' && (
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={showOnlyDifferences}
                onChange={e => setShowOnlyDifferences(e.target.checked)}
                className="rounded accent-cyan-400 cursor-pointer"
              />
              <span className="font-mono text-[11px]">Show Differences Only</span>
            </label>
          )}
        </div>

        {/* Main Diff Content Pane */}
        <div className="flex-1 overflow-y-auto overflow-x-auto custom-scrollbar p-4">
          {activeTab === 'headers' ? (
            /* Header Fields Side-by-Side Comparison */
            <div className="space-y-4">
              {layerDiffs
                .filter(layer => (showOnlyDifferences ? layer.hasDifferences : true))
                .map((layer, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-slate-800 bg-slate-950/60 overflow-hidden shadow-sm font-mono text-xs"
                  >
                    {/* Layer Header */}
                    <div className="px-3.5 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{layer.layerName}</span>
                        {layer.hasDifferences ? (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            Modified
                          </span>
                        ) : (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            Identical
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-slate-500">
                        {layer.fieldDiffs.filter(f => f.isDiff).length} diffs in layer
                      </span>
                    </div>

                    {/* Fields Comparison Table */}
                    <table className="w-full text-left border-collapse text-[11px]">
                      <thead>
                        <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider bg-slate-950/40">
                          <th className="px-3.5 py-1.5 w-1/3">Field Name</th>
                          <th className="px-3.5 py-1.5 w-1/3 text-cyan-400">Packet A (#{packetA.id})</th>
                          <th className="px-3.5 py-1.5 w-1/3 text-amber-400">Packet B (#{packetB.id})</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-850">
                        {layer.fieldDiffs
                          .filter(f => (showOnlyDifferences ? f.isDiff : true))
                          .map((field, fIdx) => (
                            <tr
                              key={fIdx}
                              className={`transition-colors ${
                                field.isDiff
                                  ? 'bg-amber-500/10 hover:bg-amber-500/15'
                                  : 'hover:bg-slate-900/50 text-slate-400'
                              }`}
                            >
                              <td className="px-3.5 py-2 font-semibold text-slate-300">{field.fieldName}</td>
                              <td
                                className={`px-3.5 py-2 ${
                                  field.isDiff ? 'text-cyan-300 font-bold bg-cyan-950/30' : 'text-slate-300'
                                }`}
                              >
                                {field.valA !== undefined ? String(field.valA) : <span className="text-slate-600 italic">None</span>}
                              </td>
                              <td
                                className={`px-3.5 py-2 ${
                                  field.isDiff ? 'text-amber-300 font-bold bg-amber-950/30' : 'text-slate-300'
                                }`}
                              >
                                {field.valB !== undefined ? String(field.valB) : <span className="text-slate-600 italic">None</span>}
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                ))}
            </div>
          ) : (
            /* Side-by-Side Hex Dump Comparison */
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-[11px]">
              {/* Packet A Hex Dump */}
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 overflow-x-auto custom-scrollbar">
                <div className="text-xs font-bold text-cyan-400 mb-2 border-b border-slate-800 pb-1 flex items-center justify-between">
                  <span>Packet A (#{packetA.id}) - {packetA.length} Bytes</span>
                  <span className="text-[10px] text-slate-500">Offset | Hex | ASCII</span>
                </div>
                <table className="w-full border-collapse">
                  <tbody>
                    {Array.from({ length: maxRows }).map((_, rowIdx) => {
                      const rowA = hexLinesA[rowIdx];
                      const rowB = hexLinesB[rowIdx];
                      const offsetHex = (rowIdx * 16).toString(16).padStart(4, '0');

                      return (
                        <tr key={rowIdx} className="hover:bg-slate-900/60 leading-relaxed">
                          <td className="text-slate-600 pr-3 select-none">{offsetHex}</td>
                          <td className="pr-3 whitespace-nowrap">
                            {rowA
                              ? rowA.bytes.map((byte, bIdx) => {
                                  const byteB = rowB?.bytes[bIdx];
                                  const isDifferent = byteB !== undefined && byte !== byteB;
                                  return (
                                    <span
                                      key={bIdx}
                                      className={`inline-block w-5 text-center mr-1 ${
                                        isDifferent
                                          ? 'bg-amber-500/30 text-amber-300 font-bold rounded'
                                          : 'text-cyan-200/90'
                                      }`}
                                    >
                                      {byte.toString(16).padStart(2, '0')}
                                    </span>
                                  );
                                })
                              : <span className="text-slate-700 italic">EOF</span>}
                          </td>
                          <td className="text-slate-400 whitespace-nowrap border-l border-slate-800 pl-2">
                            {rowA ? rowA.ascii : ''}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Packet B Hex Dump */}
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 overflow-x-auto custom-scrollbar">
                <div className="text-xs font-bold text-amber-400 mb-2 border-b border-slate-800 pb-1 flex items-center justify-between">
                  <span>Packet B (#{packetB.id}) - {packetB.length} Bytes</span>
                  <span className="text-[10px] text-slate-500">Offset | Hex | ASCII</span>
                </div>
                <table className="w-full border-collapse">
                  <tbody>
                    {Array.from({ length: maxRows }).map((_, rowIdx) => {
                      const rowA = hexLinesA[rowIdx];
                      const rowB = hexLinesB[rowIdx];
                      const offsetHex = (rowIdx * 16).toString(16).padStart(4, '0');

                      return (
                        <tr key={rowIdx} className="hover:bg-slate-900/60 leading-relaxed">
                          <td className="text-slate-600 pr-3 select-none">{offsetHex}</td>
                          <td className="pr-3 whitespace-nowrap">
                            {rowB
                              ? rowB.bytes.map((byte, bIdx) => {
                                  const byteA = rowA?.bytes[bIdx];
                                  const isDifferent = byteA !== undefined && byte !== byteA;
                                  return (
                                    <span
                                      key={bIdx}
                                      className={`inline-block w-5 text-center mr-1 ${
                                        isDifferent
                                          ? 'bg-amber-500/30 text-amber-300 font-bold rounded'
                                          : 'text-amber-200/90'
                                      }`}
                                    >
                                      {byte.toString(16).padStart(2, '0')}
                                    </span>
                                  );
                                })
                              : <span className="text-slate-700 italic">EOF</span>}
                          </td>
                          <td className="text-slate-400 whitespace-nowrap border-l border-slate-800 pl-2">
                            {rowB ? rowB.ascii : ''}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs font-mono shrink-0">
          <span className="text-slate-500">
            Byte match: <b>{hexDiffStats.similarity}%</b> ({hexDiffStats.diffCount} byte differences detected)
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-colors cursor-pointer"
          >
            Close Diff View
          </button>
        </div>
      </div>
    </div>
  );
};

// Helper: Format raw bytes into 16-byte aligned rows
function formatHexRows(raw: Uint8Array): { bytes: number[]; ascii: string }[] {
  const rows: { bytes: number[]; ascii: string }[] = [];
  for (let i = 0; i < raw.length; i += 16) {
    const slice = Array.from(raw.slice(i, i + 16));
    let ascii = '';
    for (const b of slice) {
      ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }
    rows.push({ bytes: slice, ascii });
  }
  return rows;
}
