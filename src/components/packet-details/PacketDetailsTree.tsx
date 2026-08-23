import React, { useState } from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import {
  ChevronRight,
  ChevronDown,
  Layers,
  Copy,
  Check,
  ShieldAlert,
  Maximize2,
  Minimize2,
} from 'lucide-react';

interface PacketDetailsTreeProps {
  packet: Packet | null;
  onHoverByteRange: (range: [number, number] | null) => void;
  activeByteRange: [number, number] | null;
  permissions: UserRolePermissions;
  isDark: boolean;
}

export const PacketDetailsTree: React.FC<PacketDetailsTreeProps> = ({
  packet,
  onHoverByteRange,
  activeByteRange,
  permissions,
  isDark,
}) => {
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({
    '0': true,
    '1': true,
    '2': true,
    '3': true,
    '4': true,
  });
  const [copiedField, setCopiedField] = useState<string | null>(null);

  if (!packet) {
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-slate-500 font-mono text-xs">
        <div className="flex flex-col items-center gap-1.5">
          <Layers className="w-6 h-6 text-slate-600 mb-1" />
          <span className="uppercase tracking-wider">No packet selected</span>
          <span className="text-[10px] text-slate-600">Select any packet from the list above for deep protocol dissection</span>
        </div>
      </div>
    );
  }

  const toggleLayer = (layerIndex: number) => {
    setExpandedLayers(prev => ({
      ...prev,
      [layerIndex]: !prev[layerIndex],
    }));
  };

  const handleExpandAll = () => {
    const all: Record<string, boolean> = {};
    packet.layers.forEach((_, idx) => (all[idx] = true));
    setExpandedLayers(all);
  };

  const handleCollapseAll = () => {
    setExpandedLayers({});
  };

  const copyFieldValue = (name: string, val: string | number | boolean) => {
    navigator.clipboard.writeText(String(val));
    setCopiedField(name);
    setTimeout(() => setCopiedField(null), 1500);
  };

  return (
    <div className="h-full flex flex-col overflow-hidden select-none">
      {/* Geometric Inspection Header */}
      <div
        className={`px-4 py-2 border-b flex items-center justify-between transition-colors ${
          isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-[#f8fafc] border-slate-200 text-slate-800 shadow-sm'
        }`}
      >
        <div className="flex items-center gap-2 text-xs font-mono font-bold">
          <span className="text-slate-500 uppercase tracking-tighter">Packet Inspection</span>
          <span className="text-cyan-400">#Frame {packet.id} ({packet.length} bytes)</span>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={handleExpandAll}
            className={`p-1 rounded text-xs transition-colors cursor-pointer ${
              isDark ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-200 text-slate-600'
            }`}
            title="Expand all protocol layers"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleCollapseAll}
            className={`p-1 rounded text-xs transition-colors cursor-pointer ${
              isDark ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-200 text-slate-600'
            }`}
            title="Collapse all protocol layers"
          >
            <Minimize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Security Threat Alert banner if present */}
      {packet.anomaly && (
        <div
          className={`p-3 m-3 rounded-lg border text-xs ${
            isDark ? 'bg-rose-500/10 border-rose-500/30 text-rose-200' : 'bg-rose-50 border-rose-300 text-rose-900'
          }`}
        >
          <div className="flex items-center gap-2 font-bold uppercase tracking-wider">
            <div className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span className="text-rose-500 text-[10px]">Alert Active</span>
            <span className="text-slate-200 font-semibold">{packet.anomaly.title}</span>
          </div>
          <p className="mt-1 text-[11px] text-rose-200/90 leading-relaxed font-sans">{packet.anomaly.description}</p>
          {packet.anomaly.recommendation && (
            <div className="mt-1.5 pt-1.5 border-t border-rose-500/20 text-[10px] text-rose-300 font-mono">
              <b>RECOMMENDED ACTION:</b> {packet.anomaly.recommendation}
            </div>
          )}
        </div>
      )}

      {/* Expandable Protocol Tree */}
      <div className="flex-1 overflow-y-auto p-3 space-y-1.5 custom-scrollbar font-mono text-xs">
        {packet.layers.map((layer, idx) => {
          const isExpanded = expandedLayers[idx] ?? true;
          const isLayerActive =
            activeByteRange &&
            layer.rawBytesRange &&
            activeByteRange[0] === layer.rawBytesRange[0] &&
            activeByteRange[1] === layer.rawBytesRange[1];

          return (
            <div
              key={idx}
              className={`rounded-md border transition-colors ${
                isLayerActive
                  ? 'border-cyan-500/80 bg-cyan-950/30'
                  : isDark
                  ? 'border-slate-800 bg-slate-900/60'
                  : 'border-slate-300 bg-white'
              }`}
            >
              {/* Layer Summary Header */}
              <div
                onClick={() => toggleLayer(idx)}
                onMouseEnter={() => onHoverByteRange(layer.rawBytesRange || null)}
                onMouseLeave={() => onHoverByteRange(null)}
                className={`flex items-center justify-between px-3 py-1.5 cursor-pointer select-none rounded ${
                  isDark ? 'hover:bg-slate-800/80 text-slate-300' : 'hover:bg-slate-100 text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2 truncate">
                  {isExpanded ? (
                    <ChevronDown className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  )}
                  <span className="font-semibold truncate text-slate-200">{layer.summary}</span>
                </div>

                {layer.rawBytesRange && (
                  <span className="text-[10px] text-slate-500 font-mono shrink-0">
                    [{layer.rawBytesRange[0]}-{layer.rawBytesRange[1]}]
                  </span>
                )}
              </div>

              {/* Layer Fields */}
              {isExpanded && layer.fields && layer.fields.length > 0 && (
                <div className="pl-6 pr-3 py-1.5 space-y-1 border-t border-slate-800/60 text-[11px]">
                  {layer.fields.map((field, fIdx) => {
                    const isFieldActive =
                      activeByteRange &&
                      field.rawBytesRange &&
                      activeByteRange[0] === field.rawBytesRange[0] &&
                      activeByteRange[1] === field.rawBytesRange[1];

                    return (
                      <div
                        key={fIdx}
                        onMouseEnter={e => {
                          e.stopPropagation();
                          onHoverByteRange(field.rawBytesRange || layer.rawBytesRange || null);
                        }}
                        onMouseLeave={e => {
                          e.stopPropagation();
                          onHoverByteRange(null);
                        }}
                        className={`flex items-center justify-between px-2 py-0.5 rounded group transition-colors ${
                          isFieldActive
                            ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                            : isDark
                            ? 'hover:bg-slate-800/60 text-slate-400'
                            : 'hover:bg-slate-100 text-slate-700'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <span className="text-slate-500">{field.name}:</span>
                          <span className="font-semibold text-slate-200 truncate">{String(field.value)}</span>
                          {field.description && (
                            <span className="text-[10px] text-slate-500 italic hidden sm:inline truncate">
                              ({field.description})
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => copyFieldValue(field.name, field.value)}
                            className="p-0.5 rounded hover:bg-slate-700 text-slate-400 hover:text-slate-200 cursor-pointer"
                            title="Copy field value"
                          >
                            {copiedField === field.name ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
