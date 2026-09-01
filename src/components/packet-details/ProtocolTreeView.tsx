import React, { useState } from 'react';
import { Packet, ProtocolField } from '../../types/packet';
import { TbChevronRight, TbChevronDown, TbCopy, TbCheck } from 'react-icons/tb';
import { renderBitfield } from '../../lib/bitfield';

/**
 * The dissected protocol tree itself, with no surrounding chrome.
 *
 * Split out of PacketDetailsTree so the same tree can be presented two ways:
 * the workspace's bottom pane wraps it in its "Packet Inspection" header, and
 * the packet detail window lays it out its own way. Neither owns the tree, so
 * the two cannot drift - a bitfield row, an expert-info colour or a
 * cross-frame link behaves identically wherever the tree is shown.
 */

// Expert-info severities reuse the palette the anomaly banners use, so one
// severity means one colour across the whole app.
const EXPERT_SEVERITY_CLASS: Record<string, string> = {
  error: 'text-rose-600 dark:text-rose-400',
  warn: 'text-amber-600 dark:text-amber-400',
  note: 'text-sky-600 dark:text-sky-400',
  chat: 'text-muted-foreground',
};

interface ProtocolTreeViewProps {
  packet: Packet;
  onHoverByteRange: (range: [number, number] | null) => void;
  activeByteRange: [number, number] | null;
  /** Follows a cross-packet reference such as `[Response In: 11]`. */
  onSelectFrame?: (frameNumber: number) => void;
  className?: string;
}

export const ProtocolTreeView: React.FC<ProtocolTreeViewProps> = ({
  packet,
  onHoverByteRange,
  activeByteRange,
  onSelectFrame,
  className,
}) => {
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({
    '0': true, '1': true, '2': true, '3': true, '4': true,
  });
  const [copiedField, setCopiedField] = useState<string | null>(null);
  // Collapsed nested fields, keyed by their path through the tree. The reference analyzer
  // gives every node with children its own disclosure triangle, independent of
  // its layer - Traffic Class can be shut while the rest of IPv6 stays open.
  // Tracking what is CLOSED rather than what is open keeps the default
  // expanded, which is how the reference analyzer opens a packet.
  const [collapsedPaths, setCollapsedPaths] = useState<Record<string, boolean>>({});

  const togglePath = (path: string) => setCollapsedPaths(prev => ({ ...prev, [path]: !prev[path] }));
  const toggleLayer = (layerIndex: number) =>
    setExpandedLayers(prev => ({ ...prev, [layerIndex]: !(prev[layerIndex] ?? true) }));

  const copyFieldValue = (name: string, val: string | number | boolean) => {
    navigator.clipboard.writeText(String(val));
    setCopiedField(name);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const renderField = (
    field: ProtocolField,
    key: string | number,
    depth: number,
    fallbackRange: [number, number] | null,
    path = '',
  ): React.ReactNode => {
    const nodePath = `${path}/${key}`;
    const hasChildren = !!field.children?.length;
    const isOpen = hasChildren && !collapsedPaths[nodePath];
    const isFieldActive =
      activeByteRange &&
      field.rawBytesRange &&
      activeByteRange[0] === field.rawBytesRange[0] &&
      activeByteRange[1] === field.rawBytesRange[1];

    // One step per level rather than capping at two: the reference analyzer nests four deep
    // in places (Queries > record, Flags > bit rows) and a flat cap makes those
    // levels indistinguishable.
    const indentStyle = { marginLeft: `${depth * 0.9}rem` };

    // A generated field is the dissector's own commentary - a stream index, a
    // time delta - so there are no bytes to point at. Offering a highlight
    // would light up whatever range the parent layer happens to occupy and
    // imply the field lives there.
    const hoverRange = field.generated ? null : field.rawBytesRange || fallbackRange || null;

    // The reference analyzer draws a sub-byte field as the containing word in binary with
    // everything outside the field dotted, which is the only way its position
    // and width are visible. Needs the frame bytes, so it degrades to the plain
    // row if a packet ever arrives without them.
    const bitfieldText =
      field.bitfield && field.rawBytesRange && packet.rawBytes?.length
        ? renderBitfield(packet.rawBytes, field.rawBytesRange[0], field.bitfield)
        : null;

    return (
      <div key={key}>
        <div
          onMouseEnter={e => { e.stopPropagation(); onHoverByteRange(hoverRange); }}
          onMouseLeave={e => { e.stopPropagation(); onHoverByteRange(null); }}
          style={indentStyle}
          className={`flex items-center justify-between px-2 py-0.5 rounded group transition-colors ${
            isFieldActive
              ? 'bg-primary/15 dark:bg-primary/20 text-primary font-bold'
              : 'hover:bg-accent/60 text-muted-foreground'
          }`}
        >
          <div className="flex items-center gap-2 truncate">
            {hasChildren ? (
              <button
                onClick={e => { e.stopPropagation(); togglePath(nodePath); }}
                className="shrink-0 cursor-pointer text-muted-foreground hover:text-foreground"
                title={isOpen ? 'Collapse' : 'Expand'}
              >
                {isOpen ? <TbChevronDown className="w-3 h-3" /> : <TbChevronRight className="w-3 h-3" />}
              </button>
            ) : (
              // Keeps every label on the same left edge whether or not the row
              // has a triangle, which is what makes the tree scannable.
              <span className="w-3 shrink-0" />
            )}
            {bitfieldText && (
              // Fixed-width and dimmed so the binary reads as a ruler behind
              // the value rather than competing with it.
              <span className="text-muted-foreground/70 whitespace-pre shrink-0">{bitfieldText} =</span>
            )}
            {/* A grouping node such as Queries or [Timestamps] carries no value
                of its own, and the reference analyzer prints no trailing colon for those. */}
            <span className={`text-muted-foreground ${field.generated ? 'italic' : ''}`}>
              {field.name}{field.value === '' ? '' : ':'}
            </span>
            {field.linkToFrame !== undefined && onSelectFrame ? (
              <button
                onClick={e => { e.stopPropagation(); onSelectFrame(field.linkToFrame!); }}
                className="font-semibold text-primary underline underline-offset-2 truncate cursor-pointer hover:opacity-80"
                title={`Go to frame ${field.linkToFrame}`}
              >
                {String(field.value)}
              </button>
            ) : (
              <span
                className={`font-semibold truncate ${
                  field.expertInfo
                    ? EXPERT_SEVERITY_CLASS[field.expertInfo.severity] ?? 'text-foreground'
                    : field.generated
                      ? 'text-muted-foreground italic'
                      : 'text-foreground'
                }`}
              >
                {String(field.value)}
              </span>
            )}
            {field.description && (
              <span className="text-[10px] text-muted-foreground italic hidden sm:inline truncate">
                ({field.description})
              </span>
            )}
          </div>

          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={() => copyFieldValue(field.name, field.value)}
              className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
              title="Copy field value"
            >
              {copiedField === field.name ? (
                <TbCheck className="w-3 h-3 text-emerald-400" />
              ) : (
                <TbCopy className="w-3 h-3" />
              )}
            </button>
          </div>
        </div>
        {hasChildren && isOpen && (
          <div className="space-y-1 mt-1">
            {field.children!.map((child, cIdx) => renderField(child, cIdx, depth + 1, fallbackRange, nodePath))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`space-y-1.5 font-mono text-xs ${className ?? ''}`}>
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
              isLayerActive ? 'border-primary/80 bg-primary/15' : 'border-border bg-card/60'
            }`}
          >
            <div
              onClick={() => toggleLayer(idx)}
              onMouseEnter={() => onHoverByteRange(layer.rawBytesRange || null)}
              onMouseLeave={() => onHoverByteRange(null)}
              className="flex items-center justify-between px-3 py-1.5 cursor-pointer select-none rounded hover:bg-accent/80 text-foreground"
            >
              <div className="flex items-center gap-2 truncate">
                {isExpanded ? (
                  <TbChevronDown className="w-3.5 h-3.5 text-primary shrink-0" />
                ) : (
                  <TbChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                )}
                <span className="font-semibold truncate text-foreground">{layer.summary}</span>
              </div>

              {layer.rawBytesRange && (
                <span className="text-[10px] text-muted-foreground font-mono shrink-0">
                  [{layer.rawBytesRange[0]}-{layer.rawBytesRange[1]}]
                </span>
              )}
            </div>

            {isExpanded && layer.fields && layer.fields.length > 0 && (
              <div className="pl-6 pr-3 py-1.5 space-y-1 border-t border-border/60 text-[11px]">
                {layer.fields.map((field, fIdx) =>
                  renderField(field, fIdx, 0, layer.rawBytesRange || null, `L${idx}`),
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
