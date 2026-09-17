import React, { useState } from 'react';
import { Packet, ProtocolField, ProtocolLayer } from '../../types/packet';
import { Copy, Check } from 'lucide-react';
import { renderBitfield } from '../../lib/bitfield';
import { copyText } from '../ui/CopyButton';
import { CATEGORY_TEXT } from '../../services/expertInfo';

/**
 * The dissected fields as an aligned two-column table.
 *
 * Deliberately NOT the workspace pane's tree. That tree is an accordion of
 * bordered cards with the name and value running together on one line, which
 * is the right shape for a 280px-tall strip you scroll through. This window has
 * room to do the thing the strip cannot: put every field name in one column and
 * every value in another, so a layer can be read down its edge instead of
 * scanned line by line.
 *
 * The two render the same data - ProtocolField, unchanged - and are expected to
 * look different. What must not diverge is meaning, so the conventions the tree
 * established are kept exactly: generated fields are italic and offer no byte
 * highlight, expert info keeps its severity colour, sub-byte fields print
 * The reference analyzer's dotted binary, and a cross-frame reference is a link.
 */

// See ProtocolTreeView: one map, in services/expertInfo, so a category means
// one colour here, in the workspace tree and in the Expert Information tab.
const EXPERT_CATEGORY_CLASS = CATEGORY_TEXT;

interface FrameFieldTableProps {
  packet: Packet;
  /** The layers to show; the caller narrows this when a layer is isolated. */
  layers: { layer: ProtocolLayer; index: number }[];
  activeByteRange: [number, number] | null;
  onHoverByteRange: (range: [number, number] | null) => void;
  onSelectFrame?: (frameNumber: number) => void;
  className?: string;
}

export const FrameFieldTable: React.FC<FrameFieldTableProps> = ({
  packet,
  layers,
  activeByteRange,
  onHoverByteRange,
  onSelectFrame,
  className,
}) => {
  const [copied, setCopied] = useState<string | null>(null);
  // Tracks what is CLOSED, so everything starts open - which is how a packet
  // reads when you have opened it deliberately to look at it.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // `copyText` rather than `navigator.clipboard` directly - it is the one home
  // for the execCommand fallback, and it reports failure so the tick below is
  // not shown for a copy that did not happen. See `ui/CopyButton`.
  const copyValue = async (path: string, value: string | number | boolean) => {
    if (!(await copyText(String(value)))) return;
    setCopied(path);
    setTimeout(() => setCopied(null), 1500);
  };

  const renderRows = (
    fields: ProtocolField[],
    depth: number,
    layerRange: [number, number] | null,
    parentPath: string,
  ): React.ReactNode[] =>
    fields.flatMap((field, idx) => {
      const path = `${parentPath}/${idx}`;
      const hasChildren = !!field.children?.length;
      const isOpen = hasChildren && !collapsed[path];

      const isActive =
        activeByteRange &&
        field.rawBytesRange &&
        activeByteRange[0] === field.rawBytesRange[0] &&
        activeByteRange[1] === field.rawBytesRange[1];

      // A generated field is the dissector's own commentary - it describes no
      // bytes, so offering a highlight would point at the parent's range and
      // imply the field lives there.
      const hoverRange = field.generated ? null : field.rawBytesRange || layerRange || null;

      const bitfieldText =
        field.bitfield && field.rawBytesRange && packet.rawBytes?.length
          ? renderBitfield(packet.rawBytes, field.rawBytesRange[0], field.bitfield)
          : null;

      const rows: React.ReactNode[] = [
        <div
          key={path}
          onMouseEnter={e => { e.stopPropagation(); onHoverByteRange(hoverRange); }}
          onMouseLeave={e => { e.stopPropagation(); onHoverByteRange(null); }}
          // The three columns come from the enclosing layer's grid (subgrid),
          // NOT from this row - see the section below for why the name column
          // is sized to the widest name in the layer rather than fixed.
          //
          // Values are NOT truncated: a device path, a resolved MAC or a long
          // TLS string is exactly the thing someone opened this window to read,
          // so long ones wrap onto a second line rather than ending in an
          // ellipsis. That is affordable here and is not in the packet list.
          className={`group grid grid-cols-subgrid col-span-3 items-baseline py-[3px] rounded transition-colors ${
            isActive ? 'bg-primary/15 dark:bg-primary/20' : 'hover:bg-accent/50'
          }`}
        >
          {/* Name column, indented by depth. */}
          <div className="flex items-baseline gap-1.5 min-w-0" style={{ paddingLeft: `${depth * 1.1}rem` }}>
            {hasChildren ? (
              <button
                onClick={e => { e.stopPropagation(); setCollapsed(p => ({ ...p, [path]: !p[path] })); }}
                className="shrink-0 w-3 text-muted-foreground hover:text-foreground cursor-pointer leading-none"
                title={isOpen ? 'Collapse' : 'Expand'}
              >
                {isOpen ? '−' : '+'}
              </button>
            ) : (
              <span className="w-3 shrink-0" />
            )}
            <span
              // The cap the max-content column is measured against: a name
              // longer than this truncates rather than pushing every value in
              // the layer out of reach.
              className={`truncate max-w-[20rem] ${
                field.generated ? 'italic text-muted-foreground/80' : 'text-muted-foreground'
              } ${isActive ? 'text-primary' : ''}`}
              title={field.name}
            >
              {field.name}
            </span>
          </div>

          {/* Value column - every value on the same left edge, which is the
              whole reason this is a table and not a tree of inline pairs. */}
          <div className="flex items-baseline gap-2 min-w-0">
            {bitfieldText && (
              <span className="text-muted-foreground/60 whitespace-pre shrink-0">{bitfieldText} =</span>
            )}
            {field.linkToFrame !== undefined && onSelectFrame ? (
              <button
                onClick={e => { e.stopPropagation(); onSelectFrame(field.linkToFrame!); }}
                className="font-semibold text-primary underline underline-offset-2 break-all text-left cursor-pointer hover:opacity-80"
                title={`Go to frame ${field.linkToFrame}`}
              >
                {String(field.value)}
              </button>
            ) : (
              <span
                className={`font-semibold break-all ${
                  field.expertInfo
                    ? EXPERT_CATEGORY_CLASS[field.expertInfo.category ?? 'Note'] ?? 'text-foreground'
                    : field.generated
                      ? 'text-muted-foreground italic'
                      : 'text-foreground'
                }`}
              >
                {String(field.value)}
              </span>
            )}
            {field.description && (
              <span className="text-[10px] text-muted-foreground/80 italic">({field.description})</span>
            )}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {field.rawBytesRange && !field.generated && (
              <span className="text-[9px] font-mono text-muted-foreground/60 tabular-nums opacity-0 group-hover:opacity-100 transition-opacity">
                {field.rawBytesRange[0]}–{field.rawBytesRange[1]}
              </span>
            )}
            <button
              onClick={() => { void copyValue(path, field.value); }}
              className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity"
              title="Copy value"
            >
              {copied === path ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
        </div>,
      ];

      if (hasChildren && isOpen) {
        rows.push(...renderRows(field.children!, depth + 1, layerRange, path));
      }
      return rows;
    });

  return (
    <div className={`font-mono text-[11px] ${className ?? ''}`}>
      {layers.map(({ layer, index }) => (
        <section key={index} className="mb-4 last:mb-0">
          {/* A sticky heading with an accent edge, rather than a bordered card.
              The heading stays visible while its own fields scroll, which is
              what makes a long layer readable in a tall window. */}
          <div
            onMouseEnter={() => onHoverByteRange(layer.rawBytesRange || null)}
            onMouseLeave={() => onHoverByteRange(null)}
            className="sticky top-0 z-10 flex items-baseline justify-between gap-3 px-3 py-1.5 bg-card/95 backdrop-blur-sm border-l-2 border-primary"
          >
            <span className="font-bold text-foreground text-xs truncate">{layer.summary}</span>
            {layer.rawBytesRange && (
              <span className="text-[10px] text-muted-foreground shrink-0 tabular-nums">
                bytes {layer.rawBytesRange[0]}–{layer.rawBytesRange[1]}
              </span>
            )}
          </div>

          {/* One grid per layer, with the rows as subgrids of it, so the name
              column is exactly as wide as the widest name in THIS layer.
              A single fixed width cannot serve both ends of a real frame: the
              Frame layer needs 327px for "[Time delta from previous displayed
              frame]" while ICMPv6's longest name is "Type" at 35px. The 16rem
              compromise it replaced managed to do both wrong at once - it
              truncated the long names anyway and still left a 162px gutter
              between the median name and its value. */}
          <div className="mt-1 grid grid-cols-[minmax(0,max-content)_minmax(0,1fr)_auto] gap-x-4 px-3">
            {layer.fields && layer.fields.length > 0 ? (
              renderRows(layer.fields, 0, layer.rawBytesRange || null, `L${index}`)
            ) : (
              <div className="col-span-3 py-1 text-muted-foreground/70 italic">No fields dissected.</div>
            )}
          </div>
        </section>
      ))}
    </div>
  );
};
