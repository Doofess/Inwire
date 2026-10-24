import React, { useEffect, useRef, useState } from 'react';
import { Packet, Capabilities } from '../../types/packet';
import { clearHoveredByte, publishHoveredByte } from '../../services/hoveredByte';
import {
  Binary,
  Check,
  ChevronDown,
  Shield,
  LoaderCircle,
  DatabaseX,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuItem,
} from '../ui/dropdown-menu';
import { copyText } from '../ui/CopyButton';
import { packetHexDump, packetAsciiDump } from '../../services/pcapParser';
import { HexDumpView } from './HexDumpView';
import { hasBytes } from '../../services/packetBytes';
import type { PacketDetailState } from '../../lib/usePacketDetail';
import { PaneHeader } from '../common/PaneHeader';
import { EmptyState } from '../common/EmptyState';
import { MICRO_LABEL } from '../common/typography';

export interface HexViewerProps {
  packet: Packet | null;
  activeByteRange: [number, number] | null;
  onHoverByte: (byteIndex: number | null) => void;
  permissions: Capabilities;
  /**
   * Whether this frame's bytes are here, coming, or gone (`usePacketDetail`).
   *
   * A big buffer cannot hold every frame's bytes, so it releases the ones the
   * store can read back and fetches them when a frame is selected
   * (docs/decisions/0013). That leaves two moments in which there is nothing to
   * dump, and they are **not** the same thing to a reader: one resolves and the
   * other does not. Rendering an empty pane for either says neither - it says
   * "this frame carried no data", which is a third thing entirely and untrue.
   */
  bytesState?: PacketDetailState;
}

type CopyFormat = 'hex' | 'c_array' | 'python' | 'ascii';

/** Renders the frame in the shape the chosen destination expects. */
export function formatPacketBytes(packet: Packet, format: CopyFormat): string {
  const rawBytes = packet.rawBytes;
  if (format === 'hex') return packetHexDump(packet);
  if (format === 'ascii') return packetAsciiDump(packet);
  const bytes = Array.from(rawBytes);
  if (format === 'c_array') {
    return (
      `unsigned char pkt[${rawBytes.length}] = {\n  ` +
      bytes
        .map((b, i) => `0x${b.toString(16).padStart(2, '0')}${i < rawBytes.length - 1 ? ',' : ''}${i % 12 === 11 ? '\n  ' : ' '}`)
        .join('') +
      '\n};'
    );
  }
  return `b"${bytes.map(b => `\\x${b.toString(16).padStart(2, '0')}`).join('')}"`;
}

/**
 * A copy icon drawn here rather than taken from the set.
 *
 * `Copy` was two identical outlined squares, which is what every icon set
 * ships and what a reader's eye slides off: two outlines of equal weight
 * overlapping read as a diagram of two squares, not as a sheet in front of a
 * sheet. The one below says the same thing with **asymmetric weight** - the
 * sheet behind is a corner bracket at less than half opacity, the sheet in
 * front is the only closed shape - so depth is what carries the metaphor and
 * there is exactly one outline for the eye to follow.
 */
const CopyMark: React.FC<{ className?: string }> = ({ className }) => (
  <svg
    viewBox="0 0 16 16"
    className={className}
    fill="none"
    stroke="currentColor"
    strokeWidth={1.5}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path
      d="M5.75 4.25V3A1.75 1.75 0 0 1 7.5 1.25h5A1.75 1.75 0 0 1 14.25 3v5a1.75 1.75 0 0 1-1.75 1.75h-1.25"
      opacity="0.45"
    />
    <rect x="1.75" y="4.25" width="9.5" height="10" rx="1.75" />
  </svg>
);

const COPY_FORMATS: { key: CopyFormat; label: string; hint: string }[] = [
  { key: 'hex', label: 'Hex dump', hint: 'Offsets, bytes and ASCII' },
  { key: 'c_array', label: 'C array', hint: 'unsigned char pkt[n]' },
  { key: 'python', label: 'Python bytes', hint: 'b"\\x00\\x01"' },
];

/**
 * One control for every shape the frame's bytes can leave in.
 *
 * It was three buttons - HEX, C-ARRAY, PY - side by side in the pane's title
 * bar, which spent the widest part of a 36px bar on three choices of which a
 * reader wants one, and read as three separate actions rather than one action
 * with three shapes. A menu says what is actually true: the verb is *copy*,
 * and the format is an argument to it.
 *
 * Shared so the bottom pane and the packet detail pane offer the same exports
 * from the same code, rather than one growing a format the other lacks.
 */
export const HexCopyMenu: React.FC<{ packet: Packet }> = ({ packet }) => {
  const [copied, setCopied] = useState<CopyFormat | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The menu closes on the click that copies, so the confirmation has to live
  // on the trigger - and the trigger can be unmounted inside the 1.5s window
  // by a frame being deselected.
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const copy = async (format: CopyFormat) => {
    if (!(await copyText(formatPacketBytes(packet, format)))) return;
    setCopied(format);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(null), 1500);
  };

  // Naming the format that was copied, not just "copied": the choice was made
  // in a menu that is no longer on screen, so the tick alone would confirm an
  // action without confirming which one.
  const confirmed = COPY_FORMATS.find(f => f.key === copied);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          title="Copy this frame's bytes"
          aria-label="Copy this frame's bytes"
          className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border
            transition-colors flex items-center gap-1 cursor-pointer border-border
            hover:bg-accent text-foreground bg-secondary/50
            data-[state=open]:bg-accent"
        >
          {confirmed
            ? <Check className="w-3 h-3 text-emerald-500" />
            : <CopyMark className="w-3.5 h-3.5" />}
          <span>{confirmed ? confirmed.label : 'Copy'}</span>
          <ChevronDown className="w-3 h-3 opacity-60" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-52">
        <DropdownMenuLabel className={MICRO_LABEL}>
          Copy {packet.rawBytes.length} bytes as
        </DropdownMenuLabel>
        {COPY_FORMATS.map(f => (
          <DropdownMenuItem key={f.key} onSelect={() => { void copy(f.key); }} className="gap-3">
            <span className="flex-1 text-xs">{f.label}</span>
            <span className="text-[10px] font-mono text-muted-foreground">{f.hint}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

/**
 * The workspace's bottom-right pane: a header, the dump, and a byte inspector.
 *
 * The dump rows and the inspector live in HexDumpView so the packet detail
 * window can arrange the same parts differently without duplicating them.
 */
/** This dump's name in the hovered-byte store. The other one is the Frame
    Detail view's, and a clear names its source so neither can blank the other's
    byte while both are mounted. */
const HOVER_SOURCE = 'packets-hex' as const;

export const HexViewer: React.FC<HexViewerProps> = ({
  packet,
  activeByteRange,
  onHoverByte,
  permissions,
  bytesState = 'ready',
}) => {
  const [hoveredByteIdx, setHoveredByteIdx] = useState<number | null>(null);

  // **Both effects sit above the early returns below, deliberately.** This
  // component returns before its main body for a frame that is missing or whose
  // bytes are not stored, and a hook declared after those returns would run on
  // some renders and not others.
  //
  // They cover the two exits a pointer event cannot: the frame changing under a
  // stationary pointer, and this pane unmounting - a view change, or the detail
  // panes being switched off in Settings. The clear is ownership-checked inside
  // the store, so neither can blank a byte the Frame Detail dump published.
  useEffect(() => {
    clearHoveredByte(HOVER_SOURCE);
  }, [packet?.id]);

  useEffect(() => () => clearHoveredByte(HOVER_SOURCE), []);

  if (!packet) {
    return (
      <div className="h-full flex items-center justify-center p-6">
        <EmptyState
          icon={Binary}
          title="No bytes to show"
          // One line and a hint, the shape of the tree's empty state beside
          // it, so the two stand at the same height.
          hint="Hover a field in the tree to light up the bytes it came from."
        >
          Select a packet to see its raw bytes in hex and ASCII.
        </EmptyState>
      </div>
    );
  }

  // Gated on the BYTES rather than on the detail state as a whole: a frame can
  // be `loading` because only its tree is still coming, and in that case the
  // dump has everything it needs and should draw at once.
  if (!hasBytes(packet)) {
    const gone = bytesState === 'unavailable';
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-muted-foreground font-mono text-xs">
        <div className="flex flex-col items-center gap-1.5 max-w-xs">
          {gone
            ? <DatabaseX className="w-6 h-6 text-muted-foreground/70 mb-1" />
            : <LoaderCircle className="w-6 h-6 text-muted-foreground/70 mb-1 animate-spin" />}
          <span className="uppercase tracking-wider">
            {gone ? `Frame ${packet.id} bytes not stored` : `Reading frame ${packet.id}`}
          </span>
          <span className="text-[10px] text-muted-foreground/70 leading-relaxed">
            {gone
              // Says which limit, because it is one the user chose and can
              // raise - and because "not stored" on its own reads like a
              // failure rather than a setting.
              ? 'This capture outgrew its storage limit, so the oldest frames’ bytes were dropped. The summary above is all that is kept for this one.'
              : 'Fetching this frame’s bytes from the stored capture.'}
          </span>
        </div>
      </div>
    );
  }

  const handleHover = (byteIndex: number | null) => {
    // The dump's OWN highlight stays local state. Round-tripping it through the
    // store would put every pointer move on a subscriber's render path for a
    // highlight this component draws itself.
    setHoveredByteIdx(byteIndex);
    onHoverByte(byteIndex);

    // The status bar gets the byte's VALUE rather than its index, which is the
    // whole design - `services/hoveredByte.ts` says why. Reading it here is what
    // makes a protocol tree unable to publish one.
    if (byteIndex === null || byteIndex >= packet.rawBytes.length) {
      clearHoveredByte(HOVER_SOURCE);
    } else {
      publishHoveredByte({
        source: HOVER_SOURCE,
        index: byteIndex,
        value: packet.rawBytes[byteIndex],
        frameId: packet.id,
      });
    }
  };

  return (
    // The selected byte, the range highlight and the byte inspector's readout
    // are the app's own accent. They carried the matched rule's hue for a while,
    // retinted from the pane above; see `PacketDetailsTree` for why that was
    // reverted.
    <div className="h-full flex flex-col overflow-hidden select-none font-mono text-xs">
      {/* The copy control is ~20px and the text beside it ~16, which is
          exactly why `PaneHeader` fixes its own height instead of padding to
          fit: this bar used to be four pixels taller than the two either side
          of it. */}
      <PaneHeader title="Hex view" detail={`(${packet.rawBytes.length} bytes)`}>
        <HexCopyMenu packet={packet} />
      </PaneHeader>

      {/* HexDumpView owns the scrolling, because it virtualizes its rows and
          needs the scroll position to decide which ones exist. */}
      <div className="flex-1 flex flex-col min-h-0">
        {!permissions.canViewPayloads && (
          <div className="m-3 mb-0 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] flex items-center gap-2 shrink-0">
            <Shield className="w-4 h-4 text-foreground shrink-0" />
            <span>Auditor / Guest Role Active: Payload inspection sanitized according to compliance policy.</span>
          </div>
        )}

        <HexDumpView
          packet={packet}
          activeByteRange={activeByteRange}
          hoveredByteIndex={hoveredByteIdx}
          onHoverByte={handleHover}
          className="flex-1 min-h-0 p-3"
        />
      </div>

      {/* **The byte inspector was this pane's footer and is the status bar's
          right-hand group now.**

          It spent one revision as the application's bottom bar before that -
          the same strip, class for class, spanning the window with its text
          indented to this pane's left edge by a CSS length built from
          `--details-pane-size` - and the indent was what argued it back in here:
          a full-width bar that has to be pushed sideways to look like it
          belongs somewhere narrower is a bar in the wrong place.

          **What changed is the alignment, not the verdict.** A status bar
          groups its items left and right by priority and never by
          correspondence with the pane above them, so the readout is an ordinary
          right-group item with no inset and no custom property anywhere near
          it. `components/status/StatusBar.tsx` carries both rules and
          `scripts/session/status-bar.ts` holds it to them.

          The footer went with the readout rather than being left empty. A
          bordered strip under one pane of this row and none under the one
          beside it is what made the row's bottom edge ragged - the complaint
          that argued for a window-spanning bar in the first place - so the
          dump's last row now sits directly above `<main>`'s own bottom border,
          which is the same line the rail and the title row meet.

          `hoveredByteIdx` stays this pane's own state, because it is what draws
          the highlight here. What the bar gets from `handleHover` is the byte's
          VALUE, which is the one thing a protocol tree cannot offer - see
          `services/hoveredByte.ts`. */}
    </div>
  );
};
