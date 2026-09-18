import React, { useEffect, useRef, useState } from 'react';
import { Packet, Capabilities } from '../../types/packet';
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
import { ByteInspector, HexDumpView } from './HexDumpView';
import { hasBytes } from '../../services/packetBytes';
import type { PacketDetailState } from '../../lib/usePacketDetail';
import { PaneHeader } from '../common/PaneHeader';

interface HexViewerProps {
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
          className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wide border
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
        <DropdownMenuLabel className="text-[10px] font-mono uppercase tracking-wide text-muted-foreground">
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
export const HexViewer: React.FC<HexViewerProps> = ({
  packet,
  activeByteRange,
  onHoverByte,
  permissions,
  bytesState = 'ready',
}) => {
  const [hoveredByteIdx, setHoveredByteIdx] = useState<number | null>(null);

  if (!packet) {
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-muted-foreground font-mono text-xs">
        <div className="flex flex-col items-center gap-1.5">
          <Binary className="w-6 h-6 text-muted-foreground/70 mb-1" />
          <span className="uppercase tracking-wider">Hex Dump Inspector</span>
          <span className="text-[10px] text-muted-foreground/70">Select a frame to inspect raw hexadecimal &amp; ASCII dump</span>
        </div>
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
    setHoveredByteIdx(byteIndex);
    onHoverByte(byteIndex);
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
      <PaneHeader title="Hex View" detail={`(${packet.rawBytes.length} bytes)`}>
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

      {/* The byte inspector, in this pane's own footer.

          **It spent one revision as the application's bottom bar** - the same
          strip, class for class, spanning the window under the rail as well as
          the panes, with its text indented to this pane's left edge by a CSS
          length built from `--details-pane-size`. The argument for that was the
          row's bottom edge: a bordered strip on one pane of the row and none on
          the other beside it. The argument against it is the stronger one and is
          why it is back - **this is a readout about the hex dump**, and a bar
          spanning the window is a claim about the window. Indenting it to line
          up under the dump was the tell: a full-width bar that has to be pushed
          sideways to look like it belongs somewhere narrower is a bar in the
          wrong place, and the mechanism that did it - a custom property on the
          ROOT element, read by a component two levels away from the panes it
          describes - was load-bearing for nothing else.

          The ragged edge is accepted rather than fixed, because the two panes
          are different things and the divider between them already says so.

          `hoveredByteIdx` is this pane's own state, which is the other thing
          that came back. As a window-spanning bar it had to be fed from `App`,
          derived from `activeByteRange` - and that range is also what the
          protocol tree publishes for a one-byte field, so the bar answered
          "this byte" for a hover in a pane that is not this one. Back in here
          it reads the dump's hover and nothing else. */}
      <div
        className="border-t px-4 py-1.5 text-[10px] font-mono flex items-center
          transition-colors bg-secondary/50 border-border text-muted-foreground
          shadow-inner shrink-0"
      >
        <div className="min-w-0 truncate">
          <ByteInspector packet={packet} hoveredByteIndex={hoveredByteIdx} />
        </div>
      </div>
    </div>
  );
};
