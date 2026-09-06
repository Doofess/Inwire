import React, { useState } from 'react';
import { Packet, Capabilities } from '../../types/packet';
import { TbBinary, TbCopy, TbCheck, TbShield, TbLoader2, TbDatabaseOff } from 'react-icons/tb';
import { packetHexDump, packetAsciiDump } from '../../services/pcapParser';
import { ByteInspector, HexDumpView } from './HexDumpView';
import { packetAccentStyle } from '../../lib/packetAccent';
import { hasBytes } from '../../services/packetBytes';
import type { PacketDetailState } from '../../lib/usePacketDetail';

interface HexViewerProps {
  packet: Packet | null;
  /** The colour the packet list painted this frame's row. Retints the pane -
   *  see packetAccent.ts. */
  accentColor?: string | null;
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
 * The HEX / C-ARRAY / PY copy controls.
 *
 * Shared so the bottom pane and the packet detail window offer the same
 * exports from the same code, rather than one growing a format the other
 * lacks.
 */
export const HexCopyButtons: React.FC<{ packet: Packet }> = ({ packet }) => {
  const [copied, setCopied] = useState<CopyFormat | null>(null);

  const copy = async (format: CopyFormat) => {
    const text = formatPacketBytes(packet, format);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API is unavailable in some sandboxed frames; fall back to a
      // hidden textarea and execCommand, which still works there.
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
      } catch (e) {
        console.error('Copy failed', e);
        textArea.remove();
        return;
      }
      textArea.remove();
    }
    setCopied(format);
    setTimeout(() => setCopied(null), 1500);
  };

  const formats: { key: CopyFormat; label: string; title: string }[] = [
    { key: 'hex', label: 'HEX', title: 'Copy raw hex sequence' },
    { key: 'c_array', label: 'C-ARRAY', title: 'Copy as C array' },
    { key: 'python', label: 'PY', title: 'Copy as Python bytes' },
  ];

  return (
    <div className="flex items-center gap-1.5">
      {formats.map(f => (
        <button
          key={f.key}
          onClick={() => copy(f.key)}
          className="px-2 py-0.5 rounded text-[10px] font-mono border transition-colors flex items-center gap-1 cursor-pointer border-border hover:bg-accent text-foreground bg-secondary/50"
          title={f.title}
        >
          {copied === f.key ? <TbCheck className="w-3 h-3 text-emerald-400" /> : <TbCopy className="w-3 h-3" />}
          <span>{f.label}</span>
        </button>
      ))}
    </div>
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
  accentColor,
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
          <TbBinary className="w-6 h-6 text-muted-foreground/70 mb-1" />
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
            ? <TbDatabaseOff className="w-6 h-6 text-muted-foreground/70 mb-1" />
            : <TbLoader2 className="w-6 h-6 text-muted-foreground/70 mb-1 animate-spin" />}
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
    // Carries the frame's colour into the dump itself: the selected byte, the
    // range highlight and the byte inspector's readout were all the app accent.
    <div
      className="h-full flex flex-col overflow-hidden select-none font-mono text-xs"
      style={packetAccentStyle(accentColor)}
    >
      <div className="px-4 py-2 border-b flex items-center justify-between transition-colors bg-card border-border text-card-foreground shadow-sm">
        <div className="flex items-center gap-2 font-semibold">
          <span className="text-muted-foreground uppercase tracking-tighter">Hex View</span>
          <span className="text-primary font-mono">({packet.rawBytes.length} bytes)</span>
        </div>
        <HexCopyButtons packet={packet} />
      </div>

      {/* HexDumpView owns the scrolling, because it virtualizes its rows and
          needs the scroll position to decide which ones exist. */}
      <div className="flex-1 flex flex-col min-h-0">
        {!permissions.canViewPayloads && (
          <div className="m-3 mb-0 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] flex items-center gap-2 shrink-0">
            <TbShield className="w-4 h-4 text-foreground shrink-0" />
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

      <div className="px-4 py-1.5 border-t text-[10px] font-mono flex items-center justify-between transition-colors bg-secondary/50 border-border text-muted-foreground shadow-inner">
        <ByteInspector packet={packet} hoveredByteIndex={hoveredByteIdx} />
        <span className="text-[10px] text-muted-foreground font-mono uppercase">Byte Dump</span>
      </div>
    </div>
  );
};
