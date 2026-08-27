import React, { useState } from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { TbBinary, TbCopy, TbCheck, TbShield } from 'react-icons/tb';
import { packetHexDump, packetAsciiDump } from '../../services/pcapParser';

interface HexViewerProps {
  packet: Packet | null;
  activeByteRange: [number, number] | null;
  onHoverByte: (byteIndex: number | null) => void;
  permissions: UserRolePermissions;
}

export const HexViewer: React.FC<HexViewerProps> = ({
  packet,
  activeByteRange,
  onHoverByte,
  permissions,
}) => {
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);
  const [hoveredByteIdx, setHoveredByteIdx] = useState<number | null>(null);

  if (!packet) {
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-muted-foreground font-mono text-xs">
        <div className="flex flex-col items-center gap-1.5">
          <TbBinary className="w-6 h-6 text-muted-foreground/70 mb-1" />
          <span className="uppercase tracking-wider">Hex Dump Inspector</span>
          <span className="text-[10px] text-muted-foreground/70">Select a frame to inspect raw hexadecimal & ASCII dump</span>
        </div>
      </div>
    );
  }

  const rawBytes = packet.rawBytes;
  const numRows = Math.ceil(rawBytes.length / 16);

  const copyAsFormat = async (format: 'hex' | 'c_array' | 'python' | 'ascii') => {
    let text = '';
    if (format === 'hex') {
      text = packetHexDump(packet);
    } else if (format === 'c_array') {
      const bytesArr = Array.from(rawBytes);
      text = `unsigned char pkt[${rawBytes.length}] = {\n  ` +
        bytesArr
          .map((b: number, i: number) => `0x${b.toString(16).padStart(2, '0')}${i < rawBytes.length - 1 ? ',' : ''}${i % 12 === 11 ? '\n  ' : ' '}`)
          .join('') +
        '\n};';
    } else if (format === 'python') {
      const bytesArr = Array.from(rawBytes);
      text = `b"${bytesArr.map((b: number) => `\\x${b.toString(16).padStart(2, '0')}`).join('')}"`;
    } else if (format === 'ascii') {
      text = packetAsciiDump(packet);
    }

    try {
      await navigator.clipboard.writeText(text);
      setCopiedFormat(format);
      setTimeout(() => setCopiedFormat(null), 1500);
    } catch (err) {
      // Fallback for iframe sandbox
      const textArea = document.createElement("textarea");
      textArea.value = text;
      // Make it invisible
      textArea.style.position = "fixed";
      textArea.style.left = "-999999px";
      textArea.style.top = "-999999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        setCopiedFormat(format);
        setTimeout(() => setCopiedFormat(null), 1500);
      } catch (e) {
        console.error("Copy failed", e);
      }
      textArea.remove();
    }
  };

  const isByteInRange = (idx: number) => {
    if (activeByteRange) {
      return idx >= activeByteRange[0] && idx <= activeByteRange[1];
    }
    return false;
  };

  const hoveredByteVal = hoveredByteIdx !== null && hoveredByteIdx < rawBytes.length ? rawBytes[hoveredByteIdx] : null;

  return (
    <div className="h-full flex flex-col overflow-hidden select-none font-mono text-xs">
      {/* Header Toolbar */}
      <div
        className="px-4 py-2 border-b flex items-center justify-between transition-colors bg-card border-border text-card-foreground shadow-sm"
      >
        <div className="flex items-center gap-2 font-semibold">
          <span className="text-muted-foreground uppercase tracking-tighter">Hex View</span>
          <span className="text-cyan-400 font-mono">({rawBytes.length} bytes)</span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => copyAsFormat('hex')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors flex items-center gap-1 cursor-pointer ${
              'border-border hover:bg-accent text-foreground bg-secondary/50'
            }`}
            title="Copy raw hex sequence"
          >
            {copiedFormat === 'hex' ? <TbCheck className="w-3 h-3 text-emerald-400" /> : <TbCopy className="w-3 h-3" />}
            <span>HEX</span>
          </button>

          <button
            onClick={() => copyAsFormat('c_array')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors flex items-center gap-1 cursor-pointer ${
              'border-border hover:bg-accent text-foreground bg-secondary/50'
            }`}
            title="Copy as C array"
          >
            {copiedFormat === 'c_array' ? <TbCheck className="w-3 h-3 text-emerald-400" /> : <TbCopy className="w-3 h-3" />}
            <span>C-ARRAY</span>
          </button>

          <button
            onClick={() => copyAsFormat('python')}
            className={`px-2 py-0.5 rounded text-[10px] font-mono border transition-colors flex items-center gap-1 cursor-pointer ${
              'border-border hover:bg-accent text-foreground bg-secondary/50'
            }`}
            title="Copy as Python bytes"
          >
            {copiedFormat === 'python' ? <TbCheck className="w-3 h-3 text-emerald-400" /> : <TbCopy className="w-3 h-3" />}
            <span>PY</span>
          </button>
        </div>
      </div>

      {/* Hex & ASCII View Body */}
      <div className="flex-1 overflow-y-auto p-3 space-y-0.5 custom-scrollbar text-[11px]">
        {/* Auditor Role Mask notice if permissions restricted */}
        {!permissions.canViewPayloads && (
          <div className="mb-2 p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] flex items-center gap-2">
            <TbShield className="w-4 h-4 text-foreground shrink-0" />
            <span>Auditor / Guest Role Active: Payload inspection sanitized according to compliance policy.</span>
          </div>
        )}

        {Array.from({ length: numRows }).map((_, rowIdx: number) => {
          const startOffset = rowIdx * 16;
          const offsetHex = startOffset.toString(16).padStart(4, '0').toUpperCase();

          const rowBytes: number[] = Array.from(rawBytes.slice(startOffset, startOffset + 16));

          return (
            <div
              key={rowIdx}
              className="flex items-center gap-3 px-1 py-0.5 rounded transition-colors hover:bg-accent/50"
            >
              {/* Offset Column (0000, 0010, 0020 ...) */}
              <span className="text-muted-foreground font-mono font-bold w-10 shrink-0 select-none">{offsetHex}</span>

              {/* Hex Bytes Column (16 bytes in two 8-byte blocks) */}
              <div className="flex items-center gap-1 shrink-0">
                {/* First 8 bytes */}
                <div className="flex items-center gap-1 w-44">
                  {rowBytes.slice(0, 8).map((byte: number, bIdx: number) => {
                    const absIdx = startOffset + bIdx;
                    const isHovered = hoveredByteIdx === absIdx;
                    const isInRange = isByteInRange(absIdx);

                    return (
                      <span
                        key={bIdx}
                        onMouseEnter={() => {
                          setHoveredByteIdx(absIdx);
                          onHoverByte(absIdx);
                        }}
                        onMouseLeave={() => {
                          setHoveredByteIdx(null);
                          onHoverByte(null);
                        }}
                        className={`w-4 text-center cursor-pointer transition-all rounded px-0.5 ${
                          isHovered
                            ? 'bg-cyan-500 text-slate-950 font-bold scale-110 shadow-sm'
                            : isInRange
                            ? 'bg-cyan-200/50 dark:bg-cyan-500/30 text-cyan-900 dark:text-cyan-200 font-bold ring-1 ring-cyan-400'
                            : 'text-muted-foreground hover:text-cyan-700 dark:hover:text-cyan-200 hover:bg-accent'
                        }`}
                      >
                        {byte.toString(16).padStart(2, '0').toUpperCase()}
                      </span>
                    );
                  })}
                </div>

                <span className="text-muted-foreground select-none"> </span>

                {/* Second 8 bytes */}
                <div className="flex items-center gap-1 w-44">
                  {rowBytes.slice(8, 16).map((byte: number, bIdx: number) => {
                    const absIdx = startOffset + 8 + bIdx;
                    const isHovered = hoveredByteIdx === absIdx;
                    const isInRange = isByteInRange(absIdx);

                    return (
                      <span
                        key={bIdx}
                        onMouseEnter={() => {
                          setHoveredByteIdx(absIdx);
                          onHoverByte(absIdx);
                        }}
                        onMouseLeave={() => {
                          setHoveredByteIdx(null);
                          onHoverByte(null);
                        }}
                        className={`w-4 text-center cursor-pointer transition-all rounded px-0.5 ${
                          isHovered
                            ? 'bg-cyan-500 text-slate-950 font-bold scale-110 shadow-sm'
                            : isInRange
                            ? 'bg-cyan-200/50 dark:bg-cyan-500/30 text-cyan-900 dark:text-cyan-200 font-bold ring-1 ring-cyan-400'
                            : 'text-muted-foreground hover:text-cyan-700 dark:hover:text-cyan-200 hover:bg-accent'
                        }`}
                      >
                        {byte.toString(16).padStart(2, '0').toUpperCase()}
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* ASCII Decode Column */}
              <div className="flex items-center pl-3 border-l border-border text-muted-foreground tracking-widest shrink-0">
                {rowBytes.map((byte: number, bIdx: number) => {
                  const absIdx = startOffset + bIdx;
                  const isHovered = hoveredByteIdx === absIdx;
                  const isInRange = isByteInRange(absIdx);
                  const char = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';

                  return (
                    <span
                      key={bIdx}
                      onMouseEnter={() => {
                        setHoveredByteIdx(absIdx);
                        onHoverByte(absIdx);
                      }}
                      onMouseLeave={() => {
                        setHoveredByteIdx(null);
                        onHoverByte(null);
                      }}
                      className={`cursor-pointer transition-colors ${
                        isHovered
                          ? 'bg-cyan-500 text-slate-950 font-bold rounded'
                          : isInRange
                          ? 'text-cyan-900 dark:text-cyan-300 font-bold bg-cyan-200/80 dark:bg-cyan-950/60 rounded'
                          : ''
                      }`}
                    >
                      {char}
                    </span>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Hovered Byte Inspector Footer */}
      <div
        className="px-4 py-1.5 border-t text-[10px] font-mono flex items-center justify-between transition-colors bg-secondary/50 border-border text-muted-foreground shadow-inner"
      >
        {hoveredByteIdx !== null && hoveredByteVal !== null ? (
          <div className="flex items-center gap-3">
            <span>
              OFFSET: <b className="text-foreground">{hoveredByteIdx} (0x{hoveredByteIdx.toString(16).toUpperCase()})</b>
            </span>
            <span>
              DEC: <b className="text-foreground">{hoveredByteVal}</b>
            </span>
            <span>
              HEX: <b className="text-cyan-400">0x{hoveredByteVal.toString(16).padStart(2, '0').toUpperCase()}</b>
            </span>
            <span>
              BITS: <b className="text-emerald-400">0b{hoveredByteVal.toString(2).padStart(8, '0')}</b>
            </span>
            <span>
              ASCII:{' '}
              <b className="text-amber-400">
                {hoveredByteVal >= 32 && hoveredByteVal <= 126 ? `'${String.fromCharCode(hoveredByteVal)}'` : 'N/A'}
              </b>
            </span>
          </div>
        ) : (
          <span>Hover any byte to inspect raw bitwise & numerical representation</span>
        )}
        <span className="text-[10px] text-muted-foreground font-mono uppercase">Byte Dump</span>
      </div>
    </div>
  );
};
