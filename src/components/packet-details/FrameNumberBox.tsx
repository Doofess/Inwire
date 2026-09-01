import React, { useRef, useState } from 'react';
import { TbArrowRight } from 'react-icons/tb';
import { Packet } from '../../types/packet';
import { lookupFrame } from './packetDetailModel';

interface FrameNumberBoxProps {
  /** The whole capture buffer. Frames are addressed by number against this. */
  packets: Packet[];
  onShowFrame: (frameNumber: number) => void;
}

/**
 * "Go to frame N".
 *
 * Lives in the rail's GO TO group rather than the header, because it is
 * navigation rather than identity - the same verb as the stream and
 * related-frame links it now sits beside. In the header it was a `shrink-0`
 * form competing with the title, which is why the title collapsed to nothing
 * below ~900px.
 *
 * The three ways the box can fail to resolve are reported INLINE, underneath
 * the input. They used to be full-width strips between the header and the
 * body, so a typo inserted a band that pushed the whole document down and then
 * pulled it back up again when the text was fixed.
 */
export const FrameNumberBox: React.FC<FrameNumberBoxProps> = ({ packets, onShowFrame }) => {
  const [text, setText] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);

  const lookup = lookupFrame(packets, text);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (lookup.kind !== 'found') return;
    onShowFrame(lookup.packet.id);
    setText('');
    inputRef.current?.blur();
    // Anything else leaves the text in place; the message below explains it.
  };

  const range = packets.length > 0
    ? `${packets[0].id}–${packets[packets.length - 1].id}`
    : '—';

  return (
    // Capped rather than fluid. In the 17rem rail this changes nothing, but
    // the same rail is reused full-width on a narrow window, where a
    // four-digit frame number in a 1000px input reads as a search box.
    <form onSubmit={submit} className="max-w-xs">
      <div className="flex items-center gap-1.5">
        <input
          ref={inputRef}
          value={text}
          onChange={e => setText(e.target.value)}
          inputMode="numeric"
          aria-label="Go to frame number"
          placeholder={range}
          className="min-w-0 flex-1 px-2 py-1 rounded border border-border bg-background text-[11px] font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <button
          type="submit"
          disabled={lookup.kind !== 'found'}
          className={`shrink-0 p-1.5 rounded-md border border-border transition-colors ${
            lookup.kind === 'found'
              ? 'hover:bg-accent text-foreground cursor-pointer'
              : 'opacity-40 cursor-not-allowed text-muted-foreground'
          }`}
          title="Load this frame"
        >
          <TbArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {lookup.kind === 'invalid' && (
        <p className="mt-1.5 text-[10px] font-mono leading-snug text-amber-600 dark:text-amber-400">
          "{lookup.text}" is not a frame number.
        </p>
      )}
      {lookup.kind === 'outOfRange' && (
        <p className="mt-1.5 text-[10px] font-mono leading-snug text-amber-600 dark:text-amber-400">
          {lookup.first !== null && lookup.last !== null
            ? `Buffer holds ${lookup.first.toLocaleString()}–${lookup.last.toLocaleString()}.`
            : 'The buffer is empty.'}
        </p>
      )}
    </form>
  );
};
