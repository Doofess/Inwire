/**
 * A set of packets with their bytes filled in.
 *
 * For the consumers that read `rawBytes` off many frames at once and render
 * synchronously - Follow Stream's three views, its copy and save actions - and
 * would otherwise each have to grow their own async path.
 *
 * **Pass-through while the buffer still holds every frame's bytes**, which is
 * every capture that fits in memory: the same array comes straight back, by
 * identity, with no state update and no read. Only a frame whose bytes the
 * buffer has dropped costs anything, and then it is one read for the whole set
 * (`services/packetBytes.ts`, `docs/decisions/0013`).
 *
 * The pass-through mattering by *identity* is the point: these packets feed
 * memos and render loops, and a hook that returned a fresh array every render
 * would defeat them for the sake of a case that has not happened yet.
 */
import { useEffect, useState } from 'react';
import { hasBytes, packetsBytes } from '../services/packetBytes';
import type { Packet } from '../types/packet';

export function useHydratedBytes(packets: readonly Packet[]): readonly Packet[] {
  const [hydrated, setHydrated] = useState<readonly Packet[] | null>(null);

  // Cheap and synchronous: a boolean over the set, not a copy of it.
  const complete = packets.every(hasBytes);

  // The effect is keyed on WHICH frames these are, not on the array holding
  // them. Callers build this list on the fly - `framesOnStream(packets, target)`
  // is a filter, so it is a new array on every render - and keying on identity
  // would start a fresh read on every render, whose result would set state and
  // cause the next one. A live capture re-renders ten times a second.
  const signature = packets.length === 0
    ? 'empty'
    : `${packets.length}:${packets[0].id}:${packets[packets.length - 1].id}`;

  useEffect(() => {
    if (complete) { setHydrated(null); return; }

    let live = true;
    void packetsBytes(packets).then((bytesById) => {
      if (!live) return;
      setHydrated(packets.map((p) => {
        const bytes = bytesById.get(p.id);
        // Replaced, not mutated: these packets are the buffer's own, and a
        // stream view must not write into the frames the list is rendering.
        return bytes && bytes !== p.rawBytes ? { ...p, rawBytes: bytes } : p;
      }));
    });
    return () => { live = false; };
    // `packets` is deliberately absent: `signature` is what says the set
    // changed. eslint would ask for it and would be wrong here.
  }, [signature, complete]);   // eslint-disable-line react-hooks/exhaustive-deps

  if (complete) return packets;
  // A stale hydration - the set changed while a read was in flight - is worse
  // than none: it would show one stream's bytes under another's frames.
  if (hydrated && hydrated.length === packets.length
    && (packets.length === 0 || hydrated[0].id === packets[0].id)) {
    return hydrated;
  }
  // Until the read lands, the packets as they are. Their bytes are empty, so a
  // hex view renders empty for a moment rather than flickering wrong content -
  // and a frame the store cannot supply stays that way, which is honest.
  return packets;
}
