/**
 * Where the packet map's "you are here" box sits, as a scrollbar places its
 * thumb.
 *
 * The box is the visible fraction of the list, with a floor so it stays
 * grabbable when thousands of frames squeeze it to a sliver. It used to be
 * placed at `scrollTop / scrollHeight` of the track - which is right only for
 * the proportional height. Once the floor wins, the box is taller than its
 * position assumed, and at the bottom of the list it hung past the end of the
 * map by up to the floor: on a real 3,714-frame capture it ran from 631 to 639
 * px on a map ending at 635, under whatever sat below the list.
 *
 * A scrollbar solves this by mapping the scroll range onto the track that is
 * LEFT after the thumb - `scrollTop / (scrollHeight - clientHeight)` of
 * `track - height` - so the top of the list puts the box at 0 and the bottom
 * puts it flush with the end, whatever its height. Lifted here from
 * `PacketListMinimap` so a script can hold it to that.
 */
export const MIN_INDICATOR_HEIGHT = 8;

export function minimapIndicator(
  scrollTop: number,
  scrollHeight: number,
  clientHeight: number,
  trackHeight: number,
  minHeight = MIN_INDICATOR_HEIGHT,
): { top: number; height: number } {
  // Nothing to scroll: the whole list is on screen, so the box is the map.
  if (scrollHeight <= clientHeight || scrollHeight <= 0) return { top: 0, height: trackHeight };
  const height = Math.min(trackHeight, Math.max((clientHeight / scrollHeight) * trackHeight, minHeight));
  const fraction = Math.min(1, Math.max(0, scrollTop / (scrollHeight - clientHeight)));
  return { top: fraction * (trackHeight - height), height };
}
