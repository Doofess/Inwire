import React from 'react';
import { HexViewer, type HexViewerProps } from './HexViewer';
import { PacketDetailsTree, type PacketDetailsTreeProps } from './PacketDetailsTree';
import { clearByteRange, publishByteRange, useActiveByteRange } from '../../services/byteRange';

/**
 * The packets view's two bottom panes, wired to each other instead of to `App`.
 *
 * ## What these are for
 *
 * `PacketDetailsTree` and `HexViewer` take the highlighted byte range as a prop
 * and report hovers back through a callback, which is the right shape for a
 * component and is why `PacketDetailPane` can hold that state itself. In the
 * packets view the two panes are SIBLINGS, so props meant App owned the state -
 * and every pointer move over a byte re-rendered the whole application.
 * `services/byteRange.ts` has the measurements and the history.
 *
 * These two wrappers are the whole of the fix. Each subscribes to the store and
 * fills in the one prop, so the panes below are untouched, `PacketDetailPane`
 * is untouched, and `App` never learns that a pointer moved.
 *
 * ## Why wrappers rather than a flag on the panes themselves
 *
 * The alternative was a `source` prop on each pane switching it between "read
 * the store" and "read my props", which is two modes in a component that had
 * one, in order to spare two files of ten lines. A wrapper also puts the
 * subscription where it belongs: at the boundary between a store and a
 * component that knows nothing about stores.
 *
 * ## Why the handlers are module-level
 *
 * They are passed as props, so a fresh closure per render is a changed prop on
 * every render - which is the thing these components are being kept off. Both
 * are pure calls into the store and close over nothing, so there is nothing for
 * them to capture and no reason to rebuild them.
 */

/** The tree publishes a field's range, and releases it when the pointer goes. */
const onTreeHover = (range: [number, number] | null): void => {
  if (range) publishByteRange('packets-tree', range);
  else clearByteRange('packets-tree');
};

/**
 * The dump publishes ONE byte as a range of one.
 *
 * That is what lights the containing field in the tree, and it is also exactly
 * the conflation `hoveredByte.ts` exists to prevent elsewhere: a one-byte range
 * here is indistinguishable from a one-byte FIELD published by the tree. It is
 * harmless for a highlight, where both mean "these bytes", and it was not
 * harmless for the status bar's readout, which had to answer "the byte under
 * the pointer" and could not tell the two apart. The two stores are the two
 * answers.
 */
const onDumpHover = (byteIndex: number | null): void => {
  if (byteIndex === null) clearByteRange('packets-hex');
  else publishByteRange('packets-hex', [byteIndex, byteIndex]);
};

export const LinkedDetailsTree: React.FC<
  Omit<PacketDetailsTreeProps, 'activeByteRange' | 'onHoverByteRange'>
> = (props) => {
  const activeByteRange = useActiveByteRange();
  return (
    <PacketDetailsTree
      {...props}
      activeByteRange={activeByteRange}
      onHoverByteRange={onTreeHover}
    />
  );
};

/**
 * **The one `React.memo` in the application, and it is here for a measured
 * reason.**
 *
 * `App` re-renders about ten times a second during a capture, and the dump is
 * the most expensive thing under it: a full-height column of a 64KB frame
 * mounts around 79 virtualized rows, each one `<span>` per byte twice. Nothing
 * about that changes when a frame arrives, so every one of those renders was
 * rebuilding it for nothing.
 *
 * The three props are what makes this hold. `packet` is the hydrated frame,
 * which keeps its identity across renders; `bytesState` is a string; and
 * `permissions` is memoized in `App` **specifically so this boundary works** -
 * it was a fresh object literal, which is a changed prop, which is a memo that
 * never hits. The range no longer travels as a prop at all, which is the other
 * half of why this is possible.
 *
 * The tree beside it is deliberately NOT memoized. It takes `onSelectFrame`,
 * whose `useCallback` closes over `packets` - so its identity changes on every
 * flush during a capture and the memo would cost a comparison to always miss. A
 * memo that cannot hold is worse than none: it reads as a guarantee.
 *
 * `App` had exactly one memo boundary before this - `Dock`, for the same
 * reason, every widget doing a full pass over the buffer - and it went with the
 * dock.
 */
export const LinkedHexViewer: React.FC<
  Omit<HexViewerProps, 'activeByteRange' | 'onHoverByte'>
> = React.memo((props) => {
  const activeByteRange = useActiveByteRange();
  return (
    <HexViewer
      {...props}
      activeByteRange={activeByteRange}
      onHoverByte={onDumpHover}
    />
  );
});
LinkedHexViewer.displayName = 'LinkedHexViewer';
