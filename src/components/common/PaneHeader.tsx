import React from 'react';

/**
 * The title bar the two panes under the packet list share.
 *
 * ## Why this is a component and not a copied class string
 *
 * Because the copied class string did not align, and could not have.
 *
 * The panes carried the same `px-4 py-2 border-b ...` header, character for
 * character, and their bars still sat at different heights - because vertical
 * padding sizes a box from its CONTENTS, and the contents differ. Hex View's bar
 * holds a copy control (`py-0.5`, a border, a 14px icon: about 20px); Packet
 * Inspection's holds 12px text, about 16. Four pixels, on two adjacent panes,
 * with a divider running between them. (There were three while the map had a
 * pane in this row; it is a view now and wears no `PaneHeader` at all.)
 *
 * So the height is **fixed here** - `h-9`, and `shrink-0` so a tall child cannot
 * stretch it - and the padding is horizontal only. 36px is what the tallest
 * content already came to, so nothing had to shrink to fit; the short bars grew
 * to meet the tall one rather than the reverse.
 *
 * ## What it takes
 *
 * `title` is the pane's name, and `detail` is the one fact beside it - the
 * figure that says whether the pane has anything in it before you look:
 * `#Frame 12 (74 bytes)`, `(74 bytes)`. `children` is whatever sits at the far
 * right, which is the only part the two do differently.
 *
 * The name is muted and the detail is `--primary`, which is the split that was
 * already there: the pane is always called the same thing, and the number is
 * what changed.
 */
export interface PaneHeaderProps {
  /** The pane's name. Rendered uppercase; pass it in sentence case. */
  title: string;
  /** The one fact beside the name. Drawn in the accent. */
  detail?: React.ReactNode;
  /** Anything at the far right - copy buttons, a hovered field name. */
  children?: React.ReactNode;
}

export const PaneHeader: React.FC<PaneHeaderProps> = ({ title, detail, children }) => (
  <div
    className="h-9 shrink-0 px-4 border-b flex items-center justify-between gap-3
      transition-colors bg-card border-border text-card-foreground shadow-sm"
  >
    <div className="flex items-center gap-2 text-xs font-mono font-bold min-w-0">
      <span className="text-muted-foreground uppercase tracking-tighter shrink-0">{title}</span>
      {detail !== undefined && <span className="text-primary shrink-0">{detail}</span>}
    </div>
    {children}
  </div>
);
