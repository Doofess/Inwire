# 0040 — Follow Stream shows a conversation's frames, not its payload

**Status:** accepted

## Context

`StreamFollowerPane`'s Dialogue tab rendered every frame on a stream as ASCII,
a hex dump, or one unbroken hex string, chosen by three buttons. Opening a
stream of any real size froze the window for seconds.

Three costs compounded, and none of them was the payload rendering on its own:

- **`framesOnStream` ran in the render body.** It is a `.filter()` over the
  whole packet buffer — up to a million frames — so it ran on every render, ten
  times a second during a capture, and returned a new array each time, which
  changed identity for everything downstream of it.
- **The list was not virtualised.** Every frame on the stream got a card.
- **`renderPayload` was called inside that map**, so each frame's full dump was
  rebuilt on every render. A 10,000-frame stream of 1,460-byte segments is
  ~14.6 M transient strings per render and a GC storm to match.

The pane also called `useHydratedBytes` over the whole stream, so a stream whose
frames the buffer had dropped cost a round trip to the capture store and a
spinner before it could draw anything.

**Two repairs were available and they are genuinely different**, which is why
this is an ADR rather than a commit message.

## The alternative that was not taken

**Keep the payload and virtualise it.** Render the dump for the ~30 rows on
screen, memoise each frame's string by packet id, and `useMemo` the filter.
That removes every cost above without removing anything from the product.

It is more work than what was done, and it is more work *permanently*: a
payload row's height is a function of the payload's length, so the rows are not
uniform, so `lib/virtualWindow.ts` — which does arithmetic on a fixed row
height — does not apply. It would need a measured or estimated row height per
frame, which is the part of a virtualised list that actually goes wrong.

## Decision

**The Dialogue tab shows what a frame's summary record already carries**: frame
number, relative time, direction, both endpoints, and length. The ASCII, Hex
Dump and Raw Byte views are removed, along with the three buttons that chose
between them.

The list is virtualised through `lib/virtualWindow.ts` at a uniform 28 px row,
`framesOnStream` is memoised on the buffer and the target, and copy and save
share one line formatter with the row — they previously built two different
dialogue strings with two different prefix formats, so the file and the
clipboard could disagree with the screen.

The Ladder tab is untouched. It answers the other half of the question — the
shape of a conversation rather than its content — and it reads no bytes.

## What this costs, stated plainly

**This was the only place in the app that showed a reassembled conversation's
payload.** It is the thing Follow Stream exists for in Wireshark: how you read
an HTTP exchange, how you notice a credential in the clear, how you confirm that
what is on the wire is what you thought you sent. Removing it is not a cleanup
and this document exists so nobody later reads the diff as one.

The app can still show a single frame's bytes — `HexDumpView` in the detail
pane, which is virtualised and fast. What is gone is the **stitched** view
across many frames.

## Consequences

- **Opening a stream no longer touches the capture store.** The view reads only
  summary fields, so it opens on whatever the buffer holds, immediately,
  however long the stream is and whether or not its bytes were evicted.
- **`lib/useHydratedBytes.ts` is deleted.** This pane was its only consumer, and
  `scripts/session/side-bar.ts` already holds the one other candidate — the
  transfer panel — to the rule that outlived it: *hydrate at press time, not on
  render*. It is in git rather than left as a module nothing imports.
- **The saved file's name changed**, `_conversation.txt` → `_frames.txt`,
  because it no longer contains a conversation.
- **`HexDumpView` is now the only hand-rolled virtual window in the app**, and
  it is missing the `maxScrollTop` clamp that `virtualWindow.ts` exists to
  supply — the closed loop that module's header documents, where a blank list is
  held blank by its own spacer. Latent rather than observed, and recorded here
  because this commit is what made it the odd one out.

## If the payload comes back

It comes back virtualised, and the shape is fixed by what is written above:
rendered for the rows on screen, memoised per packet id, never rebuilt inside a
map over the whole stream. It needs a per-frame row height, which is the piece
`virtualWindow.ts` does not supply and the reason the alternative above was the
more expensive one. `useHydratedBytes` is the other half and is one `git show`
away.
