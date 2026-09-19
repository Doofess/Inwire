# 0034 — The side bar is a place, so Escape does not close it and navigating does not either

**Status:** accepted. Extends `viewPrefs.ts`'s "a modal is a detour, a pane is a
place" from views to a second surface. Does not supersede anything: the Escape
chain is unchanged, the sheet rule is unchanged, and `0031` still owns where a
display filter is answered.

## Context

Four surfaces moved into a VS Code-style side bar — a resizable column between
the activity rail and the workspace card. Two were Radix dropdowns hanging off
rail buttons, one was a 768px modal with a scrim, and one was a pane that took
the whole workspace.

All four of those containers are **dismissed**. A dropdown closes on an outside
click and on Escape; a modal closes on its X, its Close button and Escape; the
workspace sheet closes on Escape, on the title row's back step, and on any
navigation. So every surface that moved here arrived with the assumption that
Escape closes it, and with a caller somewhere that closed it on a view change.

The column is not dismissed by any of that, and this records why — because two
of the three decisions are **negatives**, and a negative decision leaves no
code behind to explain itself. The next session to touch `App`'s Escape handler
will find a chain that closes the palette, then the presets dropdown, then the
discard prompt, then the sheet, then returns the view to Packets, and will
reasonably wonder why the side bar is not in it.

## Decision

**1. Escape does not close the side bar.**

`viewPrefs.ts` already overturned the rule that "'which panel did I have open'
is not a setting", and left the test that replaced it: *a modal is a detour, a
pane is a place.* The Escape chain is a chain of **detours** — the command
palette, the filter presets list, the discard confirm, the geo overlay, then the
Settings sheet, then the view.

The side bar is persisted. `inwire.sideBar` holds which panel is open and how
wide the column is, and a fresh window reopens on both. That persistence is this
repository's operational definition of a place, so an Escape that closed the
column would be a key that **silently rewrites a stored preference** — the same
fault `interfacePrefs.ts` already refuses when it keeps `resetInterfacePreferences`
away from a pane width somebody dragged.

There is a second cost and it is the one that would be noticed. Escape is
documented as staying **one hop**: any non-Packets view returns to Packets in a
single press. Putting the side bar at the head of that chain makes the first
press close a column nobody asked to close and leaves the view where it was, so
the documented one-hop behaviour would quietly become two.

The keyboard is not left without a way in: **`Ctrl+B`** toggles the last-open
panel, which is VS Code's own key for the same surface. That is the same door
the rail buttons are, reached differently — not a fourth door in the sense the
Settings post-mortem forbids.

**2. Navigating does not close it, which is the exact inverse of the sheet rule.**

`handleViewChange` and `applyFilter` both call `setSheet(null)`, and that is
correct and load-bearing: a sheet renders **instead of** the view stack, so a
navigation underneath it is invisible. That bug shipped once — every icon in the
rail lit up and changed nothing on screen, and the back step was the only way
out.

The side bar renders **beside** the view stack. A navigation underneath it is
fully visible, so there is nothing to repair; closing it would instead make it
the one pane in the app that cannot be kept open while working, which is the
entire point of having it.

This is the decision most at risk of being "fixed", because the two rules sit
within a few lines of each other and the wrong one is a one-line copy.
`scripts/session/side-bar.ts` asserts both negatives by reading the **bodies**
of `handleViewChange`, `applyFilter` and the Escape effect — by their two ends,
not by a character window, because the first attempt at that check failed on
correct code: `useKeyboardNavigation`'s options object sits a few lines below
the Escape handler and legitimately contains `setSideBar`, for `Ctrl+B`.

**3. The side bar and the sheet are orthogonal, and that is the proof of 1 and 2.**

`sheet` answers *what is in the workspace card*; `sideBar` answers *what is
beside it*. They are different containers, so a panel may be open while Settings
has the card — and that is not a tolerated side effect but the demonstration
that the column is a place rather than another sheet. It is also VS Code's
arrangement exactly: the Explorer stays open while the Settings editor fills the
editor area.

## Consequences

**Accepted.** A user who expects Escape to dismiss everything will press it once
with the side bar open and see the view change underneath. That is the correct
outcome and it is in `docs/verification.md` as a thing to check rather than a
thing to fix.

**Accepted.** The column persists, so a launch can land on Export/Import rather
than on the capture. The alternative — remembering the width but always starting
closed — was considered and rejected with the user: a place that forgets where
you were is a place you have to find again every morning.

**Guarded.** The three negatives are asserted, because all three fail silently:
an Escape that closes the column looks like a feature until somebody notices the
view no longer returns to Packets in one press, and a navigation that closes it
looks like tidiness until somebody tries to keep the adapter charts up while
reading the list.

**Open.** There is no keyboard way to move focus INTO the side bar other than
tabbing. VS Code has `Ctrl+0`. Not built, because the panels are reachable by
Tab and inventing a second focus shortcut before anybody has asked would be
guessing at a problem.
