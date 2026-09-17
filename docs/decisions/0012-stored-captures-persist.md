# 0012 - A stored capture is discarded only when the user asks

> **Mechanism superseded by [0025](0025-the-capture-lives-on-disk.md)**, and 0025
> by [0027](0027-the-app-is-a-desktop-app.md) in turn. **The rule below survives
> intact and is the invariant the app still holds** - a capture is deleted only
> when the user asks. What changed is where a capture lives: not a browser
> database but real files under `%LOCALAPPDATA%`, pruned by `planPrune` and
> guarded by `scripts/capture/prune-guard.ts`.

**Status:** Accepted 2026-09-05. **Reverses the retention policy** stated in
`src/services/sessionLifecycle.ts` and `public/inwire-sw.js`.

## Context

The session store writes captured frames to disk so a refresh does not lose a
capture. The rule attached to that, until now, was stated in
`sessionLifecycle.ts`: those bytes "live exactly as long as the app is open, and
no longer." Three mechanisms enforced it.

- `public/inwire-sw.js` deleted the database a few seconds after the last window
  closed.
- A startup guard wiped the store when a fresh tab found no live sibling, which
  caught the browser-quit case the worker could not.
- `handleClearPackets` deleted it too, on the reasoning that "clearing the
  buffer clears what a refresh would restore."

That was a good rule for what the store was: a convenience, holding the last few
thousand frames so a reload was not a loss.

It is the wrong rule for what the store is becoming. Once the disk is where a
long capture actually lives - which is the point of the buffer work
(`scripts/perf/buffer-cost.ts`: 1,385 MB at a million frames, 85% of it raw
bytes) - every one of those three mechanisms destroys real work:

- Closing a tab after three hours of capture threw the capture away. Tabs are
  closed by accident constantly.
- **None of the signals distinguished "leftovers" from "a capture someone still
  wants."** A per-tab marker and a liveness ping tell you the app was closed.
  They do not tell you the user was finished, and those are not the same fact.
- Clearing the view to free memory silently destroyed the ability to export what
  had been captured - two unrelated jobs behind one button.

## Decision

**A stored capture persists until the user discards it.**

1. **Nothing deletes automatically.** `decideStartupAction` returns `restore`
   for every input; `scripts/session/lifecycle.ts` now asserts that
   exhaustively, so reintroducing an automatic wipe fails a test and has to
   argue with this file rather than slipping in.

2. **The service worker is kept, and kept registered, precisely so it can stop
   deleting.** A worker already installed in a browser runs until a new one
   replaces it, so deleting the file would have left the deleting version in
   place. The new version claims clients immediately and does nothing.

3. **"Clear Buffer" became two controls.** *Clear View* empties the list and
   frees the memory; the capture stays on disk. *Discard Capture* is the only
   thing in the app that deletes stored bytes.

4. **The size is on screen next to the button that removes it.** Bytes that
   outlive the app and are neither visible nor mentioned would be the wrong
   trade; the panel states how much is stored and that closing Inwire no longer
   deletes it.

## The trade, stated plainly

Raw frames now persist on disk after the app is closed. That includes payloads,
and this app can decrypt TLS when given a key log - so the stored capture may
contain plaintext that never appeared in the clear on the wire. It is readable
by anything running as that user until they discard it.

That is a real cost and it was weighed against the alternative, which is
software that deletes hours of a user's work without asking because a tab was
closed. Between "the app kept your capture and told you so" and "the app threw
your capture away and did not," the first is the better failure. The mitigation
is honesty rather than deletion: the size is shown, the retention is stated, and
one clearly-named action removes it.

Two things this does **not** change:

- **Key material still never touches the disk** (ADR 0008). A key log lives in
  memory, and travels in an export only behind the explicit Decryption Secrets
  Block switch. Persisting ciphertext is not persisting the keys to it.
- **Anonymise still strips on export** (Phase 12). What is stored is the capture
  as taken; what leaves the machine is still the user's decision.

## Consequences

- `clearSession()` is still exported and still does what it says; it is called
  from exactly one place now, the explicit discard.
- The old policy's hardest-won property - that a second window opening beside a
  live capture must not delete the first one's frames - still holds, by the
  stronger route that nothing deletes at all.
- A capture left on disk is bounded only by `STORAGE_BUDGET_BYTES` (512 MB),
  which evicts oldest-first when exceeded. That bound predates this decision and
  is now the only automatic deletion left in the system, so it is **counted and
  shown**: `pendingWriteBacklog()` reports `evictedForBudget`, and the panel says
  how many frames stopped being stored and why, next to the size and the limit.
  "The app kept your capture, except the beginning of it" is the same surprise
  this ADR exists to remove, and an app that promises to keep a capture until
  asked has to say when it could not.

  The arithmetic is `planBudgetEviction`, a pure exported function, so the one
  thing left that deletes a user's frames can be tested directly rather than
  only through IndexedDB (`scripts/session/storage-budget.ts`).
