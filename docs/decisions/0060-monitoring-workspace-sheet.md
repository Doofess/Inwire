# 0060 — Monitoring is a third sheet, opened from the Network panel and the palette

**Status:** accepted 2026-10-17; implementation landed 2026-10-18 (merge 41b4a43).

## Context

[0058](0058-monitoring-intake-and-lifetime.md) and
[0059](0059-monitoring-evidence-journal-and-rollups.md) give monitoring a
listener and a history. Both need somewhere in the window to live. The rail
has three groups and is full at 452px of 618 (`src/components/CLAUDE.md`).
`APP_VIEWS` (`src/services/viewPrefs.ts`) is five places with `Ctrl+1..5`
bound to them, and a sixth view would move every key after it. The speed test
had the same problem and solved it ([0054](0054-an-internet-speed-test-against-cloudflare.md)):
a sheet opened from the Network panel, which covers the workspace and leaves
the view underneath untouched.

Monitoring is the same kind of surface. It is opened deliberately, it lasts
longer than a glance, and it keeps running after you leave it.

## Decision

### A sheet on the speed test's precedent

`App`'s slot becomes `'settings' | 'speedtest' | 'monitoring' | null`. It
stays a union, so "the card holds exactly one surface" remains a fact the
type carries. The monitoring sheet follows every rule the other two follow:

- **Three ways out and no fourth:** the title row's back step reading
  "Back to &lt;the view underneath&gt;", Escape (outermost surface first,
  [0034](0034-the-side-bar-is-a-place.md)'s chain), and choosing any view.
- **Landing on a view closes it**, through `handleViewChange` and
  `applyFilter`, the same two doors the other sheets use.
- **Leaving does not stop collection.** Collection state belongs to the
  utility and to a module store under `src/services/monitoring/`, not to the
  sheet. App does not re-render on every datagram, for the same reason it
  does not on the speed test's updates.
- **`APP_VIEWS` and `Ctrl+1..5` are unchanged**, and the rail gets no button.

### Two ways in

- **The Network panel** gets a *Monitoring* section beside *Speed test*. It
  shows a one-line state (stopped, listening, receiving, stale, or a failure
  in its own words) and opens the sheet.
- **A `commands.ts` entry**, `monitoring.open`, under the Window group with
  keywords `netflow`, `flow`, `exporter` and `collector`. It has no chord.
  [0057](0057-command-registry-and-palette.md)'s rule is that the palette has
  no features of its own, and this command opens a sheet the panel also
  opens.

The talker pivot goes the other way. **Filter capture by this host** applies
`ip.addr == <address>` through the existing display-filter path, which closes
the sheet as `applyFilter` always does. Its label says it is a filter over the
open capture, never the flow's own packets.

### What the sheet says before and after Start

**Before the first Start**, the sheet explains, in what 0058 observed:

> Windows will ask whether Inwire may receive on the network. Choose
> **Allow**. If you choose Cancel, Windows will not ask again, and nothing
> will arrive until an administrator removes the rule in Windows Defender
> Firewall.

This replaces the spec's "choose **Private networks**", which the observed
dialog does not offer. The packaged `Inwire.exe` raised the same dialog word
for word, naming *Inwire* (see the measurement report).

**After 60 seconds of listening with nothing arriving**, the sheet names the
two usual causes beside the listener state:

- the firewall, with Cancel's consequence spelled out
- the exporter's target address, which must be this bind address and port

The rejected-sender list sits with them whenever it is non-empty, because a
router sending from an unexpected address looks exactly like silence.

**Listening is never shown as receiving.** Listener state and exporter state
are separate rows. Stale means *no recent export*, and the history draws
collection gaps as gaps, never as zeros.

### The sheet's own layout

The sheet's layout, its states and their screenshots are decided when it is
built, under the `inwire-visual-design` skill and the owner's screenshot
review. Every state is reviewed: empty, first Start, listening with nothing
arriving, live, stale, rebuilding and failure, at the minimum and default
window sizes and in all four themes. This ADR fixes only where the sheet
lives and what it must say.

## Later, not built

A rail button, a sixth view, a monitoring view in the floating panels, and
any key chord. Each of those changes navigation that already works, and none
is needed for one source.

## Consequences

- A third member of the sheet union, held by the same assertions as the
  other two, and a new section in the Network panel.
- Monitoring is one click further away than a rail view would be. That is
  the price of keeping `Ctrl+1..5` and a full rail as they are.
