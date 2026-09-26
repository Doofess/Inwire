# 0048 — A capture's adapters are fixed for its life

**Status:** accepted 2026-09-26. **Reverses one behaviour that
[0047](0047-windows-ships-the-rust-agent-signed-on-this-pc.md)'s parity audit
ported**: `set_interfaces` during a capture no longer restarts it on the new
set. It is refused, in both agents, and the app no longer offers it.

## Context

The owner's decision, in their words: *"i don't want the ability to change
adapter mid capture. the only thing a user can do is select multiple
interfaces before starting a capture."*

Until now the adapter list in the side bar stayed live during a capture. A
click sent `set_interfaces`, and both agents stopped the capture and started it
again on the new set (agent.py's `_handle_message`, and the Rust agent's
`control.rs` once 0047 brought it to parity). The panel carried a warning
saying so, because nothing else on screen could.

The restart cost more than the feature. It zeroed the driver's and the agent's
counters, and the app's `capture_stats` handler replaces its totals rather than
adding to them (`useAgentConnection.ts`). Every drop from before the change
vanished from the status bar's total and from the metadata every export
carries.

## Decision

**The adapters are chosen before Start and change only after Stop.**

- **The app.** `CaptureInterfacePanel` disables its rows while this window
  captures, and says why in one line: *Capturing. Stop the capture to change
  adapters.* The rates keep drawing, and the chosen rows keep their colour,
  because they are what is being captured. Another window's capture locks the
  list the same way: the agent refuses that window's selection, and a row that
  changed anyway would name adapters nobody is capturing on. That gap predates
  this decision. `handleToggleInterface` in `App.tsx` returns early in both
  cases, for any way in other than the panel.
- **Both agents.** A `set_interfaces` that arrives while a capture runs is
  answered with `capture_running`, *Stop the capture before changing
  interfaces.*, to the sender alone. No `state` is broadcast, the stored
  selection is untouched, and the capture carries on as it was. The ownership
  gate still runs first, so another window is told `capture_busy`, which names
  whose capture it is. A malformed selection still gets its own error, because
  validation runs before either.

Nothing else moves. `set_interfaces` while idle stores the selection and
broadcasts the idle `state`, as before. The reconnect resync
(`captureResync.ts`) is unaffected. A reconnected agent is either idle, because
the owner leaving stopped its capture, or owned by another window, in which
case the resync sends nothing.

**No version bump.** The app never sends `set_interfaces` mid-capture, so it
behaves the same against an agent of either kind, and `REQUIRED_AGENT_VERSION`
has nothing to require. The installed agent picks the refusal up at the next
install. 0047's two new error codes took the same route.

## Consequences

- **Drop counts hold for the life of a capture again.** The loss is closed by
  removing its cause, not by teaching the app to add.
- **Moving to another adapter is Stop, change, Start.** Start begins a new
  capture and discards the current one, after its confirm. That is the owner's
  intent: one capture, one set of adapters.
- `agent.py`'s change is kept line-neutral on purpose. The Rust crate and the
  ADRs cite about 250 of its line numbers, and a five-line block became another
  five-line block.
- Enforced by `set_interfaces_while_sniffing_is_refused_and_the_capture_carries_on`
  and `set_interfaces_from_another_window_while_sniffing_is_busy_not_running` in
  `agent-rs/src/control.rs`, and by `test_protocol.py`'s *set_interfaces
  mid-capture is refused* checks. The first Rust test and the Python checks
  fail against the restart they replace. The second Rust test passes against it
  too: it guards the order of the checks, not the refusal.
  `scripts/agent/control-vectors.json` carries the new message, so the app's
  parser is held to it.
