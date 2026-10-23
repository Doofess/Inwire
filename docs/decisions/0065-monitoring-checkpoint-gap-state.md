# 0065 — The template checkpoint records collection-gap state, and a template applies from where it lies in its datagram

**Status:** accepted 2026-10-23 by the owner, before Task 8 implemented
0064. It supersedes two details of
[0064](0064-monitoring-v9-ipfix-collection.md) and leaves everything else in
it standing.

## Context

0064 states two rules that its checkpoint format cannot carry, and one
sentence that the recorded exporters contradict.

- **Collection gaps.** For the first datagram of each scope after a gap,
  the lifetime's message condition counts as met. Refresh intervals are
  measured only between two receipts in the same collection session. Both
  rules depend on state that 0064's encoding has no field for:
  - whether a gap has ended since the scope's last datagram;
  - whether a template was last received in an earlier session.

  Role-1 and archive-cut checkpoints fall mid-session. Without these two
  facts, a rebuild that starts from such a checkpoint would expire templates
  and record longest intervals differently from a full replay. That breaks
  0064's own rule that the live path, a rebuild and a raw scan agree.
- **Which boundaries end a gap.** 0064 triggers on a session's `start`
  boundary but names suspend as a gap. 0059 defines a gap as the time from a
  `stop`, `suspend` or `interrupted` boundary to the next `start` or
  `resume`, and also writes `gap` boundaries.
- **Templates in the same datagram.** 0064's raw-scan definition decodes a
  datagram only with templates received "strictly earlier in entry order".
  Every pass in `scripts/monitoring/exporter-vectors.json`, from both
  softflowd and pmacct, sends a template set and then data that uses it in
  the same datagram: 1 to 6 times per pass. tshark and the lab's readers
  decode that data, and RFC 3954 and RFC 7011 intend it. Read literally, the
  sentence would leave it awaiting template, and every total would fall
  short of tshark.

## Decision

- **Scope flags, bit 2:** a collection gap has ended since this scope's
  last datagram. It is set on every scope when a gap ends, and cleared by
  the scope's next datagram, after that datagram's lifetime check has
  treated the message condition as met.
- **Template flags, bit 2:** this template was last received in an earlier
  collection session. It is set on every template when a gap ends. The
  template's next receipt measures no interval and clears the bit.
- **A gap ends** at a `start`, `resume` or `gap` boundary.
- All other flag bits stay zero. The layout, the sizes and the sort order of
  0064's encoding are unchanged. The 246-byte test vector has both bits
  clear, so it is byte-identical.
- **A template applies from where it lies.** A template or options template
  applies to the data sets that follow it in the same datagram, in set
  order, and to later datagrams. It never applies to an earlier entry, or
  to a data set before it in the same datagram. Data with no such template
  is awaiting template, as 0064 says.
- **The raw-scan definition** therefore reads: a data set is decoded with
  the templates received before it, in entry order and then set order,
  that are still within their lifetime at its datagram's receipt time.

## Consequences

- A rebuild that starts from any checkpoint makes the same expiry and
  interval decisions as a full replay. Task 9's `checkpoint-rebuild-equals-raw`
  test covers a checkpoint taken mid-session.
- The recorded passes decode to tshark's totals, with nothing awaiting
  template.
- Format 1 stays format 1. No file holds a checkpoint before this decision,
  so no reader of the narrower meaning exists.
