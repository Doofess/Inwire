# 0070 — An exporter's identities are recycled, least recently heard first: every datagram is counted, a row is kept while its identity is held, and the checkpoint records when each was last heard

**Status:** accepted 2026-11-01 by the owner, with the three rulings below, chosen on
2026-11-01, in answer to the open item the Milestone 2 final review left. It
amends [0064](0064-monitoring-v9-ipfix-collection.md)'s bound on identities and
its checkpoint layout (format 2 beside format 1, which stays readable), and
[0059](0059-monitoring-evidence-journal-and-rollups.md)'s engine rule. It
leaves everything else in 0059, 0062, 0064, 0065 and 0066 standing.

## Context

An exporter speaks through **identities**: a v5 engine (type and ID), a v9
Source ID, an IPFIX Observation Domain with its source port. Since the final
review of Milestone 2, an exporter holds at most `LIMITS.enginesPerExporter`
(16) of them, and the bound **refuses**: the first 16 in journal order are
admitted for the life of the dataset, and a datagram from a 17th decodes as
`unsupported`, touches no state and is counted nowhere. The bound exists so a
checkpoint, a minute's held-back rollups and the health rows stay bounded
against a spoofed or rotating identity. It is enforced in four places, each
with its own copy of the rule:

- `CollectorTemplateStore.canOpen` (`templates.ts`) and `ExporterState`'s
  sources (`exporterState.ts`): the decoder;
- `EngineAdmission` (`rollup.ts`): which identities get rollup rows, "the
  first 16 forever", which the Worker re-learns from the sidecar's source keys
  and the archive's sources because it is not in any checkpoint;
- `canAdmitEngine` and the `valid-template` branch (`sourceHealth.ts`): the
  health rows.

The case that breaks: an exporter that takes a new Source ID or domain at each
restart. After its 16th restart it is silent in History for good, while the
sheet shows datagrams arriving. Nothing tells the user why except an
`unsupported` count.

## Decision

### Least recently heard is recycled (owner's ruling 1)

When a datagram from an identity the exporter does not hold arrives, and the
exporter already holds 16, the identity **heard from least recently** gives up
its place, and the newcomer takes it. "Heard" is a valid datagram's entry id.
Ties cannot occur live; after a format 1 restore (below) they are broken by the
checkpoint's sort order.

- A v9/IPFIX identity that is evicted loses its scope (templates, uptime,
  system init, message count) and its source (sequence, sampling, samplers)
  together. If it speaks again it is new: its data sets wait for templates, as
  after any restart, and the sheet's counters say so.
- A v5 identity has no decode state. Evicting it costs only its health row.
- The rule is the same for all three kinds (owner's ruling 3). The decoder's
  16 places hold v9/IPFIX scopes, the only identities with decode state. The
  health rows' 16 places are shared by all three kinds, as today, and are
  recycled by health's own record of when each row was last heard (below).

### A row while held (owner's ruling 2)

Row admission follows the decoder. Because recycling always makes room, every
valid datagram's identity is held when the datagram is counted, so **every
valid datagram is counted** in its identity's row and its exporter's totals.

- An evicted identity's earlier minutes stay. They are history, not state. If
  it comes back it continues under the same source key, so its rows join up.
- `EngineAdmission` and its "learned from the sidecar's keys" path go away:
  there is nothing to learn. `SessionContext.knownSources` goes with it.
- **Per minute, an exporter gets at most 16 identity rows.** A datagram from a
  17th distinct identity in one minute is counted with the exporter's
  unsupported datagrams in its own row (`addUnsupported`, as today), and in
  health as `engineLimitRejected`. This document calls that case
  *identity churn*. This keeps `MAX_APPEND_BYTES` and the held-back minutes where they
  are against an identity rotating faster than once a minute.
- **The per-minute count is a decode decision.** `DecodeState` keeps, per
  exporter, the receipt minute and the identities seen in it. It starts a new
  set when the minute changes, at the first entry of a segment, and at `stop`,
  `suspend` and `interrupted` boundaries. Every checkpoint (role 1 at a segment
  start, role 2 at a stop, an archive cut at a segment's end) lies at a reset,
  so the checkpoint does not carry the set, and every path (live, rebuild,
  expiry replay, raw query) decides the same datagrams as churn. The step
  returns such a datagram as `unsupported`. The rollups, the raw scan and
  health then only read the decision.
  *(2026-11-01, after review: the set is replaced only by a **later** minute, not
  by any different one. A receipt clock that steps back and forth, B then A then
  B, would otherwise start a fresh set at each change and give minute B sixteen
  new identities per re-entry, past the bound this section exists to keep. A
  datagram stamped earlier than the held minute counts against the newest set
  held. The held minute still depends only on the entries since the last reset,
  so every path decides the same datagrams.)*

### Health

A health row is live state. When a 17th identity of an exporter is heard, the
row heard least recently (by the entry id of its last valid datagram) gives
up its place to the new identity, and the exporter's `identitiesReplaced`
counter goes up by one. `engineLimitRejected` stays in the snapshot, counting
identity-churn datagrams, so older readers keep their meaning. The sheet's
source status (`SourceStatus.tsx`) lists "Identities replaced" beside the
other counters when n > 0, and "Past the engine limit" there becomes "Too many
identities in one minute". Its explanation is one sentence:
the exporter took a new Source ID or Observation Domain, the oldest one's
templates were dropped, and its History is kept.

### The checkpoint, format 2

Which identity is least recent is decode state: it decides whose templates are
dropped. So it is checkpointed, or a rebuild from a checkpoint could drop a
different one than the live run did.

- Format 2 is format 1 with each scope record grown from 36 to 44 bytes: an
  8-byte **last heard entry id** at offset 36, after the reserved field. The
  header's format field is `2`. Everything else, sources included, is
  unchanged. A source is evicted with the scope of the same key, so it needs
  no field of its own.
- `encodeCheckpoint` writes only format 2. `decodeCheckpoint` reads both. A
  format 1 scope is restored with its last heard set to the checkpoint's own
  through entry id. An archive cut's checkpoint is never rewritten (0062), so
  format 1 stays readable for good.
- Restoring then encoding gives the same bytes for format 2. For format 1 it
  gives format 2, and this is the one accepted exception to "restore and encode
  are identity" in 0064. A format 1 checkpoint is only ever a starting point, so
  every replay from it restores the same state, and replays stay deterministic.
- A new vector is pinned beside 0064's 246-byte one, printed by
  `measurement.ts checkpoint`. The format 1 vector stays as a decode-only test.
- Policy is unchanged. The decoder policy (2) is what a datagram means. This is
  how many identities the state holds.

## Consequences

- An exporter that renumbers at every restart keeps being counted. Its newest
  16 identities decode normally, and History lists one row per identity it ever
  used. That list is not bounded over the dataset's life, but within any one
  minute it is (16).
- A collector receiving 17 genuinely live identities from one exporter thrashes
  the least recent one: its templates are dropped, and it waits for a resend.
  The sheet's "Identities replaced" counter makes that visible. 16 is
  `LIMITS.enginesPerExporter` and is not raised here.
- The checkpoint grows by 8 bytes a scope, at most 128 bytes, far inside
  `checkpointBytes`.
- Sidecars written before this change hold checkpoints of format 1. They are
  continued, not rebuilt: a format 1 checkpoint restores. 0071's sidecar format
  bump rebuilds them anyway, once.
- Rejected: **evict and refuse the rows** (identities past the first 16 counted
  only in the exporter's totals). It needs a second rule beside the decoder's,
  which is the duplication this removes. **Raise the cap**: it postpones the
  same failure. **Keep refusing and say so**: the exporter stays uncounted.

## Enforcers

- `scripts/monitoring/checkpoint-codec.ts`: the format 2 vector; format 1
  restores with last heard = through, and encodes to format 2; a 17th identity
  evicts the least recently heard one, and its templates and source go with it.
- `scripts/monitoring/templates.ts` and `exporter-state.ts`: eviction order,
  ties broken by sort order after a format 1 restore.
- `scripts/monitoring/rollup.ts`: a rotating identity is counted in every
  minute; the 17th distinct identity in one minute is identity churn; a
  rebuild from a checkpoint gives the live run's answers.
- `scripts/monitoring/health-budget.ts` and `health-push.ts`: the row is
  recycled, and `identitiesReplaced` counts it.
- `scripts/monitoring/sheet-source.ts`: the sentence comes from
  `monitoringCopy.ts`.
