# 0002 - One field registry feeds the tree, the filter engine and the columns

**Status:** Accepted 2026-09-04

## Context

The protocol tree names fields for humans (`ProtocolField.name`, e.g. `Time to Live`),
the filter engine names them for machines (`Packet.fields['ip.ttl']`), and
`filterEngine.ts:134-161` keeps a third, hand-maintained `KNOWN_FIELD_NAMES` list for
typo checking. Autocomplete is a fourth fixed list. Nothing links them, so:

- right-click "Apply as filter" on a tree row is impossible (the row has no abbrev);
- the shipped colour preset references fields no dissector publishes
  (`hsrp.state`, `ip.checksum.status`, `tcp.analysis.window_update`) and silently never
  matches;
- adding a field means editing up to four places and forgetting one is invisible.

## Decision

`src/services/dissect/fieldRegistry.ts` is the single source of truth:

```ts
export interface FieldDef {
  abbrev: string;                 // 'tcp.flags.syn' - Wireshark's name where one exists
  label: string;                  // 'Syn'
  type: 'uint' | 'int' | 'bool' | 'string' | 'bytes' | 'ipv4' | 'ipv6' | 'mac' | 'time' | 'proto';
  layer: string;                  // 'tcp' - the frameProtocols token that owns it
  column?: { label: string; align: 'left' | 'right'; width?: number };  // offered by "Apply as column"
  generated?: boolean;
}
export const FIELDS: readonly FieldDef[];
export const FIELD_BY_ABBREV: ReadonlyMap<string, FieldDef>;
```

- `ProtocolField` gains `abbrev?: string`. A field with an `abbrev` renders its filter
  name in the status bar on hover and offers Apply/Prepare as filter, Apply as column,
  Copy field name.
- `DissectSummary.fields` may only contain keys present in `FIELD_BY_ABBREV`. An
  assertion script (`scripts/dissect/registry.ts`) greps every `fields['...']` /
  `fields.x =` write under `src/services` and fails on an unregistered key, and fails
  on a registered key with no writer.
- `KNOWN_FIELD_NAMES`, autocomplete, the "Apply as column" catalogue and the column
  type (for numeric vs string comparison and alignment) are all derived from `FIELDS`.
  The hand lists are deleted in Phase 9.
- Layer-presence barewords (`tcp`, `tls`, `quic`) are the set of `layer` values, and
  the filter engine tests them against `frameProtocols` as it does today.
- Colour rules and presets are validated against the registry at load; a rule naming
  an unknown field is shown disabled with a reason rather than silently never matching.

## Consequences

- Every field added in Phases 4-8 is registered first, one line, and is immediately
  filterable, columnable and validated. This is the point.
- Wireshark's abbrevs are used verbatim where they exist so that users' muscle memory
  and the parity harness's tshark field lists line up. Inwire-only fields use an
  `inwire.` prefix.
- The registry is a list, not a schema language: no per-field parsing logic lives in
  it. Dissectors still write the values.
