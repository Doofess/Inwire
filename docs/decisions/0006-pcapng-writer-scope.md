# 0006 - pcapng writer scope and the pcap fallback

**Status:** Accepted 2026-09-04

## Context

Export writes classic pcap only (`PcapService.generatePcapBinary`, linktype 1 and
snaplen 65535 hardcoded, microseconds derived from ms, unsorted). The reader already
handles pcapng (SHB, IDB with `if_tsresol`, EPB) but discards the interface id. Once
ADR 0005 gives frames `iface` and `ts_us`, and Phase 10 builds a passive name map,
pcapng is the only format that can carry them.

## Decision

`src/services/pcapng/writer.ts` (Phase 12) writes, in order:

1. **SHB** - `shb_userappl` = `Inwire <app version>`, `shb_os` from `navigator`
   platform only if the user opted in (privacy toggle, default off), `shb_hardware`
   omitted.
2. **One IDB per interface** seen in the export set, in `iface` order: `if_name`,
   `if_description` (label), `if_tsresol` = 6, linktype from the capture (1 for live).
   Imported captures preserve their own IDBs and linktype.
3. **EPBs** for every frame, sorted stable by `(ts_us, seq)`, with `interface_id`,
   64-bit timestamp in us, `caplen`/`origlen` from the frame, and an `epb_flags`
   option carrying direction when known. Frame comments (Phase 10 marks) as
   `opt_comment`.
4. **NRB** - every entry of the passive name-resolution map whose source is
   `dns|mdns|dhcp|lldp|manual` (never SNI, never an ECH outer name), as `nrb_record_ipv4`
   / `nrb_record_ipv6`. Written only when the user has name resolution enabled.
5. **ISB** per interface from the last `capture_stats`: `isb_ifrecv`, `isb_ifdrop`.
6. **DSB** (Phase 13) when a key log is loaded.

Classic `.pcap` remains available and is the default when the export set has more
than one linktype (pcap cannot express it) or the user asks for it; it is written
with the frame's linktype, us from `ts_us`, and the same sort.

Anonymise-on-export (Phase 12) runs before the writer and rewrites the NRB, the
IDB names and the frame bytes consistently, so both formats get the same treatment.

## Consequences

- The reader keeps the interface id on the `Packet` (`iface`) so a re-import of an
  Inwire export round-trips interfaces.
- `test/fixtures/acceptance.json` gains a round-trip check: export the fixture as
  pcapng, run tshark on the result, expect the same frame count and 0 negative deltas.
