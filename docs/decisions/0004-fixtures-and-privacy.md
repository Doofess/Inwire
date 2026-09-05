# 0004 - Fixture captures stay untracked; only aggregate counts are committed

**Status:** Accepted 2026-09-04

## Context

The acceptance oracle for every phase is tshark parity on two real captures from the
author's PC (`inwire_capture_1788478187989.pcap`, `netview_capture_1788426090876.pcap`).
They contain the author's DNS and SNI history, mDNS device names, and the home
network's rotating IPv6 addresses. The tshark ground-truth `.psv` files carry the same
names in their Info column. The repository's `origin` is on GitHub and its visibility
cannot be assumed private.

Anonymising the captures is not yet possible without breaking what they test: SNI
lives in plaintext ClientHellos whose lengths feed JA3/JA4 and TLS record parsing, and
DNS names are the very thing Phase 7 and Phase 10 are measured on.

## Decision

- Captures and ground truth live in `test/fixtures/` which is **gitignored**. A
  committed `test/fixtures/README.md` lists each file's name, SHA-256, frame count,
  tshark version used, and the regen command.
- What is committed is `test/fixtures/acceptance.json`: per fixture, per column, the
  match percentage floor, plus the fixed counts from spec Part A.4 (ClientHellos,
  QUIC frames, TCP analysis flags, conversations). No names, no addresses, no Info
  text.
- `scripts/parity/parity-check.ts` fails when a fixture listed in `acceptance.json`
  is missing locally and prints how to obtain it; it is excluded from `npm run check`
  (as now) but is a required step in the recurring gate.
- Byte-level dissector assertions (`scripts/<proto>/dissect.ts`) may embed **short**
  hand-extracted frames (a single hello, one DNS response) only after replacing any
  personal name or address with an example.com / RFC 5737 / RFC 3849 value and
  re-computing lengths and checksums. A script comment records the source frame
  number.
- Revisit when Phase 12's anonymiser exists: if a prefix-preserving, length-preserving
  rewrite can be validated to leave every acceptance count unchanged, anonymised
  fixtures may be committed and this decision superseded.

## Consequences

- CI cannot run the parity harness; it runs the assertion scripts. The gate makes a
  human run parity locally before a phase is marked done.
- The two captures are the only copies; the README asks for them to be backed up
  outside `Downloads/`.
