## What this changes, and why

<!--
The why matters more than the what - the diff already says what. If you
considered an approach and rejected it, say which and on what grounds; that is
the part nobody can reconstruct later.
-->

## Checks

- [ ] `npm run check` passes
- [ ] If this touches the shell, the installer, or anything privileged, the
      relevant items in `docs/verification.md` were checked by hand — that file
      exists because everything in it fails silently
- [ ] If this changes dissection, parity floors were re-recorded rather than
      lowered (`test/fixtures/acceptance.json`)
- [ ] If this closes off a future option, there is an ADR in `docs/decisions/`
