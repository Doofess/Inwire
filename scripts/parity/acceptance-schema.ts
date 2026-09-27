/**
 * The shape of `test/fixtures/acceptance.json`, in one place.
 *
 * ## Why this file exists rather than a type beside each reader
 *
 * There were **four** copies of this shape and they were drifting:
 * `parity-check.ts` exported one, `acceptance.ts` redeclared it privately,
 * `tree-coverage.ts` cast a partial `{ fixtures: Record<string, { file: string }> }`,
 * and the fourth was the JSON itself. Three readers of one file is the moment a
 * hand-kept shape stops being cheaper than a shared one - the same argument
 * `parity-check.ts` makes about `REFERENCE_COUNTERS`, that a hand-kept
 * expectation is a second implementation of the thing it is checking.
 *
 * **It carries no runtime statements, and that is load-bearing.**
 * `parity-check.ts` calls `main()` at module scope, so importing a *value*
 * from it runs the entire parity check as a side effect - minutes of tshark on
 * two 16 MB captures, from a script that only wanted a type name. `import
 * type` is erased and would be safe today; it is one careless edit from not
 * being. A types-only module cannot have that failure at all.
 */

/** One capture, its floors, and what the reference counted on it. */
export interface FixtureSpec {
  file: string;
  sha256: string;
  frames: number;
  /** Per-column minimum match percentage. Raised, never lowered, phase by phase. */
  floors: Record<string, number>;
  /** What tshark counts. Only the keys in `enforce` fail the run. */
  counts: Record<string, number>;
  enforce: string[];
  /**
   * What the protocol TREE is held to, which is a different question from the
   * columns above and is measured by a different script
   * (`scripts/parity/tree-coverage.ts`, ADR 0039).
   *
   * Optional only so a fixture added before that script existed still parses;
   * `acceptance.ts` fails a fixture that has `floors` and no `tree`.
   */
  tree?: TreeAcceptance;
  /**
   * What a snaplen does to this fixture, per cut (`scripts/parity/snaplen.ts`,
   * ADR 0050). Optional so a fixture measured before that script still parses.
   */
  snaplen?: SnaplenAcceptance;
}

/**
 * Counts per snaplen, keyed by the snaplen as a string. `tcpLenKept`,
 * `analysisKept`, `protocolKept`, `infoKept` and `limitedBoth` are floors;
 * `limitedMissed` is a ceiling; the rest are recorded. Counts rather than
 * ratios for ADR 0039's reason.
 */
export type SnaplenAcceptance = Record<string, Record<string, number>>;

/**
 * The tree's side of the acceptance file.
 *
 * **Counts, never percentages**, and that is the whole design. The denominator
 * of a coverage ratio is the *reference's* vocabulary, which grows when
 * Wireshark ships a release - so a ratio floor fails a build that changed
 * nothing, on the very upgrade `test/fixtures/README.md` instructs you to
 * perform. An absolute count moves only when our own dissectors do. ADR 0039.
 */
export interface TreeAcceptance {
  /**
   * Per layer, the number of distinct field abbrevs **both** sides emit on
   * this fixture. A floor: it may only rise.
   *
   * Deliberately asymmetric between fixtures - a layer is floored on the
   * captures that contain it and absent from the others, so the ratchet
   * compares each fixture against its own past and never across.
   */
  layers: Record<string, number>;
  /**
   * Protocols the reference names on this fixture that this build can also
   * name, through `frameProtocols` or a synthetic filter predicate. A floor.
   */
  protosNamed: number;
  /**
   * The two numbers that may only **fall**.
   *
   * `filterableNotInTree` is the count of names a filter here answers and the
   * detail pane does not - every one is a defect by construction, because the
   * app accepts a filter for a row it refuses to draw. `valueMismatches` is
   * the count of abbrevs where both sides emit a value and the values differ.
   */
  ceilings: Record<string, number>;
  /**
   * Recorded and **never enforced**, so there is a historical series with none
   * of the chase. `absentDistinct` is the size of the ranked gap list; a
   * ceiling on it would turn a measurement into a backlog, which is exactly
   * what ADR 0021 ended.
   */
  counts: Record<string, number>;
  /**
   * Layers the reference dissects on this fixture and this build does not, one
   * sentence each.
   *
   * **Not a floor of zero.** A zero floor protects nothing and reads as though
   * it had been measured and accepted; this says outright that the floor is
   * deliberately absent. An entry may only leave by moving into `layers` with
   * a positive floor.
   */
  unimplemented: Record<string, string>;
}

export interface Acceptance {
  tshark: string;
  groundTruthFields: string[];
  fixtures: Record<string, FixtureSpec>;
}
