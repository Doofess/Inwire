/**
 * Whether the dissection under way is asked to build a frame's full tree.
 *
 * A live TCP shard (ADR 0072) keeps no tree: a frame's tree is rebuilt from its
 * record when somebody looks at it (ADR 0049), so what the shard builds is only
 * what the row and the frame's record need - and the record is read from the
 * trackers, not from the tree. A layer that can skip the nodes nothing reads
 * asks `treeWanted()` once per call and keeps only its findings when the answer
 * is no.
 *
 * Outside any scope the answer is yes: lane 0, import, revisit and replay all
 * build the whole tree. A shard turns it off for the length of one synchronous
 * dissection (`withoutTree`), the way a revisit installs its environment
 * (`withDissectEnv`).
 */
let wanted = true;

import type { ProtocolField } from '../../types/packet';

/**
 * The rows of `rows` that carry a finding, flattened depth-first (a row before
 * its children, which is the order `collectExpert` walks) and stripped of
 * their children. What a tree-free layer holds in place of rows built for the
 * tree, for a layer whose rows come from a helper that builds the whole tree
 * anyway - IPv4 options, a reassembled-fragment row - and are rare enough that
 * building and then thinning them is cheaper than a second builder.
 */
export function findingsOf(rows: readonly ProtocolField[]): ProtocolField[] {
  const out: ProtocolField[] = [];
  const walk = (list: readonly ProtocolField[]) => {
    for (const row of list) {
      if (row.expertInfo !== undefined) {
        const { children: _children, ...flat } = row;
        out.push(flat);
      }
      if (row.children !== undefined) walk(row.children);
    }
  };
  walk(rows);
  return out;
}

/** True unless a `withoutTree` scope is open. */
export function treeWanted(): boolean {
  return wanted;
}

/**
 * Runs `fn` - one synchronous dissection - with no tree wanted, and puts the
 * previous answer back however `fn` ends. Dissection never awaits, so nothing
 * else can observe the swap. Scopes nest.
 */
export function withoutTree<T>(fn: () => T): T {
  const previous = wanted;
  wanted = false;
  try {
    return fn();
  } finally {
    wanted = previous;
  }
}
