/**
 * How many surfaces want the adapters sampled, and whether the agent should be
 * told now.
 *
 * The Interfaces panel and the welcome both draw sparklines, and each turns
 * sampling on when it mounts and off when it unmounts. A boolean let the
 * second one to close turn sampling off under the first. `acquire` and
 * `release` return true only on the edges - 0 to 1 and 1 to 0 - which are the
 * only moments the agent hears about it. A release at zero does nothing.
 */
export interface SamplingCount {
  acquire(): boolean;
  release(): boolean;
  readonly active: boolean;
}

export function createSamplingCount(): SamplingCount {
  let holders = 0;
  return {
    acquire() {
      holders++;
      return holders === 1;
    },
    release() {
      if (holders === 0) return false;
      holders--;
      return holders === 0;
    },
    get active() {
      return holders > 0;
    },
  };
}
