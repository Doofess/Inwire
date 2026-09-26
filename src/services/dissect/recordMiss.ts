/**
 * Why a revisit could not give a frame's tree back from its record (ADR 0049).
 *
 * Its own module, because a dissector can raise one too - a TLS conversation
 * whose keys the key log no longer agrees about - and a dissector is in the
 * renderer's eager chunk, where the recorder and its codec are not.
 */
export class RecordMiss extends Error {
  constructor(readonly reason: string) {
    super(`frame record: ${reason}`);
    this.name = 'RecordMiss';
  }
}
