/**
 * Which end of a conversation is the client, and on what evidence.
 *
 * Moved here from `followStream.ts` so the capture store, which folds rows
 * with no `StreamTarget` in hand, decides it the same way the ladder does
 * (ADR 0055). The order of evidence, and why a guess is labelled as one, is
 * unchanged. See the doc comment on `ClientEndBasis`.
 */
import type { Packet } from '../../types/packet';
import { isWellKnownPort } from '../portServices';
import { fieldValue } from '../dissect/fieldAccess';

/**
 * How well the client end is known.
 *
 *  - `well-known-port` - one end is a port nothing dials out FROM. Close to
 *    conclusive, and it holds on a capture that started mid-connection.
 *  - `syn` - the first frame on the stream is a SYN, so its sender opened the
 *    connection and is the client by definition.
 *  - `first-speaker` - neither of the above. This is a **guess**: whoever
 *    happened to speak first in what was captured, which is the client only if
 *    the capture caught the start.
 *
 * The distinction is the point. Getting the ends backwards mislabels the whole
 * conversation and reverses its colours - the module's own comment calls it
 * "the kind of wrong that reads as a fact" - and the only defence against that
 * is for the guess to be labelled as one where it is shown.
 */
export type ClientEndBasis = 'well-known-port' | 'syn' | 'first-speaker';
export interface Endpoint { address: string; port: number }

export function chooseClient(
  a: Endpoint, b: Endpoint, first: Packet | undefined,
): { client: Endpoint; server: Endpoint; basis: ClientEndBasis } {
  const aWellKnown = isWellKnownPort(a.port);
  const bWellKnown = isWellKnownPort(b.port);
  if (aWellKnown !== bWellKnown) {
    return aWellKnown ? { client: b, server: a, basis: 'well-known-port' } : { client: a, server: b, basis: 'well-known-port' };
  }
  if (first?.sourcePort !== undefined) {
    const opens = fieldValue(first, 'tcp.flags.syn') === 1 && fieldValue(first, 'tcp.flags.ack') !== 1;
    const sender = { address: first.source, port: first.sourcePort };
    const other = sender.address === a.address && sender.port === a.port ? b : a;
    return { client: sender, server: other, basis: opens ? 'syn' : 'first-speaker' };
  }
  return { client: a, server: b, basis: 'first-speaker' };
}
