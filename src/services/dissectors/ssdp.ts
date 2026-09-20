/**
 * SSDP: HTTP/1.1 syntax on UDP/1900, and the reference files it under HTTP's
 * own field names.
 *
 * This build labelled the Protocol column `SSDP`, put the request line in the
 * Info column, and stopped - **no layer, and not one field.** The measurement
 * is blunt: `ssdp 0/13` on inwire and `0/7` on bulk, and since neither fixture
 * holds a single frame of real HTTP, those 20 names were the entire HTTP
 * vocabulary either capture contains.
 *
 * Everything below the start line is `httpFields.ts`, which is shared with the
 * TCP-side HTTP dissector rather than copied - the reference reuses its HTTP
 * dissector here for the same reason, and `tree-coverage.ts`'s `REATTRIBUTE`
 * rule records the consequence from the other end.
 *
 * **NOTIFY is marked as an announcement rather than a request.** It is a
 * request by syntax - a method, a target, a version - and answers nobody:
 * `ssdp:alive` says a device has appeared and `ssdp:byebye` that it has gone.
 * The reference gives it `http.notification` instead of `http.request` for
 * exactly that, so a filter can ask for the announcements without also
 * catching every M-SEARCH on the segment.
 */
import type { ProtocolLayer } from '../../types/packet';
import { dissectHttp1, freshHttp1Direction } from './http1';
import { httpMessageFields, httpMessageRows } from './httpFields';

export interface SsdpResult {
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * Reads one SSDP datagram, or null when the payload is not an HTTP message.
 *
 * A fresh direction every time, and that is the difference from the TCP side:
 * a datagram is a whole message by definition, so there is no pending prefix,
 * no body to walk past and no next message to find. `dissectHttp1` is handed
 * the payload and hands back what it read.
 */
export function dissectSsdp(rawBytes: Uint8Array, start: number, end: number): SsdpResult | null {
  if (start >= end) return null;
  const { messages } = dissectHttp1(rawBytes.subarray(start, end), freshHttp1Direction());
  const message = messages[0];
  if (message === undefined) return null;

  const notification = message.kind === 'request' && message.method === 'NOTIFY';
  // The reference's HTTP-style dissectors put a trailing space after the start
  // line; kept, because the Info column's text is what the parity harness
  // compares and it compared equal before this layer existed.
  const info = `${message.summary} `;
  return {
    info,
    fields: httpMessageFields(message, { notification }),
    layer: {
      name: 'Simple Service Discovery Protocol',
      summary: 'Simple Service Discovery Protocol',
      rawBytesRange: [start, end - 1],
      fields: httpMessageRows(message, { notification, datagram: true }),
    },
  };
}
