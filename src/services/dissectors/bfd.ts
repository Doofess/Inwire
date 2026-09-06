/**
 * BFD (RFC 5880), UDP 3784/3785/4784 - "is this link still up?"
 *
 *   Diag: No Diagnostic, State: Up, Flags: 0x00
 *
 * A fixed 24-byte header and no state, which makes it about the cheapest
 * useful thing an analyzer can read. It earns its place because of what it
 * says: BFD is what routing protocols use to notice a neighbour has gone
 * before their own timers would, so the **diagnostic code on the first packet
 * after an outage names the reason the session dropped** - a control-detection
 * timeout is a different fault from a neighbour that signalled its own
 * shutdown, and the two are indistinguishable from the routing protocol's
 * behaviour alone.
 *
 * **Port 3785 is not this.** 3784 and 4784 (multihop) carry the control packet
 * below; 3785 carries an *echo* packet, which has no format at all - see
 * `dissectBfdEcho`. Reading one with these rules would print a diagnostic and
 * a session state out of an opaque payload.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';

export interface BfdResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 5880 §4.1. */
const DIAGNOSTICS: Record<number, string> = {
  0: 'No Diagnostic',
  1: 'Control Detection Time Expired',
  2: 'Echo Function Failed',
  3: 'Neighbor Signaled Session Down',
  4: 'Forwarding Plane Reset',
  5: 'Path Down',
  6: 'Concatenated Path Down',
  7: 'Administratively Down',
  8: 'Reverse Concatenated Path Down',
};

const STATES: Record<number, string> = {
  0: 'AdminDown',
  1: 'Down',
  2: 'Init',
  3: 'Up',
};

/** The mandatory header's size; anything shorter is not a control packet. */
const HEADER_BYTES = 24;

/**
 * A BFD **Echo** packet, which is not a control packet and has no format.
 *
 * RFC 5880 §5 is explicit: an echo packet's contents are entirely up to the
 * sender, because only the sender ever reads one - it is transmitted to a
 * neighbour purely to be looped back, and it is the round trip that carries
 * the information. So there is nothing here to decode and the reference
 * analyzer decodes nothing, calling it "Originator specific content".
 *
 * Reading it with the control header's rules would print a diagnostic and a
 * session state out of somebody's opaque payload. The port is the only thing
 * that distinguishes the two, which is why this is a separate entry point.
 */
export function dissectBfdEcho(_bytes: Uint8Array, start: number, end: number): BfdResult | null {
  if (start >= end) return null;
  return {
    protocolLabel: 'BFD Echo',
    info: 'Originator specific content',
    fields: {},
    layer: {
      name: 'BFD Echo Message',
      summary: 'BFD Echo message',
      rawBytesRange: [start, end - 1],
      fields: [
        { name: 'Originator specific content', value: `${end - start} bytes`,
          rawBytesRange: [start, end - 1] },
      ],
    },
  };
}

/** Microseconds as RFC 5880 writes them in a tree: `1000 ms (1000000 us)`. */
function interval(us: number): string {
  return `${Math.round(us / 1000)} ms (${us} us)`;
}

export function dissectBfd(bytes: Uint8Array, start: number, end: number): BfdResult | null {
  if (start + HEADER_BYTES > end) return null;

  const version = bytes[start] >> 5;
  if (version !== 1) return null;
  const diagnostic = bytes[start] & 0x1f;
  const state = bytes[start + 1] >> 6;
  const flags = bytes[start + 1] & 0x3f;
  const detectMultiplier = bytes[start + 2];
  const length = bytes[start + 3];
  // The header declares its own size, which is the check that makes this safe
  // to read on a port somebody reassigned.
  if (length < HEADER_BYTES || start + length > end) return null;

  const u32 = (at: number) => ((bytes[at] << 24) | (bytes[at + 1] << 16)
    | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
  const myDiscriminator = u32(start + 4);
  const yourDiscriminator = u32(start + 8);
  const desiredMinTx = u32(start + 12);
  const requiredMinRx = u32(start + 16);
  const requiredMinEchoRx = u32(start + 20);

  const diagnosticName = DIAGNOSTICS[diagnostic] ?? `Unknown (${diagnostic})`;
  const stateName = STATES[state];

  const fields: Record<string, string | number> = {
    'bfd.version': version,
    'bfd.diag': diagnostic,
    'bfd.sta': state,
    'bfd.flags': flags,
    'bfd.detect_time_multiplier': detectMultiplier,
    'bfd.message_length': length,
    'bfd.my_discriminator': myDiscriminator,
    'bfd.your_discriminator': yourDiscriminator,
    'bfd.desired_min_tx_interval': desiredMinTx,
    'bfd.required_min_rx_interval': requiredMinRx,
    'bfd.required_min_echo_interval': requiredMinEchoRx,
  };

  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'bfd.version', rawBytesRange: [start, start] },
    { name: 'Diagnostic', value: `${diagnosticName} (0x${diagnostic.toString(16).padStart(2, '0')})`,
      abbrev: 'bfd.diag', rawBytesRange: [start, start] },
    { name: 'Session State', value: `${stateName} (${state})`, abbrev: 'bfd.sta',
      rawBytesRange: [start + 1, start + 1] },
    { name: 'Message Flags', value: `0x${flags.toString(16).padStart(2, '0')}`, abbrev: 'bfd.flags',
      rawBytesRange: [start + 1, start + 1],
      children: [
        { name: 'Poll', value: (flags & 0x20) !== 0 ? 'Set' : 'Not set' },
        { name: 'Final', value: (flags & 0x10) !== 0 ? 'Set' : 'Not set' },
        { name: 'Control Plane Independent', value: (flags & 0x08) !== 0 ? 'Set' : 'Not set' },
        { name: 'Authentication Present', value: (flags & 0x04) !== 0 ? 'Set' : 'Not set' },
        { name: 'Demand', value: (flags & 0x02) !== 0 ? 'Set' : 'Not set' },
        { name: 'Multipoint', value: (flags & 0x01) !== 0 ? 'Set' : 'Not set' },
      ] },
    { name: 'Detect Time Multiplier',
      value: `${detectMultiplier} (detection time: ${detectMultiplier} x ${interval(desiredMinTx)})`,
      abbrev: 'bfd.detect_time_multiplier', rawBytesRange: [start + 2, start + 2] },
    { name: 'Message Length', value: `${length} bytes`, abbrev: 'bfd.message_length',
      rawBytesRange: [start + 3, start + 3] },
    { name: 'My Discriminator', value: `0x${myDiscriminator.toString(16).padStart(8, '0')}`,
      abbrev: 'bfd.my_discriminator', rawBytesRange: [start + 4, start + 7] },
    { name: 'Your Discriminator', value: `0x${yourDiscriminator.toString(16).padStart(8, '0')}`,
      abbrev: 'bfd.your_discriminator', rawBytesRange: [start + 8, start + 11] },
    { name: 'Desired Min TX Interval', value: interval(desiredMinTx),
      abbrev: 'bfd.desired_min_tx_interval', rawBytesRange: [start + 12, start + 15] },
    { name: 'Required Min RX Interval', value: interval(requiredMinRx),
      abbrev: 'bfd.required_min_rx_interval', rawBytesRange: [start + 16, start + 19] },
    { name: 'Required Min Echo Interval', value: interval(requiredMinEchoRx),
      abbrev: 'bfd.required_min_echo_interval', rawBytesRange: [start + 20, start + 23] },
  ];

  return {
    protocolLabel: 'BFD Control',
    // Wireshark's Info names the diagnostic first, before the state, because
    // the diagnostic is what changes when something breaks.
    info: `Diag: ${diagnosticName}, State: ${stateName}, Flags: 0x${flags.toString(16).padStart(2, '0')}`,
    fields,
    layer: {
      name: 'BFD Control Message',
      summary: `BFD Control message`,
      rawBytesRange: [start, start + length - 1],
      fields: rows,
    },
  };
}
