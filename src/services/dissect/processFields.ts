/**
 * Publishing the owning process as fields on a frame.
 *
 * Split from the store in `services/flowAnnotations.ts` on purpose. The store
 * is mutable state about sockets over time; this is the pure step that turns
 * one answer from it into `Packet.fields`, and it lives here because a field a
 * filter and a column can see has to be written where the registry's assertion
 * script can find its writer.
 *
 * The fields sit on the **frame** layer, not on `tcp` or `udp`. They describe
 * the capture rather than the packet - the same category as the interface a
 * frame arrived on - and a process is not a protocol layer, so giving it a
 * token of its own would put it in the protocol hierarchy as a child of
 * whatever it happened to follow.
 */
import type { Packet, ProtocolLayer } from '../../types/packet';
import type { FlowAnnotationStore, ProcessInfo } from '../flowAnnotations';
import { fieldValue } from './fieldAccess';

/** Written only when there is something to write - see `flowAnnotations`. */
export function writeProcessFields(packet: Packet, process: ProcessInfo | null): void {
  if (!process) return;
  if (!packet.fields) packet.fields = {};
  packet.fields['inwire.process.name'] = process.name;
  packet.fields['inwire.process.pid'] = process.pid;
  // Absent rather than empty when the OS named the process but refused its
  // path, which services do routinely. An empty string in a column reads as a
  // path that is blank; no key at all reads as a field this frame does not
  // carry, which is what it is.
  if (process.exe) packet.fields['inwire.process.path'] = process.exe;
}

/**
 * The process behind a frame, or null.
 *
 * One implementation, used by both paths that need it: the Worker as frames
 * are dissected, and the retro-patch when a socket table arrives describing
 * frames already in the buffer. Two copies of this rule would be two chances
 * to disagree about which end of a frame is the local one.
 */
export function processForPacket(packet: Packet, store: FlowAnnotationStore): ProcessInfo | null {
  if (store.isEmpty) return null;
  const layers = packet.frameProtocols;
  // `frameProtocols` and not `protocol`: `protocol` defaults to TCP for any
  // frame that never reached a transport decoder, which would send ARP and
  // broadcast Ethernet looking for a TCP socket.
  const proto = layers?.includes('tcp') ? 'tcp' : layers?.includes('udp') ? 'udp' : null;
  if (!proto) return null;
  if (packet.sourcePort === undefined || packet.destPort === undefined) return null;
  return store.forEndpoints(
    proto, packet.source, packet.sourcePort, packet.destination, packet.destPort, packet.tsUs,
  );
}

/**
 * Adds the process to the Frame layer of a dissected tree.
 *
 * On **Frame** because that layer is where this analyzer already puts what it
 * knows about the capture rather than about the bytes - the interface, the
 * clocks, the frame number. A process belongs with those.
 *
 * `generated: true` and `abbrev` set, both load-bearing: generated is what
 * renders it in brackets and suppresses the byte-range highlight, since there
 * are no bytes to highlight - this is the one field in the tree that no part of
 * the frame contains. The abbrev is what stops the row being display-only, so
 * its "Apply as Filter" and "Apply as Column" items work like any other row's.
 */
export function addProcessRow(layers: ProtocolLayer[], process: ProcessInfo | null): void {
  if (!process) return;
  const frame = layers.find((layer) => layer.name === 'Frame');
  if (!frame) return;
  frame.fields.push({
    name: 'Process',
    value: `${process.name} (pid ${process.pid})`,
    generated: true,
    abbrev: 'inwire.process.name',
    children: [
      { name: 'Process ID', value: process.pid, generated: true, abbrev: 'inwire.process.pid' },
      ...(process.exe
        ? [{ name: 'Process path', value: process.exe, generated: true, abbrev: 'inwire.process.path' }]
        : []),
    ],
  });
}

/**
 * The program to show beside the Source column, or null.
 *
 * **Only for frames that LEFT this machine.** Attribution is a property of the
 * local socket, so both directions of a flow carry it - the reply from a server
 * is attributed to the local process that asked for it, which is correct and is
 * exactly what makes this check necessary. Without it every inbound packet
 * would render as `93.184.216.34\chrome.exe`, claiming a web server somewhere
 * is running the browser.
 *
 * Null, not an empty string, when there is nothing to say: the caller renders
 * the address alone rather than an address with a trailing separator.
 */
export function sendingProcessName(packet: Packet, store: FlowAnnotationStore): string | null {
  const name = fieldValue(packet, 'inwire.process.name');
  if (typeof name !== 'string' || !name) return null;
  if (!store.isLocalAddress(packet.source)) return null;
  return name;
}

/** Looks the process up and publishes it, for callers that want both. */
export function annotatePacket(packet: Packet, store: FlowAnnotationStore): boolean {
  const process = processForPacket(packet, store);
  if (!process) return false;
  writeProcessFields(packet, process);
  // Before the caller caches or discards the tree, so the detail pane shows the
  // same thing the column does.
  addProcessRow(packet.layers, process);
  return true;
}
