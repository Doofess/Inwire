/**
 * Classic libpcap, a page at a time.
 *
 * **The header's link type is read from the frames, not assumed.** Classic
 * pcap has exactly one for the whole file, which is the format's own limit and
 * the reason the pcapng row says it keeps things this one cannot - but writing
 * `1` unconditionally meant a loopback capture exported a file that declared
 * Ethernet, so Wireshark reproduced this app's own misparse from the file
 * rather than from the wire. It is the **first** frame's, not the first
 * non-Ethernet one: `linkType` is absent on an Ethernet frame, so searching
 * for a defined one would let a single loopback frame at the end of an
 * Ethernet capture relabel the whole file. So the header waits for the first
 * frame, and is written with it.
 *
 * Nothing about the capture travels: the format has no place for a comment,
 * an adapter name or a drop count. That is the loss the export panel names.
 *
 * Frames are written in the order they are handed over. A caller that wants
 * the file in time order - every caller - orders the pages first
 * (`export/orderByTime.ts`), or sorts the array (`export/oneShot.generatePcapBinary`).
 */
import type { Packet } from '../../../types/packet';
import { LINKTYPE } from '../../dissect/types';
import type { ExportWriter } from './writer';

export const PCAP_MIME = 'application/vnd.tcpdump.pcap';

const GLOBAL_HEADER = 24;
const RECORD_HEADER = 16;

/**
 * Snaplen 65535, as this writer has always declared. A record longer than it -
 * a segmentation-offload frame the NIC had not split yet - is still written
 * whole; readers bound a record by their own maximum, not by this field.
 */
const SNAPLEN = 65535;

function globalHeader(linkType: number): Uint8Array {
  const out = new Uint8Array(GLOBAL_HEADER);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xa1b2c3d4, true); // magic: microseconds, little-endian
  view.setUint16(4, 2, true);           // version 2.4
  view.setUint16(6, 4, true);
  view.setInt32(8, 0, true);            // thiszone: UTC
  view.setUint32(12, 0, true);          // sigfigs
  view.setUint32(16, SNAPLEN, true);
  view.setUint32(20, linkType, true);
  return out;
}

export class PcapWriter implements ExportWriter {
  private headerWritten = false;

  write(page: readonly Packet[]): Uint8Array[] {
    if (page.length === 0) return [];
    const out: Uint8Array[] = [];
    if (!this.headerWritten) {
      out.push(globalHeader(page[0].linkType ?? LINKTYPE.ETHERNET));
      this.headerWritten = true;
    }

    // One buffer a page rather than one a frame: a page is a few thousand
    // frames, and a chunk per frame is a few thousand sink writes.
    let size = 0;
    for (const p of page) size += RECORD_HEADER + p.rawBytes.length;
    const records = new Uint8Array(size);
    const view = new DataView(records.buffer);
    let at = 0;
    for (const p of page) {
      const seconds = Math.floor(p.tsUs / 1_000_000);
      const capLen = p.rawBytes.length;
      view.setUint32(at, seconds, true);
      view.setUint32(at + 4, p.tsUs - seconds * 1_000_000, true);
      view.setUint32(at + 8, capLen, true);
      // The wire length, never less than what was captured: a record claiming
      // more captured bytes than the frame had is the one shape a reader
      // refuses.
      view.setUint32(at + 12, Math.max(p.length, capLen), true);
      records.set(p.rawBytes, at + RECORD_HEADER);
      at += RECORD_HEADER + capLen;
    }
    out.push(records);
    return out;
  }

  /** An empty capture is still a file: a header, declaring Ethernet. */
  finish(): Uint8Array[] {
    if (this.headerWritten) return [];
    this.headerWritten = true;
    return [globalHeader(LINKTYPE.ETHERNET)];
  }
}
