import { X } from 'lucide-react';
import { isV5Record, type DetailResult } from '../../services/monitoring/client';
import type { NormalizedFlow } from '../../services/monitoring/flowDecode';
import type { NormalizedV5 } from '../../services/monitoring/types';
import { formatBytes } from '../../lib/formatBytes';
import { count, PROTOCOLS } from './monitoringCopy';

const at = (ms: number) => new Date(ms).toLocaleString(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
});

/**
 * One supporting reference opened: the datagram as it arrived (when, from
 * whom, how big), the header it carried, and the one record of it that the
 * selection matched, decoded. Everything here is what the exporter reported;
 * nothing is measured.
 */
export function DatagramDetail({ detail, onClose }: { detail: DetailResult; onClose: () => void }) {
  const { evidence, record } = detail;
  const header = isV5Record(record) ? readHeader(evidence.bytes) : readTemplatedHeader(evidence.bytes);
  return (
    <section aria-label="Datagram detail" className="rounded-md border border-border bg-card">
      <div className="flex items-center justify-between gap-3 border-b border-border px-3.5 py-2">
        <h3 className="text-xs font-semibold text-foreground">
          Datagram {count(evidence.ref.entryId)}, record {record.recordIndex + 1}
          {header !== null && header.count !== null && ` of ${header.count}`}
        </h3>
        <button type="button" onClick={onClose} aria-label="Close the datagram detail"
          className="rounded-sm p-1 text-muted-foreground hover:bg-accent hover:text-foreground cursor-pointer
            focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <X className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>
      <div className="grid gap-x-6 gap-y-3 px-3.5 py-3 @2xl:grid-cols-2 @4xl:grid-cols-3">
        <Group title="Received">
          <Item label="At">{at(evidence.receivedMs)}</Item>
          <Item label="From"><span className="font-mono">{evidence.remoteIPv4}:{evidence.remotePort}</span></Item>
          <Item label="To"><span className="font-mono">{evidence.localIPv4}:{evidence.localPort}</span></Item>
          <Item label="Size">{formatBytes(evidence.bytes.byteLength)} ({count(evidence.bytes.byteLength)} B)</Item>
        </Group>
        {isV5Record(record) ? <V5Header record={record} bytes={evidence.bytes} /> : <TemplatedHeader record={record} bytes={evidence.bytes} />}
        {isV5Record(record) ? <V5Record record={record} /> : <FlowRecord record={record} />}
      </div>
      <p className="border-t border-border px-3.5 py-2 text-[11px] text-muted-foreground">
        Counters as reported by the exporter, not measured here.
      </p>
    </section>
  );
}

function V5Header({ record, bytes }: { record: NormalizedV5; bytes: Uint8Array }) {
  const header = readHeader(bytes);
  return (
    <Group title="v5 header">
      {header ? (
        <>
          <Item label="Records">{header.count}</Item>
          <Item label="Sequence">{count(header.sequence)}</Item>
          <Item label="Engine">{header.engineType}/{header.engineId}</Item>
          <Item label="Exporter time">{at(header.exportMs)}</Item>
          <Item label="Uptime">{uptime(header.sysUptimeMs)}</Item>
          <Item label="Sampling">
            {record.sampling.kind === 'unknown'
              ? 'not reported'
              : `mode ${record.sampling.mode}, 1 in ${record.sampling.interval || '?'}`}
          </Item>
        </>
      ) : <p className="text-xs text-muted-foreground">The header could not be read.</p>}
    </Group>
  );
}

function V5Record({ record }: { record: NormalizedV5 }) {
  return (
    <Group title="Record">
      <Item label="Source"><span className="font-mono">{record.srcAddr}:{record.srcPort}</span></Item>
      <Item label="Destination"><span className="font-mono">{record.dstAddr}:{record.dstPort}</span></Item>
      <Item label="Protocol">{PROTOCOLS[record.protocol] ?? `IP protocol ${record.protocol}`}</Item>
      <Item label="Bytes">{formatBytes(Number(record.reportedOctets))} ({count(record.reportedOctets)})</Item>
      <Item label="Packets">{count(record.reportedPackets)}</Item>
      <Item label="Interfaces">in {record.inputIf}, out {record.outputIf}</Item>
      <Item label="Flow">{at(record.startMs)} to {new Date(record.endMs).toLocaleTimeString()}</Item>
    </Group>
  );
}

function TemplatedHeader({ record, bytes }: { record: NormalizedFlow; bytes: Uint8Array }) {
  const header = readTemplatedHeader(bytes);
  return (
    <Group title={header === null ? 'Header' : header.version === 9 ? 'v9 header' : 'IPFIX header'}>
      {header ? (
        <>
          {header.count !== null && <Item label="Records">{header.count}</Item>}
          <Item label="Sequence">{count(header.sequence)}</Item>
          <Item label={header.version === 9 ? 'Source ID' : 'Domain'}>{count(header.domain)}</Item>
          <Item label="Exporter time">{at(header.exportMs)}</Item>
          {header.sysUptimeMs !== null && <Item label="Uptime">{uptime(header.sysUptimeMs)}</Item>}
          <Item label="Sampling">{record.samplingInterval === null ? 'not in the record' : `1 in ${record.samplingInterval}`}</Item>
        </>
      ) : <p className="text-xs text-muted-foreground">The header could not be read.</p>}
    </Group>
  );
}

function FlowRecord({ record }: { record: NormalizedFlow }) {
  const port = (p: number | null) => (p === null ? '' : `:${p}`);
  const known = (n: number | null) => (n === null ? 'not reported' : String(n));
  return (
    <Group title="Record">
      <Item label="Source"><span className="font-mono">{record.srcAddr}{port(record.srcPort)}</span></Item>
      <Item label="Destination"><span className="font-mono">{record.dstAddr}{port(record.dstPort)}</span></Item>
      <Item label="Protocol">
        {record.protocol === null ? 'not reported' : PROTOCOLS[record.protocol] ?? `IP protocol ${record.protocol}`}
      </Item>
      <Item label="Bytes">{formatBytes(Number(record.reportedOctets))} ({count(record.reportedOctets)})</Item>
      <Item label="Packets">{count(record.reportedPackets)}</Item>
      {record.reverseOctets !== null && (
        <Item label="Reverse">
          {formatBytes(Number(record.reverseOctets))} ({count(record.reverseOctets)}), {count(record.reversePackets ?? 0n)} packets
        </Item>
      )}
      <Item label="Interfaces">in {known(record.inputIf)}, out {known(record.outputIf)}</Item>
      <Item label="Flow">
        {record.startMs === null || record.endMs === null
          ? 'times not reported'
          : <>{at(record.startMs)} to {new Date(record.endMs).toLocaleTimeString()}</>}
      </Item>
    </Group>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <h4 className="mb-1.5 text-[11px] font-semibold text-muted-foreground">{title}</h4>
      <dl className="space-y-1">{children}</dl>
    </div>
  );
}

function Item({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-2 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words tabular-nums text-foreground">{children}</dd>
    </div>
  );
}

function uptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d > 0 ? `${d} d ${h} h` : h > 0 ? `${h} h ${m} min` : `${m} min ${s % 60} s`;
}

/** The v9 (20-byte) or IPFIX (16-byte) message header, read for display; the decoder already validated it. IPFIX has no record count. */
function readTemplatedHeader(bytes: Uint8Array): {
  version: 9 | 10; count: number | null; sysUptimeMs: number | null; exportMs: number; sequence: number; domain: number;
} | null {
  if (bytes.byteLength < 16) return null;
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = v.getUint16(0);
  if (version === 9 && bytes.byteLength >= 20) {
    return { version, count: v.getUint16(2), sysUptimeMs: v.getUint32(4), exportMs: v.getUint32(8) * 1000, sequence: v.getUint32(12), domain: v.getUint32(16) };
  }
  if (version === 10) return { version, count: null, sysUptimeMs: null, exportMs: v.getUint32(4) * 1000, sequence: v.getUint32(8), domain: v.getUint32(12) };
  return null;
}

/** The 24-byte v5 header, read for display; the decoder already validated it. */
function readHeader(bytes: Uint8Array): {
  count: number; sysUptimeMs: number; exportMs: number; sequence: number; engineType: number; engineId: number;
} | null {
  if (bytes.byteLength < 24) return null;
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (v.getUint16(0) !== 5) return null;
  return {
    count: v.getUint16(2),
    sysUptimeMs: v.getUint32(4),
    exportMs: v.getUint32(8) * 1000 + Math.floor(v.getUint32(12) / 1e6),
    sequence: v.getUint32(16),
    engineType: v.getUint8(20),
    engineId: v.getUint8(21),
  };
}
