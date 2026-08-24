# Wireshark Parity Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring NetView's packet dissection closer to real Wireshark by adding TCP relative sequence/ack numbers with conversation-completeness tracking, richer Frame/Ethernet/IP metadata (MAC vendor resolution, DSCP/ECN, IP flags/fragmentation, header-checksum verification, frame timing/protocol summary), ICMP echo request/reply correlation across packets, and TCP Keep-Alive detection plus MSS/Window-Scale/SACK option parsing.

**Architecture:** All new dissection logic lives in `src/services/pcapParser.ts` (the single place that decodes raw Ethernet frames for both pcap-import and live-capture paths) plus two new small stateful tracker classes (`TcpStreamTracker`, extended; `IcmpEchoTracker`, new) that carry cross-packet state through a single-pass decode, exactly like the existing retransmission-detection tracker already does. A new `macVendors.ts` module supplies a pure lookup function. `PacketDetailsTree.tsx` gains recursive rendering of `ProtocolField.children` so the new nested fields are actually visible, since it currently only renders one flat level despite the type already supporting nesting.

**Tech Stack:** TypeScript, React 19, Vite. No test runner is configured in this repo (no jest/vitest/RTL) — verification uses one-off `npx tsx` scripts created at the repo root and deleted immediately after confirming output, per this project's established convention, plus `npm run lint` (`tsc --noEmit`) for type-checking, plus manual browser smoke-testing for the one React-component task and the one live-capture wiring task where no other verification is possible.

**Spec:** `docs/superpowers/specs/2026-08-24-wireshark-parity-design.md`

## Global Constraints

- No test runner is configured (no jest/vitest) — use throwaway `npx tsx __scratch_test_taskN.ts` scripts at the repo root, deleted immediately after the assertions pass, per established project convention. Never commit these files.
- `npm run lint` (`tsc --noEmit`) must stay clean after every task.
- Never use naive bitwise ops for TCP sequence-number math — use unsigned modular arithmetic: `(a - b + 2**32) % 2**32`.
- TLS (TCP:443) and QUIC (UDP:443) must never be scanned for plaintext — this constraint is already satisfied by existing code and must not regress.
- No comments explaining *what* code does — only *why*, and only where non-obvious (matches existing file style in `pcapParser.ts`).
- Follow existing code style: no semicolon-free style, existing quote/format conventions, `>>> 0` for unsigned 32-bit reinterpretation.
- **Out of scope (per spec, do not implement here):** TLS handshake parsing, DNS answer parsing, TCP reassembly, `[Frame is marked]`/`[Frame is ignored]`, Coloring Rule Name/String in the Frame layer, "Time shift for this packet", `[Time delta from previous displayed frame]` (only "previous captured frame" and "since first frame" are implemented, using existing `timeDelta`/`relativeTime` params).

---

## Task 1: Fix TCP header-length bug + parse TCP options

The current code hardcodes the TCP header as exactly 20 bytes everywhere (`Len=` calculation, hostname-scan payload offset), ignoring the real Data Offset field. This is a genuine correctness bug: any TCP segment carrying real options (which is most real-world TCP traffic, since MSS/SACK_PERM/WS appear on virtually every SYN) currently reports a wrong `Len=` and scans the wrong bytes for a hostname. This must be fixed before Keep-Alive detection (Task 5) can be correct, since Keep-Alive detection depends on an accurate payload length.

**Files:**
- Modify: `src/services/pcapParser.ts:408-596` (`decodeTransportLayer`, TCP branch)
- Test: temporary `__scratch_test_task1.ts` at repo root (created and deleted within this task — do not commit)

**Interfaces:**
- Produces: TCP branch now computes `tcpHeaderLen` from the real Data Offset nibble instead of a hardcoded `20`; adds an unexported `parseTcpOptions(rawBytes: Uint8Array, optionsStart: number, optionsEnd: number): { fields: ProtocolField[]; mss?: number; windowScale?: number; sackPermitted: boolean; sackBlocks: { leftEdge: number; rightEdge: number }[] }` used by this task and by Task 5.

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task1.ts` at the repo root:

```ts
import { decodeRawEthernetPacket } from './src/services/pcapParser';

function buildFrame(tcpOptionsHex: string, payloadLen: number): Uint8Array {
  const optionBytes = tcpOptionsHex.length > 0
    ? Uint8Array.from(Buffer.from(tcpOptionsHex, 'hex'))
    : new Uint8Array(0);
  const paddedOptionsLen = Math.ceil(optionBytes.length / 4) * 4;
  const dataOffsetWords = 5 + paddedOptionsLen / 4; // 5 words = 20-byte fixed header
  const tcpHeaderLen = dataOffsetWords * 4;

  const eth = new Uint8Array(14); // dst(6) + src(6) + ethertype(2)
  eth.set([0x08, 0x00], 12); // IPv4

  const ipHeaderLen = 20;
  const ip = new Uint8Array(ipHeaderLen);
  ip[0] = 0x45; // version 4, header len 5 words
  const totalLen = ipHeaderLen + tcpHeaderLen + payloadLen;
  ip[2] = (totalLen >> 8) & 0xff; ip[3] = totalLen & 0xff;
  ip[8] = 64; // TTL
  ip[9] = 6; // TCP
  ip.set([10, 0, 0, 1], 12);
  ip.set([10, 0, 0, 2], 16);

  const tcp = new Uint8Array(tcpHeaderLen + optionBytes.length - optionBytes.length); // base alloc, options appended below
  const tcpFull = new Uint8Array(tcpHeaderLen);
  tcpFull[0] = 0; tcpFull[1] = 80; // src port 80
  tcpFull[2] = 0; tcpFull[3] = 443; // dst port 443... but 443 forces TLS proto, use 8080 instead
  tcpFull[2] = 0x1f; tcpFull[3] = 0x90; // dst port 8080
  tcpFull[12] = (dataOffsetWords << 4) & 0xf0; // data offset, no flags
  tcpFull[13] = 0x02; // SYN
  tcpFull.set(optionBytes, 20);

  const payload = new Uint8Array(payloadLen).fill(0x41);

  const frame = new Uint8Array(eth.length + ip.length + tcpFull.length + payload.length);
  frame.set(eth, 0);
  frame.set(ip, eth.length);
  frame.set(tcpFull, eth.length + ip.length);
  frame.set(payload, eth.length + ip.length + tcpFull.length);
  return frame;
}

// SYN with MSS(4) + SACK_PERM(2) + NOP(1) + WS(3) = 10 bytes options, padded to 12
const frame = buildFrame('020405b4' + '0204' /*wrong, fix below*/, 0);
```

Rather than hand-rolling the padded options above (error-prone), replace the last two lines with a concrete, correct 12-byte options block: `020405b4` (MSS=1460) + `0402` (SACK_PERM... note kind/length order is `04 02`) + `030308` (WindowScale, shift=8) + `01` (NOP pad to 4-byte boundary):

```ts
const optionsHex = '020405b4' + '0402' + '030308' + '01'; // MSS=1460, SACK_PERM, WS=8, NOP pad
const frame = buildFrame(optionsHex, 5);
const packet = decodeRawEthernetPacket(frame, 1, Date.now(), 0, 0, frame.length);

const tcpLayer = packet.layers.find(l => l.name === 'Transmission Control Protocol')!;
console.log('Info:', packet.info);
console.log('Header Length field:', tcpLayer.fields.find(f => f.name === 'Header Length')?.value);

if (!packet.info.includes('Len=5')) throw new Error(`Expected Len=5 (payload past real 32-byte header), got: ${packet.info}`);
if (tcpLayer.fields.find(f => f.name === 'Header Length')?.value !== '32 bytes') {
  throw new Error(`Expected Header Length "32 bytes", got: ${tcpLayer.fields.find(f => f.name === 'Header Length')?.value}`);
}
const mssField = tcpLayer.fields.find(f => f.name === 'TCP Option - Maximum Segment Size');
if (!mssField || !String(mssField.value).includes('1460')) throw new Error('Expected MSS option field with value 1460');
const sackPermField = tcpLayer.fields.find(f => f.name === 'TCP Option - SACK Permitted');
if (!sackPermField) throw new Error('Expected SACK Permitted option field');
const wsField = tcpLayer.fields.find(f => f.name === 'TCP Option - Window Scale');
if (!wsField) throw new Error('Expected Window Scale option field');

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task1.ts`
Expected: FAIL — `Len=5` assertion fails because the current code always uses `rawBytes.length - transportOffset - 20`, which yields `Len=17` (5 real payload bytes + 12 bytes of options misread as payload), and there is no `TCP Option - *` field at all.

- [ ] **Step 3: Write minimal implementation**

In `src/services/pcapParser.ts`, add the options parser near the other standalone helper functions (right before `formatHexDump`, i.e. just after the closing brace of `decodeTransportLayer`):

```ts
/**
 * Parses the variable-length TCP options region (RFC 9293 3.1) starting at
 * the first byte past the fixed 20-byte header, up to (not including)
 * `optionsEnd` (the start of the real payload, derived from the Data Offset
 * field). Stops early on End-of-Option-List or anything malformed, rather
 * than guessing - a truncated/corrupt options list is common in captured
 * traffic and should degrade gracefully, not throw.
 */
function parseTcpOptions(
  rawBytes: Uint8Array,
  optionsStart: number,
  optionsEnd: number
): {
  fields: ProtocolField[];
  mss?: number;
  windowScale?: number;
  sackPermitted: boolean;
  sackBlocks: { leftEdge: number; rightEdge: number }[];
} {
  const fields: ProtocolField[] = [];
  let mss: number | undefined;
  let windowScale: number | undefined;
  let sackPermitted = false;
  const sackBlocks: { leftEdge: number; rightEdge: number }[] = [];

  let offset = optionsStart;
  while (offset < optionsEnd && offset < rawBytes.length) {
    const kind = rawBytes[offset];
    if (kind === 0) break; // End of Option List
    if (kind === 1) {
      fields.push({ name: 'TCP Option - No-Operation (NOP)', value: 'NOP', rawBytesRange: [offset, offset] });
      offset += 1;
      continue;
    }

    if (offset + 1 >= optionsEnd) break; // no room for a length byte
    const length = rawBytes[offset + 1];
    if (length < 2 || offset + length > optionsEnd) break; // malformed - stop rather than misread

    if (kind === 2 && length === 4) {
      mss = (rawBytes[offset + 2] << 8) | rawBytes[offset + 3];
      fields.push({ name: 'TCP Option - Maximum Segment Size', value: `MSS: ${mss}`, rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 3 && length === 3) {
      windowScale = rawBytes[offset + 2];
      fields.push({ name: 'TCP Option - Window Scale', value: `${windowScale} (multiply by ${2 ** windowScale})`, rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 4 && length === 2) {
      sackPermitted = true;
      fields.push({ name: 'TCP Option - SACK Permitted', value: 'True', rawBytesRange: [offset, offset + length - 1] });
    } else if (kind === 5) {
      const blockCount = Math.floor((length - 2) / 8);
      for (let i = 0; i < blockCount; i++) {
        const blockOffset = offset + 2 + i * 8;
        const leftEdge = ((rawBytes[blockOffset] << 24) | (rawBytes[blockOffset + 1] << 16) | (rawBytes[blockOffset + 2] << 8) | rawBytes[blockOffset + 3]) >>> 0;
        const rightEdge = ((rawBytes[blockOffset + 4] << 24) | (rawBytes[blockOffset + 5] << 16) | (rawBytes[blockOffset + 6] << 8) | rawBytes[blockOffset + 7]) >>> 0;
        sackBlocks.push({ leftEdge, rightEdge });
        fields.push({ name: `TCP Option - SACK Block ${i + 1}`, value: `${leftEdge}-${rightEdge}`, rawBytesRange: [blockOffset, blockOffset + 7] });
      }
    } else if (kind === 8 && length === 10) {
      const tsval = ((rawBytes[offset + 2] << 24) | (rawBytes[offset + 3] << 16) | (rawBytes[offset + 4] << 8) | rawBytes[offset + 5]) >>> 0;
      const tsecr = ((rawBytes[offset + 6] << 24) | (rawBytes[offset + 7] << 16) | (rawBytes[offset + 8] << 8) | rawBytes[offset + 9]) >>> 0;
      fields.push({ name: 'TCP Option - Timestamps', value: `TSval ${tsval}, TSecr ${tsecr}`, rawBytesRange: [offset, offset + length - 1] });
    } else {
      fields.push({ name: `TCP Option - Unknown (Kind ${kind})`, value: `${length} bytes`, rawBytesRange: [offset, offset + length - 1] });
    }

    offset += length;
  }

  return { fields, mss, windowScale, sackPermitted, sackBlocks };
}
```

Now replace the entire TCP branch of `decodeTransportLayer` (the `if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) { ... }` block) with:

```ts
  if (ipProtocolNum === 6 && rawBytes.length >= transportOffset + 20) {
    const srcPort = (rawBytes[transportOffset] << 8) | rawBytes[transportOffset + 1];
    const dstPort = (rawBytes[transportOffset + 2] << 8) | rawBytes[transportOffset + 3];
    const seqNum = ((rawBytes[transportOffset + 4] << 24) | (rawBytes[transportOffset + 5] << 16) | (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7]) >>> 0;
    const ackNum = ((rawBytes[transportOffset + 8] << 24) | (rawBytes[transportOffset + 9] << 16) | (rawBytes[transportOffset + 10] << 8) | rawBytes[transportOffset + 11]) >>> 0;
    // Data Offset is the top 4 bits of this byte, in 32-bit words - hardcoding
    // 20 bytes here (as this file previously did everywhere) silently
    // misreads Len= and the payload-scan offset whenever real options are
    // present, which is most real-world TCP traffic.
    const dataOffsetWords = (rawBytes[transportOffset + 12] >> 4) & 0x0f;
    const tcpHeaderLen = Math.max(20, dataOffsetWords * 4);
    const flags = rawBytes[transportOffset + 13];
    const syn = (flags & 0x02) !== 0;
    const ack = (flags & 0x10) !== 0;
    const fin = (flags & 0x01) !== 0;
    const rst = (flags & 0x04) !== 0;
    const psh = (flags & 0x08) !== 0;

    const flagList: string[] = [];
    if (syn) flagList.push('SYN');
    if (ack) flagList.push('ACK');
    if (fin) flagList.push('FIN');
    if (rst) flagList.push('RST');
    if (psh) flagList.push('PSH');

    let proto: Packet['protocol'] = 'TCP';
    if (srcPort === 443 || dstPort === 443) proto = 'TLS';
    else if (srcPort === 80 || dstPort === 80) proto = 'HTTP';
    else if (srcPort === 22 || dstPort === 22) proto = 'SSH';

    const tcpOptions = tcpHeaderLen > 20 ? parseTcpOptions(rawBytes, transportOffset + 20, transportOffset + tcpHeaderLen) : null;
    const optionsSummaryParts: string[] = [];
    if (tcpOptions) {
      if (syn) {
        if (tcpOptions.mss !== undefined) optionsSummaryParts.push(`MSS=${tcpOptions.mss}`);
        if (tcpOptions.windowScale !== undefined) optionsSummaryParts.push(`WS=${2 ** tcpOptions.windowScale}`);
        if (tcpOptions.sackPermitted) optionsSummaryParts.push('SACK_PERM');
      } else {
        for (const block of tcpOptions.sackBlocks) {
          optionsSummaryParts.push(`SLE=${block.leftEdge} SRE=${block.rightEdge}`);
        }
      }
    }
    const optionsSummary = optionsSummaryParts.length > 0 ? ' ' + optionsSummaryParts.join(' ') : '';

    const tcpPayloadStart = transportOffset + tcpHeaderLen;
    const payloadLength = Math.max(0, rawBytes.length - tcpPayloadStart);
    // TLS payloads are encrypted from essentially the first byte - never
    // scan them, since any "match" there would be a false positive.
    const tcpHost =
      proto !== 'TLS' && tcpPayloadStart < rawBytes.length
        ? extractLiteralUrlOrHost(rawBytes, tcpPayloadStart)
        : null;
    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${seqNum} Ack=${ackNum} Len=${payloadLength}${optionsSummary}${tcpHost ? ' ' + tcpHost : ''}`;

    let streamId: number | undefined;
    let status: Packet['status'] | undefined;
    let anomalies: AnomalyInfo[] | undefined;
    if (tcpTracker) {
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      const seqResult = tcpTracker.checkSequence(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength);
      if (seqResult === 'retransmit') {
        status = 'retransmit';
        anomalies = [{
          type: 'tcp-retransmission',
          severity: 'low',
          title: 'TCP Retransmission',
          description: `Segment with sequence number ${seqNum} was already seen on stream #${streamId} - likely a retransmission after packet loss or a duplicate ACK race.`,
          recommendation: 'Check for network congestion, packet loss, or an unusually high round-trip time on this path.',
        }];
      } else if (seqResult === 'out-of-order') {
        status = 'warning';
        anomalies = [{
          type: 'tcp-out-of-order',
          severity: 'low',
          title: 'TCP Out-of-Order Segment',
          description: `Segment with sequence number ${seqNum} arrived out of order relative to previously seen data on stream #${streamId}.`,
          recommendation: 'Usually harmless (multi-path routing or reordering in transit) - investigate further only if paired with retransmissions or application-level errors.',
        }];
      }
    }

    return {
      proto,
      srcPort,
      dstPort,
      info,
      streamId,
      status,
      anomalies,
      layer: {
        name: 'Transmission Control Protocol',
        summary: `Transmission Control Protocol, Src Port: ${srcPort}, Dst Port: ${dstPort}`,
        rawBytesRange: [transportOffset, transportOffset + tcpHeaderLen - 1],
        fields: [
          { name: 'Source Port', value: srcPort, rawBytesRange: [transportOffset, transportOffset + 1] },
          { name: 'Destination Port', value: dstPort, rawBytesRange: [transportOffset + 2, transportOffset + 3] },
          { name: 'Sequence Number', value: seqNum, rawBytesRange: [transportOffset + 4, transportOffset + 7] },
          { name: 'Acknowledgment Number', value: ackNum, rawBytesRange: [transportOffset + 8, transportOffset + 11] },
          { name: 'Header Length', value: `${tcpHeaderLen} bytes`, rawBytesRange: [transportOffset + 12, transportOffset + 12] },
          { name: 'Flags', value: `0x${flags.toString(16).padStart(3, '0')} (${flagList.join(', ')})`, rawBytesRange: [transportOffset + 12, transportOffset + 13] },
          ...(tcpOptions ? tcpOptions.fields : []),
        ],
      },
    };
  } else if (ipProtocolNum === 17 && rawBytes.length >= transportOffset + 8) {
```

Leave the rest of the function (UDP and ICMP branches) unchanged for this task.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task1.ts`
Expected: PASS (prints `Info: ... Len=5 MSS=1460 WS=256 SACK_PERM` and `Header Length field: 32 bytes`, then `PASS`).

- [ ] **Step 5: Run full type-check and clean up**

Run: `npm run lint`
Expected: no errors.

Delete the scratch file: `rm __scratch_test_task1.ts` (or `Remove-Item __scratch_test_task1.ts` in PowerShell).

- [ ] **Step 6: Commit**

```bash
git add src/services/pcapParser.ts
git commit -m "Fix TCP header-length bug and parse TCP options (MSS/WS/SACK)"
```

---

## Task 2: Recursive nested-field rendering in PacketDetailsTree

`ProtocolField` already has an optional `children?: ProtocolField[]` in its type, but `PacketDetailsTree.tsx` only ever reads `layer.fields` one level deep — it never looks at `field.children`. Every subsequent task in this plan (relative seq/ack raw sub-field, DSCP/ECN, IP Flags bit breakdown) adds nested fields that would otherwise be silently invisible in the UI. This task has no user-visible effect on its own (no field in the codebase has `children` yet) — it only becomes observable once Task 3 adds real nested data. Verification here is limited to a clean type-check; the actual visual confirmation happens in Task 3's manual step.

**Files:**
- Modify: `src/components/packet-details/PacketDetailsTree.tsx:1-2, 162-216`

**Interfaces:**
- Consumes: `ProtocolField.children?: ProtocolField[]` (already defined in `src/types/packet.ts:29`, unchanged).
- Produces: a `renderField(field: ProtocolField, key: string | number, depth: number): React.ReactNode` closure inside the component, used recursively for `field.children`.

- [ ] **Step 1: Write the failing test**

There is no automated test harness for React components in this project (no jest/RTL configured). Verification for this step is a type-check plus a manual visual check once real nested data exists (Task 3). Skip to Step 3.

- [ ] **Step 2: (n/a — no test runner)**

- [ ] **Step 3: Implement recursive field rendering**

In `src/components/packet-details/PacketDetailsTree.tsx`, update the import on line 2 to include `ProtocolField`:

```tsx
import { Packet, ProtocolField, UserRolePermissions } from '../../types/packet';
```

Add a `renderField` function inside the component, right before the `return (` statement (after `copyFieldValue`):

```tsx
  const renderField = (field: ProtocolField, key: string | number, depth: number): React.ReactNode => {
    const isFieldActive =
      activeByteRange &&
      field.rawBytesRange &&
      activeByteRange[0] === field.rawBytesRange[0] &&
      activeByteRange[1] === field.rawBytesRange[1];

    const indentClass = depth === 0 ? '' : depth === 1 ? 'ml-4' : 'ml-8';

    return (
      <div key={key}>
        <div
          onMouseEnter={e => {
            e.stopPropagation();
            onHoverByteRange(field.rawBytesRange || null);
          }}
          onMouseLeave={e => {
            e.stopPropagation();
            onHoverByteRange(null);
          }}
          className={`flex items-center justify-between px-2 py-0.5 rounded group transition-colors ${indentClass} ${
            isFieldActive
              ? 'bg-cyan-100 dark:bg-cyan-500/20 text-cyan-800 dark:text-cyan-300 font-bold'
              : 'hover:bg-accent/60 text-muted-foreground'
          }`}
        >
          <div className="flex items-center gap-2 truncate">
            <span className="text-muted-foreground">{field.name}:</span>
            <span className="font-semibold text-foreground truncate">{String(field.value)}</span>
            {field.description && (
              <span className="text-[10px] text-muted-foreground italic hidden sm:inline truncate">
                ({field.description})
              </span>
            )}
          </div>

          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={() => copyFieldValue(field.name, field.value)}
              className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
              title="Copy field value"
            >
              {copiedField === field.name ? (
                <Check className="w-3 h-3 text-emerald-400" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </button>
          </div>
        </div>
        {field.children && field.children.length > 0 && (
          <div className="space-y-1 mt-1">
            {field.children.map((child, cIdx) => renderField(child, cIdx, depth + 1))}
          </div>
        )}
      </div>
    );
  };
```

Replace the existing "Layer Fields" block (currently `layer.fields.map((field, fIdx) => { ... })` at lines 165-214) with a single call into the new helper:

```tsx
              {/* Layer Fields */}
              {isExpanded && layer.fields && layer.fields.length > 0 && (
                <div className="pl-6 pr-3 py-1.5 space-y-1 border-t border-border/60 text-[11px]">
                  {layer.fields.map((field, fIdx) => renderField(field, fIdx, 0))}
                </div>
              )}
```

- [ ] **Step 4: Verify type-check passes**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add src/components/packet-details/PacketDetailsTree.tsx
git commit -m "Render nested ProtocolField.children recursively in packet detail tree"
```

---

## Task 3: TCP relative sequence/ack numbers

Wireshark shows relative sequence/ack numbers (starting from 0 at each connection's first observed segment) by default, with the raw 32-bit number available as a nested field. This task extends `TcpStreamTracker` with per-direction base-sequence tracking and switches the Info-column numbers from raw to relative, matching Wireshark's default display.

**Files:**
- Modify: `src/services/tcpStreamTracker.ts`
- Modify: `src/services/pcapParser.ts` (TCP branch — the `info` string and `Sequence Number`/`Acknowledgment Number` fields set up in Task 1)
- Test: temporary `__scratch_test_task3.ts` at repo root

**Interfaces:**
- Produces (on `TcpStreamTracker`): `getRelativeSeq(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number): number` and `getExpectedNext(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number | undefined`.
- Consumes: existing `getStreamId`/`checkSequence`/`connectionKey` (private) from `src/services/tcpStreamTracker.ts`.

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task3.ts`:

```ts
import { TcpStreamTracker } from './src/services/tcpStreamTracker';

const tracker = new TcpStreamTracker();

// First segment client->server establishes the base (ISN).
const rel1 = tracker.getRelativeSeq('10.0.0.1', 5000, '10.0.0.2', 80, 1000);
if (rel1 !== 0) throw new Error(`Expected first relative seq 0, got ${rel1}`);

// Second segment, 100 bytes later.
const rel2 = tracker.getRelativeSeq('10.0.0.1', 5000, '10.0.0.2', 80, 1100);
if (rel2 !== 100) throw new Error(`Expected relative seq 100, got ${rel2}`);

// Reverse direction has its own independent base.
const relServer1 = tracker.getRelativeSeq('10.0.0.2', 80, '10.0.0.1', 5000, 500000);
if (relServer1 !== 0) throw new Error(`Expected server-direction first relative seq 0, got ${relServer1}`);

// getExpectedNext before any checkSequence call is undefined.
if (tracker.getExpectedNext('10.0.0.1', 5000, '10.0.0.2', 80) !== undefined) {
  throw new Error('Expected getExpectedNext to be undefined before any checkSequence call');
}
tracker.checkSequence('10.0.0.1', 5000, '10.0.0.2', 80, 1000, 100);
if (tracker.getExpectedNext('10.0.0.1', 5000, '10.0.0.2', 80) !== 1100) {
  throw new Error(`Expected getExpectedNext 1100, got ${tracker.getExpectedNext('10.0.0.1', 5000, '10.0.0.2', 80)}`);
}

// Wraparound: base near the top of uint32 range.
const wrapTracker = new TcpStreamTracker();
wrapTracker.getRelativeSeq('10.0.0.3', 1, '10.0.0.4', 2, 4294967290); // base
const wrapRel = wrapTracker.getRelativeSeq('10.0.0.3', 1, '10.0.0.4', 2, 5); // wrapped past 2**32
if (wrapRel !== 11) throw new Error(`Expected wrapped relative seq 11, got ${wrapRel}`);

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task3.ts`
Expected: FAIL with a TypeScript error — `getRelativeSeq`/`getExpectedNext` don't exist on `TcpStreamTracker` yet.

- [ ] **Step 3: Write minimal implementation**

In `src/services/tcpStreamTracker.ts`, add a new private map and two new public methods, and clear the map in `reset()`:

```ts
  private baseSeq = new Map<string, number>();
```

(add this line right after `private highWaterSeq = new Map<string, number>();`)

```ts
  /**
   * Returns the sequence number relative to the first one seen in this
   * direction (Wireshark's default display), establishing that base the
   * first time a direction is seen. Wraparound-safe: uses unsigned modular
   * subtraction rather than naive arithmetic, since raw TCP sequence numbers
   * legitimately wrap past 2**32 on long-lived connections.
   */
  public getRelativeSeq(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number): number {
    const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
    let base = this.baseSeq.get(directionKey);
    if (base === undefined) {
      base = seqNum;
      this.baseSeq.set(directionKey, base);
    }
    return ((seqNum - base) + 2 ** 32) % 2 ** 32;
  }

  /**
   * Returns the raw sequence number expected in the next segment from this
   * direction (i.e. the current high-water mark), or undefined if no segment
   * from this direction has been through checkSequence() yet.
   */
  public getExpectedNext(srcIp: string, srcPort: number, dstIp: string, dstPort: number): number | undefined {
    const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
    return this.highWaterSeq.get(directionKey);
  }
```

Add `this.baseSeq.clear();` inside `reset()`, alongside the existing `.clear()` calls.

Now in `src/services/pcapParser.ts`, in the TCP branch (from Task 1), change the Info-string sequence numbers to relative and add raw sub-fields. Replace:

```ts
    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${seqNum} Ack=${ackNum} Len=${payloadLength}${optionsSummary}${tcpHost ? ' ' + tcpHost : ''}`;
```

with:

```ts
    const relSeq = tcpTracker ? tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, seqNum) : seqNum;
    const relAck = tcpTracker && ack ? tcpTracker.getRelativeSeq(dstIp, dstPort, srcIp, srcPort, ackNum) : ackNum;
    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${relSeq} Ack=${relAck} Len=${payloadLength}${optionsSummary}${tcpHost ? ' ' + tcpHost : ''}`;
```

Then update the `checkSequence`/`getExpectedNext` block (it currently comes after the `info` line) to compute the `[Next Sequence Number]` field, and update the two Sequence/Acknowledgment field entries to show relative values with raw children. Replace the whole `if (tcpTracker) { ... }` block with:

```ts
    let streamId: number | undefined;
    let status: Packet['status'] | undefined;
    let anomalies: AnomalyInfo[] | undefined;
    let expectedNextRel: number | undefined;
    if (tcpTracker) {
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      const seqResult = tcpTracker.checkSequence(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength);
      if (seqResult === 'retransmit') {
        status = 'retransmit';
        anomalies = [{
          type: 'tcp-retransmission',
          severity: 'low',
          title: 'TCP Retransmission',
          description: `Segment with sequence number ${seqNum} was already seen on stream #${streamId} - likely a retransmission after packet loss or a duplicate ACK race.`,
          recommendation: 'Check for network congestion, packet loss, or an unusually high round-trip time on this path.',
        }];
      } else if (seqResult === 'out-of-order') {
        status = 'warning';
        anomalies = [{
          type: 'tcp-out-of-order',
          severity: 'low',
          title: 'TCP Out-of-Order Segment',
          description: `Segment with sequence number ${seqNum} arrived out of order relative to previously seen data on stream #${streamId}.`,
          recommendation: 'Usually harmless (multi-path routing or reordering in transit) - investigate further only if paired with retransmissions or application-level errors.',
        }];
      }
      const expectedNextRaw = tcpTracker.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
      expectedNextRel = expectedNextRaw !== undefined ? tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, expectedNextRaw) : undefined;
    }
```

Finally, update the TCP layer's `fields` array (from Task 1) to replace the flat `Sequence Number`/`Acknowledgment Number` entries:

```ts
          { name: 'Sequence Number', value: seqNum, rawBytesRange: [transportOffset + 4, transportOffset + 7] },
          { name: 'Acknowledgment Number', value: ackNum, rawBytesRange: [transportOffset + 8, transportOffset + 11] },
```

with:

```ts
          {
            name: 'Sequence Number',
            value: `${relSeq} (relative sequence number)`,
            rawBytesRange: [transportOffset + 4, transportOffset + 7],
            children: [
              { name: 'Sequence Number (raw)', value: seqNum, rawBytesRange: [transportOffset + 4, transportOffset + 7] },
            ],
          },
          {
            name: 'Acknowledgment Number',
            value: `${relAck} (relative ack number)`,
            rawBytesRange: [transportOffset + 8, transportOffset + 11],
            children: [
              { name: 'Acknowledgment Number (raw)', value: ackNum, rawBytesRange: [transportOffset + 8, transportOffset + 11] },
            ],
          },
          ...(expectedNextRel !== undefined ? [{ name: '[Next Sequence Number]', value: expectedNextRel }] : []),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task3.ts`
Expected: PASS.

- [ ] **Step 5: Manual verification of Task 2 + Task 3 together**

Run `npm run lint` (expect clean), then start the dev server (`npm run dev`), import any `.pcap` with a real TCP conversation (or capture live traffic briefly), select a TCP packet, and confirm in the packet detail tree that:
- "Sequence Number" shows a small relative number (e.g. `0 (relative sequence number)`) with an indented child row "Sequence Number (raw)" showing the actual large 32-bit number.
- The Info column shows small `Seq=`/`Ack=` numbers instead of large raw ones.

Stop the dev server when done.

- [ ] **Step 6: Commit**

```bash
git add src/services/tcpStreamTracker.ts src/services/pcapParser.ts
git commit -m "Add TCP relative sequence/ack numbers with raw sub-fields"
```

---

## Task 4: TCP stream packet counter + conversation completeness

Wireshark's `[Stream index]`/`[TCP Segment Len]`-adjacent fields include a per-stream packet counter and a plain-English summary of whether a handshake completed. This task adds both, using the SYN/SYN-ACK/FIN-or-RST flags already extracted per packet.

**Files:**
- Modify: `src/services/tcpStreamTracker.ts`
- Modify: `src/services/pcapParser.ts` (TCP branch)
- Test: temporary `__scratch_test_task4.ts` at repo root

**Interfaces:**
- Produces (on `TcpStreamTracker`): `recordStreamPacket(streamId: number): number`, `updateConnectionState(streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean): void`, `getConversationCompleteness(streamId: number): string`.

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task4.ts`:

```ts
import { TcpStreamTracker } from './src/services/tcpStreamTracker';

const tracker = new TcpStreamTracker();
const streamId = tracker.getStreamId('10.0.0.1', 5000, '10.0.0.2', 80);

if (tracker.getConversationCompleteness(streamId) !== 'Incomplete') {
  throw new Error(`Expected 'Incomplete' before any state, got ${tracker.getConversationCompleteness(streamId)}`);
}

if (tracker.recordStreamPacket(streamId) !== 1) throw new Error('Expected first recordStreamPacket to return 1');
if (tracker.recordStreamPacket(streamId) !== 2) throw new Error('Expected second recordStreamPacket to return 2');

tracker.updateConnectionState(streamId, true, false, false, false); // SYN
if (tracker.getConversationCompleteness(streamId) !== 'SYN sent, no reply seen') {
  throw new Error(`Expected SYN-only state, got ${tracker.getConversationCompleteness(streamId)}`);
}

tracker.updateConnectionState(streamId, true, true, false, false); // SYN-ACK
if (tracker.getConversationCompleteness(streamId) !== 'Established, no close seen') {
  throw new Error(`Expected established state, got ${tracker.getConversationCompleteness(streamId)}`);
}

tracker.updateConnectionState(streamId, false, true, true, false); // FIN
if (tracker.getConversationCompleteness(streamId) !== 'Complete, WITH_DATA') {
  throw new Error(`Expected complete state, got ${tracker.getConversationCompleteness(streamId)}`);
}

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task4.ts`
Expected: FAIL — none of the three methods exist yet.

- [ ] **Step 3: Write minimal implementation**

In `src/services/tcpStreamTracker.ts`, add two new private maps (after `baseSeq`):

```ts
  private packetCountByStream = new Map<number, number>();
  private connState = new Map<number, { sawSyn: boolean; sawSynAck: boolean; sawFinOrRst: boolean }>();
```

Add three new public methods (after `getExpectedNext`):

```ts
  /** Returns this packet's 1-based position within its stream, recording it. */
  public recordStreamPacket(streamId: number): number {
    const count = (this.packetCountByStream.get(streamId) ?? 0) + 1;
    this.packetCountByStream.set(streamId, count);
    return count;
  }

  public updateConnectionState(streamId: number, syn: boolean, ack: boolean, fin: boolean, rst: boolean): void {
    const state = this.connState.get(streamId) ?? { sawSyn: false, sawSynAck: false, sawFinOrRst: false };
    if (syn && !ack) state.sawSyn = true;
    if (syn && ack) state.sawSynAck = true;
    if (fin || rst) state.sawFinOrRst = true;
    this.connState.set(streamId, state);
  }

  /**
   * A plain-English summary of handshake progress - deliberately not
   * Wireshark's internal numeric completeness bitmask, since that's an
   * implementation detail nobody reading this UI needs to decode.
   */
  public getConversationCompleteness(streamId: number): string {
    const state = this.connState.get(streamId);
    if (!state) return 'Incomplete';
    if (state.sawSyn && state.sawSynAck && state.sawFinOrRst) return 'Complete, WITH_DATA';
    if (state.sawSyn && state.sawSynAck) return 'Established, no close seen';
    if (state.sawSyn) return 'SYN sent, no reply seen';
    return 'Incomplete';
  }
```

Add clearing calls inside `reset()`: `this.packetCountByStream.clear(); this.connState.clear();`.

In `src/services/pcapParser.ts`'s TCP branch, inside the `if (tcpTracker) { ... }` block (from Task 3), add stream-packet recording and connection-state tracking right after `streamId = tcpTracker.getStreamId(...)`:

```ts
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      const packetNumberInStream = tcpTracker.recordStreamPacket(streamId);
      tcpTracker.updateConnectionState(streamId, syn, ack, fin, rst);
```

And capture the completeness string for use in the fields array — add right after the `expectedNextRel` line at the end of the `if (tcpTracker)` block:

```ts
      expectedNextRel = expectedNextRaw !== undefined ? tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, expectedNextRaw) : undefined;
      streamPacketNumber = packetNumberInStream;
      conversationCompleteness = tcpTracker.getConversationCompleteness(streamId);
```

Declare the two new `let` variables alongside `expectedNextRel` above the `if (tcpTracker)` block:

```ts
    let expectedNextRel: number | undefined;
    let streamPacketNumber: number | undefined;
    let conversationCompleteness: string | undefined;
```

Finally, append two more fields to the TCP layer's `fields` array, after the `[Next Sequence Number]` entry:

```ts
          ...(expectedNextRel !== undefined ? [{ name: '[Next Sequence Number]', value: expectedNextRel }] : []),
          ...(streamPacketNumber !== undefined ? [{ name: '[Stream Packet Number]', value: streamPacketNumber }] : []),
          ...(conversationCompleteness !== undefined ? [{ name: '[Conversation completeness]', value: conversationCompleteness }] : []),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task4.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task4.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/tcpStreamTracker.ts src/services/pcapParser.ts
git commit -m "Add TCP stream packet counter and conversation completeness tracking"
```

---

## Task 5: TCP Keep-Alive detection

A TCP Keep-Alive is a 0-or-1-byte segment resending the last byte of already-acknowledged data, purely to provoke an ACK and confirm the peer is alive. Without special-casing, Task 1's fixed-length logic would misclassify a classic 1-byte keep-alive as a retransmission (since its sequence number is deliberately one less than the expected next sequence number). This task detects keep-alives before `checkSequence` runs, so they get their own `[TCP Keep-Alive]` label instead of a false retransmission alert, and labels the peer's reply `[TCP Keep-Alive ACK]`.

**Files:**
- Modify: `src/services/tcpStreamTracker.ts`
- Modify: `src/services/pcapParser.ts` (TCP branch)
- Test: temporary `__scratch_test_task5.ts` at repo root

**Interfaces:**
- Produces (on `TcpStreamTracker`): `checkKeepAlive(srcIp: string, srcPort: number, dstIp: string, dstPort: number, seqNum: number, payloadLength: number, syn: boolean, fin: boolean, rst: boolean): boolean`, `consumeKeepAliveAck(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean`.
- Consumes: `getExpectedNext` (Task 3), `checkSequence` (pre-existing).

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task5.ts`:

```ts
import { TcpStreamTracker } from './src/services/tcpStreamTracker';

const tracker = new TcpStreamTracker();

// Establish expected-next = 1100 via a normal 100-byte segment.
tracker.checkSequence('10.0.0.1', 5000, '10.0.0.2', 80, 1000, 100);
if (tracker.getExpectedNext('10.0.0.1', 5000, '10.0.0.2', 80) !== 1100) throw new Error('Setup failed');

// A 1-byte keep-alive resends seq = expectedNext - 1.
const isKeepAlive = tracker.checkKeepAlive('10.0.0.1', 5000, '10.0.0.2', 80, 1099, 1, false, false, false);
if (!isKeepAlive) throw new Error('Expected 1-byte segment at expectedNext-1 to be detected as keep-alive');

// The peer's ACK in reply should be recognized as a keep-alive ACK exactly once.
const isKeepAliveAck = tracker.consumeKeepAliveAck('10.0.0.2', 80, '10.0.0.1', 5000);
if (!isKeepAliveAck) throw new Error('Expected the reply ACK to be recognized as a keep-alive ACK');
const secondCheck = tracker.consumeKeepAliveAck('10.0.0.2', 80, '10.0.0.1', 5000);
if (secondCheck) throw new Error('Expected consumeKeepAliveAck to be one-shot, not stay true');

// A normal 100-byte segment at the correct expected sequence is NOT a keep-alive.
const notKeepAlive = tracker.checkKeepAlive('10.0.0.1', 5001, '10.0.0.2', 81, 5000, 100, false, false, false);
if (notKeepAlive) throw new Error('Expected a fresh direction with no prior state to not be flagged as keep-alive');

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task5.ts`
Expected: FAIL — `checkKeepAlive`/`consumeKeepAliveAck` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

In `src/services/tcpStreamTracker.ts`, add one more private map (after `connState`):

```ts
  private lastWasKeepAlive = new Map<string, boolean>();
```

Add two public methods (after `getConversationCompleteness`):

```ts
  /**
   * A classic TCP Keep-Alive resends 0-1 bytes at (expected next seq - 1),
   * purely to provoke an ACK - without this check, checkSequence() would
   * misread it as a retransmission, since its sequence number is
   * deliberately behind the high-water mark.
   */
  public checkKeepAlive(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    seqNum: number, payloadLength: number, syn: boolean, fin: boolean, rst: boolean
  ): boolean {
    if (syn || fin || rst || payloadLength > 1) return false;
    const expectedNext = this.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
    if (expectedNext === undefined) return false;
    const isKeepAlive = seqNum === ((expectedNext - 1 + 2 ** 32) % 2 ** 32);
    if (isKeepAlive) {
      const directionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${srcIp}:${srcPort}`;
      this.lastWasKeepAlive.set(directionKey, true);
    }
    return isKeepAlive;
  }

  /**
   * Checks (and clears) whether the peer direction just sent a keep-alive
   * that this ACK is replying to - one-shot, so the same ACK isn't
   * re-labeled on a later unrelated lookup.
   */
  public consumeKeepAliveAck(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    const peerDirectionKey = `${this.connectionKey(srcIp, srcPort, dstIp, dstPort)}>${dstIp}:${dstPort}`;
    const wasKeepAlive = this.lastWasKeepAlive.get(peerDirectionKey) === true;
    if (wasKeepAlive) this.lastWasKeepAlive.set(peerDirectionKey, false);
    return wasKeepAlive;
  }
```

Add `this.lastWasKeepAlive.clear();` inside `reset()`.

In `src/services/pcapParser.ts`'s TCP branch, replace the `if (tcpTracker) { ... }` block (from Task 4) to check for keep-alive before calling `checkSequence`, and skip the retransmit/out-of-order check when it's a keep-alive:

```ts
    let streamId: number | undefined;
    let status: Packet['status'] | undefined;
    let anomalies: AnomalyInfo[] | undefined;
    let expectedNextRel: number | undefined;
    let streamPacketNumber: number | undefined;
    let conversationCompleteness: string | undefined;
    let isKeepAlive = false;
    let isKeepAliveAck = false;
    if (tcpTracker) {
      streamId = tcpTracker.getStreamId(srcIp, srcPort, dstIp, dstPort);
      const packetNumberInStream = tcpTracker.recordStreamPacket(streamId);
      tcpTracker.updateConnectionState(streamId, syn, ack, fin, rst);

      isKeepAlive = tcpTracker.checkKeepAlive(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength, syn, fin, rst);
      isKeepAliveAck = !isKeepAlive && payloadLength === 0 && ack && !syn && !fin && !rst
        && tcpTracker.consumeKeepAliveAck(srcIp, srcPort, dstIp, dstPort);

      if (!isKeepAlive) {
        const seqResult = tcpTracker.checkSequence(srcIp, srcPort, dstIp, dstPort, seqNum, payloadLength);
        if (seqResult === 'retransmit') {
          status = 'retransmit';
          anomalies = [{
            type: 'tcp-retransmission',
            severity: 'low',
            title: 'TCP Retransmission',
            description: `Segment with sequence number ${seqNum} was already seen on stream #${streamId} - likely a retransmission after packet loss or a duplicate ACK race.`,
            recommendation: 'Check for network congestion, packet loss, or an unusually high round-trip time on this path.',
          }];
        } else if (seqResult === 'out-of-order') {
          status = 'warning';
          anomalies = [{
            type: 'tcp-out-of-order',
            severity: 'low',
            title: 'TCP Out-of-Order Segment',
            description: `Segment with sequence number ${seqNum} arrived out of order relative to previously seen data on stream #${streamId}.`,
            recommendation: 'Usually harmless (multi-path routing or reordering in transit) - investigate further only if paired with retransmissions or application-level errors.',
          }];
        }
      }

      const expectedNextRaw = tcpTracker.getExpectedNext(srcIp, srcPort, dstIp, dstPort);
      expectedNextRel = expectedNextRaw !== undefined ? tcpTracker.getRelativeSeq(srcIp, srcPort, dstIp, dstPort, expectedNextRaw) : undefined;
      streamPacketNumber = packetNumberInStream;
      conversationCompleteness = tcpTracker.getConversationCompleteness(streamId);
    }
```

Finally, update the `info` string to append the Keep-Alive label. Replace:

```ts
    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${relSeq} Ack=${relAck} Len=${payloadLength}${optionsSummary}${tcpHost ? ' ' + tcpHost : ''}`;
```

with (note this line must move to *after* the `if (tcpTracker)` block above, since it now depends on `isKeepAlive`/`isKeepAliveAck` computed there — cut the original `const info = ...` line from its current position and paste this in its place after the tracker block):

```ts
    const keepAliveLabel = isKeepAlive ? ' [TCP Keep-Alive]' : isKeepAliveAck ? ' [TCP Keep-Alive ACK]' : '';
    const info = `${srcPort} → ${dstPort} [${flagList.join(', ')}] Seq=${relSeq} Ack=${relAck} Len=${payloadLength}${optionsSummary}${keepAliveLabel}${tcpHost ? ' ' + tcpHost : ''}`;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task5.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task5.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/tcpStreamTracker.ts src/services/pcapParser.ts
git commit -m "Detect TCP Keep-Alive and Keep-Alive ACK instead of false retransmit"
```

---

## Task 6: MAC vendor resolution

Wireshark resolves the first 3 bytes of a MAC address (the OUI) to a manufacturer name, showing e.g. `Apple_a1:b2:c3 (a4:83:e7:a1:b2:c3)`. This task adds a small, independently-compiled OUI lookup table (built from IEEE's public OUI registry data - factual assignments, not copied from any GPL codebase) and wires it into the Ethernet layer's Source/Destination fields.

**Files:**
- Create: `src/services/macVendors.ts`
- Modify: `src/services/pcapParser.ts:238-246` (Ethernet II layer fields)
- Test: temporary `__scratch_test_task6.ts` at repo root

**Interfaces:**
- Produces: `resolveMacVendor(mac: string): string` — takes a lowercase colon-separated MAC (as produced by the existing `formatMac`), returns `"Vendor_xx:xx:xx (aa:bb:cc:dd:ee:ff)"` when the OUI is known, otherwise returns `mac` unchanged.

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task6.ts`:

```ts
import { resolveMacVendor } from './src/services/macVendors';

const known = resolveMacVendor('b8:27:eb:11:22:33'); // Raspberry Pi Foundation OUI
if (!known.startsWith('Raspberry_Pi_Foundation_11:22:33 (b8:27:eb:11:22:33)')) {
  throw new Error(`Expected Raspberry Pi vendor string, got: ${known}`);
}

const unknown = resolveMacVendor('ff:ff:ff:ff:ff:ff');
if (unknown !== 'ff:ff:ff:ff:ff:ff') {
  throw new Error(`Expected unresolved MAC to pass through unchanged, got: ${unknown}`);
}

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task6.ts`
Expected: FAIL — module `./src/services/macVendors` doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `src/services/macVendors.ts`:

```ts
/**
 * A small, hand-curated subset of IEEE's public OUI (Organizationally Unique
 * Identifier) registry - the first 3 bytes of a MAC address map to the
 * manufacturer that was assigned that block. This is independently compiled
 * from IEEE's public assignment data (not copied from any third-party
 * project's manuf database) and intentionally covers only common,
 * easily-recognized vendors rather than IEEE's full multi-thousand-entry
 * list - full coverage isn't worth the maintenance burden for a UI nicety.
 */
const OUI_VENDOR_MAP: Record<string, string> = {
  '00:1A:11': 'Google',
  '3C:5A:B4': 'Google',
  'F4:F5:D8': 'Google',
  '00:50:56': 'VMware',
  '00:0C:29': 'VMware',
  '00:1C:14': 'VMware',
  '08:00:27': 'Oracle_VirtualBox',
  '52:54:00': 'QEMU_KVM',
  '00:15:5D': 'Microsoft_Hyper-V',
  '00:1B:63': 'Apple',
  '3C:07:54': 'Apple',
  'A4:83:E7': 'Apple',
  'F0:18:98': 'Apple',
  'DC:A6:32': 'Raspberry_Pi_Foundation',
  'B8:27:EB': 'Raspberry_Pi_Foundation',
  'E4:5F:01': 'Raspberry_Pi_Foundation',
  '00:1D:D8': 'Microsoft',
  '00:03:FF': 'Microsoft',
  '00:0D:3A': 'Microsoft',
  '00:1B:21': 'Intel',
  '00:1C:C0': 'Intel',
  '3C:97:0E': 'Intel',
  '00:1E:C2': 'Dell',
  '18:03:73': 'Dell',
  'B0:83:FE': 'Dell',
  '00:1A:64': 'Cisco',
  '00:0F:34': 'Cisco',
  '00:50:BA': 'D-Link',
  'C8:D3:A3': 'D-Link',
  '00:14:78': 'TP-Link',
  '50:C7:BF': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  '00:1F:33': 'Netgear',
  'A0:40:A0': 'Netgear',
  '3C:37:86': 'Huawei',
  '00:E0:FC': 'Huawei',
  '00:1D:0F': 'Samsung',
  'BC:14:85': 'Samsung',
  '00:16:6F': 'Sony',
  '00:1A:80': 'Sony',
};

/**
 * Formats a MAC address with its resolved vendor name, Wireshark-style
 * ("Vendor_xx:xx:xx (aa:bb:cc:dd:ee:ff)"), falling back to the raw MAC
 * unchanged when the OUI isn't in the table.
 */
export function resolveMacVendor(mac: string): string {
  const oui = mac.slice(0, 8).toUpperCase();
  const vendor = OUI_VENDOR_MAP[oui];
  if (!vendor) return mac;
  return `${vendor}_${mac.slice(9).toUpperCase()} (${mac})`;
}
```

In `src/services/pcapParser.ts`, update the Ethernet II layer fields (in `decodeRawEthernetPacket`). Add the import at the top of the file (after the existing `TcpStreamTracker` import):

```ts
import { resolveMacVendor } from './macVendors';
```

Replace:

```ts
      fields: [
        { name: 'Destination', value: dstMac, rawBytesRange: [0, 5] },
        { name: 'Source', value: srcMac, rawBytesRange: [6, 11] },
        { name: 'Type', value: `0x${etherType.toString(16).padStart(4, '0')} (${describeEtherType(etherType)})`, rawBytesRange: [12, 13] },
      ],
```

with:

```ts
      fields: [
        { name: 'Destination', value: resolveMacVendor(dstMac), rawBytesRange: [0, 5] },
        { name: 'Source', value: resolveMacVendor(srcMac), rawBytesRange: [6, 11] },
        { name: 'Type', value: `0x${etherType.toString(16).padStart(4, '0')} (${describeEtherType(etherType)})`, rawBytesRange: [12, 13] },
      ],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task6.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task6.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/macVendors.ts src/services/pcapParser.ts
git commit -m "Resolve MAC OUI to vendor name in Ethernet layer"
```

---

## Task 7: Richer IPv4 metadata (DSCP/ECN, Flags/Fragment Offset, checksum verification, stream index)

Adds Wireshark's standard IPv4 field breakdown that's currently missing: the Differentiated Services byte split into DSCP/ECN, the 3-bit Flags split into Reserved/DF/MF with Fragment Offset, and header-checksum verification (computed and compared, not just displayed) — plus a `[Stream index]` cross-reference once the transport layer resolves one. IPv6 is intentionally left untouched here (no header checksum field exists in IPv6, and the two reference screenshots that motivated this work were IPv4) except for the same `[Stream index]` addition, which is cheap and equally useful there.

**Files:**
- Modify: `src/services/pcapParser.ts:281-348` (IPv4 and IPv6 branches inside `decodeRawEthernetPacket`)
- Test: temporary `__scratch_test_task7.ts` at repo root

**Interfaces:**
- Produces: an unexported `computeIpHeaderChecksum(rawBytes: Uint8Array, l3Offset: number, ipHeaderLen: number): number` helper.
- Produces: a `const ttl = rawBytes[l3Offset + 8];` local variable in the IPv4 branch (consumed by Task 9 to pass into `decodeTransportLayer`).

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task7.ts`:

```ts
import { decodeRawEthernetPacket } from './src/services/pcapParser';

function buildIpv4Frame(opts: { dscp: number; ecn: number; df: boolean; mf: boolean; fragOffset: number; corruptChecksum?: boolean }): Uint8Array {
  const eth = new Uint8Array(14);
  eth.set([0x08, 0x00], 12);

  const ip = new Uint8Array(20);
  ip[0] = 0x45;
  ip[1] = (opts.dscp << 2) | opts.ecn;
  const totalLen = 20 + 20; // IP + bare TCP header, no payload
  ip[2] = (totalLen >> 8) & 0xff; ip[3] = totalLen & 0xff;
  ip[4] = 0x12; ip[5] = 0x34; // Identification
  const flagsAndFrag = ((opts.df ? 1 : 0) << 14) | ((opts.mf ? 1 : 0) << 13) | (opts.fragOffset & 0x1fff);
  ip[6] = (flagsAndFrag >> 8) & 0xff; ip[7] = flagsAndFrag & 0xff;
  ip[8] = 55; // TTL
  ip[9] = 6; // TCP
  ip.set([10, 0, 0, 1], 12);
  ip.set([10, 0, 0, 2], 16);

  // Compute a correct checksum first, then optionally corrupt it.
  let sum = 0;
  for (let i = 0; i < 20; i += 2) {
    if (i === 10) continue;
    sum += (ip[i] << 8) | ip[i + 1];
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  const checksum = (~sum) & 0xffff;
  ip[10] = (checksum >> 8) & 0xff;
  ip[11] = opts.corruptChecksum ? (checksum & 0xff) ^ 0xff : checksum & 0xff;

  const tcp = new Uint8Array(20);
  tcp[12] = (5 << 4); // data offset 5 words, no options

  const frame = new Uint8Array(eth.length + ip.length + tcp.length);
  frame.set(eth, 0);
  frame.set(ip, eth.length);
  frame.set(tcp, eth.length + ip.length);
  return frame;
}

const good = buildIpv4Frame({ dscp: 46, ecn: 1, df: true, mf: false, fragOffset: 0 });
const goodPacket = decodeRawEthernetPacket(good, 1, Date.now(), 0, 0, good.length);
const goodIpLayer = goodPacket.layers.find(l => l.name === 'Internet Protocol Version 4')!;

const dscpField = goodIpLayer.fields.find(f => f.name === 'Differentiated Services Field');
if (!dscpField?.children?.some(c => c.name === 'Differentiated Services Codepoint' && c.value === 46)) {
  throw new Error(`Expected DSCP child field with value 46, got: ${JSON.stringify(dscpField)}`);
}
if (!dscpField?.children?.some(c => c.name === 'Explicit Congestion Notification' && c.value === 1)) {
  throw new Error('Expected ECN child field with value 1');
}

const flagsField = goodIpLayer.fields.find(f => f.name === 'Flags');
if (!flagsField?.children?.some(c => c.name === "Don't fragment" && c.value === 'Set')) {
  throw new Error(`Expected DF flag Set, got: ${JSON.stringify(flagsField)}`);
}

const checksumField = goodIpLayer.fields.find(f => f.name === 'Header Checksum');
if (!String(checksumField?.value).includes('correct')) {
  throw new Error(`Expected checksum marked correct, got: ${checksumField?.value}`);
}

const corrupt = buildIpv4Frame({ dscp: 0, ecn: 0, df: false, mf: false, fragOffset: 100, corruptChecksum: true });
const corruptPacket = decodeRawEthernetPacket(corrupt, 2, Date.now(), 0, 0, corrupt.length);
const corruptIpLayer = corruptPacket.layers.find(l => l.name === 'Internet Protocol Version 4')!;
const corruptChecksumField = corruptIpLayer.fields.find(f => f.name === 'Header Checksum');
if (!String(corruptChecksumField?.value).includes('incorrect')) {
  throw new Error(`Expected checksum marked incorrect, got: ${corruptChecksumField?.value}`);
}
const fragOffsetField = corruptIpLayer.fields.find(f => f.name === 'Fragment Offset');
if (fragOffsetField?.value !== 100) throw new Error(`Expected fragment offset 100, got: ${fragOffsetField?.value}`);

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task7.ts`
Expected: FAIL — no `Differentiated Services Field`/`Flags`/`Header Checksum` fields exist yet in this shape.

- [ ] **Step 3: Write minimal implementation**

In `src/services/pcapParser.ts`, add a checksum helper near `formatHexDump`:

```ts
/**
 * Standard Internet checksum (RFC 1071) over the IPv4 header, with the
 * checksum field itself treated as zero - the same algorithm the sender
 * used to produce it, so a correct header always recomputes to the value
 * actually stored there.
 */
function computeIpHeaderChecksum(rawBytes: Uint8Array, l3Offset: number, ipHeaderLen: number): number {
  let sum = 0;
  for (let i = 0; i < ipHeaderLen; i += 2) {
    if (i === 10) continue;
    const word = i + 1 < ipHeaderLen ? (rawBytes[l3Offset + i] << 8) | rawBytes[l3Offset + i + 1] : rawBytes[l3Offset + i] << 8;
    sum += word;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}
```

Replace the entire IPv4 branch's field-building section. Find:

```ts
  // IPv4 Decode
  if (currentEtherType === 0x0800 && rawBytes.length >= l3Offset + 20) {
    const ipHeaderLen = (rawBytes[l3Offset] & 0x0f) * 4;
    const ipTotalLen = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];
    const ipProtocolNum = rawBytes[l3Offset + 9];
    srcIp = `${rawBytes[l3Offset + 12]}.${rawBytes[l3Offset + 13]}.${rawBytes[l3Offset + 14]}.${rawBytes[l3Offset + 15]}`;
    dstIp = `${rawBytes[l3Offset + 16]}.${rawBytes[l3Offset + 17]}.${rawBytes[l3Offset + 18]}.${rawBytes[l3Offset + 19]}`;

    layers.push({
      name: 'Internet Protocol Version 4',
      summary: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + ipHeaderLen - 1],
      fields: [
        { name: 'Version', value: '4', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Header Length', value: `${ipHeaderLen} bytes`, rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Total Length', value: ipTotalLen, rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Time to Live (TTL)', value: rawBytes[l3Offset + 8], rawBytesRange: [l3Offset + 8, l3Offset + 8] },
        { name: 'Protocol', value: ipProtocolNum === 6 ? 'TCP (6)' : ipProtocolNum === 17 ? 'UDP (17)' : `${ipProtocolNum}`, rawBytesRange: [l3Offset + 9, l3Offset + 9] },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 12, l3Offset + 15] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 16, l3Offset + 19] },
      ],
    });

    const transportOffset = l3Offset + ipHeaderLen;
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
    }
  } else if (currentEtherType === 0x86dd && rawBytes.length >= l3Offset + 40) {
```

Replace with:

```ts
  // IPv4 Decode
  if (currentEtherType === 0x0800 && rawBytes.length >= l3Offset + 20) {
    const ipHeaderLen = (rawBytes[l3Offset] & 0x0f) * 4;
    const tos = rawBytes[l3Offset + 1];
    const dscp = tos >> 2;
    const ecn = tos & 0x3;
    const ipTotalLen = (rawBytes[l3Offset + 2] << 8) | rawBytes[l3Offset + 3];
    const identification = (rawBytes[l3Offset + 4] << 8) | rawBytes[l3Offset + 5];
    const flagsAndFragOffset = (rawBytes[l3Offset + 6] << 8) | rawBytes[l3Offset + 7];
    const ipReservedBit = (flagsAndFragOffset >> 15) & 0x1;
    const dontFragment = (flagsAndFragOffset >> 14) & 0x1;
    const moreFragments = (flagsAndFragOffset >> 13) & 0x1;
    const fragmentOffset = flagsAndFragOffset & 0x1fff;
    const ttl = rawBytes[l3Offset + 8];
    const ipProtocolNum = rawBytes[l3Offset + 9];
    const headerChecksumActual = (rawBytes[l3Offset + 10] << 8) | rawBytes[l3Offset + 11];
    const headerChecksumComputed = computeIpHeaderChecksum(rawBytes, l3Offset, ipHeaderLen);
    const checksumCorrect = headerChecksumActual === headerChecksumComputed;
    srcIp = `${rawBytes[l3Offset + 12]}.${rawBytes[l3Offset + 13]}.${rawBytes[l3Offset + 14]}.${rawBytes[l3Offset + 15]}`;
    dstIp = `${rawBytes[l3Offset + 16]}.${rawBytes[l3Offset + 17]}.${rawBytes[l3Offset + 18]}.${rawBytes[l3Offset + 19]}`;

    const ipLayer: ProtocolLayer = {
      name: 'Internet Protocol Version 4',
      summary: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + ipHeaderLen - 1],
      fields: [
        { name: 'Version', value: '4', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Header Length', value: `${ipHeaderLen} bytes`, rawBytesRange: [l3Offset, l3Offset] },
        {
          name: 'Differentiated Services Field',
          value: `0x${tos.toString(16).padStart(2, '0')} (DSCP: ${dscp}, ECN: ${ecn})`,
          rawBytesRange: [l3Offset + 1, l3Offset + 1],
          children: [
            { name: 'Differentiated Services Codepoint', value: dscp, rawBytesRange: [l3Offset + 1, l3Offset + 1] },
            { name: 'Explicit Congestion Notification', value: ecn, rawBytesRange: [l3Offset + 1, l3Offset + 1] },
          ],
        },
        { name: 'Total Length', value: ipTotalLen, rawBytesRange: [l3Offset + 2, l3Offset + 3] },
        { name: 'Identification', value: `0x${identification.toString(16).padStart(4, '0')} (${identification})`, rawBytesRange: [l3Offset + 4, l3Offset + 5] },
        {
          name: 'Flags',
          value: `0x${((flagsAndFragOffset >> 13) & 0x7).toString(16).padStart(2, '0')}`,
          rawBytesRange: [l3Offset + 6, l3Offset + 6],
          children: [
            { name: 'Reserved bit', value: ipReservedBit === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: "Don't fragment", value: dontFragment === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
            { name: 'More fragments', value: moreFragments === 1 ? 'Set' : 'Not set', rawBytesRange: [l3Offset + 6, l3Offset + 6] },
          ],
        },
        { name: 'Fragment Offset', value: fragmentOffset, rawBytesRange: [l3Offset + 6, l3Offset + 7] },
        { name: 'Time to Live (TTL)', value: ttl, rawBytesRange: [l3Offset + 8, l3Offset + 8] },
        { name: 'Protocol', value: ipProtocolNum === 6 ? 'TCP (6)' : ipProtocolNum === 17 ? 'UDP (17)' : `${ipProtocolNum}`, rawBytesRange: [l3Offset + 9, l3Offset + 9] },
        {
          name: 'Header Checksum',
          value: `0x${headerChecksumActual.toString(16).padStart(4, '0')} [${checksumCorrect ? 'correct' : 'incorrect'}]`,
          rawBytesRange: [l3Offset + 10, l3Offset + 11],
          children: [
            { name: '[Header checksum status]', value: checksumCorrect ? 'Correct' : `Incorrect, should be 0x${headerChecksumComputed.toString(16).padStart(4, '0')}` },
          ],
        },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 12, l3Offset + 15] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 16, l3Offset + 19] },
      ],
    };
    layers.push(ipLayer);

    const transportOffset = l3Offset + ipHeaderLen;
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      if (transport.streamId !== undefined) {
        ipLayer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
  } else if (currentEtherType === 0x86dd && rawBytes.length >= l3Offset + 40) {
```

Note the call to `decodeTransportLayer` here is intentionally left with its current 6 arguments (`ttl` is not yet threaded through — that happens in Task 9). `ProtocolLayer` is already imported at the top of the file from `../types/packet`.

Now do the equivalent `[Stream index]` addition for IPv6 (same pattern, no DSCP/ECN/checksum changes). Find the IPv6 branch:

```ts
    layers.push({
      name: 'Internet Protocol Version 6',
      summary: `Internet Protocol Version 6, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + 39],
      fields: [
        { name: 'Version', value: '6', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Next Header', value: nextHeader === 6 ? 'TCP (6)' : nextHeader === 17 ? 'UDP (17)' : nextHeader === 58 ? 'ICMPv6 (58)' : `${nextHeader}`, rawBytesRange: [l3Offset + 6, l3Offset + 6] },
        { name: 'Hop Limit', value: hopLimit, rawBytesRange: [l3Offset + 7, l3Offset + 7] },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 8, l3Offset + 23] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 24, l3Offset + 39] },
      ],
    });

    const transportOffset = l3Offset + 40;
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
    }
  }
```

Replace with:

```ts
    const ipv6Layer: ProtocolLayer = {
      name: 'Internet Protocol Version 6',
      summary: `Internet Protocol Version 6, Src: ${srcIp}, Dst: ${dstIp}`,
      rawBytesRange: [l3Offset, l3Offset + 39],
      fields: [
        { name: 'Version', value: '6', rawBytesRange: [l3Offset, l3Offset] },
        { name: 'Next Header', value: nextHeader === 6 ? 'TCP (6)' : nextHeader === 17 ? 'UDP (17)' : nextHeader === 58 ? 'ICMPv6 (58)' : `${nextHeader}`, rawBytesRange: [l3Offset + 6, l3Offset + 6] },
        { name: 'Hop Limit', value: hopLimit, rawBytesRange: [l3Offset + 7, l3Offset + 7] },
        { name: 'Source Address', value: srcIp, rawBytesRange: [l3Offset + 8, l3Offset + 23] },
        { name: 'Destination Address', value: dstIp, rawBytesRange: [l3Offset + 24, l3Offset + 39] },
      ],
    };
    layers.push(ipv6Layer);

    const transportOffset = l3Offset + 40;
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      if (transport.streamId !== undefined) {
        ipv6Layer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task7.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task7.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/pcapParser.ts
git commit -m "Add IPv4 DSCP/ECN, flags/fragmentation, checksum verification, stream index"
```

---

## Task 8: Frame layer metadata (time deltas + protocol summary)

Adds Wireshark's `[Time delta from previous captured frame]`, `[Time since reference or first frame]`, and `[Protocols in frame]` fields to the Frame layer, using data already threaded into `decodeRawEthernetPacket` (`timeDelta`, `relativeTime`) plus a summary built from the final `layers` array.

**Files:**
- Modify: `src/services/pcapParser.ts:224-247` (Frame layer construction) and just before the function's `return` (end of `decodeRawEthernetPacket`)
- Test: temporary `__scratch_test_task8.ts` at repo root

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task8.ts`:

```ts
import { decodeRawEthernetPacket } from './src/services/pcapParser';

const eth = new Uint8Array(14);
eth.set([0x08, 0x00], 12);
const ip = new Uint8Array(20);
ip[0] = 0x45;
ip[9] = 6; // TCP
ip.set([10, 0, 0, 1], 12);
ip.set([10, 0, 0, 2], 16);
const tcp = new Uint8Array(20);
tcp[12] = (5 << 4);
const frame = new Uint8Array(eth.length + ip.length + tcp.length);
frame.set(eth, 0); frame.set(ip, eth.length); frame.set(tcp, eth.length + ip.length);

const packet = decodeRawEthernetPacket(frame, 3, Date.now(), 1.5, 0.25, frame.length);
const frameLayer = packet.layers.find(l => l.name === 'Frame')!;

const deltaField = frameLayer.fields.find(f => f.name === '[Time delta from previous captured frame]');
if (!deltaField || deltaField.value !== '0.250000 seconds') throw new Error(`Expected time delta field, got: ${JSON.stringify(deltaField)}`);

const sinceFirstField = frameLayer.fields.find(f => f.name === '[Time since reference or first frame]');
if (!sinceFirstField || sinceFirstField.value !== '1.500000 seconds') throw new Error(`Expected time-since-first field, got: ${JSON.stringify(sinceFirstField)}`);

const protocolsField = frameLayer.fields.find(f => f.name === '[Protocols in frame]');
if (protocolsField?.value !== 'frame:eth:ip:tcp') throw new Error(`Expected 'frame:eth:ip:tcp', got: ${protocolsField?.value}`);

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task8.ts`
Expected: FAIL — none of the three fields exist yet.

- [ ] **Step 3: Write minimal implementation**

In `src/services/pcapParser.ts`, update the Frame layer's `fields` array (inside the initial `layers` array literal in `decodeRawEthernetPacket`). Find:

```ts
    {
      name: 'Frame',
      summary: `Frame ${id}: ${rawBytes.length} bytes on wire (${rawBytes.length * 8} bits), ${origLen} bytes captured`,
      rawBytesRange: [0, rawBytes.length - 1],
      fields: [
        { name: 'Interface id', value: '0 (eth0)' },
        { name: 'Frame Number', value: id },
        { name: 'Frame Length', value: `${rawBytes.length} bytes` },
        { name: 'Capture Length', value: `${origLen} bytes` },
        { name: 'Epoch Time', value: new Date(epochMs).toISOString() },
      ],
    },
```

Replace with:

```ts
    {
      name: 'Frame',
      summary: `Frame ${id}: ${rawBytes.length} bytes on wire (${rawBytes.length * 8} bits), ${origLen} bytes captured`,
      rawBytesRange: [0, rawBytes.length - 1],
      fields: [
        { name: 'Interface id', value: '0 (eth0)' },
        { name: 'Frame Number', value: id },
        { name: 'Frame Length', value: `${rawBytes.length} bytes` },
        { name: 'Capture Length', value: `${origLen} bytes` },
        { name: 'Epoch Time', value: new Date(epochMs).toISOString() },
        { name: '[Time delta from previous captured frame]', value: `${timeDelta.toFixed(6)} seconds` },
        { name: '[Time since reference or first frame]', value: `${relativeTime.toFixed(6)} seconds` },
      ],
    },
```

At the very end of `decodeRawEthernetPacket`, right before the final `return { ... }` statement, add the protocol summary (this runs after every layer has been pushed, so `layers` is complete):

```ts
  const protocolNameMap: Record<string, string> = {
    'Frame': 'frame',
    'Ethernet II': 'eth',
    '802.1Q Virtual LAN': 'vlan',
    'Internet Protocol Version 4': 'ip',
    'Internet Protocol Version 6': 'ipv6',
    'Transmission Control Protocol': 'tcp',
    'User Datagram Protocol': 'udp',
    'Internet Control Message Protocol': 'icmp',
    'Internet Control Message Protocol v6': 'icmpv6',
  };
  const protocolsInFrame = layers.map(l => protocolNameMap[l.name] ?? l.name.toLowerCase().replace(/\s+/g, '_')).join(':');
  layers[0].fields.push({ name: '[Protocols in frame]', value: protocolsInFrame });

  return {
```

(keep the existing `return { id, timestamp: epochMs, ... }` body unchanged — only the new block above it is added.)

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task8.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task8.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/pcapParser.ts
git commit -m "Add Frame layer time-delta and protocol-summary fields"
```

---

## Task 9: ICMP echo id/seq/ttl parsing

Parses the 2-byte Identifier and 2-byte Sequence Number that follow the 4-byte ICMP header on Echo Request/Reply messages, and threads the already-computed TTL/Hop Limit into `decodeTransportLayer` so the Info string can show `id=0x0004, seq=351/24321, ttl=255`, matching Wireshark's format (including the BE/LE sequence-number pair convention it uses, since ping implementations commonly increment the sequence counter in host byte order while the wire format is big-endian).

**Files:**
- Modify: `src/services/pcapParser.ts:408-424, 550-593` (`decodeTransportLayer` signature + ICMP branch), plus its two call sites in `decodeRawEthernetPacket`
- Test: temporary `__scratch_test_task9.ts` at repo root

**Interfaces:**
- Produces: `decodeTransportLayer` gains a 7th parameter, `ttl?: number`.

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task9.ts`:

```ts
import { decodeRawEthernetPacket } from './src/services/pcapParser';

const eth = new Uint8Array(14);
eth.set([0x08, 0x00], 12);
const ip = new Uint8Array(20);
ip[0] = 0x45;
ip[8] = 255; // TTL
ip[9] = 1; // ICMP
ip.set([10, 0, 0, 1], 12);
ip.set([10, 0, 0, 2], 16);

const icmp = new Uint8Array(8);
icmp[0] = 8; icmp[1] = 0; // Echo request
icmp[4] = 0x00; icmp[5] = 0x04; // Identifier = 0x0004
icmp[6] = 0x01; icmp[7] = 0x5f; // Sequence = 351 (0x015F)

const frame = new Uint8Array(eth.length + ip.length + icmp.length);
frame.set(eth, 0); frame.set(ip, eth.length); frame.set(icmp, eth.length + ip.length);

const packet = decodeRawEthernetPacket(frame, 1, Date.now(), 0, 0, frame.length);
if (!packet.info.includes('id=0x0004, seq=351/24321, ttl=255')) {
  throw new Error(`Expected id/seq/ttl in info string, got: ${packet.info}`);
}
const icmpLayer = packet.layers.find(l => l.name === 'Internet Control Message Protocol')!;
const idField = icmpLayer.fields.find(f => f.name === 'Identifier (BE)');
if (!idField || String(idField.value) !== '0x0004 (4)') throw new Error(`Expected Identifier field, got: ${JSON.stringify(idField)}`);
const seqField = icmpLayer.fields.find(f => f.name === 'Sequence Number (BE)');
if (seqField?.value !== 351) throw new Error(`Expected Sequence Number field 351, got: ${seqField?.value}`);

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task9.ts`
Expected: FAIL — the Info string currently has no `id=`/`seq=`/`ttl=` suffix, and there is no `Identifier (BE)`/`Sequence Number (BE)` field.

- [ ] **Step 3: Write minimal implementation**

In `src/services/pcapParser.ts`, update `decodeTransportLayer`'s signature to accept `ttl`:

```ts
function decodeTransportLayer(
  rawBytes: Uint8Array,
  transportOffset: number,
  ipProtocolNum: number,
  srcIp: string,
  dstIp: string,
  tcpTracker?: TcpStreamTracker,
  ttl?: number
): {
```

(the return type object literal below this stays the same for this task.)

Replace the ICMP branch (from `} else if ((ipProtocolNum === 1 || ipProtocolNum === 58) ...` through its closing `};`) with:

```ts
  } else if ((ipProtocolNum === 1 || ipProtocolNum === 58) && rawBytes.length >= transportOffset + 4) {
    const isIcmpv6 = ipProtocolNum === 58;
    const icmpType = rawBytes[transportOffset];
    const icmpCode = rawBytes[transportOffset + 1];
    const isEchoRequest = isIcmpv6 ? icmpType === 128 : icmpType === 8;
    const isEchoReply = isIcmpv6 ? icmpType === 129 : icmpType === 0;

    let icmpId: number | undefined;
    let icmpSeq: number | undefined;
    if ((isEchoRequest || isEchoReply) && rawBytes.length >= transportOffset + 8) {
      icmpId = (rawBytes[transportOffset + 4] << 8) | rawBytes[transportOffset + 5];
      icmpSeq = (rawBytes[transportOffset + 6] << 8) | rawBytes[transportOffset + 7];
    }

    let info: string;
    if (isIcmpv6) {
      switch (icmpType) {
        case 128: info = 'Echo (ping) request'; break;
        case 129: info = 'Echo (ping) reply'; break;
        case 133: info = 'Router Solicitation'; break;
        case 134: info = 'Router Advertisement'; break;
        case 135: info = 'Neighbor Solicitation'; break;
        case 136: info = 'Neighbor Advertisement'; break;
        case 137: info = 'Redirect'; break;
        default: info = `ICMPv6 Type ${icmpType} Code ${icmpCode}`;
      }
    } else if (icmpType === 8) {
      info = 'Echo (ping) request';
    } else if (icmpType === 0) {
      info = 'Echo (ping) reply';
    } else {
      info = `ICMP Type ${icmpType} Code ${icmpCode}`;
    }

    if (icmpId !== undefined && icmpSeq !== undefined) {
      // Wireshark shows both the big-endian wire value and the same 16 bits
      // reinterpreted little-endian, since many ping implementations
      // increment the sequence counter in host (LE) byte order.
      const seqLe = ((icmpSeq << 8) | (icmpSeq >> 8)) & 0xffff;
      const ttlPart = ttl !== undefined ? `, ttl=${ttl}` : '';
      info += ` id=0x${icmpId.toString(16).padStart(4, '0')}, seq=${icmpSeq}/${seqLe}${ttlPart}`;
    }

    const fields: ProtocolField[] = [
      { name: 'Type', value: icmpType, rawBytesRange: [transportOffset, transportOffset] },
      { name: 'Code', value: icmpCode, rawBytesRange: [transportOffset + 1, transportOffset + 1] },
    ];
    if (icmpId !== undefined && icmpSeq !== undefined) {
      fields.push(
        { name: 'Identifier (BE)', value: `0x${icmpId.toString(16).padStart(4, '0')} (${icmpId})`, rawBytesRange: [transportOffset + 4, transportOffset + 5] },
        { name: 'Sequence Number (BE)', value: icmpSeq, rawBytesRange: [transportOffset + 6, transportOffset + 7] },
      );
    }

    return {
      proto: 'ICMP',
      info,
      layer: {
        name: isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol',
        summary: `${isIcmpv6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol'}, ${info}`,
        rawBytesRange: [transportOffset, transportOffset + (icmpId !== undefined ? 7 : 3)],
        fields,
      },
    };
  }
```

Now update the IPv4 branch's call site (from Task 7) to pass `ttl` (the local var Task 7 already introduced). Find:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker);
```

Replace with:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker, ttl);
```

And the IPv6 branch's call site — find:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker);
```

Replace with:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker, hopLimit);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task9.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task9.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/pcapParser.ts
git commit -m "Parse ICMP echo identifier/sequence and include TTL in info string"
```

---

## Task 10: ICMP request/reply correlation tracker + pcap-import wiring

Adds a new `IcmpEchoTracker` that records unanswered echo requests and matches them against later echo replies (keyed by the unordered endpoint pair plus id/sequence, since request and reply swap source/destination). Wires it into `decodeRawEthernetPacket` and `PcapService.parsePcapFile`'s import loop, which can directly patch an earlier packet in the already-built `parsedPackets` array once a reply is matched — this task deliberately does not touch the live-capture path (`App.tsx`), which needs different patch logic and is Task 11.

Because this task changes `decodeRawEthernetPacket`'s return type (from a bare `Packet` to `{ packet: Packet; icmpMatchedRequestFrameId?: number }`), it also updates the one other existing call site (`App.tsx`) with a minimal compile-compatible one-line change, so the repo stays buildable — Task 11 will replace that same line again with the full live-capture patch logic.

**Files:**
- Create: `src/services/icmpEchoTracker.ts`
- Modify: `src/services/pcapParser.ts` (`decodeTransportLayer` ICMP branch + signature, `decodeRawEthernetPacket` signature/return/call sites, `PcapService.parsePcapFile`)
- Modify: `src/App.tsx` (one-line call-site compile fix only — no new behavior yet)
- Test: temporary `__scratch_test_task10.ts` at repo root

**Interfaces:**
- Produces: `IcmpEchoTracker` with `recordRequest(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number, frameId: number): void`, `matchReply(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number): number | undefined`, `reset(): void`.
- Produces: `decodeRawEthernetPacket(...): { packet: Packet; icmpMatchedRequestFrameId?: number }` (return-shape change — all callers must destructure `.packet`).
- Consumes: `ProtocolField`, `TcpStreamTracker` (existing).

- [ ] **Step 1: Write the failing test**

Create `__scratch_test_task10.ts`:

```ts
import { IcmpEchoTracker } from './src/services/icmpEchoTracker';
import { decodeRawEthernetPacket } from './src/services/pcapParser';

// Unit-test the tracker directly first.
const tracker = new IcmpEchoTracker();
tracker.recordRequest('10.0.0.1', '10.0.0.2', 4, 351, 10);
const matched = tracker.matchReply('10.0.0.2', '10.0.0.1', 4, 351); // reply has src/dst swapped
if (matched !== 10) throw new Error(`Expected matchReply to return frame 10, got ${matched}`);
const secondMatch = tracker.matchReply('10.0.0.2', '10.0.0.1', 4, 351);
if (secondMatch !== undefined) throw new Error('Expected matchReply to be one-shot (consumed on first match)');

// Now the integration shape: decodeRawEthernetPacket must return { packet, icmpMatchedRequestFrameId }.
function buildIcmpFrame(type: number, id: number, seq: number): Uint8Array {
  const eth = new Uint8Array(14);
  eth.set([0x08, 0x00], 12);
  const ip = new Uint8Array(20);
  ip[0] = 0x45; ip[8] = 64; ip[9] = 1;
  ip.set([10, 0, 0, 1], 12);
  ip.set([10, 0, 0, 2], 16);
  const icmp = new Uint8Array(8);
  icmp[0] = type;
  icmp[4] = (id >> 8) & 0xff; icmp[5] = id & 0xff;
  icmp[6] = (seq >> 8) & 0xff; icmp[7] = seq & 0xff;
  const frame = new Uint8Array(eth.length + ip.length + icmp.length);
  frame.set(eth, 0); frame.set(ip, eth.length); frame.set(icmp, eth.length + ip.length);
  return frame;
}

const echoTracker = new IcmpEchoTracker();
const requestFrame = buildIcmpFrame(8, 99, 1);
const requestResult = decodeRawEthernetPacket(requestFrame, 20, Date.now(), 0, 0, requestFrame.length, undefined, echoTracker);
if (requestResult.icmpMatchedRequestFrameId !== undefined) throw new Error('A request should never match anything');

// Build the reply with swapped src/dst.
const replyFrame = buildIcmpFrame(0, 99, 1);
replyFrame.set([10, 0, 0, 2], 26); // src at ip offset (14+12)
replyFrame.set([10, 0, 0, 1], 30); // dst at ip offset (14+16)
const replyResult = decodeRawEthernetPacket(replyFrame, 21, Date.now(), 0, 0, replyFrame.length, undefined, echoTracker);
if (replyResult.icmpMatchedRequestFrameId !== 20) {
  throw new Error(`Expected reply to match request frame 20, got ${replyResult.icmpMatchedRequestFrameId}`);
}
if (!replyResult.packet.info.includes('(request in 20)')) {
  throw new Error(`Expected reply info to mention request frame, got: ${replyResult.packet.info}`);
}

console.log('PASS');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx __scratch_test_task10.ts`
Expected: FAIL — module `./src/services/icmpEchoTracker` doesn't exist, and `decodeRawEthernetPacket` still returns a bare `Packet`.

- [ ] **Step 3: Write minimal implementation**

Create `src/services/icmpEchoTracker.ts`:

```ts
/**
 * Correlates ICMP echo request/reply pairs across packets so each side's
 * Info column can reference the other by frame number, mirroring Wireshark's
 * "(reply in #N)" / "(request in #N)" annotations. Keyed by the unordered
 * pair of endpoints plus the echo id/sequence, since a request and its reply
 * swap source/destination but keep the same id and sequence number.
 */
export class IcmpEchoTracker {
  private pendingRequests = new Map<string, number>();

  private conversationKey(ipA: string, ipB: string, icmpId: number, icmpSeq: number): string {
    const pair = ipA <= ipB ? `${ipA}|${ipB}` : `${ipB}|${ipA}`;
    return `${pair}:${icmpId}:${icmpSeq}`;
  }

  /** Records an unanswered echo request so a later matching reply can find it. */
  public recordRequest(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number, frameId: number): void {
    this.pendingRequests.set(this.conversationKey(srcIp, dstIp, icmpId, icmpSeq), frameId);
  }

  /**
   * Looks up (and consumes) the request frame matching this reply, if any.
   * Returns undefined when no matching request has been seen.
   */
  public matchReply(srcIp: string, dstIp: string, icmpId: number, icmpSeq: number): number | undefined {
    const key = this.conversationKey(srcIp, dstIp, icmpId, icmpSeq);
    const requestFrameId = this.pendingRequests.get(key);
    if (requestFrameId !== undefined) this.pendingRequests.delete(key);
    return requestFrameId;
  }

  public reset(): void {
    this.pendingRequests.clear();
  }
}
```

In `src/services/pcapParser.ts`, add the import (with the other imports at the top):

```ts
import { IcmpEchoTracker } from './icmpEchoTracker';
```

Update `decodeTransportLayer`'s signature to accept the tracker and the current frame's id, and its return type to surface a match:

```ts
function decodeTransportLayer(
  rawBytes: Uint8Array,
  transportOffset: number,
  ipProtocolNum: number,
  srcIp: string,
  dstIp: string,
  tcpTracker?: TcpStreamTracker,
  ttl?: number,
  icmpTracker?: IcmpEchoTracker,
  frameId?: number
): {
  proto: Packet['protocol'];
  srcPort?: number;
  dstPort?: number;
  info: string;
  layer: ProtocolLayer;
  streamId?: number;
  status?: Packet['status'];
  anomalies?: AnomalyInfo[];
  icmpMatchedRequestFrameId?: number;
} | null {
```

In the ICMP branch (from Task 9), insert the recording/matching logic right after the `info` string gets its id/seq/ttl suffix, and add the returned field:

```ts
    if (icmpId !== undefined && icmpSeq !== undefined) {
      const seqLe = ((icmpSeq << 8) | (icmpSeq >> 8)) & 0xffff;
      const ttlPart = ttl !== undefined ? `, ttl=${ttl}` : '';
      info += ` id=0x${icmpId.toString(16).padStart(4, '0')}, seq=${icmpSeq}/${seqLe}${ttlPart}`;
    }

    let icmpMatchedRequestFrameId: number | undefined;
    if (icmpTracker && icmpId !== undefined && icmpSeq !== undefined && frameId !== undefined) {
      if (isEchoRequest) {
        icmpTracker.recordRequest(srcIp, dstIp, icmpId, icmpSeq, frameId);
      } else if (isEchoReply) {
        icmpMatchedRequestFrameId = icmpTracker.matchReply(srcIp, dstIp, icmpId, icmpSeq);
        if (icmpMatchedRequestFrameId !== undefined) {
          info += ` (request in ${icmpMatchedRequestFrameId})`;
        }
      }
    }
```

And add `icmpMatchedRequestFrameId` to the ICMP branch's return object:

```ts
    return {
      proto: 'ICMP',
      info,
      icmpMatchedRequestFrameId,
      layer: {
```

Now update `decodeRawEthernetPacket`. Add `icmpTracker?: IcmpEchoTracker` to its signature and change its return type. Find:

```ts
export function decodeRawEthernetPacket(
  rawBytes: Uint8Array,
  id: number,
  epochMs: number,
  relativeTime: number,
  timeDelta: number,
  origLen: number,
  tcpTracker?: TcpStreamTracker
): Packet {
```

Replace with:

```ts
export function decodeRawEthernetPacket(
  rawBytes: Uint8Array,
  id: number,
  epochMs: number,
  relativeTime: number,
  timeDelta: number,
  origLen: number,
  tcpTracker?: TcpStreamTracker,
  icmpTracker?: IcmpEchoTracker
): { packet: Packet; icmpMatchedRequestFrameId?: number } {
```

Add `let icmpMatchedRequestFrameId: number | undefined;` alongside the other `let` declarations near the top of the function body (next to `let anomalies: AnomalyInfo[] | undefined;`).

Update both `decodeTransportLayer(...)` call sites to pass `icmpTracker` and `id`, and to capture the match. IPv4 branch:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, ipProtocolNum, srcIp, dstIp, tcpTracker, ttl, icmpTracker, id);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      if (transport.streamId !== undefined) {
        ipLayer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
```

IPv6 branch, same additions:

```ts
    const transport = decodeTransportLayer(rawBytes, transportOffset, nextHeader, srcIp, dstIp, tcpTracker, hopLimit, icmpTracker, id);
    if (transport) {
      proto = transport.proto;
      srcPort = transport.srcPort;
      dstPort = transport.dstPort;
      info = transport.info;
      layers.push(transport.layer);
      if (transport.status) status = transport.status;
      streamId = transport.streamId;
      anomalies = transport.anomalies;
      icmpMatchedRequestFrameId = transport.icmpMatchedRequestFrameId;
      if (transport.streamId !== undefined) {
        ipv6Layer.fields.push({ name: '[Stream index]', value: transport.streamId });
      }
    }
```

Finally, update the function's `return` to the new shape. Find the existing `return { id, timestamp: epochMs, ... };` (immediately after the `[Protocols in frame]` line added in Task 8) and wrap it:

```ts
  return {
    packet: {
      id,
      timestamp: epochMs,
      relativeTime,
      timeDelta,
      source: srcIp,
      destination: dstIp,
      sourcePort: srcPort,
      destPort: dstPort,
      protocol: proto,
      length: rawBytes.length,
      info,
      status,
      streamId,
      layers,
      rawBytes,
      hexDump,
      asciiDump,
      anomalies,
      interfaceName: 'eth0',
    },
    icmpMatchedRequestFrameId,
  };
```

Now update `PcapService.parsePcapFile` to create an `IcmpEchoTracker`, pass it through, and patch the earlier request packet when a reply matches. Find:

```ts
    let offset = 24;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let prevTime = 0;
    const tcpTracker = new TcpStreamTracker();

    while (offset + 16 <= arrayBuffer.byteLength) {
```

Replace with:

```ts
    let offset = 24;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let prevTime = 0;
    const tcpTracker = new TcpStreamTracker();
    const icmpTracker = new IcmpEchoTracker();

    while (offset + 16 <= arrayBuffer.byteLength) {
```

Then find the decode call and its push:

```ts
      // Extract basic layers from Ethernet frame
      const packet = decodeRawEthernetPacket(rawBytes, packetIndex++, epochMs, relativeTime, timeDelta, origLen, tcpTracker);
      parsedPackets.push(packet);
```

Replace with:

```ts
      // Extract basic layers from Ethernet frame
      const { packet, icmpMatchedRequestFrameId } = decodeRawEthernetPacket(rawBytes, packetIndex++, epochMs, relativeTime, timeDelta, origLen, tcpTracker, icmpTracker);
      parsedPackets.push(packet);

      if (icmpMatchedRequestFrameId !== undefined) {
        const requestPacket = parsedPackets.find(p => p.id === icmpMatchedRequestFrameId);
        if (requestPacket) {
          requestPacket.info += ` (reply in ${packet.id})`;
        }
      }
```

Finally, make the one-line compile-compatible fix in `src/App.tsx` so the whole repo still type-checks (full live-capture wiring is Task 11). Find:

```ts
              safePkt = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker);
```

Replace with:

```ts
              safePkt = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker).packet;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx __scratch_test_task10.ts`
Expected: PASS.

- [ ] **Step 5: Type-check and clean up**

Run: `npm run lint` — expect clean. Delete `__scratch_test_task10.ts`.

- [ ] **Step 6: Commit**

```bash
git add src/services/icmpEchoTracker.ts src/services/pcapParser.ts src/App.tsx
git commit -m "Correlate ICMP echo request/reply frames in pcap-import path"
```

---

## Task 11: ICMP request/reply correlation — live-capture wiring in App.tsx

Wires the same `IcmpEchoTracker` into the live-capture WebSocket path in `App.tsx`. Unlike the pcap-import loop (which can mutate an already-built local array), live capture appends to React state one packet at a time, so a matched reply must patch the earlier request's `info` inside the same `setPackets` state update that appends the new packet.

**Files:**
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `IcmpEchoTracker` (Task 10), `decodeRawEthernetPacket(...): { packet: Packet; icmpMatchedRequestFrameId?: number }` (Task 10).

- [ ] **Step 1: Manual verification plan (no automated test — see Step 4)**

This task touches only the live WebSocket handler in a React component with no test harness. Verification is a manual browser smoke test using the local capture agent, described in Step 4.

- [ ] **Step 2: Write the implementation**

Add the import near the top of `src/App.tsx`, alongside the existing `TcpStreamTracker` import:

```ts
import { IcmpEchoTracker } from "./services/icmpEchoTracker";
```

Add the tracker instance next to `tcpTracker` (around line 136):

```ts
  const icmpTracker = useMemo(() => new IcmpEchoTracker(), []);
```

In `handleClearPackets`, reset it alongside `tcpTracker.reset()`:

```ts
  const handleClearPackets = () => {
    packetGenerator.reset();
    tcpTracker.reset();
    icmpTracker.reset();
    setPackets([]);
    setSelectedPacket(null);
    setActiveByteRange(null);
  };
```

In the WebSocket `onmessage` handler, replace the raw-bytes decode branch. Find:

```ts
          let safePkt: Packet;
          if (typeof rawPkt.raw === 'string' && rawPkt.raw.length > 0) {
            // Authoritative path: dissect the real captured bytes exactly
            // like an imported pcap file would be dissected.
            const binaryString = atob(rawPkt.raw);
            const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
            safePkt = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker).packet;
          } else {
```

Replace with:

```ts
          let safePkt: Packet;
          let icmpMatchedRequestFrameId: number | undefined;
          if (typeof rawPkt.raw === 'string' && rawPkt.raw.length > 0) {
            // Authoritative path: dissect the real captured bytes exactly
            // like an imported pcap file would be dissected.
            const binaryString = atob(rawPkt.raw);
            const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
            const decoded = decodeRawEthernetPacket(bytes, id, epochMs, relativeTime, timeDelta, rawPkt.length ?? bytes.length, tcpTracker, icmpTracker);
            safePkt = decoded.packet;
            icmpMatchedRequestFrameId = decoded.icmpMatchedRequestFrameId;
          } else {
```

Then update the final combine step inside the same `setPackets((prev) => { ... })` callback. Find:

```ts
            const updated = [...prev, safePkt];
            if (updated.length > 4000) {
              return updated.slice(updated.length - 4000);
            }
            return updated;
```

Replace with:

```ts
            const patchedPrev = icmpMatchedRequestFrameId !== undefined
              ? prev.map((p) => (p.id === icmpMatchedRequestFrameId ? { ...p, info: p.info + ` (reply in ${id})` } : p))
              : prev;
            const updated = [...patchedPrev, safePkt];
            if (updated.length > 4000) {
              return updated.slice(updated.length - 4000);
            }
            return updated;
```

- [ ] **Step 3: Type-check**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 4: Manual verification**

Start the dev server: `npm run dev`. With the local capture agent running and connected, start a capture, then from a terminal run a small number of pings to any reachable host (e.g. `ping -n 4 8.8.8.8` on Windows). Confirm in the packet list:
- Each ICMP echo request's Info column eventually gets ` (reply in <N>)` appended once its reply arrives.
- Each ICMP echo reply's Info column shows ` (request in <N>)` referencing the correct earlier frame number.
- Clearing the capture (Clear Cache) and starting a fresh ping sequence does not carry over stale matches from the previous capture (confirms `icmpTracker.reset()` works).

Stop the capture and dev server when done.

- [ ] **Step 5: Commit**

```bash
git add src/App.tsx
git commit -m "Correlate ICMP echo request/reply frames in live-capture path"
```

---

## Self-Review Notes

**Spec coverage:** All four in-scope items from `docs/superpowers/specs/2026-08-24-wireshark-parity-design.md` are covered — TCP relative seq/ack + conversation completeness (Tasks 3-4), richer Frame/Ethernet/IP metadata (Tasks 6-8), ICMP request/reply correlation (Tasks 9-11), TCP Keep-Alive + options (Tasks 1, 5). The prerequisite TCP-header-length bug fix is Task 1. The previously-undocumented UI gap (no recursive rendering of `ProtocolField.children`, which several tasks' nested fields depend on) is Task 2, added during planning since without it the new nested fields from Tasks 3 and 7 would be invisible in the UI despite being correctly computed.

**Placeholder scan:** No task contains "TBD"/"implement later"/"add appropriate handling" — every step shows complete, real code. Test scripts build real synthetic Ethernet/IP/TCP/ICMP frames byte-by-byte rather than referencing prior tasks' scripts.

**Type consistency:** `TcpStreamTracker` method names are used identically everywhere they're introduced and consumed (`getRelativeSeq`, `getExpectedNext` in Task 3; `recordStreamPacket`, `updateConnectionState`, `getConversationCompleteness` in Task 4; `checkKeepAlive`, `consumeKeepAliveAck` in Task 5). `IcmpEchoTracker`'s `recordRequest`/`matchReply`/`reset` (Task 10) match their usage in Task 11. `decodeTransportLayer`'s signature grows monotonically and consistently across Tasks 1/3/9/10 (`tcpTracker?`, then `ttl?`, then `icmpTracker?, frameId?`), and every call site is updated in the same task that changes the signature. `decodeRawEthernetPacket`'s return-shape change (Task 10, from `Packet` to `{ packet, icmpMatchedRequestFrameId? }`) updates both call sites in the same task (one fully in Task 10's `parsePcapFile` edit, one as a minimal compile-fix in `App.tsx`, fully realized in Task 11).
