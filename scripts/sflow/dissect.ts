/**
 * sFlow v5 against the reference, row for row, and the decode a collector
 * will read without a tree.
 *
 *   npx tsx scripts/sflow/dissect.ts
 *
 * A switch or router running sFlow sends a collector one packet in N, and
 * every interface's counters every few seconds - the two numbers a bandwidth
 * graph is drawn from. Neither fixture holds a datagram, so they are built in
 * `frames.ts` from sflow_version_5.txt: every sample type, the flow and
 * counter records agents actually send, an IPv6 agent, a gateway's AS path,
 * dropped and multi-port outputs, and formats nobody names.
 *
 * Not compared: what the reference dissects INSIDE a sampled header (its
 * Ethernet, IP and TCP layers), which this build leaves as the header's
 * bytes - see `dissectors/sflow.ts`. Those layers' abbrevs are not `sflow*`,
 * so the row filter leaves them out by itself.
 */
import { check, checkRevisit, compareWithReference, finish } from '../parity/treeOracle';
import { cases, otherEnterprise, sampledFrame, AGENT } from './frames';
import { PcapService } from '../../src/services/pcapParser';
import { pcapOf } from '../parity/synthetic';
import { decodeSflow, interfaceReadings, sampledPackets } from '../../src/services/flow/sflow';

const packets = await compareWithReference(cases, { rows: /^sflow(_245|_5)?\./ });
await checkRevisit(cases);

check('a datagram is the `sflow` layer over UDP',
  packets[0]?.frameProtocols?.slice(-2).join(':') === 'udp:sflow', packets[0]?.frameProtocols?.join(':'));
check('the agent is a field', packets[0]?.fields?.['sflow_245.agent'] === AGENT);
check('an IPv6 agent is a field of its own', packets[4]?.fields?.['sflow_245.agent.v6'] === '2001:db8::1');
check('an interface\'s input octets are a field, past 2^32', packets[1]?.fields?.['sflow_245.ifinoct'] === 123_456_789_012);

// --- the decode, as a collector reads it ------------------------------------
const payloadOf = (frame: Uint8Array) => frame.subarray(14 + 20 + 8);
const decode = (i: number) => {
  const p = payloadOf(cases[i].frame);
  return decodeSflow(p, 0, p.length);
};

const flow = decode(0);
const sampled = flow === null ? [] : sampledPackets(flow, AGENT);
check('a flow sample decodes to one sampled packet', sampled.length === 1, JSON.stringify(sampled));
check('it carries the sampling rate and both interfaces',
  sampled[0]?.samplingRate === 1000 && sampled[0]?.inputIfIndex === 7 && sampled[0]?.outputIfIndex === 9 && !sampled[0]?.dropped);
check('and the frame length and header the agent copied',
  sampled[0]?.frameLength === 1514 && sampled[0]?.headerProtocol === 1
  && sampled[0]?.header?.length === sampledFrame().length && sampled[0]?.header?.every((x, k) => x === sampledFrame()[k]) === true);
check('the header is a copy, not a view of the datagram', sampled[0]?.header?.buffer !== cases[0].frame.buffer);

const counters = decode(1);
const readings = counters === null ? [] : interfaceReadings(counters, AGENT);
check('a counter sample decodes to one interface reading', readings.length === 1);
const r = readings[0];
check('the reading carries 64-bit octets exactly, and the agent\'s clock',
  r?.inOctets === 123_456_789_012n && r?.outOctets === 98_765_432_109n && r?.speedBps === 1_000_000_000n && r?.uptimeMs === 3_600_123);
check('and the packets, errors and discards',
  r?.ifIndex === 7 && r?.inPackets === 1050 && r?.outPackets === 2090 && r?.inErrors === 5 && r?.outErrors === 8
  && r?.inDiscards === 4 && r?.outDiscards === 7);

const dropped = decode(11);
const drops = dropped === null ? [] : sampledPackets(dropped, AGENT);
check('a discarded packet has no output interface and says it was dropped',
  drops[0]?.dropped === true && drops[0]?.outputIfIndex === null);
check('one sent out of several ports has no single output interface',
  drops[1]?.dropped === false && drops[1]?.outputIfIndex === null);

const unknown = decode(6);
check('records nobody names are kept, by enterprise and format',
  unknown?.samples[0]?.kind === 'flow' && unknown.samples[0].records.map((x) => `${x.enterprise}:${x.format}:${x.kind}`).join(',') === '0:4000:unknown,4413:5:unknown');

const v6 = decode(4);
check('an IPv6 agent decodes as one', v6?.agent?.v6 === true && v6.agent.address.length === 16);

const whole = payloadOf(cases[1].frame);
const cut = decodeSflow(whole, 0, whole.length - 20);
check('a datagram cut short keeps its header and says it was cut', cut !== null && cut.truncated && cut.sequence === 42);
check('a version other than 5 is not sFlow', decodeSflow(Uint8Array.from([0, 0, 0, 4, ...whole.subarray(4)]), 0, whole.length) === null);

// The reference stops at a sample from another enterprise; this build reads past it.
const [skipped] = (await PcapService.parseCaptureFile(new File([pcapOf([otherEnterprise])], 'enterprise.pcap'), Number.POSITIVE_INFINITY, true)).packets;
const headings = skipped?.layers.at(-1)?.fields.filter((f) => f.abbrev === undefined).map((f) => f.name) ?? [];
check('a sample from another enterprise is skipped by its length, and the next one read',
  headings.join(' | ') === 'Unknown enterprise format | Counters sample, seq 5', headings.join(' | '));

finish('sflow');
