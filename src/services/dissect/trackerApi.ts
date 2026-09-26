/**
 * What a dissector may ask of the cross-frame state, and nothing more.
 *
 * The dissectors used to take the tracker CLASSES, which made the class the
 * contract: anything public on `TcpStreamTracker` was reachable from a
 * dissector, and the only implementation there could ever be was the one that
 * keeps the state. These are the exact methods the dissectors call, picked off
 * the classes so the two cannot drift - a method a dissector starts calling
 * fails to compile until it is named here.
 *
 * **Why the seam exists** (ADR 0049): a frame's tree is rebuilt from that frame
 * alone plus what its first dissection recorded. At arrival the real trackers
 * answer and a recorder keeps the answers; on revisit a stand-in answers from
 * the record, through this same surface, to the same unchanged dissector code.
 * One dissector, two sources of truth about the past - never two dissectors.
 */
import type { TcpStreamTracker } from '../tcpStreamTracker';
import type { QuicFlowTracker } from '../quicFlowTracker';
import type { DnsTracker } from '../dnsTracker';
import type { IcmpEchoTracker } from '../icmpEchoTracker';
import type { L3Tracker } from '../l3Tracker';

export type TcpTrackerApi = Pick<TcpStreamTracker,
  | 'setWindowScaleShift' | 'getWindowScaleShift' | 'getRelativeSeq'
  | 'getStreamId' | 'recordStreamPacket' | 'updateConnectionState' | 'noteFin'
  | 'isAtOrPastExpected' | 'analyze' | 'noteGap'
  | 'getConversationCompleteness' | 'getCompletenessMask'
  | 'ldapConversation' | 'smb2Conversation' | 'peekBgpDirection' | 'bgpDirection'
  | 'peekTlsCursor' | 'tlsCursor' | 'tlsConversation' | 'getTlsStreamId'>;

export type QuicTrackerApi = Pick<QuicFlowTracker,
  | 'isKnownFlow' | 'matchConnectionId' | 'createInitialDecryptor'
  | 'addCryptoFragments' | 'noteLongHeader' | 'connectionNumberForFlow' | 'readStreams'>;

export type DnsTrackerApi = Pick<DnsTracker, 'recordQuery' | 'matchResponse'>;

export type IcmpTrackerApi = Pick<IcmpEchoTracker, 'recordRequest' | 'matchReply'>;

export type L3TrackerApi = Pick<L3Tracker,
  | 'ethStream' | 'ipStream' | 'ipv6Stream' | 'udpStream'
  | 'fragment' | 'forgetFragments' | 'arpClaim'>;
