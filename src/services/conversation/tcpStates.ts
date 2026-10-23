/**
 * A TCP connection's RFC 793 states, inferred from what one vantage point saw
 * (ADR 0055).
 *
 * The wire shows segments, never a host's state, so every state here is an
 * inference, and each transition says how it was reached:
 *
 *  - `sent`: the side was seen sending the segment that moved it.
 *  - `received`: the segment that moved it was seen on the wire and assumed to
 *    have arrived. That is the assumption, and it is the only one.
 *  - `inferred`: nothing on the wire shows it. A connection joined mid-stream,
 *    or a listener, which no segment can show.
 *
 * FIN acknowledgement is judged by sequence number when the row carries one
 * (`tcp.seq`, `tcp.len`, `tcp.ack`): an ACK reaching one past the FIN's
 * sequence number acknowledges it. Without numbers, the other side's next ACK
 * is taken to, which is what a ladder drawn by hand would assume.
 *
 * A bare SYN can open a second connection on the same five-tuple, and nothing
 * in the old one need have announced its end: the close may be unseen, or its
 * last ACK missed. Each side's raw initial sequence number (`tcp.seq_raw`) is
 * kept, and a SYN with a different one, or one the TCP analysis flagged as
 * reused ports, starts a new incarnation; the old one's FINs, RST and states are
 * dropped first so the new handshake cannot acknowledge them. A SYN with the
 * same ISN is the same connection (a retransmission, or a mirror-port
 * duplicate) and changes nothing. With no ISN to compare, a side already past
 * SYN_SENT cannot be sending its first SYN, so that starts over as well.
 */

export type TcpState =
  | 'UNKNOWN' | 'CLOSED' | 'LISTEN' | 'SYN_SENT' | 'SYN_RCVD' | 'ESTABLISHED'
  | 'FIN_WAIT_1' | 'FIN_WAIT_2' | 'CLOSING' | 'TIME_WAIT' | 'CLOSE_WAIT' | 'LAST_ACK';

export type Side = 'client' | 'server';
export const otherSide = (side: Side): Side => (side === 'client' ? 'server' : 'client');

export interface TcpSegment {
  from: Side;
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  /** `tcp.seq`, `tcp.len` and `tcp.ack` as the row carries them. */
  seq?: number;
  len?: number;
  ackNo?: number;
  /** `tcp.seq_raw`: the sequence number as sent, which relative `seq` hides. */
  rawSeq?: number;
  /** The row carries the `reused_ports` analysis flag: tshark saw a new session on old ports. */
  reused?: boolean;
}

export type Evidence = 'sent' | 'received' | 'inferred';
export type TransitionCause = 'syn' | 'syn+ack' | 'ack' | 'fin' | 'rst' | 'joined' | 'listen';

export interface TcpTransition {
  side: Side;
  from: TcpState;
  to: TcpState;
  evidence: Evidence;
  cause: TransitionCause;
}

/**
 * Everything the machine knows, as plain data, so the capture store can
 * persist it in a snapshot and resume folding where it stopped.
 */
export interface TcpMachineState {
  client: TcpState;
  server: TcpState;
  /** One past each side's FIN, when its sequence number was seen. */
  finEnd: { client: number | null; server: number | null };
  finSent: { client: boolean; server: boolean };
  finAcked: { client: boolean; server: boolean };
  /** Who sent the first RST, or null. */
  rstFrom: Side | null;
  everEstablished: boolean;
  /** The connection was already open when the capture first saw it. */
  joined: boolean;
  sawSyn: boolean;
  sawSynAck: boolean;
  /**
   * Each side's initial sequence number, raw, from its SYN or SYN+ACK. Relative
   * numbers read 0 on every SYN, so only this tells two connections on one
   * five-tuple apart. Absent in snapshots from before it existed: read it as
   * `st.isn?.[side] ?? null`.
   */
  isn: { client: number | null; server: number | null };
}

export function freshMachineState(): TcpMachineState {
  return {
    client: 'UNKNOWN', server: 'UNKNOWN',
    finEnd: { client: null, server: null },
    finSent: { client: false, server: false },
    finAcked: { client: false, server: false },
    rstFrom: null, everEstablished: false, joined: false, sawSyn: false, sawSynAck: false,
    isn: { client: null, server: null },
  };
}

const CLOSED_LIKE = new Set<TcpState>(['UNKNOWN', 'CLOSED', 'TIME_WAIT']);

export class TcpStateMachine {
  readonly state: TcpMachineState;

  constructor(state: TcpMachineState = freshMachineState()) {
    this.state = state;
  }

  apply(seg: TcpSegment): TcpTransition[] {
    const out: TcpTransition[] = [];
    const st = this.state;
    const s = seg.from;
    const r = otherSide(s);
    const move = (side: Side, to: TcpState, evidence: Evidence, cause: TransitionCause): void => {
      const from = st[side];
      if (from === to) return;
      st[side] = to;
      if (to === 'ESTABLISHED') st.everEstablished = true;
      out.push({ side, from, to, evidence, cause });
    };

    if (seg.rst) {
      if (st.rstFrom === null) st.rstFrom = s;
      move(s, 'CLOSED', 'sent', 'rst');
      move(r, 'CLOSED', 'received', 'rst');
      return out;
    }

    if (seg.syn) {
      if (!seg.ack) {
        const known = st.isn?.[s] ?? null;
        // The same ISN is the same connection: a retransmission, or a copy the
        // mirror port delivered twice, and it never splits one, however far
        // along it is. It is not a new fact either, so it moves nothing.
        if (known !== null && seg.rawSeq === known) return out;
        // A new incarnation on a five-tuple: everything the connection before
        // it left behind belongs to that connection, and the FIN of the old
        // one must not be acknowledged by the handshake of the new. The reset
        // runs first, so the SYN below is the new one's first fact.
        if (this.startsNewIncarnation(seg, known)) this.resetIncarnation(s);
        st.sawSyn = true;
        if (seg.rawSeq !== undefined) this.recordIsn(s, seg.rawSeq);
        if (CLOSED_LIKE.has(st[s])) move(s, 'SYN_SENT', 'sent', 'syn');
        if (st[r] === 'UNKNOWN' || st[r] === 'CLOSED') move(r, 'LISTEN', 'inferred', 'listen');
        else if (st[r] === 'SYN_SENT') move(r, 'SYN_RCVD', 'received', 'syn');
        return out;
      }
      st.sawSynAck = true;
      if (seg.rawSeq !== undefined) this.recordIsn(s, seg.rawSeq);
      if (st[s] === 'UNKNOWN' || st[s] === 'CLOSED') move(s, 'LISTEN', 'inferred', 'listen');
      if (st[s] === 'LISTEN' || st[s] === 'SYN_SENT') move(s, 'SYN_RCVD', 'sent', 'syn+ack');
      if (st[r] === 'UNKNOWN') move(r, 'SYN_SENT', 'inferred', 'syn');
      // Simultaneous open: the receiver already answered a SYN of its own.
      else if (st[r] === 'SYN_RCVD') move(r, 'ESTABLISHED', 'received', 'ack');
      return out;
    }

    if (st[s] === 'UNKNOWN' && st[r] === 'UNKNOWN') {
      st.joined = true;
      move(s, 'ESTABLISHED', 'inferred', 'joined');
      move(r, 'ESTABLISHED', 'inferred', 'joined');
    }

    if (seg.ack) {
      if (st[s] === 'SYN_SENT' && st[r] === 'SYN_RCVD') {
        move(s, 'ESTABLISHED', 'sent', 'ack');
        move(r, 'ESTABLISHED', 'received', 'ack');
      }
      if (st.finSent[r] && !st.finAcked[r] && this.acknowledges(seg, r)) {
        st.finAcked[r] = true;
        if (st[r] === 'FIN_WAIT_1') move(r, 'FIN_WAIT_2', 'received', 'ack');
        else if (st[r] === 'CLOSING') move(r, 'TIME_WAIT', 'received', 'ack');
        else if (st[r] === 'LAST_ACK') move(r, 'CLOSED', 'received', 'ack');
        if (st[s] === 'FIN_WAIT_2') move(s, 'TIME_WAIT', 'sent', 'ack');
      }
    }

    if (seg.fin && !st.finSent[s]) {
      st.finSent[s] = true;
      // Sequence numbers are 32-bit: a FIN at the top of the range ends at 0.
      if (seg.seq !== undefined) st.finEnd[s] = (seg.seq + (seg.len ?? 0) + 1) >>> 0;
      if (st[s] === 'ESTABLISHED' || st[s] === 'SYN_RCVD') move(s, 'FIN_WAIT_1', 'sent', 'fin');
      else if (st[s] === 'CLOSE_WAIT') move(s, 'LAST_ACK', 'sent', 'fin');
      if (st[r] === 'ESTABLISHED') move(r, 'CLOSE_WAIT', 'received', 'fin');
      else if (st[r] === 'FIN_WAIT_1') move(r, 'CLOSING', 'received', 'fin');
      // FIN_WAIT_2 waits here until it acknowledges this FIN (the ACK branch).
    }
    return out;
  }

  private acknowledges(seg: TcpSegment, finSender: Side): boolean {
    const end = this.state.finEnd[finSender];
    if (end === null || seg.ackNo === undefined) return true;
    // Modular 32-bit distance: the ACK covers the FIN when it is at or past
    // `end`, counting around the wrap.
    return ((seg.ackNo - end) | 0) >= 0;
  }

  /**
   * Whether a bare SYN is not part of the connection folded so far. The row's
   * reused-ports flag says so outright; a different ISN says so when this
   * side's is known; with neither to go on, a side already past SYN_SENT cannot
   * be sending its first SYN (SYN_RCVD is the simultaneous open, and SYN_SENT
   * and LISTEN are retransmissions and the inferred listener).
   */
  private startsNewIncarnation(seg: TcpSegment, known: number | null): boolean {
    if (seg.reused) return true;
    if (known !== null && seg.rawSeq !== undefined) return known !== seg.rawSeq;
    const was = this.state[seg.from];
    return was !== 'UNKNOWN' && was !== 'LISTEN' && was !== 'SYN_SENT' && was !== 'SYN_RCVD';
  }

  private recordIsn(side: Side, rawSeq: number): void {
    // A state restored from a snapshot older than `isn` has none.
    const isn = this.state.isn ?? (this.state.isn = { client: null, server: null });
    isn[side] = rawSeq;
  }

  /**
   * Forget the connection before a new one's SYN. A side that had closed keeps
   * its state, so the new SYN reads as leaving it. Any other side's close went
   * unseen, and is taken to have happened: it is put in CLOSED without a step,
   * so the new handshake reads as an active and a passive open. UNKNOWN would
   * read as "SYN not captured" on the map, and this SYN was.
   */
  private resetIncarnation(sender: Side): void {
    const st = this.state;
    for (const side of ['client', 'server'] as const) {
      if (side === sender ? !CLOSED_LIKE.has(st[side]) : st[side] !== 'CLOSED' && st[side] !== 'UNKNOWN') {
        st[side] = 'CLOSED';
      }
    }
    st.isn = { client: null, server: null };
    st.finEnd = { client: null, server: null };
    st.finSent = { client: false, server: false };
    st.finAcked = { client: false, server: false };
    st.rstFrom = null;
    st.everEstablished = false;
    st.joined = false;
    st.sawSyn = false;
    st.sawSynAck = false;
  }
}

export type TcpOutcome =
  | 'closed cleanly' | 'closing'
  | 'half-closed by client' | 'half-closed by server'
  | 'reset by client' | 'reset by server'
  | 'refused' | 'no reply' | 'handshake unfinished' | 'open';

/** How the connection ended, or has not, as far as the capture shows. */
export function outcomeOf(st: TcpMachineState): TcpOutcome {
  // A clean close stays one: a stray RST after both FINs were acknowledged is
  // the stack tidying up, not the connection failing.
  if (st.finAcked.client && st.finAcked.server) return 'closed cleanly';
  if (st.rstFrom !== null) {
    if (!st.everEstablished && st.sawSyn && !st.sawSynAck && st.rstFrom === 'server') return 'refused';
    return st.rstFrom === 'client' ? 'reset by client' : 'reset by server';
  }
  if (st.finSent.client && st.finSent.server) return 'closing';
  if (st.finSent.client) return 'half-closed by client';
  if (st.finSent.server) return 'half-closed by server';
  if (!st.everEstablished) {
    if (st.sawSynAck) return 'handshake unfinished';
    if (st.sawSyn) return 'no reply';
  }
  return 'open';
}
