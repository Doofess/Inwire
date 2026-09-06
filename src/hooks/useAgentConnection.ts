/**
 * Everything about the link to the local capture agent, in one place.
 *
 * This was sixteen `useState` calls, four refs and five effects sitting inline
 * in `App.tsx` among forty-six other pieces of state - about 450 lines of one
 * subject scattered through a 2,850-line component, where the only thing
 * marking them as related was the `agent` prefix on most of the names.
 *
 * It is a **move**, not a redesign: the state, the refs, the effects and their
 * dependency arrays are the ones App had, in the order it had them, so the
 * connection behaves identically. What changed is the seam. Four things the
 * effect used to reach for directly belong to whoever owns the packet buffer
 * rather than to the connection, and they are callbacks now:
 *
 *   - `onFrames`      - a flush of dissected frames, to be queued and committed
 *   - `onSocketTable` - re-annotating frames dissected before the table arrived
 *   - `onHostIdentity`- the MACs and addresses the adapter list reveals
 *   - `onNetworkFacts`- what the Worker derived from the capture
 *
 * They are held in a **ref**, deliberately. The connection effect's deps are
 * `[canCapture, agentLinkEnabled]` and must stay that way: a callback whose
 * identity changed between renders would otherwise tear the socket down and
 * reconnect it, which is a reconnect per render on the hottest path in the app.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { pipeline } from '../services/pipelineClient';
import {
  AGENT_WS_URL, summarizeCaptureStats,
  type AgentCommand, type AgentInterface, type AgentAdapter, type AgentLogEntry,
  type AgentMessage, type CaptureDropStats,
} from '../services/agentProtocol';
import { filterCapturableInterfaces } from '../services/captureInterfaces';
import { hostFromAdapters } from '../services/hostIdentity';
import { loadAgentToken, saveAgentToken } from '../services/interfacePrefs';
import type { HostIdentity } from '../services/direction';
import type { NetworkFacts } from '../services/networkFacts';
import type { FrameBatch } from '../services/pipelineClient';

/** How many of the agent's own log lines Driver Info keeps. */
const AGENT_LOG_BUFFER_LIMIT = 1000;

// Samples kept per interface for the picker's sparklines. At the agent's
// 500ms sampling period this is a 15-second window - long enough to show a
// burst arriving and passing, short enough that it still reads as "now".
const INTERFACE_RATE_SAMPLES = 30;

export interface AgentConnectionHost {
  /** False while the user may not capture; the socket is not opened at all. */
  canCapture: boolean;
  /**
   * Whether this window believes capture is running, and how to say it is not.
   *
   * A ref because the message handlers are created once per connection and
   * must read the current value, not the one that existed when they were made
   * - the same reason `selectedInterfacesRef` exists below.
   */
  isCapturingRef: React.RefObject<boolean>;
  /** The agent says idle while this window thinks otherwise. It is the authority. */
  onCaptureStopped: () => void;
  onFrames: (batch: FrameBatch) => void;
  onSocketTable: (message: Extract<AgentMessage, { type: 'socket_table' }>) => void;
  onHostIdentity: (identity: HostIdentity) => void;
  onNetworkFacts: (facts: NetworkFacts) => void;
}

export function useAgentConnection(host: AgentConnectionHost) {
  const { canCapture, isCapturingRef, onCaptureStopped } = host;

  // See the note at the top: the effect's deps must not include these.
  const callbacks = useRef(host);
  callbacks.current = host;

  const [agentStatus, setAgentStatus] = useState<
    "disconnected" | "connecting" | "connected" | "error"
  >("disconnected");
  const [agentCaptureState, setAgentCaptureState] = useState<'idle' | 'sniffing'>('idle');
  /**
   * This connection's id, and whose capture the agent is running.
   *
   * Two Inwire windows on one machine used to fight over a single global
   * sniffer: the second one's remembered adapter selection restarted the
   * capture on *its* adapter the moment it connected, and Stop in either
   * stopped both. The agent owns a capture now, and these two are how this
   * window tells its own capture from somebody else's.
   */
  const [agentClientId, setAgentClientId] = useState<string | null>(null);
  const [captureOwner, setCaptureOwner] = useState<string | null>(null);
  /**
   * Whether this agent wants a pairing token, and whether the one we hold was
   * accepted. `needsToken` is the state Driver Info asks about: the agent is
   * there and answering, and will do nothing until it is paired.
   */
  const [agentNeedsToken, setAgentNeedsToken] = useState(false);
  const [agentToken, setAgentTokenState] = useState<string>(() => loadAgentToken());
  const agentTokenRef = useRef(agentToken);
  useEffect(() => { agentTokenRef.current = agentToken; }, [agentToken]);
  /**
   * A token pasted into Driver Info. Stored and offered immediately, so the
   * pairing takes effect on the connection that is already open rather than
   * waiting for a reconnect.
   */
  const setAgentToken = (token: string) => {
    const trimmed = token.trim();
    saveAgentToken(trimmed);
    setAgentTokenState(trimmed);
    setAgentError(null);
    if (trimmed) sendAgentCommand({ type: 'authenticate', token: trimmed });
  };
  /**
   * Whether the app should be holding a link to the agent at all.
   *
   * Distinct from agentStatus, which reports what the socket is actually
   * doing: "disconnected" covers both "you pressed Disconnect" and "the agent
   * is not running", and Driver Info has to tell those apart to say anything
   * useful. This is the intent; agentStatus is the outcome.
   *
   * Not persisted, on purpose. A reload reconnects - an app that comes back
   * permanently dead with no visible cause reads as broken, and everything
   * else about a reload here is built to look like continuity.
   */
  const [agentLinkEnabled, setAgentLinkEnabled] = useState(true);
  const [agentVersion, setAgentVersion] = useState<string | null>(null);
  // Set when a connection's socket opened but no `hello` arrived within the
  // grace period below - the only signal available for a pre-Task-4 agent,
  // which never sends `hello` at all (see final review finding #5).
  const [agentIncompatible, setAgentIncompatible] = useState(false);
  const [agentInterfaces, setAgentInterfaces] = useState<AgentInterface[]>([]);
  /**
   * What the driver and the agent dropped during this capture, from the
   * agent's once-a-second capture_stats. Null until the first tick, and reset
   * when a capture starts so the number is this capture's. `droppedKernel` is
   * null when the driver's counters could not be read - shown as unknown, not
   * as zero.
   */
  const [captureStats, setCaptureStats] = useState<CaptureDropStats | null>(null);

  const [adapters, setAdapters] = useState<AgentAdapter[]>([]);

  const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);

  const [agentLog, setAgentLog] = useState<AgentLogEntry[]>([]);
  /** Whether Driver Info is open, so a reconnect knows to resubscribe. */
  const logSubscribedRef = useRef(false);
  /**
   * The agent's most recent rejection, surfaced in Driver Info.
   *
   * Agent errors only reached console.warn before, which was tolerable while
   * the sole one was an empty interface list the picker already prevented. A
   * refused Restart has no other visible outcome at all - the button would
   * simply appear to do nothing - so the reason has to reach the panel.
   */
  const [agentError, setAgentError] = useState<string | null>(null);
  // Recent packets/sec per interface, oldest first, for the picker's
  // sparklines. Only populated while the picker is open - the agent samples
  // nothing otherwise.
  const [interfaceRates, setInterfaceRates] = useState<Record<string, number[]>>({});

  /**
   * Drops a selected adapter the agent does not offer.
   *
   * An effect on the interface list rather than a line inside the `hello`
   * handler, because a selection restored from a previous session can be set
   * either before or after that message arrives - and a name that was valid
   * yesterday can belong to an adapter that has since been unplugged or
   * renamed. Keyed on the list, this is correct in both orderings and is a
   * no-op when nothing is stale.
   */
  useEffect(() => {
    if (agentInterfaces.length === 0) return;
    setSelectedInterfaces((prev) => {
      const valid = prev.filter((name) => agentInterfaces.some((iface) => iface.name === name));
      return valid.length === prev.length ? prev : valid;
    });
  }, [agentInterfaces]);

  // Same reasoning as isCapturingRef: the post-reconnect resync in the
  // `hello` handler below needs the *current* interface selection, not
  // whatever it was when the WebSocket effect's handlers were created.
  const selectedInterfacesRef = useRef(selectedInterfaces);
  useEffect(() => {
    selectedInterfacesRef.current = selectedInterfaces;
  }, [selectedInterfaces]);

  // `agentInterfacesRef` and `captureInterfaceRef` used to sit here: the
  // adapter a live frame arrived on, kept in refs because the decode happened
  // inside the WebSocket message handler. It does not any more - dissection is
  // in the Worker, which is told the list through `pipeline.setInterfaces`
  // below - so both were written on every list change and read by nothing.

  // Local Agent Connection - always tries to reach ws://localhost:8999 so
  // the "Download Driver" button can auto-detect the agent running and
  // flip to "Agent Connected", independent of whether capture is active.
  // Packets are only recorded into the buffer while isCapturing is true.
  //
  // The socket itself lives in the pipeline Worker now, along with the
  // ordering window, the trackers and dissection (docs/decisions/0003). What
  // reaches this effect is what always reached it: control messages, and
  // batches of finished frames. Nothing here parses a packet.
  useEffect(() => {
    if (!canCapture) return;
    // Driver Info's Disconnect. Bailing out here rather than tearing the
    // connection down somewhere else is the point: React runs this effect's
    // existing cleanup on the way in, and that cleanup already does exactly
    // what disconnecting means - it stops the Worker retrying, closes the
    // socket, and reports "disconnected". A second teardown path would be a
    // second thing to keep correct.
    if (!agentLinkEnabled) return;

    let connectedDelay: NodeJS.Timeout | null = null;
    // A pre-Task-4 agent never sends `hello` at all, so its absence within
    // this window (started on every fresh socket open, cleared the moment
    // `hello` arrives) is the only way to flag it as incompatible instead of
    // silently showing a normal "Agent Connected" with zero packets ever
    // arriving.
    let helloTimeout: NodeJS.Timeout | null = null;
    // Only the very first connection attempt shows "Connecting..." - once we
    // know the agent isn't there, silent background retries every 3s keep
    // the status calmly on "disconnected" instead of flashing "Connecting"
    // on every retry (which read as a repeating loop when the agent was
    // never running to begin with).
    let isFirstAttempt = true;

    pipeline.onStatus = (status) => {
      if (status === 'connecting') {
        if (isFirstAttempt) setAgentStatus("connecting");
        return;
      }
      if (status === 'connected') {
        console.log("[Inwire] Connected to Local Agent");
        // Hold "Connecting..." for a beat after the handshake succeeds so
        // the button doesn't flash instantly - and so a socket that drops
        // right back off (e.g. a page reload racing the connection) reads
        // as still-connecting rather than a confusing connect/disconnect flicker.
        if (connectedDelay) clearTimeout(connectedDelay);
        connectedDelay = setTimeout(() => setAgentStatus("connected"), 2000);
        setAgentIncompatible(false);
        if (helloTimeout) clearTimeout(helloTimeout);
        helloTimeout = setTimeout(() => {
          console.warn("[Inwire] No hello received from agent within 5s - treating it as incompatible.");
          setAgentIncompatible(true);
        }, 5000);
        return;
      }

      if (connectedDelay) { clearTimeout(connectedDelay); connectedDelay = null; }
      if (helloTimeout) { clearTimeout(helloTimeout); helloTimeout = null; }
      if (status === 'error') {
        console.warn("[Inwire] WebSocket connection failed. Agent might not be running.");
        if (isFirstAttempt) setAgentStatus("error");
      } else {
        console.log("[Inwire] Disconnected from Local Agent. Reconnecting in 3s...");
        setAgentStatus("disconnected");
        setAgentIncompatible(false);
        // Facts about a connection that no longer exists. Driver Info kept
        // showing the version and the last rejection of an agent that was
        // gone, which read as "still there, still refusing".
        setAgentVersion(null);
        setAgentError(null);
      }
      isFirstAttempt = false;
    };

    pipeline.onAgentMessage = (message) => {
      if (message.type === 'hello') {
        if (helloTimeout) {
          clearTimeout(helloTimeout);
          helloTimeout = null;
        }
        setAgentIncompatible(false);
        setAgentError(null);
        setAgentVersion(message.version);
        setAgentCaptureState(message.state);
        setAgentClientId(message.clientId ?? null);
        setCaptureOwner(message.owner ?? null);

        // Pairing comes before anything else: an agent with a token
        // configured answers every other command with `auth_required`.
        const needsToken = message.authRequired === true;
        setAgentNeedsToken(needsToken);
        if (needsToken) {
          if (agentTokenRef.current) {
            pipeline.command({ type: 'authenticate', token: agentTokenRef.current });
          } else {
            // Nothing else is sent. The resync below would only collect
            // refusals, and Driver Info is where the token goes in.
            return;
          }
        }
        setAgentInterfaces(filterCapturableInterfaces(message.interfaces));

        // Deliberately does NOT default to every interface. Capture is
        // single-interface and the user has to name the adapter before a
        // capture can start; pre-selecting all nine would hand Start a
        // ready-made selection and quietly defeat that. An existing
        // selection survives a reconnect untouched.
        setSelectedInterfaces((prev) => (prev.length > 1 ? [prev[0]] : prev));

        // Reconnect resync. A fresh connection always finds the agent idle
        // with every interface selected - it stops capturing when the last
        // client drops - so push our desired state back to it. `hello` is the
        // only per-connection signal there is.
        //
        // On a first-ever connection selectedInterfacesRef is still empty
        // (it gets populated from this very message), so nothing is sent and
        // the agent keeps its own default of every interface. That is correct.
        //
        // Not when another window owns the capture: this resync is what used
        // to hijack it. Both commands would be refused now, but asking at all
        // would put a `capture_busy` error in front of a user who has done
        // nothing.
        const ownedElsewhere = (message.owner ?? null) !== null
          && message.owner !== (message.clientId ?? null);
        if (!ownedElsewhere) {
          if (selectedInterfacesRef.current.length > 0) {
            pipeline.command({ type: 'set_interfaces', interfaces: selectedInterfacesRef.current });
          }
          if (isCapturingRef.current) {
            pipeline.command({ type: 'start_capture' });
          }
        }
        // A log subscription lives on the agent's socket, so a reconnect
        // drops it. Resubscribing here, and clearing first, avoids showing
        // a fresh backlog stitched onto the tail of the dead connection's
        // timeline as though it were continuous.
        if (logSubscribedRef.current) {
          setAgentLog([]);
          pipeline.command({ type: 'subscribe_logs' });
        }

        // Who owns which socket, for process attribution.
        //
        // Here rather than when the WebSocket opens, and the difference is not
        // cosmetic: an agent with a pairing token answers every command with
        // `auth_required` until `authenticate` has been accepted, and the
        // socket is open well before that. Sent from this handler it queues
        // behind the `authenticate` above on the same connection, which
        // delivers in order.
        //
        // Unconditional, like the log resync: a subscription lives on the
        // agent's socket and dies with it, so a reconnect has to ask again.
        // The opening snapshot is the valuable half - it describes connections
        // that were already open, which are exactly the long-lived ones a
        // capture catches mid-stream.
        pipeline.command({ type: 'subscribe_sockets' });
        // How this machine's adapters are configured. The Network panel shows
        // it, and the packet list needs one field out of it - the adapter's
        // own MAC - to say which way each frame went. Subscribed here for the
        // same ordering reason as the socket table: it queues behind
        // `authenticate` on a connection that may still be unpaired.
        pipeline.command({ type: 'subscribe_adapters' });
        return;
      }

      if (message.type === 'state') {
        setAgentCaptureState(message.state);
        setCaptureOwner(message.owner ?? null);
        // A `state` arriving on a connection that was waiting to be paired is
        // the agent saying the token was accepted.
        setAgentNeedsToken(false);
        setAgentInterfaces(filterCapturableInterfaces(message.interfaces));
        // The agent is the authority on whether capture is running. It says
        // idle while this tab believes otherwise when every selected adapter
        // failed to open, or when another tab stopped it - either way the
        // Start button showing "stop" would be a promise about traffic
        // nobody is capturing.
        if (message.state === 'idle' && isCapturingRef.current) {
          onCaptureStopped();
        }
        return;
      }

      if (message.type === 'error') {
        console.warn('[Inwire] Agent error:', message.code ?? '', message.message);
        setAgentError(message.message);
        // A rejected token is worth more than an error line: the field has to
        // come back so it can be corrected, and the stored one is wrong.
        if (message.code === 'auth_failed') setAgentNeedsToken(true);
        return;
      }

      if (message.type === 'capture_stats') {
        setCaptureStats(summarizeCaptureStats(message));
        return;
      }

      if (message.type === 'adapter_config') {
        setAdapters(message.adapters);
        // The one fact the packet list needs from this: which MACs and
        // addresses are ours. Told to the Worker, which dissects live frames
        // and is the only side that can decide a direction as a frame arrives.
        const identity = hostFromAdapters(message.adapters);
        if (identity !== null) callbacks.current.onHostIdentity(identity);
        return;
      }

      if (message.type === 'socket_table') {
        // The buffer is the host's, so the re-annotation pass is too - this
        // hook only routes the message. See `App.applySocketTable`.
        callbacks.current.onSocketTable(message);
        return;
      }

      if (message.type === 'log') {
        setAgentLog((prev) => {
          const next = prev.concat(message.lines);
          return next.length > AGENT_LOG_BUFFER_LIMIT
            ? next.slice(next.length - AGENT_LOG_BUFFER_LIMIT)
            : next;
        });
        return;
      }

      if (message.type === 'interface_stats') {
        setInterfaceRates((prev) => {
          const next: Record<string, number[]> = {};
          for (const rate of message.interfaces) {
            const series = prev[rate.name] ?? [];
            // A fixed-length window, so the sparkline scrolls rather than
            // compressing an ever-longer history into the same 68px.
            next[rate.name] = series.concat(rate.packetsPerSec).slice(-INTERFACE_RATE_SAMPLES);
          }
          return next;
        });
      }
    };

    // Dissected frames, in capture order, once per flush. Queued rather than
    // committed: the flush below commits the batch in one state update, which
    // is what keeps ingest cost independent of buffer size.
    // Dissected frames, in capture order, once per flush. Handed straight to
    // the host: the queueing and the flush belong to whoever owns the buffer.
    pipeline.onFrames = (batch) => callbacks.current.onFrames(batch);

    pipeline.onFailure = (message) => {
      console.warn('[Inwire] packet pipeline:', message);
    };

    // Derived in the Worker and only read here, so a fact cannot be invented
    // on its way to the screen.
    pipeline.onNetworkFacts = (facts) => callbacks.current.onNetworkFacts(facts);

    pipeline.connect(AGENT_WS_URL);

    return () => {
      if (connectedDelay) clearTimeout(connectedDelay);
      if (helloTimeout) clearTimeout(helloTimeout);
      pipeline.onStatus = () => {};
      pipeline.onAgentMessage = () => {};
      pipeline.onFrames = () => {};
      pipeline.onFailure = () => {};
      pipeline.onNetworkFacts = () => {};
      pipeline.disconnect();
      setAgentStatus("disconnected");
    };
  }, [canCapture, agentLinkEnabled]);

  // Which adapter each frame's `iface` index names. The Worker builds the
  // Frame layer's interface rows from it.
  useEffect(() => {
    pipeline.setInterfaces(agentInterfaces.map((iface, index) => ({
      id: iface.id ?? index,
      name: iface.name,
      label: iface.label ?? iface.name,
    })));
  }, [agentInterfaces]);

  const sendAgentCommand = (command: AgentCommand) => {
    pipeline.command(command);
  };

  // Memoized with an empty dep array on purpose: DriverInfoPanel subscribes
  // in a mount effect keyed on these identities, so a fresh function each
  // render would drive an unsubscribe/subscribe loop. That is safe only
  // while sendAgentCommand reads nothing but module-level helpers - if it
  // ever depends on state, these captures go stale.
  const subscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = true;
    setAgentLog([]);
    pipeline.command({ type: 'subscribe_logs' });
    // A closed socket is not an error: the hello handler resubscribes on
    // reconnect, so opening the panel while the agent is down and having it
    // fill in when the agent returns is the intended behavior.
  }, []);

  const unsubscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = false;
    pipeline.command({ type: 'unsubscribe_logs' });
  }, []);

  const clearAgentLog = useCallback(() => setAgentLog([]), []);

  /**
   * Cleared on open so a reopened picker draws from now rather than stitching
   * a fresh series onto samples from minutes ago as if the intervening time
   * had been idle.
   */
  const clearInterfaceRates = useCallback(() => setInterfaceRates({}), []);

  /**
   * The drop counters describe ONE capture. The agent resets its own on
   * `start_capture` and the first tick replaces this within a second, but a
   * stale "dropped" chip for that second would be a lie.
   */
  const clearCaptureStats = useCallback(() => setCaptureStats(null), []);

  return {
    agentStatus, agentCaptureState, agentClientId, captureOwner,
    agentNeedsToken, agentToken, setAgentToken,
    agentLinkEnabled, setAgentLinkEnabled,
    agentVersion, agentIncompatible, agentInterfaces,
    captureStats, adapters, agentLog, agentError, interfaceRates,
    selectedInterfaces, setSelectedInterfaces, selectedInterfacesRef,
    sendAgentCommand, subscribeAgentLog, unsubscribeAgentLog,
    clearAgentLog, clearInterfaceRates, clearCaptureStats,
  };
}
