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
  summarizeCaptureStats,
  type AgentCommand, type AgentInterface, type AgentAdapter, type AgentLogEntry,
  type AgentMessage, type CaptureDropStats,
} from '../services/agentProtocol';
import { filterCapturableInterfaces } from '../services/captureInterfaces';
import { diagnoseAgent, type AgentServiceFacts } from '../services/agentHealth';
import { hostFromAdapters } from '../services/hostIdentity';
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
   * What main could learn about the service while the link was down.
   *
   * Null until it answers, and that is not the same as "nothing is wrong":
   * `diagnoseAgent` treats the two apart, so a panel opened in the first
   * second says it is still checking rather than naming a cause.
   */
  const [agentService, setAgentService] = useState<AgentServiceFacts | null>(null);
  const [agentShortConnections, setAgentShortConnections] = useState(0);
  const [agentLinkEnabled, setAgentLinkEnabled] = useState(true);
  const [agentVersion, setAgentVersion] = useState<string | null>(null);
  /**
   * The Npcap device object's DACL, as the agent read it - the SYSTEM half of
   * the driver-access answer the Update Center shows. Null until an agent that
   * reports it says hello, which is also what it stays on a machine with no
   * driver installed. ADR 0033.
   */
  const [agentNpcapAccess, setAgentNpcapAccess] = useState<string | null>(null);
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
  /** The same shape, for the interface counters the adapter panel draws. */
  const interfaceStatsSubscribedRef = useRef(false);
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
  // whatever it was when the agent-link effect's handlers were created.
  const selectedInterfacesRef = useRef(selectedInterfaces);
  useEffect(() => {
    selectedInterfacesRef.current = selectedInterfaces;
  }, [selectedInterfaces]);

  // `agentInterfacesRef` and `captureInterfaceRef` used to sit here: the
  // adapter a live frame arrived on, kept in refs because the decode happened
  // inside the agent message handler. It does not any more - dissection is
  // in the Worker, which is told the list through `pipeline.setInterfaces`
  // below - so both were written on every list change and read by nothing.

  // Local Agent Connection - opened as soon as this hook runs, whether or not
  // capture is active, so Driver Info can tell "the agent is there and idle"
  // from "the agent is not running" without anybody pressing Start. Packets
  // are only recorded into the buffer while isCapturing is true.
  //
  // **There is no socket here, and no port to dial.** The link is the named
  // pipe `\\.\pipe\inwire-agent`, held by MAIN, whose ACL is the whole of the
  // authentication (ADR 0029). Main deframes it and posts the payload onto one
  // end of a `MessageChannelMain`; the renderer's main thread receives that
  // port from the preload and transfers it straight into the pipeline Worker,
  // where the ordering window, the trackers and dissection live
  // (docs/decisions/0007). `pipelineClient` is this side's handle on that
  // Worker and is deliberately shaped like the WebSocket it replaced -
  // `connect`, `send`, a message callback, a status callback - which is why
  // this effect reads as if a socket were still here. It is not: what reaches
  // it is control messages and batches of finished frames, and nothing here
  // parses a packet.
  useEffect(() => {
    if (!canCapture) return;
    // Driver Info's Disconnect. Bailing out here rather than tearing the
    // connection down somewhere else is the point: React runs this effect's
    // existing cleanup on the way in, and that cleanup already does exactly
    // what disconnecting means - it stops the Worker retrying, closes the
    // socket, and reports "disconnected". A second teardown path would be a
    // second thing to keep correct.
    if (!agentLinkEnabled) return;

    // A pre-Task-4 agent never sends `hello` at all, so its absence within
    // this window (started on every fresh socket open, cleared the moment
    // `hello` arrives) is the only way to flag it as incompatible instead of
    // silently showing a normal "Agent Connected" with zero packets ever
    // arriving.
    let helloTimeout: NodeJS.Timeout | null = null;
    // Whether a retry should be silent.
    //
    // This replaces a latched `isFirstAttempt`, and the difference is that it
    // is **cleared by a working connection**. Latched once, it meant every
    // attempt after the first was invisible for the life of the window - so
    // the agent stopping and restarting, which is now the ordinary case
    // (ADR 0035), left the bar saying "disconnected" all the way through a
    // reconnect that was going fine. What the latch was right about is kept:
    // once we know the agent is not there, three-second retries must not flash
    // "Connecting" for ever.
    let quietRetry = false;

    pipeline.onStatus = (status) => {
      if (status === 'connecting') {
        if (!quietRetry) setAgentStatus("connecting");
        return;
      }
      if (status === 'connected') {
        // **Not `connected` yet, and this is the fix rather than an omission.**
        // An accepted socket says a pipe answered; it does not say the thing
        // answering speaks this protocol or knows what its own state is. The
        // status moves on `hello`, which is the message that carries both.
        //
        // What used to be here was a 2,000 ms timer to `connected`, which on a
        // successful *retry* left the bar reading "Agent not running" for two
        // seconds after `hello` had already been processed - the app knew and
        // was waiting out a timer to say so.
        console.log("[Inwire] Pipe open - waiting for hello");
        if (helloTimeout) clearTimeout(helloTimeout);
        helloTimeout = setTimeout(() => {
          console.warn("[Inwire] No hello received from agent within 5s - treating it as incompatible.");
          setAgentIncompatible(true);
          // The socket is up and the agent is not answering, which is neither
          // "connecting" nor "connected". Without this the bar sits on
          // "Connecting..." for ever against an agent that will never reply,
          // and `agentIncompatible` reaches no surface that says why.
          setAgentStatus("error");
          quietRetry = true;
        }, 5000);
        return;
      }

      if (helloTimeout) { clearTimeout(helloTimeout); helloTimeout = null; }
      if (status === 'error') {
        console.warn("[Inwire] Agent link failed. Agent might not be running.");
        if (!quietRetry) setAgentStatus("error");
      } else {
        console.log("[Inwire] Disconnected from Local Agent. Reconnecting in 3s...");
        setAgentStatus("disconnected");
        setAgentIncompatible(false);
        // Facts about a connection that no longer exists. Driver Info kept
        // showing the version and the last rejection of an agent that was
        // gone, which read as "still there, still refusing".
        //
        // `agentNpcapAccess` is in here for a sharper reason than tidiness:
        // `decideDriverAccess` gives the DACL priority over the registry, so a
        // DACL left behind by a dead link outranks every later registry read
        // for the life of the window. The direction that must not happen is a
        // stale `admin-only` describing a driver that has since been
        // reinstalled open - `npcapAccess.ts` says the answer must never be
        // wrong that way round, and keeping it would be exactly that.
        //
        // Only here, not in the `error` branch above: `close` always follows an
        // `error` on the pipe (`pipeTransport.ts`), so this runs either way.
        setAgentVersion(null);
        setAgentError(null);
        setAgentNpcapAccess(null);
      }
      // Every path to here is a connection that did not work. The next attempt
      // is silent; `hello` is what makes it loud again.
      quietRetry = true;
    };

    pipeline.onAgentMessage = (message) => {
      if (message.type === 'hello') {
        if (helloTimeout) {
          clearTimeout(helloTimeout);
          helloTimeout = null;
        }
        // The one message that proves the link works, so it is the one that
        // moves the status. A reconnect after this is worth showing again.
        setAgentStatus("connected");
        quietRetry = false;
        console.log("[Inwire] Connected to Local Agent");
        setAgentIncompatible(false);
        setAgentError(null);
        setAgentVersion(message.version);
        setAgentNpcapAccess(message.npcapAccess ?? null);
        setAgentCaptureState(message.state);
        setAgentClientId(message.clientId ?? null);
        setCaptureOwner(message.owner ?? null);

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
        // The interface counters live on that socket too, and their failure is
        // quieter than the log's: the adapter panel keeps drawing the last
        // thirty samples, so a frozen chart reads as a genuinely idle adapter
        // rather than as a dropped subscription. Cleared first for the same
        // reason the log is - a fresh series stitched onto a dead connection's
        // tail would be read as continuous.
        if (interfaceStatsSubscribedRef.current) {
          setInterfaceRates({});
          pipeline.command({ type: 'subscribe_interface_stats' });
        }

        // Who owns which socket, for process attribution.
        //
        // Sent from the `hello` handler rather than when the link opens, so it
        // cannot race the handshake.
        //
        // Unconditional, like the log resync: a subscription lives on the
        // connection and dies with it, so a reconnect has to ask again.
        // The opening snapshot is the valuable half - it describes connections
        // that were already open, which are exactly the long-lived ones a
        // capture catches mid-stream.
        pipeline.command({ type: 'subscribe_sockets' });
        // How this machine's adapters are configured. The Network panel shows
        // it, and the packet list needs one field out of it - the adapter's
        // own MAC - to say which way each frame went. Subscribed here for the
        // same ordering reason as the socket table.
        pipeline.command({ type: 'subscribe_adapters' });
        return;
      }

      if (message.type === 'state') {
        setAgentCaptureState(message.state);
        setCaptureOwner(message.owner ?? null);
        setAgentInterfaces(filterCapturableInterfaces(message.interfaces));
        // The agent is the authority on whether capture is running. It says
        // idle while this window believes otherwise when every selected adapter
        // failed to open, or when another Inwire window stopped it - either way the
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

    pipeline.onAgentService = (facts, shortConnections) => {
      setAgentService(facts);
      setAgentShortConnections(shortConnections);
    };

    pipeline.connect();

    return () => {
      if (helloTimeout) clearTimeout(helloTimeout);
      pipeline.onStatus = () => {};
      pipeline.onAgentMessage = () => {};
      pipeline.onFrames = () => {};
      pipeline.onFailure = () => {};
      pipeline.onNetworkFacts = () => {};
      pipeline.onAgentService = () => {};
      pipeline.disconnect();
      setAgentStatus("disconnected");
    };
  }, [canCapture, agentLinkEnabled]);

  // Which adapter each frame's `iface` index names, and how to read its
  // frames. The Worker builds the Frame layer's interface rows from the first
  // and picks a link-layer dissector with the second - it is the only side
  // that dissects, so this is the only route either fact has.
  useEffect(() => {
    pipeline.setInterfaces(agentInterfaces.map((iface, index) => ({
      id: iface.id ?? index,
      name: iface.name,
      label: iface.label ?? iface.name,
      // Forwarded rather than defaulted here. An agent that did not say and an
      // agent that said Ethernet are different facts, and only the first may
      // be overridden by a later answer.
      linkType: iface.linkType,
    })));
  }, [agentInterfaces]);

  /**
   * Why the agent is not there, in a sentence somebody can act on.
   *
   * Derived rather than stored: every input is already state, and a fifth
   * piece of state holding a conclusion drawn from four others is a fifth
   * thing that can be stale.
   */
  const agentHealth = diagnoseAgent({
    status: agentStatus,
    service: agentService,
    shortConnections: agentShortConnections,
  });

  /** Asks main to raise the UAC prompt that starts the service. */
  const startAgentService = () => {
    pipeline.startAgentService();
  };

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
   * The adapter panel's sampling, remembered across a reconnect.
   *
   * The flag is the whole point. A subscription lives on the agent's socket, so
   * a drop takes it silently - and unlike the log, whose absence is a panel
   * that stops filling, this one leaves thirty stale samples on screen that
   * read as a quiet adapter. `hello` re-sends it when this is set.
   */
  const setInterfaceStatsSubscribed = useCallback((on: boolean) => {
    interfaceStatsSubscribedRef.current = on;
    if (on) {
      setInterfaceRates({});
      pipeline.command({ type: 'subscribe_interface_stats' });
    } else {
      pipeline.command({ type: 'unsubscribe_interface_stats' });
    }
  }, []);

  /**
   * The drop counters describe ONE capture. The agent resets its own on
   * `start_capture` and the first tick replaces this within a second, but a
   * stale "dropped" chip for that second would be a lie.
   */
  const clearCaptureStats = useCallback(() => setCaptureStats(null), []);

  return {
    agentStatus, agentCaptureState, agentClientId, captureOwner,
    agentHealth, startAgentService,
    agentLinkEnabled, setAgentLinkEnabled,
    agentVersion, agentNpcapAccess, agentIncompatible, agentInterfaces,
    captureStats, adapters, agentLog, agentError, interfaceRates,
    selectedInterfaces, setSelectedInterfaces, selectedInterfacesRef,
    sendAgentCommand, subscribeAgentLog, unsubscribeAgentLog,
    clearAgentLog, clearInterfaceRates, clearCaptureStats, setInterfaceStatsSubscribed,
  };
}
