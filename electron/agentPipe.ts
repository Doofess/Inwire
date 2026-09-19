/**
 * The connection to the capture agent: a named pipe, owned by main.
 *
 * ## Why this is not in the Worker any more
 *
 * It could not be. `net.connect` is Node, and the renderer has no Node - a
 * `sandbox: true` renderer least of all. So the OS handle lives here, and the
 * pipeline Worker gets the other end of a `MessageChannelMain`; see
 * `src/services/agentLink.ts` for what travels over it and why the renderer's
 * main thread never appears in the frame path.
 *
 * That inverts the old constraint exactly. While the transport was a
 * WebSocket, the socket *had* to be in the renderer - `is_origin_allowed`
 * refuses a connection with no `Origin`, and only a renderer sends one.
 *
 * ## What the pipe replaced, and what that deleted
 *
 * `ws://localhost:8999` was reachable by every process on the machine, and
 * everything defensive in the old agent existed because of that: a pairing
 * token the user pasted in by hand, an origin allowlist, an `icacls` call on
 * `config.json`. A named pipe carries a security descriptor, so the kernel
 * answers the question those were asked to answer - see the SDDL in
 * `local-agent/pipe_server.py`, where the interactive-user ACE is the point.
 *
 * State honestly what that does not stop: an administrator, and code injected
 * into this process. It is a materially higher bar than a bearer token any
 * process running as the user could read out of the app's own storage, and it
 * is enforced by the kernel rather than by us.
 *
 * ## What is left here
 *
 * The channel, and nothing else. Everything about the byte stream - framing,
 * reconnection, the read-boundary rule - is in `pipeTransport.ts`, which
 * imports no Electron so that `scripts/electron/agent-link.ts` can drive it
 * against a real pipe under plain `tsx`.
 */
import { MessageChannelMain, type MessagePortMain, type WebContents } from 'electron';
import { execFile } from 'node:child_process';
import type { FromAgentLink, ToAgentLink } from '../src/services/agentLink';
import { readAgentService } from './agentService';
import { classifyStart, MAX_AUTO_START_ATTEMPTS, worthStarting } from './serviceStart';
import { AGENT_PIPE_PATH, PipeTransport } from './pipeTransport';
import { AGENT_PORT_CHANNEL } from './channels';

/**
 * How often the service's registry key is re-read while the link is down.
 *
 * The retry runs every 3s and spawning `reg` that often would be a process a
 * second for as long as the agent is missing - which, for somebody who
 * uninstalled it, is for ever. The answer changes when a person changes it, so
 * a slower cadence loses nothing.
 */
const SERVICE_POLL_MS = 20_000;

/**
 * Long enough for the SCM to start a service, short enough not to wedge quit.
 *
 * `sc start` returns as soon as the SCM has accepted the request, not when the
 * service is up, so this bounds a hung SCM rather than a slow agent.
 */
const START_TIMEOUT_MS = 10_000;

/**
 * One renderer's link to the agent.
 *
 * Per renderer rather than per app because the port is: a reload makes a new
 * renderer, and the old port is dead the moment its Worker is.
 */
export class AgentPipeLink {
  private port: MessagePortMain | null = null;
  private readonly pipe: PipeTransport;
  /** When the registry was last read, so a 3s retry does not spawn `reg`. */
  private serviceCheckedAt = 0;
  /**
   * Unelevated start attempts made without being asked.
   *
   * Bounded by `MAX_AUTO_START_ATTEMPTS`, and reset by the two things that
   * change the answer: a start that worked, and a person clicking the button.
   */
  private autoStarts = 0;

  constructor(pipePath: string = AGENT_PIPE_PATH) {
    this.pipe = new PipeTransport({
      status: (status) => {
        this.tell({ type: 'status', status });
        // Only while it is down. A connected link needs no diagnosis, and
        // asking anyway would be a second source of truth that can disagree
        // with the pipe about whether the agent is there.
        if (status !== 'connected') void this.reportService();
      },
      text: (text) => this.tell({ type: 'text', text }),
      // A copy across the port, not a transfer: `MessagePortMain`'s transfer
      // list accepts only ports. One memcpy per ~256 kB batch at ~30 batches a
      // second is what the renderer's main thread staying out of the frame
      // path costs, and it is not the number worth optimising.
      binary: (bytes) => this.tell({ type: 'binary', bytes }),
    }, pipePath);
  }

  /** Gives this renderer one end of a fresh channel and keeps the other. */
  attach(contents: WebContents): void {
    // A reload replaces the link rather than adding one. Without this a dev
    // session accumulates a pipe connection per refresh, and the agent's
    // `capture_busy` starts arbitrating between a window and its own ghosts.
    this.detach();

    const { port1, port2 } = new MessageChannelMain();
    this.port = port2;
    port2.on('message', (event) => this.receive(event.data as ToAgentLink));
    // Nothing is delivered until this is called, and the failure is silent:
    // the Worker asks to connect, main never hears it, and the app sits on
    // "connecting" for ever.
    port2.start();
    contents.postMessage(AGENT_PORT_CHANNEL, null, [port1]);
  }

  /**
   * Drops the pipe and immediately reconnects, keeping the port.
   *
   * What this is for: a capture driver was just installed, and the interface
   * picker is showing the list from before it existed. `refresh_adapters` does
   * **not** fix that - it re-reads adapter *configuration* and never touches
   * `AVAILABLE_INTERFACES`, and it is filtered by that same stale list, so a
   * brand-new adapter is excluded from its own snapshot. The agent re-reads
   * the interface list in `register()`, once per client connection, so a new
   * connection is what re-enumerates.
   *
   * Preferred over `restart_agent`, which also works: that kills a LocalSystem
   * service the app deliberately has no rights to stop, and only when the
   * agent's `RESTART_SUPPORTED` says it may. This needs neither.
   *
   * The renderer sees a `disconnected` then a fresh `hello`, which is the same
   * sequence an agent restart already produces and which it already handles.
   */
  recycle(): void {
    this.pipe.close();
    this.pipe.open();
  }

  /** Drops the connection and the channel. Called on reload and on quit. */
  detach(): void {
    this.pipe.close();
    this.port?.close();
    this.port = null;
  }

  private receive(message: ToAgentLink): void {
    switch (message.type) {
      case 'open': this.pipe.open(); break;
      case 'close': this.pipe.close(); break;
      case 'send': this.pipe.send(message.text); break;
      case 'startService': void this.startService(); break;
    }
  }

  private tell(message: FromAgentLink): void {
    this.port?.postMessage(message);
  }

  /**
   * Answers "why is it not there", with facts and no conclusion.
   *
   * `services/agentHealth.ts` draws the conclusion, in the renderer, where it
   * is pure and drivable from a script. This half is here because both inputs
   * are things only main can reach.
   */
  private async reportService(): Promise<void> {
    const now = Date.now();
    if (now - this.serviceCheckedAt < SERVICE_POLL_MS) return;
    this.serviceCheckedAt = now;
    const facts = await readAgentService();
    this.tell({ type: 'service', facts, shortConnections: this.pipe.shortConnections });

    // The agent is demand-start, so a link that is down on a machine where the
    // service is installed and not disabled is the ordinary case rather than a
    // fault - it means nothing has asked for it yet. Asking is this line.
    if (worthStarting(facts) && this.autoStarts < MAX_AUTO_START_ATTEMPTS) {
      this.autoStarts += 1;
      const verdict = classifyStart(await this.runStart());
      if (verdict.outcome === 'running') {
        // Do not wait for the 20s poll to come round again: the pipe's own
        // backoff is already retrying in the hundreds of milliseconds, and it
        // is what will actually find the agent.
        this.autoStarts = 0;
      } else if (verdict.outcome === 'hopeless') {
        // Nothing about this machine will change by asking again. The facts
        // already sent say which of the three reasons it was, and
        // `agentHealth.ts` turns that into the sentence.
        this.autoStarts = MAX_AUTO_START_ATTEMPTS;
      }
      console.log('[agent-pipe] auto start:', verdict.reason);
    }
  }

  /**
   * Starts the service **without** elevating, and answers with the exit code.
   *
   * `null` means the process could not be run or did not finish - which says
   * nothing about the service, and `classifyStart` treats it that way.
   *
   * The arguments are constants. Nothing the renderer sends reaches this
   * command line; see `startService` below for why that rule is absolute here.
   */
  private runStart(): Promise<number | null> {
    if (process.platform !== 'win32') return Promise.resolve(null);
    return new Promise((resolve) => {
      execFile(
        'sc.exe', ['start', 'InwireAgent'],
        { timeout: START_TIMEOUT_MS, windowsHide: true },
        (error) => {
          if (!error) { resolve(0); return; }
          const failure = error as NodeJS.ErrnoException & { killed?: boolean };
          // Same shape rule as `provesAbsent`: a NUMERIC code is the tool's own
          // answer, and everything else - a spawn failure, a timeout - is us
          // failing to ask. A killed process carries a code on some Node
          // versions, so that is tested first.
          if (failure.killed || typeof failure.code !== 'number') { resolve(null); return; }
          resolve(failure.code);
        },
      );
    });
  }

  /**
   * Starts the service as soon as the app is ready, before any window asks.
   *
   * This is the whole of goal one on the app's side: the person launches
   * Inwire and the agent is coming up while the window is still painting,
   * rather than after a renderer has mounted, discovered the link is down,
   * diagnosed it, and offered a button.
   *
   * Deliberately not awaited by `whenReady`: a slow SCM must delay the window,
   * not the app.
   */
  ensureRunning(): void {
    void this.reportService();
  }

  /**
   * Raises the UAC prompt that starts the service.
   *
   * The app is unelevated on purpose - the dissector must never parse hostile
   * bytes as an administrator - so by default it cannot start a LocalSystem
   * service. What it can do is ask Windows to, which is a prompt the person
   * sees and refuses if they did not expect it.
   *
   * **The unelevated attempt comes first, and usually succeeds.**
   * `installer/setup.iss` runs `sc sdset` to grant `RP` on the service's `IU`
   * ACE (`GrantServiceStartToInteractiveUsers`) precisely so an unelevated
   * `sc start InwireAgent` works without a prompt. This used to escalate
   * unconditionally, so the prompt appeared every time and the grant bought
   * nothing here - and the comment that stood in its place said "no amount of
   * arranging makes it able to", which the installer had already disproved.
   *
   * Escalation is now reached only by `SC_ACCESS_DENIED`, which is the one
   * code a prompt can fix. On a disabled or uninstalled service a UAC prompt
   * would ask a person to authorise something that cannot work, and they would
   * have no way to know that before answering.
   *
   * The arguments are constants. Nothing the renderer sends reaches this
   * command line, because a privileged command built from a message is a
   * privileged command an injected script can write.
   */
  private async startService(): Promise<void> {
    if (process.platform !== 'win32') return;
    // A click is a person saying they want this, so the automatic budget is
    // refilled: whatever they just fixed - enabling the service, reinstalling
    // it - should not be met with an app that has given up asking.
    this.autoStarts = 0;
    const verdict = classifyStart(await this.runStart());
    if (verdict.outcome !== 'needsElevation') {
      console.log('[agent-pipe] start service:', verdict.reason);
      this.serviceCheckedAt = 0;
      return;
    }
    execFile(
      'powershell.exe',
      [
        '-NoProfile', '-NonInteractive', '-Command',
        "Start-Process -FilePath 'sc.exe' -ArgumentList 'start','InwireAgent' -Verb RunAs -WindowStyle Hidden",
      ],
      { windowsHide: true },
      (error) => {
        // A refused UAC prompt lands here and is not an error worth reporting:
        // the person said no, and the link's own state already says the agent
        // is not running. Re-checking is what turns a yes into a connection.
        if (error) console.warn('[agent-pipe] start service:', error.message);
        this.serviceCheckedAt = 0;
      },
    );
  }
}
