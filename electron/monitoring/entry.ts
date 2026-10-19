/**
 * Monitoring's intake, as an Electron `utilityProcess` (ADRs 0058, 0059).
 *
 * The reasons for a process rather than main or the renderer are the capture
 * store's, and are in `electron/store/entry.ts`: a crash domain of its own,
 * synchronous file I/O for the journal, and none of a renderer's privileges. A
 * UDP socket bound to a port an exporter can reach is one more reason - what
 * arrives on it is hostile bytes, and they should land in a process whose only
 * neighbours are two files.
 *
 * As little as possible lives here. The rules are `collector.ts`, driven under
 * plain `tsx` by `scripts/monitoring/runtime.ts`; the socket is `udp.ts`; the
 * files are `volume.ts`. This file only moves messages between
 * `process.parentPort`, a `MessagePortMain` and the collector.
 *
 * Control (open, inspect, discard, discard-preview, retention, retention-preview, start, stop, dispose, status) travels on `parentPort`. The
 * Worker's runtime port carries reads and live evidence and nothing else, so a
 * Stop is never queued behind a page (`control.ts`).
 *
 * The process does not exit on `dispose`: main answers it by ending the
 * process, and an exit of its own would race the reply that says it was clean.
 */
import { randomBytes } from 'node:crypto';
import type { MessagePortMain } from 'electron';
import { readToUtility, type FromMonitoringUtility, type StartResult, type StopResult } from '../../src/services/monitoring/control';
import type { RpcPort } from '../../src/services/monitoring/runtimeRpc';
import { Collector } from './collector';
import { createUdpSocket } from './udp';
import { openMonitoringFolder, openMonitoringVolume } from './volume';

const post = (message: FromMonitoringUtility): void => {
  process.parentPort.postMessage(message);
};

const collector = new Collector({
  openVolume: openMonitoringVolume,
  openFolder: openMonitoringFolder,
  createSocket: createUdpSocket,
  now: () => Date.now(),
  randomBytes: (n) => new Uint8Array(randomBytes(n)),
  setTimer: (fn, ms) => {
    const timer = setTimeout(fn, ms);
    return () => clearTimeout(timer);
  },
  defer: (fn) => { setImmediate(fn); },
  postStatus: (status) => post({ type: 'status', status }),
  log: (line) => console.error(`[inwire] ${line}`),
});

/**
 * A `MessagePortMain` as the `RpcPort` the runtime layer is written against.
 * `postMessage` copies, which is the only thing a port into this process
 * should be asked to do (a transferred `ArrayBuffer` is dropped, as the store
 * found). Nothing is delivered until `start()`, which `MessagePortMain`
 * needs and a DOM port does for itself.
 */
function rpcPort(port: MessagePortMain): RpcPort {
  return {
    postMessage: (m) => port.postMessage(m),
    onMessage: (handler) => {
      port.on('message', (event) => handler(event.data));
      port.start();
    },
    onClose: (handler) => { port.on('close', handler); },
    close: () => port.close(),
  };
}

const failure = (message: string): StartResult & StopResult => ({ ok: false, message, clean: false, snapshot: null });

process.parentPort.on('message', (event) => {
  const raw: unknown = event.data;
  const message = readToUtility(raw);
  if (message === null) {
    // A request that cannot be read still has a caller waiting, if it carried an id.
    const id = (raw as { id?: unknown } | null)?.id;
    const type = (raw as { type?: unknown } | null)?.type;
    if (typeof id === 'number' && Number.isSafeInteger(id) && id > 0) {
      const why = 'monitoring was sent a request it cannot read';
      const result = type === 'stop' || type === 'dispose' ? failure(why)
        : type === 'inspect' || type === 'discard' || type === 'discard-preview' || type === 'retention' || type === 'retention-preview' ? { ok: false as const, reason: 'failed' as const, message: why }
          : { ok: false as const, message: why };
      post({ type: 'reply', id, result });
    }
    return;
  }
  switch (message.type) {
    case 'attach': {
      const [incoming] = event.ports;
      if (incoming) collector.attach(rpcPort(incoming));
      return;
    }
    case 'open':
      void collector.open(message.root, message.limitBytes, { isDefaultLocation: message.isDefaultLocation, retention: message.retention })
        .then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'inspect':
      post({ type: 'reply', id: message.id, result: collector.inspect(message.root, message.isDefaultLocation) });
      return;
    case 'discard':
      void collector.discard(message.scope).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'discard-preview':
      void collector.discardPreview(message.scope).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'retention':
      void collector.setRetention(message.policy).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'retention-preview':
      void collector.retentionPreview(message.policy).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'start':
      void collector.start(message.config, message.sourceChangeConfirmed).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'stop':
      void collector.stop(message.reason).then((result) => post({ type: 'reply', id: message.id, result }));
      return;
    case 'dispose':
      void collector.dispose().then((result) => post({ type: 'reply', id: message.id, result }));
      return;
  }
});
