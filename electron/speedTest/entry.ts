/**
 * The speed test's `utilityProcess` (ADR 0054): forked by main for one test,
 * gone when it ends.
 *
 * **A process of its own, measured rather than assumed.** A 4-connection
 * download from Cloudflare in Node held the event loop up to 15 ms at p99 and
 * 20 ms at worst, because TLS is decrypted on the thread that runs the
 * JavaScript - and main's event loop is the one that pumps the capture pipe,
 * at up to 487 MB/s during exactly the kind of burst a speed test causes. Here
 * the test gets a core of its own and main relays a dozen small messages a
 * second.
 *
 * Takes `start` and `cancel` from main and posts the engine's events back. The
 * target is fixed here - `CLOUDFLARE`, the host `MAIN_OUTBOUND_HOSTS` records -
 * so nothing that arrives over the port can point the test anywhere else.
 */
import { CLOUDFLARE, runSpeedTest } from './engine';

let running: AbortController | null = null;

process.parentPort.on('message', (event) => {
  const message = event.data as { type?: unknown } | null;
  if (message?.type === 'cancel') {
    running?.abort();
    return;
  }
  if (message?.type !== 'start' || running !== null) return;
  running = new AbortController();
  void runSpeedTest({ target: CLOUDFLARE }, (e) => process.parentPort.postMessage(e), running.signal)
    .finally(() => {
      running = null;
      // One test per process: main forks a fresh one for the next.
      process.exit(0);
    });
});
