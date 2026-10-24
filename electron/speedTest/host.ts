/**
 * Main's side of the speed test (ADR 0054): forks the engine's utilityProcess
 * for one test and relays its events to every window, unread.
 *
 * One test at a time - a second start while one runs is ignored, because two
 * tests at once would each measure the other. A process that dies without
 * having said how the test ended is reported as a failure, so a dial never
 * spins for ever.
 */
import { BrowserWindow, utilityProcess, type UtilityProcess } from 'electron';
import path from 'node:path';
import { SPEEDTEST_EVENT_CHANNEL } from '../channels';
import { canSend } from '../rendererLife';

export class SpeedTestHost {
  private child: UtilityProcess | null = null;
  /** Whether the child has posted an ending (`done`, `failed`, `cancelled`). */
  private ended = false;

  private broadcast(event: unknown): void {
    for (const window of BrowserWindow.getAllWindows()) {
      if (!window.isDestroyed() && canSend(window.webContents)) window.webContents.send(SPEEDTEST_EVENT_CHANNEL, event);
    }
  }

  start(): boolean {
    if (this.child !== null) return false;
    this.ended = false;
    const child = utilityProcess.fork(path.join(__dirname, 'speedTest', 'speedTest.cjs'), [], {
      // Named, so Task Manager shows what is moving a gigabyte.
      serviceName: 'inwire-speed-test',
      stdio: 'pipe',
    });
    this.child = child;
    child.stdout?.on('data', (data: Buffer) => console.log(`[speed-test] ${data.toString().trimEnd()}`));
    child.stderr?.on('data', (data: Buffer) => console.error(`[speed-test] ${data.toString().trimEnd()}`));
    child.on('message', (event: unknown) => {
      const type = (event as { type?: unknown } | null)?.type;
      if (type === 'done' || type === 'failed' || type === 'cancelled') this.ended = true;
      this.broadcast(event);
    });
    child.once('spawn', () => child.postMessage({ type: 'start' }));
    child.once('exit', (code) => {
      this.child = null;
      if (!this.ended) {
        this.broadcast({ type: 'failed', phase: 'connecting', message: `the speed test stopped unexpectedly (exit ${code})` });
      }
    });
    return true;
  }

  cancel(): void {
    this.child?.postMessage({ type: 'cancel' });
  }

  /** On quit: a test is not worth keeping a process alive for. */
  dispose(): void {
    this.child?.kill();
    this.child = null;
  }
}
