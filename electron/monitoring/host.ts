/**
 * Main's `MonitoringHost` (ADRs 0058, 0059): the real `utilityProcess` and
 * `MessageChannelMain` under `hostCore.ts`, which holds every rule. Nothing
 * here decides anything.
 *
 * Forked like the speed test's engine and for the same reasons - named, so
 * Task Manager shows what holds the UDP socket, and `stdio: 'pipe'`, because a
 * packaged GUI app has no console to inherit and a utility's last words would
 * go nowhere. The difference is lifetime: this one outlives a window, and is
 * ended by `drainForQuit()` or `release()` on quit.
 */
import { MessageChannelMain, utilityProcess, type MessagePortMain } from 'electron';
import path from 'node:path';
import { DEFAULT_RETENTION } from '../../src/services/monitoring/retention';
import { MonitoringHostCore, type ChildLike } from './hostCore';
import { readMonitoringSettings } from './settings';

function fork(): ChildLike {
  const child = utilityProcess.fork(path.join(__dirname, 'monitoring', 'monitoring.cjs'), [], {
    serviceName: 'inwire-monitoring',
    stdio: 'pipe',
  });
  child.stdout?.on('data', (data: Buffer) => console.log(`[monitoring] ${data.toString().trimEnd()}`));
  child.stderr?.on('data', (data: Buffer) => console.error(`[monitoring] ${data.toString().trimEnd()}`));
  return {
    postMessage: (message, ports) => child.postMessage(message, ports as MessagePortMain[] | undefined),
    onMessage: (listener) => { child.on('message', listener); },
    onSpawn: (listener) => { child.once('spawn', listener); },
    onExit: (listener) => { child.once('exit', listener); },
    kill: () => { child.kill(); },
  };
}

export class MonitoringHost extends MonitoringHostCore {
  /** `directory` is the monitoring directory: `monitoringRoot(app.getPath('userData'))`. */
  constructor(directory: string) {
    super({
      directory,
      fork,
      createChannel: () => new MessageChannelMain(),
      timers: { setTimeout: (fn, ms) => setTimeout(fn, ms), clearTimeout: (handle) => clearTimeout(handle as NodeJS.Timeout) },
      // Unreadable settings open the default dataset with the default policy, the leniency the
      // limit always had: the page is told about the file by the config read, not by a failed open.
      settings: () => {
        const saved = readMonitoringSettings(directory);
        if (!saved.ok) return { limitBytes: null, location: null, retention: DEFAULT_RETENTION };
        return { limitBytes: saved.config?.storageLimitBytes ?? null, location: saved.location, retention: saved.retention };
      },
    });
  }
}
