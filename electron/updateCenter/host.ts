/**
 * The process that acts on `updateCenter/`'s decisions.
 *
 * Everything with a rule in it lives in the four modules beside this one and
 * is driven by `scripts/electron/update-center.ts` under plain `tsx`. What is
 * left here is the part that cannot be: a network request, a file, a child
 * process, and the clock. Same split as `saveTarget.ts` beside `saveFile.ts`
 * and `pipeTransport.ts` beside `agentPipe.ts`.
 *
 * ## Why the fetch is here and not in the renderer
 *
 * Three reasons, and the first is the one that matters. The renderer must
 * never learn a filesystem path, because the path is what gets run elevated.
 * `net.fetch` also uses Chromium's own network stack, so a machine behind a
 * corporate proxy works without this file knowing what a proxy is. And a
 * renderer fetch would need a `connect-src` entry, which `electron/csp.ts`
 * argues against having when nothing dials it.
 *
 * ## What is NOT here: the agent's row
 *
 * The capture agent ships inside the Inwire installer, so it has no manifest
 * row and nothing to apply. Its version arrives in `hello`, which the renderer
 * already holds - so the renderer composes that row itself rather than main
 * keeping a second copy of a number it would have to be told. A row this file
 * owned but could not read would be worse than no row.
 *
 * ## The temp file, and the bound on what verifying it proves
 *
 * The download lands in a freshly-created randomly-named directory under the
 * user's temp, so nothing can be waiting at the path when it is written. What
 * that does **not** defend against is the same user swapping the file between
 * the digest check and the elevation - and it cannot, because a process
 * running as the user can already rewrite the app's own payload. Recorded
 * because a sha256 check next to a UAC prompt looks like more of a guarantee
 * than it is.
 */
import { app, net } from 'electron';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, open, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
  decideState, type Component, type ComponentId, type ComponentKind, type ComponentState,
} from './components';
import {
  ELEVATE_ARGV, INSTALLER_ARGS, LAUNCH_ARGV, awaitsInstaller, elevationEnv,
  readElevationResult, type ElevationOutcome,
} from './elevate';
import { parseManifest, resolveFeedUrl, type Manifest } from './manifest';
import { readNpcap } from './npcap';
import { createDigest, overSize, verifyDownload } from './verify';

/** Long enough for a slow feed, short enough that "Check now" answers. */
const FEED_TIMEOUT_MS = 15_000;

/** An installer wizard is answered by a person, so this is generous on purpose. */
const INSTALL_TIMEOUT_MS = 30 * 60_000;

export interface UpdateCenterSnapshot {
  checking: boolean;
  /** Epoch ms of the last check that actually reached the feed. */
  lastChecked: number | null;
  components: Component[];
}

/** The rows main owns. The agent's is the renderer's - see the header. */
const ROWS: { id: ComponentId; displayName: string }[] = [
  { id: 'inwire', displayName: 'Inwire' },
  { id: 'npcap', displayName: 'Npcap capture driver' },
  { id: 'oui', displayName: 'MAC vendor database' },
  { id: 'geoip', displayName: 'Offline location database' },
];

/** Declared so the tab shows its whole shape, with no consumer yet. */
const PLANNED: ReadonlySet<ComponentId> = new Set<ComponentId>(['oui', 'geoip']);

export interface UpdateCenterOptions {
  /** Called whenever anything a person would see has changed. */
  onChange: (snapshot: UpdateCenterSnapshot) => void;
  /**
   * Called after Npcap is installed, to make the new adapters visible without
   * a relaunch.
   *
   * It has to be a link cycle and not `refresh_adapters`: that command
   * re-reads adapter *configuration* and never touches `AVAILABLE_INTERFACES`,
   * the capture-interface list the picker is built from - and it is filtered
   * by that same stale list, so a brand-new adapter is excluded from its own
   * snapshot. The agent refreshes the list in `register()`, once per client
   * connection, so a reconnect is what re-enumerates.
   */
  onDriverInstalled: () => void;
}

export class UpdateCenter {
  private manifest: Manifest | null = null;
  private lastChecked: number | null = null;
  private checking = false;
  private installed = new Map<ComponentId, string | null>();
  /** The Npcap row's registry-recorded access mode. Null until `detect` runs. */
  private npcapAdminOnly: boolean | null = null;
  /** Set while a row is mid-pipeline, so its transient state wins over the resting one. */
  private busy = new Map<ComponentId, ComponentState>();

  constructor(private readonly options: UpdateCenterOptions) {}

  snapshot(): UpdateCenterSnapshot {
    const appVersion = app.getVersion();
    const components = ROWS.map(({ id, displayName }): Component => {
      const available = this.manifest?.components[id] ?? null;
      const installed = this.installed.get(id) ?? null;
      const state = this.busy.get(id)
        ?? (PLANNED.has(id) ? { kind: 'planned' as const } : decideState(installed, available, appVersion));
      const row: Component = { id, displayName, installed, available, state };
      // Only the Npcap row, and only when there is a driver for it to describe.
      // A mode reported beside "Not installed" would be an answer about
      // something that is not there.
      if (id === 'npcap' && installed !== null) row.adminOnly = this.npcapAdminOnly;
      return row;
    });
    return { checking: this.checking, lastChecked: this.lastChecked, components };
  }

  private publish(): void {
    this.options.onChange(this.snapshot());
  }

  private setBusy(id: ComponentId, state: ComponentState | null): void {
    if (state === null) this.busy.delete(id);
    else this.busy.set(id, state);
    this.publish();
  }

  /**
   * Reads what is installed. Cheap enough to redo after every install, which
   * is what makes a row prove itself rather than assume the install worked.
   */
  async detect(): Promise<void> {
    this.installed.set('inwire', app.getVersion());
    const npcap = await readNpcap();
    this.installed.set('npcap', npcap.installed ? npcap.version : null);
    this.npcapAdminOnly = npcap.adminOnly;
    this.publish();
  }

  /**
   * Asks the feed, quietly.
   *
   * An unreachable or malformed feed is **not an error state**: it is the
   * ordinary case on a machine that is offline, and an offline packet analyzer
   * is a supported way to run this app. Nothing is cleared, `lastChecked` does
   * not move, and one info line goes to the log. Anything louder would train
   * somebody to dismiss a dialog every launch.
   */
  async check(): Promise<void> {
    if (this.checking) return;
    this.checking = true;
    this.publish();
    try {
      await this.detect();
      const feedUrl = resolveFeedUrl(process.env);
      const text = await this.fetchFeed(feedUrl);
      if (text === null) return;
      const parsed = parseManifest(text, feedUrl);
      if (parsed === null) {
        // Deliberately the same outcome as unreachable. A feed we cannot read
        // is a feed we have no answer from, and treating a malformed document
        // as "no updates available" would be a confident lie.
        console.info('[update-center] the update feed could not be read');
        return;
      }
      this.manifest = parsed;
      this.lastChecked = Date.now();
    } finally {
      this.checking = false;
      this.publish();
    }
  }

  private async fetchFeed(feedUrl: string): Promise<string | null> {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), FEED_TIMEOUT_MS);
    try {
      // A header rather than `cache: 'no-store'`: Electron's `net.fetch` does
      // not accept the RequestInit cache field, and a check that answers from
      // a cache is a check that never notices a new release.
      const response = await net.fetch(feedUrl, {
        signal: abort.signal, headers: { 'cache-control': 'no-cache' },
      });
      if (!response.ok) {
        console.info(`[update-center] the update feed answered ${response.status}`);
        return null;
      }
      return await response.text();
    } catch (error) {
      console.info('[update-center] the update feed is not reachable:',
        error instanceof Error ? error.message : String(error));
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Download, verify, elevate, prove.
   *
   * One path for every row, so a component cannot acquire its own quirks: the
   * only per-kind differences are the installer's arguments and whether it is
   * awaited, and both are decisions in `elevate.ts`.
   */
  async apply(id: ComponentId): Promise<void> {
    const available = this.manifest?.components[id] ?? null;
    if (available === null || this.busy.has(id)) return;
    if (PLANNED.has(id)) return;

    let file: string | null = null;
    try {
      file = await this.download(id, available.url, available.size, available.sha256);
      if (file === null) return;

      this.setBusy(id, { kind: 'elevating' });
      const outcome = await this.runInstaller(file, available.kind);
      await this.settle(id, outcome, available.kind);
    } catch (error) {
      this.setBusy(id, {
        kind: 'failed',
        reason: error instanceof Error ? error.message : String(error),
      });
    } finally {
      if (file !== null) await rm(file, { force: true }).catch(() => {});
    }
  }

  private async download(
    id: ComponentId, url: string, size: number, sha256: string,
  ): Promise<string | null> {
    this.setBusy(id, { kind: 'downloading', received: 0, total: size });

    const directory = join(app.getPath('temp'), 'inwire-updates', randomBytes(8).toString('hex'));
    await mkdir(directory, { recursive: true });
    const file = join(directory, `${id}.exe`);

    const response = await net.fetch(url, { headers: { 'cache-control': 'no-cache' } });
    if (!response.ok || response.body === null) {
      this.setBusy(id, { kind: 'failed', reason: `the download answered ${response.status}` });
      return null;
    }

    const digest = createDigest();
    const handle = await open(file, 'w');
    let received = 0;
    try {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        // Checked before the write, so an endless body fills nothing.
        if (overSize(received, size)) {
          await reader.cancel().catch(() => {});
          this.setBusy(id, { kind: 'failed', reason: 'the download was larger than published' });
          return null;
        }
        digest.update(value);
        await handle.write(value);
        this.setBusy(id, { kind: 'downloading', received, total: size });
      }
    } finally {
      await handle.close();
    }

    this.setBusy(id, { kind: 'verifying' });
    const verdict = verifyDownload(received, size, digest.hex(), sha256);
    if (!verdict.ok) {
      await rm(file, { force: true }).catch(() => {});
      this.setBusy(id, { kind: 'failed', reason: verdict.reason });
      return null;
    }
    return file;
  }

  /**
   * Runs it elevated.
   *
   * `ELEVATE_ARGV` is a constant and the path goes in the environment, so
   * nothing here builds a command line - see `elevate.ts` for why that is the
   * invariant and not a preference.
   */
  private runInstaller(file: string, kind: ComponentKind): Promise<ElevationOutcome> {
    const awaited = awaitsInstaller(kind);
    const argv = awaited ? ELEVATE_ARGV : LAUNCH_ARGV;
    return new Promise((resolve) => {
      execFile(
        'powershell.exe', [...argv],
        {
          windowsHide: true,
          timeout: INSTALL_TIMEOUT_MS,
          env: { ...process.env, ...elevationEnv(file, INSTALLER_ARGS[kind]) },
        },
        (error, stdout) => {
          if (error && stdout.trim() === '') {
            resolve({ kind: 'failed', code: null, reason: 'the installer could not be started' });
            return;
          }
          resolve(readElevationResult(stdout, kind));
        },
      );
    });
  }

  private async settle(
    id: ComponentId, outcome: ElevationOutcome, kind: ComponentKind,
  ): Promise<void> {
    if (outcome.kind === 'cancelled') {
      // Back to where it was, and nothing on screen. Somebody thought better
      // of it, which is the prompt working.
      this.setBusy(id, null);
      return;
    }
    if (outcome.kind === 'failed') {
      this.setBusy(id, { kind: 'failed', reason: outcome.reason });
      return;
    }

    if (kind === 'inwire-installer') {
      // Launched, not awaited: it is about to close us through the Restart
      // Manager. Quitting now means the quit guard gets to ask about a live
      // capture, rather than the installer taking the window out from under it.
      this.setBusy(id, { kind: 'installing' });
      app.quit();
      return;
    }

    await this.detect();
    this.setBusy(id, outcome.kind === 'reboot-required' ? { kind: 'reboot-required' } : null);

    if (id === 'npcap') this.options.onDriverInstalled();
  }
}
