import React, { useEffect, useRef, useState } from 'react';
import { FileSearch, Key, Radio, Square, Trash, Upload } from 'lucide-react';
import { keyLog, type KeyLogStats } from '../../services/tls/keyLog';
import { KEYLOG_CAP_BYTES } from '../../services/tls/keyLogLimits';
import { formatBytes } from '../../lib/formatBytes';
import { readKeyLogFile } from '../../lib/keyLogFile';
import {
  chooseKeyLog,
  followSuggestedKeyLog,
  forgetKeyLog,
  keyLogFollowStatus,
  onKeyLogFollow,
  type KeyLogFollowStatus,
} from '../../lib/keyLogFollow';

/**
 * Loading a TLS key log.
 *
 * The one thing that turns an encrypted capture into a readable one, and the
 * one thing this app cannot obtain for itself: the secrets belong to the
 * browser that made the connections, and it only writes them out when asked
 * to before it starts.
 *
 * One store is fed: the page's. Dissection of live capture runs in a Worker
 * that reads the same buffer in place (an append needs no message and a Clear
 * reaches it as a cleared snapshot from `pipelineClient.ts`); an imported file
 * is dissected on the main thread against the same store.
 */
/** A file this big takes long enough to read that the panel says it is reading. */
const LOADING_NOTICE_BYTES = 16 * 1024 * 1024;

export const DecryptionSettingsPanel: React.FC = () => {
  const [stats, setStats] = useState<KeyLogStats>(() => keyLog.stats());
  const [follow, setFollow] = useState<KeyLogFollowStatus | null>(() => keyLogFollowStatus());
  const [message, setMessage] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // A followed file changes under the panel: every chunk main sends moves the
  // counts, and every status change moves the line above them. Subscribed for
  // the life of the panel only, with the disposer `onKeyLogFollow` returns.
  useEffect(() => onKeyLogFollow(() => {
    setStats(keyLog.stats());
    setFollow(keyLogFollowStatus());
  }), []);

  const load = async (file: File): Promise<void> => {
    // In chunks from the newest `KEYLOG_CAP_BYTES`, never as one string: a log
    // at the cap is longer than V8's longest (`keyLogFile.ts`, ADR 0073).
    if (file.size > LOADING_NOTICE_BYTES) setMessage(`Loading ${file.name} (${formatBytes(file.size)})…`);
    const before = keyLog.stats();
    let skippedBytes: number;
    try {
      ({ skippedBytes } = await readKeyLogFile(file, (text) => { keyLog.add(text); }));
    } catch (error) {
      // Moved or deleted since it was picked; what was read before the error stays loaded.
      setStats(keyLog.stats());
      setMessage(`Could not read ${file.name}: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    const after = keyLog.stats();
    setStats(after);
    const added = after.secrets - before.secrets;
    const cut = skippedBytes > 0 ? `${file.name} is ${formatBytes(file.size)}; loaded its newest ${formatBytes(KEYLOG_CAP_BYTES)}. ` : '';
    setMessage(cut + (added === 0
      ? `${file.name} added no new secrets - every line was already loaded, or none was a key log line.`
      : `${file.name}: ${added.toLocaleString()} secret${added === 1 ? '' : 's'} for ${(after.connections - before.connections).toLocaleString()} new connection${after.connections - before.connections === 1 ? '' : 's'}.`));
  };

  const clear = (): void => {
    keyLog.clear();
    // The Worker reads the page's buffer, which is the one live capture
    // decrypts with: the cleared snapshot reaches it by itself. When it was a
    // separate copy, "Cleared" left every secret in use.
    const wasFollowing = follow !== null && follow.path !== null;
    // And stop following, or the next line Chrome writes would quietly start
    // decrypting again under a panel that just said it would not.
    if (wasFollowing) void forgetKeyLog();
    setStats(keyLog.stats());
    setMessage(wasFollowing
      ? 'Cleared, and stopped following the key log. Frames already dissected keep what they showed; new ones will not be decrypted.'
      : 'Cleared. Frames already dissected keep what they showed; new ones will not be decrypted.');
  };

  const following = follow !== null && follow.path !== null;
  const suggestedIsFollowed = follow?.suggested != null && follow.path === follow.suggested;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h3 className="text-sm font-semibold text-foreground mb-1">TLS decryption</h3>
        <p className="text-xs text-muted-foreground leading-relaxed">
          With a browser&apos;s TLS key log, Inwire reads the HTTP inside TLS 1.2 and 1.3
          connections. A pcapng file that carries its own secrets needs nothing here.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-muted/30 p-3">
        <div className="text-xs font-semibold text-foreground mb-1.5">How to produce one</div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Set <code className="font-mono text-foreground">SSLKEYLOGFILE</code> to a file path, then
          start Chrome, Edge or Firefox. A browser that was already running will not write to it.
        </p>
        <p className="text-[11px] text-muted-foreground leading-relaxed mt-2">
          Anyone with this file can decrypt every connection in it. Inwire keeps it in memory, never
          saves it with a capture, and sends it nowhere unless you attach it to an export.
        </p>
      </div>

      {/* Following a key log: the way decryption works on a LIVE capture.

          A browser appends each connection's secrets the moment it derives
          them, so a file loaded before a capture holds nothing for the
          connections the capture sees - which is why "Load once" below used to
          leave live QUIC reading `Protected Payload`. Following reads what is
          appended as it is appended, and the choice is remembered, so it
          resumes on the next launch without being loaded again. */}
      <div
        className="rounded-lg border border-border p-3 flex flex-col gap-2"
        data-keylog-follow={follow?.state ?? 'off'}
        data-keylog-skipped={following ? follow!.skippedBytes : 0}
      >
        <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
          <Radio className="w-3.5 h-3.5 text-muted-foreground" />
          Follow a key log
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed" data-keylog-follow-path={follow?.path ?? ''}>
          {!following && 'Not following a file. Choose the one your browser writes to and new connections are readable as they happen - and it is remembered for next time.'}
          {following && follow!.state === 'following' && (
            <>Following <code className="font-mono text-foreground break-all">{follow!.path}</code> - new secrets are picked up as the browser writes them.</>
          )}
          {following && follow!.state === 'missing' && (
            <><code className="font-mono text-foreground break-all">{follow!.path}</code> does not exist yet. The browser creates it on its first connection, and it will be read from then on.</>
          )}
          {following && follow!.state === 'unreadable' && (
            <>Could not read <code className="font-mono text-foreground break-all">{follow!.path}</code>{follow!.error ? `: ${follow!.error}` : '.'}</>
          )}
        </p>
        {/* Past the cap, main read only the newest part (ADR 0073). The file's
            size is the cut plus the cap: what it was when it was read from the
            top, before the browser appended more. */}
        {following && follow!.skippedBytes > 0 && (
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            Loaded the newest {formatBytes(follow!.capBytes)} of this {formatBytes(follow!.skippedBytes + follow!.capBytes)} file;
            the oldest {formatBytes(follow!.skippedBytes)} were skipped.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {follow?.suggested != null && !suggestedIsFollowed && (
            <button
              type="button"
              onClick={() => void followSuggestedKeyLog()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-primary text-primary-foreground hover:opacity-90 transition-opacity"
              title={follow.suggested}
            >
              <Radio className="w-3.5 h-3.5" />
              Follow SSLKEYLOGFILE
            </button>
          )}
          <button
            type="button"
            onClick={() => void chooseKeyLog()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border border-border text-foreground hover:bg-muted transition-colors"
          >
            <FileSearch className="w-3.5 h-3.5" />
            {following ? 'Choose another file' : 'Choose a file to follow'}
          </button>
          {following && (
            <button
              type="button"
              onClick={() => void forgetKeyLog()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border border-border text-foreground hover:bg-muted transition-colors"
            >
              <Square className="w-3.5 h-3.5" />
              Stop following
            </button>
          )}
        </div>
        {follow?.suggested != null && !suggestedIsFollowed && (
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            <code className="font-mono">SSLKEYLOGFILE</code> is set to{' '}
            <code className="font-mono text-foreground break-all">{follow.suggested}</code>.
          </p>
        )}
      </div>

      <div className="flex items-center gap-2">
        <input
          ref={inputRef}
          type="file"
          accept=".log,.keys,.txt,text/plain"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void load(file);
            event.target.value = '';
          }}
        />
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-primary text-primary-foreground hover:opacity-90 transition-opacity"
        >
          <Upload className="w-3.5 h-3.5" />
          Load a file once
        </button>
        {stats.connections > 0 && (
          <button
            type="button"
            onClick={clear}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border border-border text-foreground hover:bg-muted transition-colors"
          >
            <Trash className="w-3.5 h-3.5" />
            Clear
          </button>
        )}
      </div>

      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">Connections covered</dt>
        <dd className="flex items-center gap-1.5">
          <Key className="w-3.5 h-3.5 text-muted-foreground" />
          {stats.connections.toLocaleString()}
        </dd>
        <dt className="text-muted-foreground">Secrets</dt>
        <dd className="" data-keylog-secrets={stats.secrets}>{stats.secrets.toLocaleString()}</dd>
        {stats.ignored > 0 && (
          <>
            <dt className="text-muted-foreground">Lines ignored</dt>
            <dd className="">{stats.ignored.toLocaleString()}</dd>
          </>
        )}
        {stats.dropped > 0 && (
          <>
            <dt className="text-muted-foreground">Not loaded</dt>
            <dd className="" data-keylog-dropped={stats.dropped}>
              {stats.dropped.toLocaleString()} secrets: the key log store is full. Restart Inwire to load the newest part of the file.
            </dd>
          </>
        )}
      </dl>

      {message && <p className="text-[11px] text-muted-foreground leading-relaxed">{message}</p>}

      <p className="text-[11px] text-muted-foreground leading-relaxed">
        A key log decrypts packets that arrive after it loads. For a live capture, follow the file:
        the browser adds secrets as each connection starts. To decrypt packets you already have,
        import the file again or reopen the capture.
      </p>
    </div>
  );
};
