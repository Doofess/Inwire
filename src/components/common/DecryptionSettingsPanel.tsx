import React, { useRef, useState } from 'react';
import { Key, Trash, Upload } from 'lucide-react';
import { keyLog, type KeyLogStats } from '../../services/tls/keyLog';
import { pipeline } from '../../services/pipelineClient';

/**
 * Loading a TLS key log.
 *
 * The one thing that turns an encrypted capture into a readable one, and the
 * one thing this app cannot obtain for itself: the secrets belong to the
 * browser that made the connections, and it only writes them out when asked
 * to before it starts.
 *
 * Two stores are fed, not one. Dissection of live capture runs in a Worker
 * with its own module instances; an imported file is dissected on the main
 * thread. A key log loaded here goes to both, which is why this calls
 * `pipeline.addKeyLog` as well as `keyLog.add`.
 */
export const DecryptionSettingsPanel: React.FC = () => {
  const [stats, setStats] = useState<KeyLogStats>(() => keyLog.stats());
  const [message, setMessage] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const load = async (file: File): Promise<void> => {
    const text = await file.text();
    const before = keyLog.stats();
    const after = keyLog.add(text);
    pipeline.addKeyLog(text);
    setStats(after);
    const added = after.secrets - before.secrets;
    setMessage(added === 0
      ? `${file.name} added no new secrets - every line was already loaded, or none was a key log line.`
      : `${file.name}: ${added} secret${added === 1 ? '' : 's'} for ${after.connections - before.connections} new connection${after.connections - before.connections === 1 ? '' : 's'}.`);
  };

  const clear = (): void => {
    keyLog.clear();
    setStats(keyLog.stats());
    setMessage('Cleared. Frames already dissected keep what they showed; new ones will not be decrypted.');
  };

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h3 className="text-sm font-semibold text-foreground mb-1">TLS decryption</h3>
        <p className="text-xs text-muted-foreground leading-relaxed">
          A key log holds the session secrets for connections a browser made, keyed on the client
          random each ClientHello sends in the clear. With one loaded, this app reads the HTTP
          inside TLS 1.2 and TLS 1.3 the way it reads anything else - the same is true of a pcapng
          file that carries its own secrets, which needs nothing loaded here at all.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-muted/30 p-3">
        <div className="text-xs font-semibold text-foreground mb-1.5">How to produce one</div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Set <code className="font-mono text-foreground">SSLKEYLOGFILE</code> to a path before
          starting Chrome, Edge or Firefox, and every connection that browser makes appends its
          secrets there. It has to be set before the browser starts - a running one has already
          decided not to write them.
        </p>
        <p className="text-[11px] text-muted-foreground leading-relaxed mt-2">
          The file opens every connection in it, permanently and for anybody who has it. Treat it
          as the traffic itself: it is held in memory here, never written to the stored session,
          and only leaves this machine if you deliberately attach it to an export.
        </p>
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
          Load key log
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
        <dd className="font-mono flex items-center gap-1.5">
          <Key className="w-3.5 h-3.5 text-muted-foreground" />
          {stats.connections.toLocaleString()}
        </dd>
        <dt className="text-muted-foreground">Secrets</dt>
        <dd className="font-mono">{stats.secrets.toLocaleString()}</dd>
        {stats.ignored > 0 && (
          <>
            <dt className="text-muted-foreground">Lines ignored</dt>
            <dd className="font-mono">{stats.ignored.toLocaleString()}</dd>
          </>
        )}
      </dl>

      {message && <p className="text-[11px] text-muted-foreground leading-relaxed">{message}</p>}

      <p className="text-[11px] text-muted-foreground leading-relaxed">
        A key log applies to frames dissected after it is loaded. Frames already in the buffer keep
        what they showed when they arrived; re-import the file, or reload a stored session, to read
        them with the secrets in hand.
      </p>
    </div>
  );
};
