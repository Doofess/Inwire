import React, { useState } from 'react';
import { TbKey, TbShieldCheck } from 'react-icons/tb';

interface AgentPairingPanelProps {
  /** True while the agent is connected and waiting to be paired. */
  needsToken: boolean;
  token: string;
  onTokenChange: (token: string) => void;
}

/**
 * Pairing the app with the agent on this machine.
 *
 * The agent binds to loopback and checks the browser's `Origin`, and neither
 * of those distinguishes this app from any other program running on the same
 * computer: `Origin` is a header the client writes, so anything that can open
 * a socket can claim to be an Inwire tab and stream every captured frame from
 * a service running as LocalSystem. The token is the control that closes that,
 * because it lives in a file only an administrator can read.
 *
 * Which is also why it has to be pasted once. The browser cannot read
 * `%ProgramData%` - that is the whole point of putting it there - so the one
 * moment of friction is the security property, not a gap in it.
 */
export const AgentPairingPanel: React.FC<AgentPairingPanelProps> = ({
  needsToken,
  token,
  onTokenChange,
}) => {
  const [draft, setDraft] = useState(token);

  if (!needsToken) {
    return token ? (
      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
        <TbShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
        Paired with this machine&apos;s agent.
      </div>
    ) : null;
  }

  return (
    <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 flex flex-col gap-2">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
        <TbKey className="w-3.5 h-3.5" />
        This agent needs its pairing token
      </div>
      <p className="text-[11px] text-muted-foreground leading-relaxed">
        The agent is running and answering, and will do nothing else until it is paired. Open{' '}
        <code className="font-mono text-foreground">%ProgramData%\Inwire\config.json</code> as an
        administrator and copy the <code className="font-mono text-foreground">token</code> value.
      </p>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => { if (event.key === 'Enter') onTokenChange(draft); }}
          placeholder="64 hex characters"
          spellCheck={false}
          autoComplete="off"
          className="flex-1 min-w-0 px-2 py-1.5 rounded-md border border-border bg-background text-xs font-mono"
          aria-label="Agent pairing token"
        />
        <button
          type="button"
          onClick={() => onTokenChange(draft)}
          disabled={draft.trim().length === 0}
          className="px-3 py-1.5 rounded-md text-xs font-semibold bg-primary text-primary-foreground disabled:opacity-50 hover:opacity-90 transition-opacity"
        >
          Pair
        </button>
      </div>
      <p className="text-[11px] text-muted-foreground leading-relaxed">
        Kept in this browser, on this machine. It is as good as the traffic it opens, so treat it
        the way you would the capture itself.
      </p>
    </div>
  );
};
