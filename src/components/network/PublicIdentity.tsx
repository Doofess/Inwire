import React, { useEffect, useRef, useState } from 'react';
import { Shield } from 'lucide-react';
import { Row, Section, Empty, Value } from './rows';
import { failureForStatus, nextRetry, type LookupFailure, type RetryStep } from '../../services/lookupRetry';

/**
 * The public-identity lookup: what the internet sees when this machine
 * connects. Named rather than inline in the effect, so every host this app
 * contacts is greppable - it is behind the `nameResolution.geoIp` consent
 * switch like the others.
 */
const IPAPI_ENDPOINT = 'https://ipapi.co/json/';

/**
 * How this machine looks from the outside: its public address, and the ISP,
 * network block and location it is registered to.
 *
 * The old ISP panel, moved here whole. It is the last section of seven and the
 * only one that asks anybody anything - everything above it is read from this
 * machine or from the capture, and reaches nothing.
 *
 * **The consent moved with it, and got narrower.** The whole panel used to be
 * behind `nameResolution.geoIp`, which meant that turning the switch off cost
 * you the adapter's MAC, its lease and its gateway as well - none of which
 * involves anybody else. Now only this section is gated, and it asks inline
 * rather than rendering empty: a switch buried in Settings that the user has to
 * go and find is a worse consent moment than the one in front of them.
 *
 * The disclosure is the request itself. Nothing from the capture is sent;
 * `ipapi.co` simply sees this machine's public address because it is the one
 * asking, and answers with what that address is registered to.
 *
 * **A failed lookup retries by itself**, within the bound `services/lookupRetry.ts`
 * sets: when the connection comes back, or after a growing delay, never after a
 * refusal. The Try again button appears only once that is spent.
 */

interface IspData {
  ip: string;
  network: string;
  version: string;
  city: string;
  region: string;
  country_name: string;
  latitude: number;
  longitude: number;
  timezone: string;
  utc_offset: string;
  asn: string;
  org: string;
}

interface PublicIdentityProps {
  allowed: boolean;
  hidden: boolean;
  onAllow: () => void;
}

/** A failed attempt, with what `lookupRetry.ts` should make of it. */
class LookupError extends Error {
  constructor(message: string, readonly failure: LookupFailure) { super(message); }
}

export const PublicIdentity: React.FC<PublicIdentityProps> = ({ allowed, hidden, onAllow }) => {
  const [data, setData] = useState<IspData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** What happens next after a failure; `stop` is the only one that needs a click. */
  const [next, setNext] = useState<RetryStep | null>(null);
  /** Bumped to run the lookup again. */
  const [run, setRun] = useState(0);
  /** Requests spent on retries, against `RETRY_DELAYS_MS`. A ref: it is not drawn. */
  const retries = useRef(0);

  useEffect(() => {
    if (!allowed) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const again = () => { if (live) setRun((r) => r + 1); };
    setLoading(true);
    (async () => {
      try {
        let response: Response;
        try {
          response = await fetch(IPAPI_ENDPOINT);
        } catch {
          throw new LookupError(navigator.onLine === false ? 'This machine is offline' : 'Could not reach the lookup service',
            navigator.onLine === false ? 'offline' : 'network');
        }
        const failure = failureForStatus(response.status);
        if (failure !== null) {
          throw new LookupError(failure === 'server' ? 'The lookup service is having trouble' : 'The lookup service refused the request', failure);
        }
        const json = await response.json();
        if (json.error) throw new LookupError(json.reason || 'The lookup service refused the request', 'refused');
        if (!live) return;
        setData(json);
        setError(null);
        setNext(null);
        retries.current = 0;
      } catch (err) {
        if (!live) return;
        const failure = err instanceof LookupError ? err.failure : 'network';
        const step = nextRetry(failure, retries.current);
        setError(err instanceof Error ? err.message : 'The lookup failed');
        setNext(step);
        if (step.kind === 'after') {
          retries.current++;
          timer = setTimeout(again, step.ms);
        } else if (step.kind === 'when-online') {
          window.addEventListener('online', again, { once: true });
        }
      } finally {
        if (live) setLoading(false);
      }
    })();
    return () => {
      live = false;
      clearTimeout(timer);
      window.removeEventListener('online', again);
    };
  }, [allowed, run]);

  /** The one manual way back, offered only once the automatic ones are spent. */
  const tryAgain = () => {
    retries.current = 0;
    setRun((r) => r + 1);
  };

  if (!allowed) {
    return (
      <Section title="Public identity">
        <div className="text-center py-8 px-6">
          <Shield className="w-9 h-9 mx-auto mb-3 text-muted-foreground" />
          <p className="font-semibold text-sm text-foreground">This section has to ask the internet</p>
          <p className="text-xs mt-2 text-muted-foreground max-w-md mx-auto leading-relaxed">
            Nothing from your capture is sent. The request itself is the disclosure:{' '}
            <span className="font-mono text-foreground">ipapi.co</span> sees this machine&rsquo;s
            public IP address and answers with the ISP, network block and location it is
            registered to. Every other section of this panel reaches nobody.
          </p>
          <button onClick={onAllow}
            className="mt-5 px-4 py-2 rounded-md text-sm font-semibold bg-primary
              text-primary-foreground hover:opacity-90">
            Allow external lookups
          </button>
          <p className="text-[11px] mt-3 text-muted-foreground">
            Turns on Settings &rarr; Interface &rarr; Locate addresses, which the map uses too.
          </p>
        </div>
      </Section>
    );
  }

  // A retry in flight keeps the last result on screen rather than a spinner;
  // only a lookup with nothing to show yet spins.
  if (loading && data === null && error === null) {
    return (
      <Section title="Public identity">
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <div className="w-7 h-7 border-4 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-muted-foreground">Asking ipapi.co&hellip;</p>
        </div>
      </Section>
    );
  }

  if (error && data === null) {
    const status = loading ? 'Trying again…'
      : next?.kind === 'after' ? `Trying again in ${Math.round(next.ms / 1000)} seconds.`
        : next?.kind === 'when-online' ? 'Will try again when the connection comes back.'
          : null;
    return (
      <Section title="Public identity">
        <Empty>
          {error}.{' '}
          {status ?? (next?.kind === 'stop' && retries.current > 0
            ? 'Gave up after a few tries. Check your connection, or whether an ad-blocker is refusing the request.'
            : 'Check your connection, or whether an ad-blocker is refusing the request.')}
          {status === null && (
            <button onClick={tryAgain}
              className="block mx-auto mt-3 px-3 py-1 rounded-md text-xs font-semibold border border-border
                text-foreground hover:bg-secondary">
              Try again
            </button>
          )}
        </Empty>
      </Section>
    );
  }

  if (data === null) return <Section title="Public identity"><Empty>Nothing yet.</Empty></Section>;

  return (
    <>
      <Section title="Public identity" note="What this machine looks like from outside the gateway.">
        <Row label="Public IP" value={data.ip} sensitive hidden={hidden} source="ipapi.co" />
        <Row label="Version" source="ipapi.co"
          // ipapi.co returns this already spelled "IPv4"/"IPv6", so the old
          // `IPv{version}` template rendered "IPvIPv6". Tolerates a bare 4 or 6
          // in case the field ever goes back to what that template assumed.
          value={/^IPv/i.test(String(data.version)) ? data.version : `IPv${data.version}`} />
        <Row label="Network block" value={data.network} sensitive hidden={hidden} source="ipapi.co" />
      </Section>

      <Section title="Provider">
        <Row label="ISP" source="ipapi.co">
          {/* Wraps rather than truncating. WHOIS org strings run long - the
              local one is 48 characters - and `truncate` hid half of every
              real name regardless of how much room the window had. */}
          <span className="font-semibold break-words">{data.org}</span>
        </Row>
        <Row label="ASN" value={data.asn} source="ipapi.co" />
      </Section>

      <Section title="Registered location"
        note="Where the address is registered, which is not necessarily where the machine is.">
        <Row label="Location" source="ipapi.co">
          <Value mono={false} sensitive hidden={hidden}
            value={[data.city, data.region, data.country_name].filter(Boolean).join(', ')} />
        </Row>
        <Row label="Coordinates" value={`${data.latitude}, ${data.longitude}`}
          sensitive hidden={hidden} source="ipapi.co" />
        <Row label="Timezone" value={`${data.timezone} (UTC ${data.utc_offset})`} source="ipapi.co" />
      </Section>
    </>
  );
};
