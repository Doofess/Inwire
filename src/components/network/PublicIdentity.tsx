import React, { useEffect, useState } from 'react';
import { TbShield } from 'react-icons/tb';
import { Row, Section, Empty, Value } from './rows';

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

export const PublicIdentity: React.FC<PublicIdentityProps> = ({ allowed, hidden, onAllow }) => {
  const [data, setData] = useState<IspData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!allowed) return;
    let live = true;
    setLoading(true);
    (async () => {
      try {
        const response = await fetch('https://ipapi.co/json/');
        if (!response.ok) throw new Error('Could not reach the lookup service');
        const json = await response.json();
        if (json.error) throw new Error(json.reason || 'The lookup service refused the request');
        if (live) setData(json);
      } catch (err) {
        if (live) setError(err instanceof Error ? err.message : 'The lookup failed');
      } finally {
        if (live) setLoading(false);
      }
    })();
    return () => { live = false; };
  }, [allowed]);

  if (!allowed) {
    return (
      <Section title="Public identity">
        <div className="text-center py-8 px-6">
          <TbShield className="w-9 h-9 mx-auto mb-3 text-muted-foreground" />
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

  if (loading) {
    return (
      <Section title="Public identity">
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <div className="w-7 h-7 border-4 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-muted-foreground">Asking ipapi.co&hellip;</p>
        </div>
      </Section>
    );
  }

  if (error) {
    return (
      <Section title="Public identity">
        <Empty>{error}. Check your connection, or whether an ad-blocker is refusing the request.</Empty>
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
