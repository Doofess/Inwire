/**
 * The Network panel says "not reported" once, and shows only what can be filled.
 *
 *   npx tsx scripts/session/network-pane.ts
 *
 * With no adapter configuration from the agent - every stub run, the first
 * second of every real one, and any run with the agent gone - the panel
 * printed the same "the agent has not reported…" paragraph three times, under
 * Capture adapter, Addresses and DHCP, and drew Gateway, DNS and DHCP as grids
 * of dashes. Now the notice renders once, after Monitoring; the two sections
 * only the OS can fill are hidden; and Gateway, DNS and DHCP appear when the
 * capture observed something for them. With an adapter, nothing changes.
 */
import { readFileSync } from 'node:fs';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const pane = readFileSync('src/components/network/NetworkPane.tsx', 'utf8');
// The panel's JSX: the first `return (` after `const noAdapter = (`. An earlier
// component in the file has a `return (` of its own.
const jsx = pane.slice(pane.indexOf('  return (\n', pane.indexOf('const noAdapter = (')));

check('the notice is placed exactly once', (jsx.match(/\bnoAdapter\b/g) ?? []).length === 1,
  `found ${(jsx.match(/\bnoAdapter\b/g) ?? []).length}`);
check('...directly after the Monitoring section',
  /<MonitoringSection[^\n]*\n\s*\{adapter === null && noAdapter\}/.test(jsx));

check('Capture adapter is drawn only with an adapter',
  /\{adapter !== null && \(\s*<>\s*<Section title="Capture adapter">/.test(jsx));
check('the "Addresses" placeholder section is gone', !jsx.includes('<Section title="Addresses">'));

check('Gateway shows without an adapter only if the capture saw one',
  /\{\(adapter !== null \|\| facts\.gatewayAddresses\.length > 0 \|\| facts\.gatewayMac !== null\) && \(\s*<Section title="Gateway">/.test(jsx));
check('DNS shows without an adapter only if the capture saw a resolver',
  /\{\(adapter !== null \|\| facts\.dnsServers\.length > 0 \|\| facts\.encryptedDns\.length > 0\) && \(\s*<Section title="DNS">/.test(jsx));
check('DHCP shows without an adapter only if the capture saw a lease',
  /\{\(adapter !== null \|\| facts\.dhcpServer !== null\) && \(\s*<Section title="DHCP">/.test(jsx));
check('DHCP no longer carries its own copy of the notice', !jsx.includes('{!agentConnected && noAdapter}'));

check('IPv6 router keeps its unconditional section', /\n\s*<Section title="IPv6 router"/.test(jsx));

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('\nAll network pane checks passed.');
process.exit(0);
