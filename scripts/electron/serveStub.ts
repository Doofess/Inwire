/**
 * The stub agent, served on its own, so the app can be driven by hand.
 *
 *   npx tsx scripts/electron/serveStub.ts
 *   npm run start:app          (in a second terminal)
 *
 * `stubAgent.ts` exists for `smoke.ts`, which starts and stops it inside one
 * process. This is the same server with nobody driving it: start it, launch
 * the app, and pick "Ethernet (stub)" - synthetic DNS queries arrive at the
 * agent's real cadence over the real pipe.
 *
 * Why it is worth a file. Testing the app by hand otherwise needs the real
 * agent, which needs Administrator, Npcap, and a machine with traffic on it -
 * and on a development machine the installed service is usually a WebSocket
 * agent from before the pipe, so the app shows "not connected" and there is
 * nothing to click. This gets frames on screen in two commands and no
 * elevation.
 *
 * What it cannot tell you: anything about the real agent. It is the app's half
 * of the protocol that gets exercised here, against a server that always
 * behaves. Capture on real traffic still needs the real service.
 */
import { startStubAgent, STUB_PIPE } from './stubAgent';

if (process.platform !== 'win32') {
  console.log('The app dials a named pipe and is Windows-only; nothing here to serve.');
} else {
  const agent = await startStubAgent();
  console.log(`Serving the stub agent on ${STUB_PIPE}`);
  console.log('Launch the app (`npm run start:app`), choose "Ethernet (stub)", press Start.');
  console.log('Ctrl+C to stop.\n');

  let reported = 0;
  setInterval(() => {
    const sent = agent.sent();
    if (sent === reported) return;
    reported = sent;
    console.log(`  ${sent.toLocaleString()} frames handed over`);
  }, 2000);

  // Closing the server releases the pipe name. Without this the next run of
  // this script - or of `smoke.ts` - fails to listen, and the app happily
  // stays connected to a process that is meant to be gone.
  process.on('SIGINT', () => {
    console.log('\nstopping');
    void agent.close().then(() => process.exit(0));
  });
}
