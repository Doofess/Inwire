/**
 * The stub agent, served on its own, so the app can be driven by hand.
 *
 *   npx tsx scripts/electron/serveStub.ts
 *   npm run start:app          (in a second terminal)
 *
 * `--burst <n>` sends n frames per 100 ms tick instead of 40. That is how a
 * capture is driven past the RAM buffer's smallest budget - 128 MB, about
 * 180,000 frames - so the window trims, rows go under it, and the disk-backed
 * half of the list can be looked at. At 4,000 it takes about five seconds.
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
  const burst = process.argv.indexOf('--burst');
  const perTick = burst >= 0 ? Number(process.argv[burst + 1]) : undefined;
  if (perTick !== undefined && !Number.isFinite(perTick)) {
    console.log('--burst needs a number of frames per 100 ms tick');
    process.exit(1);
  }

  const agent = await startStubAgent(STUB_PIPE, perTick);
  console.log(`Serving the stub agent on ${STUB_PIPE}`
    + (perTick === undefined ? '' : ` at ${(perTick * 10).toLocaleString()} frames/s`));
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
