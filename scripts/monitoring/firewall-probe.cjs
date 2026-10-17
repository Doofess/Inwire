/**
 * Electron main with no window: forks a utilityProcess that binds one UDP
 * address, the way the monitoring host will, and reports what arrives once a
 * second on stdout. It exists to raise Windows Defender Firewall's first-bind
 * prompt for a person to answer; `measurement.ts firewall` drives it.
 *
 *   <electron.exe> firewall-probe.cjs --bind <ipv4> --port <n> --seconds <n>
 *
 * Not the packaged app: Inwire.exe is fused to load only its own asar, so the
 * prompt this raises names whichever electron.exe ran it.
 */
const dgram = require('node:dgram');

if (process.parentPort) {
  // The utility process.
  process.parentPort.once('message', ({ data }) => {
    const socket = dgram.createSocket('udp4');
    let received = 0;
    let bytes = 0;
    socket.on('message', (msg) => { received++; bytes += msg.length; });
    socket.on('error', (e) => { process.parentPort.postMessage({ error: e.code || e.message }); });
    socket.bind(data.port, data.bind, () => {
      socket.setRecvBufferSize(8 * 1024 * 1024);
      process.parentPort.postMessage({ bound: socket.address() });
      setInterval(() => process.parentPort.postMessage({ received, bytes }), 1000);
    });
  });
} else {
  const { app, utilityProcess } = require('electron');
  const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i + 1]; };
  const bind = arg('bind');
  const port = Number(arg('port'));
  const seconds = Number(arg('seconds') || 60);
  app.whenReady().then(() => {
    const child = utilityProcess.fork(__filename, [], { serviceName: 'monitoring-firewall-probe' });
    child.on('message', (m) => { process.stdout.write(`${JSON.stringify({ t: Date.now(), ...m })}\n`); });
    child.postMessage({ bind, port });
    setTimeout(() => { child.kill(); app.quit(); }, seconds * 1000);
  });
}
