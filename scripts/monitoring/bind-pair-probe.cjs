// Run as Electron's main: `electron bind-pair-probe.cjs --plan <json>`. The plan is
// an array of processes, each an array of sockets ({ id, addr, port, reuse }).
// Each process is a utilityProcess, forked only once the one before it has
// finished binding, so the order of binds across processes is the plan's.
// Prints one JSON line per bind result, `{ all: true }` once every process
// is ready, and `{ counts }` - datagrams received per socket id - every 500 ms.
const dgram = require('node:dgram');

if (process.parentPort) {
  process.parentPort.once('message', ({ data }) => {
    const counts = {};
    let i = 0;
    const next = () => {
      if (i >= data.sockets.length) {
        process.parentPort.postMessage({ ready: true });
        setInterval(() => process.parentPort.postMessage({ counts }), 500);
        return;
      }
      const spec = data.sockets[i++];
      counts[spec.id] = 0;
      const socket = dgram.createSocket({ type: 'udp4', reuseAddr: spec.reuse });
      socket.on('message', () => { counts[spec.id]++; });
      socket.once('error', (e) => {
        process.parentPort.postMessage({ id: spec.id, error: e.code || e.message });
        delete counts[spec.id];
        next();
      });
      socket.bind(spec.port, spec.addr, () => {
        process.parentPort.postMessage({ id: spec.id, bound: socket.address() });
        next();
      });
    };
    next();
  });
} else {
  const { app, utilityProcess } = require('electron');
  const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i < 0 ? undefined : process.argv[i + 1]; };
  const plan = JSON.parse(arg('plan'));
  const seconds = Number(arg('seconds') || 30);
  const out = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);
  app.whenReady().then(async () => {
    const counts = {};
    const children = [];
    for (const sockets of plan) {
      const child = utilityProcess.fork(__filename, [], { serviceName: 'monitoring-bind-pair-probe' });
      children.push(child);
      await new Promise((ready) => {
        child.on('message', (m) => {
          if (m.ready) ready();
          else if (m.counts) { Object.assign(counts, m.counts); out({ counts }); }
          else out(m);
        });
        child.postMessage({ sockets });
      });
    }
    out({ all: true });
    setTimeout(() => { for (const c of children) c.kill(); app.quit(); }, seconds * 1000);
  });
}
