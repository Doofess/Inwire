/**
 * The `dgram` adapter under the collector's `UdpSocket` (ADR 0058). It holds no
 * rule: which sender counts, how much to hold and what an error is called are
 * all `collector.ts`. What it does hold is the three options that make a bind
 * mean what the user typed.
 *
 * - `reuseAddr: false` and `exclusive: true`. Node's default lets a second
 *   process share a UDP port on some platforms, and a listener that silently
 *   shares its port with another collector gets half of the exporter's
 *   datagrams and says nothing. A taken port must be `EADDRINUSE`.
 * - `recvBufferSize` of 8 MiB, asked for and not checked: the kernel clamps it,
 *   and what the app can actually do about a burst is the inbox and the
 *   journal, not this number.
 * - One permanent `error` listener. A socket with none turns an error into an
 *   uncaught exception in the utility process, which is the whole monitoring
 *   service gone for a datagram.
 */
import dgram from 'node:dgram';
import type { UdpError, UdpSocket } from './collector';

const RECV_BUFFER_BYTES = 8 * 1024 * 1024;

export function createUdpSocket(): UdpSocket {
  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: false, recvBufferSize: RECV_BUFFER_BYTES });
  let bound = false;
  let onError: (error: UdpError) => void = () => {};
  let failBind: ((error: unknown) => void) | null = null;

  socket.on('error', (error: NodeJS.ErrnoException) => {
    if (!bound) {
      // A bind that failed: the caller of `bind` is told, and nobody else needs to be.
      failBind?.(error);
      return;
    }
    onError({ ...(error.code === undefined ? {} : { code: error.code }), message: error.message });
  });

  return {
    onMessage(handler) {
      // The buffer is handed over as it is; the collector copies it.
      socket.on('message', (data, remote) => handler(data, { address: remote.address, port: remote.port }));
    },
    onError(handler) { onError = handler; },
    bind(address, port) {
      return new Promise<void>((resolve, reject) => {
        failBind = reject;
        socket.bind({ address, port, exclusive: true }, () => {
          bound = true;
          failBind = null;
          resolve();
        });
      });
    },
    close() {
      try { socket.close(); } catch { /* already closed */ }
    },
  };
}
