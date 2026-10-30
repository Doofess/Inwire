/**
 * Runs uses of a port in call order, and in the same turn once it can.
 *
 * The store client used to post from inside `ensurePort().then(...)`, so every
 * message left a microtask after its call. An import dissects in one
 * synchronous pass, and no microtask runs until that pass ends: the whole
 * file's rows and records waited in the renderer as queued callbacks, and a
 * 2.4M-frame import ran it out of memory before the store saw a frame (#19).
 *
 * Here a use runs at once when the port is in hand and nothing is waiting
 * ahead of it. Otherwise it waits behind the connection with the others, so
 * an `open` never overtakes a read that was asked for first.
 */
export class PortQueue<P> {
  private port: P | null = null;
  private waiting = 0;
  private dropped = false;

  constructor(private readonly connect: () => Promise<P | null>) {}

  run(use: (port: P | null) => void): void {
    if (this.port !== null && this.waiting === 0) {
      use(this.port);
      return;
    }
    this.waiting++;
    void this.connect().then((port) => {
      this.waiting--;
      if (port !== null && !this.dropped) this.port = port;
      use(this.dropped ? null : port);
    });
  }

  /** The port is gone for good: nothing runs against it again. */
  drop(): void {
    this.dropped = true;
    this.port = null;
  }
}
