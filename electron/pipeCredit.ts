/**
 * How much of the agent's stream main lets the pipeline Worker owe it, and
 * what main does past that: ADR 0053's first bound.
 *
 * Main used to post every batch it read off the pipe straight to the Worker
 * and forget it. A Worker slower than arrival therefore grew its port queue
 * and its ordering window without limit - nothing anywhere said no - and a
 * real 36,000 frame-a-second download ran the app into its heap guards rather
 * than into anything a person could see. **Only disk is unbounded now**: the
 * agent writes every frame into the capture's pcapng before it puts it on the
 * pipe (ADR 0052), so the live stream may fall behind, and when it does the
 * frames it skips are still in that file.
 *
 * **Credit, counted in batches.** Each batch posted carries an id; the Worker
 * answers with the ids whose every frame it has dissected (`drained`). What
 * is posted and not yet answered is the backlog - in the port, in the
 * ordering window, or being dissected - and its oldest entry is how far the
 * view is behind live, in the wall-clock time since main read that batch.
 *
 * **Past the budget main sheds whole batches itself, and it does not stop
 * reading the pipe.** The obvious lever - `socket.pause()`, so the agent's
 * per-client queue sheds (`outbound.rs`) - sheds whatever is oldest in that
 * queue, and the queue carries control messages too: a `capture_boundary`
 * lost there misfiles a ring (ADR 0052), a state message lost there leaves the
 * app believing a stopped capture is running. Main can tell a control message
 * from a batch by its frame kind alone, so it sheds only batches and passes
 * every control message on. Reading at wire rate costs main little: the pipe
 * was measured at 487 MB/s (CLAUDE.md §3).
 *
 * **With hysteresis, so a hole is one hole.** Shedding starts past the budget
 * and stops only once the backlog is back under half of it. Admitting and
 * shedding batch by batch at the line would cut a hole every few batches, and
 * every hole is a lost segment in every TCP stream crossing it (ADR 0053 says
 * why those verdicts are left standing). One long gap is one note.
 *
 * Imports no Electron, so `scripts/electron/pipe-credit.ts` drives it.
 */
import type { LiveBacklog } from '../src/services/agentLink';

/**
 * The bytes of batches the Worker may owe main before main sheds.
 *
 * 256 MB is about 230,000 frames at the 1.1 kB a frame averages - six
 * seconds of the 36,000 frame-a-second burst that prompted this, which is
 * long enough to ride out the 5-second swings that capture had without
 * shedding at all. It sits in the renderer's Worker, a V8 isolate with a
 * ~4 GB wall, beside a buffer budget of up to half that (ADR 0036): about a
 * sixteenth of the wall, so the backlog can never be what takes it down.
 */
export const LIVE_BACKLOG_BYTES = 256 * 1024 * 1024;

/** Shedding stops once the backlog is back under this share of the budget. */
export const RESUME_FRACTION = 0.5;

interface Outstanding {
  bytes: number;
  frames: number;
  /** When main read it off the pipe. */
  at: number;
}

export class PipeCredit {
  private nextId = 1;
  /** Insertion order is id order, so the first entry is always the oldest. */
  private readonly outstanding = new Map<number, Outstanding>();
  private bytes = 0;
  private frames = 0;
  private shedding = false;
  private shed = 0;

  constructor(
    private readonly budget: number = LIVE_BACKLOG_BYTES,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * A batch main just read: the id to post it with, or null to shed it.
   *
   * A batch is admitted while nothing is outstanding whatever its size, or a
   * single batch larger than the budget would be shed for ever.
   */
  admit(bytes: number, frames: number): number | null {
    this.settle();
    if (!this.shedding && this.outstanding.size > 0 && this.bytes + bytes > this.budget) {
      this.shedding = true;
    }
    if (this.shedding) {
      this.shed += frames;
      return null;
    }
    const id = this.nextId++;
    this.outstanding.set(id, { bytes, frames, at: this.now() });
    this.bytes += bytes;
    this.frames += frames;
    return id;
  }

  /** Batches whose every frame the Worker has dissected, or dropped. */
  drained(ids: readonly number[]): void {
    for (const id of ids) {
      const entry = this.outstanding.get(id);
      if (entry === undefined) continue;
      this.outstanding.delete(id);
      this.bytes -= entry.bytes;
      this.frames -= entry.frames;
    }
    this.settle();
  }

  backlog(): LiveBacklog {
    const oldest = this.outstanding.values().next();
    return {
      frames: this.frames,
      bytes: this.bytes,
      oldestMs: oldest.done ? 0 : Math.max(0, this.now() - oldest.value.at),
      shedFrames: this.shed,
      shedding: this.shedding,
    };
  }

  /**
   * A new connection: nothing is owed. The Worker is told the link dropped and
   * a reconnect is a new stream, so ids it never answers are not waited for.
   */
  reset(): void {
    this.outstanding.clear();
    this.bytes = 0;
    this.frames = 0;
    this.shedding = false;
    this.shed = 0;
  }

  private settle(): void {
    if (this.shedding && this.bytes <= this.budget * RESUME_FRACTION) this.shedding = false;
  }
}
