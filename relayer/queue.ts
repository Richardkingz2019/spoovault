/**
 * @file relayer/queue.ts
 * @description Durable in-process relay queue with automatic retries.
 *
 * BullMQ/Redis is intentionally not required: this queue persists its journal
 * atomically to disk after every transition, survives restarts, dedupes jobs
 * by id and retries failures with exponential backoff before dead-lettering.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";

export interface PersistedJob<T> {
  id: string;
  payload: T;
  attempts: number;
  nextAttemptAtMs: number;
  lastError?: string;
}

interface QueueState<T> {
  jobs: PersistedJob<T>[];
  /** Recently finished job ids, kept so replays never re-dispatch. */
  completedIds: string[];
  dead: Array<PersistedJob<T> & { error: string }>;
}

export interface QueueStats {
  pending: number;
  inflight: boolean;
  completed: number;
  dead: number;
}

export interface QueueOptions<T> {
  name: string;
  stateDir: string;
  handler: (payload: T, job: PersistedJob<T>) => Promise<void>;
  maxAttempts?: number;
  retryBaseMs?: number;
  retryMaxBackoffMs?: number;
  tickMs?: number;
  now?: () => number;
}

const MAX_COMPLETED_IDS = 2000;
const MAX_DEAD_JOBS = 100;

export class DurableRelayQueue<T> {
  private readonly file: string;
  private readonly handler: (payload: T, job: PersistedJob<T>) => Promise<void>;
  private readonly maxAttempts: number;
  private readonly retryBaseMs: number;
  private readonly retryMaxBackoffMs: number;
  private readonly tickMs: number;
  private readonly now: () => number;

  private state: QueueState<T> = { jobs: [], completedIds: [], dead: [] };
  private timer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<void> | null = null;
  private stopped = true;

  constructor(opts: QueueOptions<T>) {
    this.file = join(opts.stateDir, `queue-${opts.name}.json`);
    this.handler = opts.handler;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.retryBaseMs = opts.retryBaseMs ?? 500;
    this.retryMaxBackoffMs = opts.retryMaxBackoffMs ?? 30_000;
    this.tickMs = opts.tickMs ?? 200;
    this.now = opts.now ?? Date.now;
    this.load();
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.file, "utf-8")) as QueueState<T>;
      if (Array.isArray(parsed.jobs)) this.state.jobs = parsed.jobs;
      if (Array.isArray(parsed.completedIds)) this.state.completedIds = parsed.completedIds;
      if (Array.isArray(parsed.dead)) this.state.dead = parsed.dead;
    } catch {
      // Corrupt journal: keep running from an empty state rather than crash.
    }
  }

  private persist(): void {
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      const tmp = `${this.file}.tmp`;
      writeFileSync(tmp, JSON.stringify(this.state), "utf-8");
      renameSync(tmp, this.file);
    } catch (err) {
      console.error("[queue] Failed to persist state:", err);
    }
  }

  /** Enqueue a job. Duplicate ids (active or recently completed) are ignored. */
  enqueue(id: string, payload: T): boolean {
    const seen =
      this.state.jobs.some((job) => job.id === id) ||
      this.state.completedIds.includes(id) ||
      this.state.dead.some((job) => job.id === id);
    if (seen) return false;

    this.state.jobs.push({ id, payload, attempts: 0, nextAttemptAtMs: this.now() });
    this.persist();
    return true;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    const tick = (): void => {
      if (this.stopped) return;
      void this.pump().finally(() => {
        if (!this.stopped) this.timer = setTimeout(tick, this.tickMs);
      });
    };
    tick();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.inFlight) await this.inFlight;
  }

  private async pump(): Promise<void> {
    const dueIndex = this.state.jobs.findIndex((job) => job.nextAttemptAtMs <= this.now());
    if (dueIndex === -1 || this.inFlight) return;

    const job = this.state.jobs[dueIndex];
    job.attempts += 1;
    this.inFlight = (async () => {
      try {
        await this.handler(job.payload, job);
        this.state.jobs.splice(dueIndex, 1);
        this.state.completedIds.push(job.id);
        if (this.state.completedIds.length > MAX_COMPLETED_IDS) {
          this.state.completedIds.splice(0, this.state.completedIds.length - MAX_COMPLETED_IDS);
        }
        this.persist();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (job.attempts >= this.maxAttempts) {
          this.state.jobs.splice(dueIndex, 1);
          this.state.dead.push({ ...job, error: message });
          if (this.state.dead.length > MAX_DEAD_JOBS) this.state.dead.shift();
          console.error(`[queue] Job ${job.id} dead-lettered after ${job.attempts} attempts: ${message}`);
        } else {
          const backoff = Math.min(
            this.retryBaseMs * Math.pow(2, job.attempts - 1),
            this.retryMaxBackoffMs,
          );
          job.nextAttemptAtMs = this.now() + backoff;
          job.lastError = message;
          console.warn(`[queue] Job ${job.id} failed (attempt ${job.attempts}), retry in ${backoff}ms`);
        }
        this.persist();
      } finally {
        this.inFlight = null;
      }
    })();
    await this.inFlight;
  }

  stats(): QueueStats {
    return {
      pending: this.state.jobs.length,
      inflight: this.inFlight !== null,
      completed: this.state.completedIds.length,
      dead: this.state.dead.length,
    };
  }
}

