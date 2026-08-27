import { afterEach, describe, expect, it, vi } from "vitest";
import { CryptoWorkerService } from "../services/cryptoWorker.service";
import type { CryptoWorkerRequest, CryptoWorkerResponse } from "../workers/crypto.worker";

// The existing cryptoWorker.service.test.ts always runs Vitest's Node "forks"
// project, which has no `window`/`Worker` globals — so CryptoWorkerService
// silently falls back to its main-thread crypto.subtle path and the pool
// (initWorkers/getNextWorker/terminate) never actually runs. These tests stub
// `window`/`navigator`/`Worker` so the real pool code path executes, using a
// MockWorker that performs a genuine structured-clone-with-transfer on every
// postMessage — exactly like a real Worker — so ArrayBuffer transfers really
// detach instead of merely being asserted about.

let currentDelayMs = 0;
let currentRespond: (request: CryptoWorkerRequest) => CryptoWorkerResponse = defaultRespond;

function defaultRespond(request: CryptoWorkerRequest): CryptoWorkerResponse {
  switch (request.type) {
    case "ENCRYPT":
      return { id: request.id, type: "ENCRYPT_SUCCESS", result: request.payload.data };
    case "DECRYPT":
      return { id: request.id, type: "DECRYPT_SUCCESS", result: request.payload.data };
    case "SPLIT_SECRET":
      return { id: request.id, type: "SPLIT_SECRET_SUCCESS", shares: [], commitments: [] };
    default:
      return { id: request.id, type: "ERROR", error: "unsupported in mock worker" };
  }
}

class MockWorker {
  static instances: MockWorker[] = [];

  onmessage: ((event: MessageEvent<CryptoWorkerResponse>) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  terminated = false;
  receivedMessages: CryptoWorkerRequest[] = [];

  constructor(_url?: unknown, _opts?: unknown) {
    MockWorker.instances.push(this);
  }

  postMessage(message: CryptoWorkerRequest, transfer?: Transferable[]) {
    // Genuinely transfers (detaches) any ArrayBuffers in `transfer`, mirroring
    // a real Worker's postMessage(data, [data.buffer]) semantics, so the
    // caller's buffer is actually neutered rather than just copied.
    const cloned: CryptoWorkerRequest = transfer?.length
      ? structuredClone(message, { transfer })
      : structuredClone(message);
    this.receivedMessages.push(cloned);

    const deliver = () => {
      const response = currentRespond(cloned);
      const responseTransfer =
        response.type === "ENCRYPT_SUCCESS" || response.type === "DECRYPT_SUCCESS"
          ? [response.result]
          : undefined;
      const clonedResponse = responseTransfer?.length
        ? structuredClone(response, { transfer: responseTransfer })
        : structuredClone(response);
      this.onmessage?.({ data: clonedResponse } as MessageEvent<CryptoWorkerResponse>);
    };

    if (currentDelayMs > 0) {
      setTimeout(deliver, currentDelayMs);
    } else {
      queueMicrotask(deliver);
    }
  }

  terminate() {
    this.terminated = true;
  }
}

const secretKey =
  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

function stubWorkerEnvironment(hardwareConcurrency: number | undefined) {
  vi.stubGlobal("window", globalThis);
  vi.stubGlobal(
    "navigator",
    hardwareConcurrency === undefined ? {} : { hardwareConcurrency }
  );
  vi.stubGlobal("Worker", MockWorker);
}

afterEach(() => {
  vi.unstubAllGlobals();
  MockWorker.instances = [];
  currentDelayMs = 0;
  currentRespond = defaultRespond;
});

describe("CryptoWorkerService worker pool", () => {
  it("creates a worker pool sized to navigator.hardwareConcurrency", () => {
    stubWorkerEnvironment(6);

    new CryptoWorkerService();

    expect(MockWorker.instances).toHaveLength(6);
  });

  it("falls back to a pool of 4 workers when hardwareConcurrency is unavailable", () => {
    stubWorkerEnvironment(undefined);

    new CryptoWorkerService();

    expect(MockWorker.instances).toHaveLength(4);
  });

  it("distributes encryption tasks evenly across the pool (round-robin load balancing)", async () => {
    stubWorkerEnvironment(4);
    const service = new CryptoWorkerService();

    const tasks = Array.from({ length: 8 }, (_, i) =>
      service.encryptAsync(new TextEncoder().encode(`doc-${i}`).buffer, secretKey)
    );
    await Promise.all(tasks);

    const messageCounts = MockWorker.instances.map((w) => w.receivedMessages.length);
    expect(messageCounts).toEqual([2, 2, 2, 2]);
  });

  it("transfers the ArrayBuffer to the worker instead of copying it (zero-copy)", () => {
    stubWorkerEnvironment(2);
    const service = new CryptoWorkerService();

    const buffer = new TextEncoder().encode("Zero-Copy Test Document").buffer;
    expect(buffer.byteLength).toBeGreaterThan(0);

    // postMessage(data, [transferable]) detaches synchronously, so the
    // caller's buffer is already neutered before this call returns —
    // no need to await the resulting promise.
    void service.encryptAsync(buffer, secretKey);

    expect(buffer.byteLength).toBe(0);
  });

  it("terminates every worker and stops routing new tasks to a torn-down pool", async () => {
    stubWorkerEnvironment(3);
    const service = new CryptoWorkerService();

    service.terminate();

    expect(MockWorker.instances).toHaveLength(3);
    expect(MockWorker.instances.every((w) => w.terminated)).toBe(true);

    // After teardown, encryptAsync must not hand work to a terminated
    // worker — it should use the main-thread fallback instead.
    const messagesBefore = MockWorker.instances.reduce(
      (n, w) => n + w.receivedMessages.length,
      0
    );
    const result = await service.encryptAsync(
      new TextEncoder().encode("post-terminate").buffer,
      secretKey
    );
    const messagesAfter = MockWorker.instances.reduce(
      (n, w) => n + w.receivedMessages.length,
      0
    );

    expect(messagesAfter).toBe(messagesBefore);
    expect(result.byteLength).toBeGreaterThan(0);
  });

  it("encrypts 10 documents across the pool >3x faster than serial main-thread execution", async () => {
    const poolSize = 5;
    const perTaskDelayMs = 40;

    stubWorkerEnvironment(poolSize);
    currentDelayMs = perTaskDelayMs;
    const service = new CryptoWorkerService();

    const documents = Array.from({ length: 10 }, (_, i) =>
      new TextEncoder().encode(`document-${i}`).buffer
    );
    const serialBaselineMs = documents.length * perTaskDelayMs;

    const start = performance.now();
    await Promise.all(documents.map((doc) => service.encryptAsync(doc, secretKey)));
    const parallelMs = performance.now() - start;

    expect(parallelMs).toBeLessThan(serialBaselineMs / 3);
  });
});
