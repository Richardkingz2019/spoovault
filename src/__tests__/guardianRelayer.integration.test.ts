/**
 * Integration test for the guardian notification relayer.
 *
 * Spins up real local HTTP servers that emulate:
 *   - an EVM JSON-RPC endpoint exposing AccessRequested logs,
 *   - a Soroban RPC `getEvents` endpoint,
 *   - the guardian contacts registry,
 *   - push / email webhook receivers.
 *
 * It then runs the actual relayer against them and asserts the acceptance
 * criteria: AccessRequested detection + notification dispatch within 3s of
 * block confirmation, structured payloads with an approval-UI deep link,
 * encrypted delivery for guardians that published a public key, automatic
 * retry on transient failures, and durable de-duplication.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ethers } from "ethers";
import { decryptFromRelayer, generateGuardianKeyPair } from "../../relayer/crypto.ts";
import { GuardianResolver, normalizeContacts } from "../../relayer/guardianResolver.ts";
import type { RelayerConfig } from "../../relayer/config.ts";
import { createRelayer } from "../../relayer/main.ts";
import { DurableRelayQueue } from "../../relayer/queue.ts";
import type {
  AccessRequestNotification,
  DispatchJob,
  GuardianContact,
} from "../../relayer/types.ts";

// ─── HTTP doubles ─────────────────────────────────────────────────────────────

interface JsonBody {
  [key: string]: unknown;
}

type Handler = (
  method: string | undefined,
  url: string | undefined,
  body: JsonBody | null,
) => { status?: number; json?: unknown };

interface RecordedPost {
  path: string;
  body: JsonBody;
  receivedAtMs: number;
}

async function startHttpServer(
  handler: Handler,
): Promise<{ server: Server; port: number; posts: RecordedPost[] }> {
  const posts: RecordedPost[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk as Buffer));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf-8");
      let parsed: JsonBody | null = null;
      if (raw.length > 0) {
        try {
          parsed = JSON.parse(raw) as JsonBody;
        } catch {
          parsed = null;
        }
      }
      if (req.method === "POST" && parsed !== null) {
        posts.push({ path: req.url ?? "/", body: parsed, receivedAtMs: Date.now() });
      }
      const outcome = handler(req.method, req.url, parsed);
      res.writeHead(outcome.status ?? 200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(outcome.json ?? {}));
    });
  });
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      resolvePromise({ server, port: (server.address() as AddressInfo).port, posts });
    });
  });
}

const CONTRACT = "0x1111111111111111111111111111111111111111";

/** Minimal EVM JSON-RPC double serving eth_chainId / eth_blockNumber / eth_getLogs. */
async function startMockEvmRpc(): Promise<{
  port: number;
  head: { value: number };
  emitAccessRequest: (requestId: number, documentId: number, requester: string) => void;
  close: () => void;
}> {
  const head = { value: 1000 };
  const topic0 = ethers.id("AccessRequested(uint256,uint256,address)");
  const logs: Array<{ blockNumber: number; logIndex: number; args: [bigint, bigint, string] }> = [];

  const hexToNum = (value: string): number => Number(BigInt(value));

  const rpc = (method: string, params: unknown[]): unknown => {
    switch (method) {
      case "eth_chainId":
        return "0x1";
      case "net_version":
        return "1";
      case "eth_blockNumber":
        return `0x${head.value.toString(16)}`;
      case "eth_getLogs": {
        const filter = params[0] as { fromBlock: string; toBlock: string };
        const from = hexToNum(filter.fromBlock);
        const to = hexToNum(filter.toBlock);
        return logs
          .filter((log) => log.blockNumber >= from && log.blockNumber <= to)
          .map((log) => ({
            address: CONTRACT,
            topics: [
              topic0,
              ethers.zeroPadValue(ethers.toBeHex(log.args[0]), 32),
              ethers.zeroPadValue(ethers.toBeHex(log.args[1]), 32),
              ethers.zeroPadValue(log.args[2].toLowerCase(), 32),
            ],
            data: "0x",
            blockNumber: `0x${log.blockNumber.toString(16)}`,
            blockHash: ethers.ZeroHash,
            transactionHash: ethers.ZeroHash,
            transactionIndex: "0x0",
            logIndex: `0x${log.logIndex.toString(16)}`,
            removed: false,
          }));
      }
      default:
        throw new Error(`unexpected method ${method}`);
    }
  };

  const { server, port } = await startHttpServer((_method, _url, body) => {
    const rpcBody = body as unknown as { id: number; method: string; params: unknown[] };
    try {
      return {
        json: {
          jsonrpc: "2.0",
          id: rpcBody.id ?? 1,
          result: rpc(rpcBody.method ?? "", rpcBody.params ?? []),
        },
      };
    } catch (err) {
      return {
        json: {
          jsonrpc: "2.0",
          id: rpcBody.id ?? 1,
          error: { message: err instanceof Error ? err.message : String(err) },
        },
      };
    }
  });

  return {
    port,
    head,
    emitAccessRequest(requestId, documentId, requester): void {
      head.value += 1; // simulate a newly confirmed block
      logs.push({
        blockNumber: head.value,
        logIndex: logs.length,
        args: [BigInt(requestId), BigInt(documentId), requester],
      });
    },
    close: () => server.close(),
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("Guardian relayer integration", () => {
  const cleanups: Array<() => void> = [];

  beforeEach(() => {
    cleanups.length = 0;
  });

  afterEach(() => {
    for (const cleanup of cleanups.reverse()) cleanup();
  });

  function trackClose(close: () => void): void {
    cleanups.push(close);
  }

  it(
    "detects AccessRequested on both chains within 3s of confirmation and dispatches notifications",
    { timeout: 30_000 },
    async () => {
      // ── Infrastructure ──────────────────────────────────────────────
      const evm = await startMockEvmRpc();
      trackClose(() => evm.close());

      const sorobanEvents: unknown[] = [];
      let sorobanLedger = 500;
      const sorobanContractId = "C" + "A".repeat(63);
      const soroban = await startHttpServer((_method, _url, body) => {
        const rpcBody = body as unknown as { id: number; method: string; params?: JsonBody };
        if (rpcBody.method !== "getEvents") {
          return { json: { jsonrpc: "2.0", id: rpcBody.id ?? 1, error: { message: "unsupported" } } };
        }
        const cursor = (
          rpcBody.params?.["pagination"] as { cursor?: string } | undefined
        )?.cursor;
        return {
          json: {
            jsonrpc: "2.0",
            id: rpcBody.id ?? 1,
            result: { events: cursor ? [] : sorobanEvents, latestLedger: sorobanLedger },
          },
        };
      });
      trackClose(() => soroban.server.close());

      const guardianKeys = generateGuardianKeyPair();

      const registry = await startHttpServer((method, url) => {
        if (method === "GET" && (url ?? "").startsWith("/contacts")) {
          return { json: contacts };
        }
        return { status: 404, json: {} };
      });
      trackClose(() => registry.server.close());

      const receiver = await startHttpServer(() => ({ json: { ok: true } }));
      trackClose(() => receiver.server.close());
      const posts = receiver.posts;

      const contacts: GuardianContact[] = [
        {
          guardian: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          publicKey: guardianKeys.publicKey,
          channels: { pushWebhook: `http://127.0.0.1:${receiver.port}/push` },
        },
        {
          guardian: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          channels: { email: "guardian@example.com" },
        },
      ];
      const stateDir = mkdtempSync(join(tmpdir(), "spoovault-relayer-test-"));
      trackClose(() => rmSync(stateDir, { recursive: true, force: true }));

      const config: RelayerConfig = {
        evmRpcUrl: `http://127.0.0.1:${evm.port}`,
        evmContractAddress: CONTRACT,
        sorobanRpcUrl: `http://127.0.0.1:${soroban.port}`,
        sorobanContractIds: [sorobanContractId],
        pollIntervalMs: 100,
        guardianContactsUrl: `http://127.0.0.1:${registry.port}/contacts`,
        approvalUiBaseUrl: "http://localhost:5173",
        emailWebhookUrl: `http://127.0.0.1:${receiver.port}/email`,
        stateDir,
        maxAttempts: 3,
        retryBaseMs: 50,
        retryMaxBackoffMs: 500,
        workerTickMs: 20,
      };

      const relayer = createRelayer(config);
      trackClose(() => void relayer.stop());
      await relayer.start();

      // ── Trigger: confirm blocks carrying AccessRequested ────────────
      const triggeredAtMs = Date.now();
      evm.emitAccessRequest(7, 42, "0xcccccccccccccccccccccccccccccccccccccc");
      sorobanLedger += 1;
      sorobanEvents.push({
        id: "soroban-evt-1",
        pagingToken: `${sorobanLedger}`,
        contractId: sorobanContractId,
        ledger: sorobanLedger,
        ledgerClosedAt: new Date().toISOString(),
        topic: [{ symbol: "AccessRequested" }],
        value: {
          request_id: { u64: "9" },
          document_id: { u64: "43" },
          requester: { string: "GAREQUESTER" },
        },
      });

      // ── Await dispatch: 2 events × 2 guardians = 4 deliveries ───────
      const countPosts = (path: string): number =>
        posts.filter((p) => p.path === path).length;
      await waitFor(() => countPosts("/push") >= 2 && countPosts("/email") >= 2, 10_000);
      const dispatchedAtMs = Math.min(...posts.map((p) => p.receivedAtMs));

      // Acceptance criterion: detection within 3 seconds of confirmation.
      expect(dispatchedAtMs - triggeredAtMs).toBeLessThan(3000);

      // Structured push payloads: one per detected event, encrypted to the key.
      const pushPosts = posts.filter((p) => p.path === "/push");
      expect(pushPosts.length).toBe(2);
      const envelopes = pushPosts.map(
        (p) =>
          decryptFromRelayer(
            guardianKeys.secretKey,
            p.body["envelope"] as string,
          ) as AccessRequestNotification,
      );
      for (const envelope of envelopes) {
        expect(envelope.type).toBe("access_request");
        expect(envelope.deepLink).toContain("http://localhost:5173/access?");
      }
      const decrypted = envelopes.find((n) => n.chain === "evm")!;
      expect(decrypted.requestId).toBe(7);
      expect(decrypted.documentId).toBe(42);
      expect(decrypted.deepLink).toBe(
        "http://localhost:5173/access?requestId=7&documentId=42&chain=evm",
      );
      const sorobanNotification = envelopes.find((n) => n.chain === "soroban")!;
      expect(sorobanNotification.requestId).toBe(9);
      expect(sorobanNotification.documentId).toBe(43);

      // Email fallback carries the same structure with the deep link.
      const emailFallback = posts.find(
        (p) => p.path === "/email" && String(p.body["text"]).includes("requestId=7"),
      )!;
      expect(emailFallback.body["to"]).toBe("guardian@example.com");
      expect(String(emailFallback.body["text"])).toContain(decrypted.deepLink);

      // Health reflects processed work.
      const health = relayer.health() as { eventsDetected: number };
      expect(health.eventsDetected).toBeGreaterThanOrEqual(2);

      await relayer.stop();
    },
  );

  it("retries failed dispatches automatically and dead-letters after max attempts", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "spoovault-relayer-retry-"));
    trackClose(() => rmSync(stateDir, { recursive: true, force: true }));

    const deliveries: number[] = [];
    const queue = new DurableRelayQueue<DispatchJob>({
      name: "retry-check",
      stateDir,
      maxAttempts: 3,
      retryBaseMs: 20,
      tickMs: 10,
      handler: async () => {
        deliveries.push(Date.now());
        throw new Error("destination down");
      },
    });
    queue.enqueue("job-1", {} as DispatchJob);
    queue.start();
    await waitFor(() => deliveries.length >= 3, 5_000);
    await queue.stop();

    expect(deliveries.length).toBe(3);
    expect(queue.stats().dead).toBe(1);
    expect(queue.stats().pending).toBe(0);
  });

  it("persists queue state so restarted workers do not re-dispatch completed jobs", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "spoovault-relayer-durable-"));
    trackClose(() => rmSync(stateDir, { recursive: true, force: true }));

    let handled = 0;
    const handler = async (): Promise<void> => {
      handled += 1;
    };
    const first = new DurableRelayQueue<DispatchJob>({
      name: "durable",
      stateDir,
      handler,
      tickMs: 10,
    });
    first.enqueue("evt-1:guardian-a", {} as DispatchJob);
    first.start();
    await waitFor(() => handled === 1, 5_000);
    await first.stop();

    const second = new DurableRelayQueue<DispatchJob>({
      name: "durable",
      stateDir,
      handler,
      tickMs: 10,
    });
    const duplicated = second.enqueue("evt-1:guardian-a", {} as DispatchJob);
    second.start();
    await new Promise((resolve) => setTimeout(resolve, 150));
    await second.stop();

    expect(duplicated).toBe(false);
    expect(handled).toBe(1);
  });

  it("resolves guardian contacts from the registry endpoint", async () => {
    let queriedUrl = "";
    const registry = await startHttpServer((_method, url) => {
      queriedUrl = url ?? "";
      return {
        json: {
          guardians: [
            {
              guardian: "0xABC0000000000000000000000000000000000009",
              publicKey: generateGuardianKeyPair().publicKey,
              channels: { pushWebhook: "https://push.example/hook", email: "a@b.c" },
            },
          ],
        },
      };
    });
    trackClose(() => registry.server.close());

    const resolver = new GuardianResolver({
      contactsUrl: `http://127.0.0.1:${registry.port}/contacts`,
    });
    const resolved = await resolver.resolve({
      id: "evm:x:1:0",
      chain: "evm",
      contractId: CONTRACT,
      requestId: 7,
      documentId: 42,
      requester: "0xabc0000000000000000000000000000000000001",
      blockNumber: 1,
      confirmedAt: new Date().toISOString(),
      detectedAtMs: Date.now(),
    });

    expect(queriedUrl).toContain("requestId=7");
    expect(resolved).toHaveLength(1);
    expect(resolved[0].guardian).toBe("0xabc0000000000000000000000000000000000009");
    expect(resolved[0].channels?.pushWebhook).toBe("https://push.example/hook");
    expect(normalizeContacts([])).toEqual([]);
  });
});

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("waitFor timed out");
}
