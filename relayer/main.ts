/**
 * @file relayer/main.ts
 * @description SpooVault guardian notification relayer entrypoint.
 *
 * Listens for AccessRequested events across EVM and Soroban chains, resolves
 * guardian contacts, and dispatches encrypted Push/Email/Telegram
 * notifications through a durable retry queue.
 *
 * Usage: node relayer/main.ts   (Node >= 22.6 runs TS natively)
 * Configuration: see .env.example (RELAYER_* variables).
 */

import { createServer, type Server } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfig, type RelayerConfig } from "./config.ts";
import { GuardianResolver } from "./guardianResolver.ts";
import { MultiChainListener } from "./listeners.ts";
import { NotificationService } from "./notifier.ts";
import { DurableRelayQueue } from "./queue.ts";
import type { AccessRequestEvent, DispatchJob } from "./types.ts";

export interface Relayer {
  start(): Promise<void>;
  stop(): Promise<void>;
  health(): Record<string, unknown>;
}

/** Wires all relayer components together; also used by the integration test. */
export function createRelayer(config: RelayerConfig): Relayer {
  const startedAtMs = Date.now();
  let eventsDetected = 0;
  let notificationsQueued = 0;

  const notifier = new NotificationService({
    approvalUiBaseUrl: config.approvalUiBaseUrl,
    telegramBotToken: config.telegramBotToken,
    emailWebhookUrl: config.emailWebhookUrl,
  });

  const resolver = config.guardianContactsUrl
    ? new GuardianResolver({
        contactsUrl: config.guardianContactsUrl,
        token: config.guardianContactsToken,
      })
    : null;

  const queue = new DurableRelayQueue<DispatchJob>({
    name: "guardian-notifications",
    stateDir: config.stateDir,
    maxAttempts: config.maxAttempts,
    retryBaseMs: config.retryBaseMs,
    retryMaxBackoffMs: config.retryMaxBackoffMs,
    tickMs: config.workerTickMs,
    handler: (job) => notifier.dispatch(job),
  });

  const listener = new MultiChainListener({
    pollIntervalMs: config.pollIntervalMs,
    onError: (source, err) =>
      console.error(`[listener:${source}]`, err instanceof Error ? err.message : err),
    onEvent: (event) => void handleEvent(event),
  });

  if (config.evmRpcUrl && config.evmContractAddress) {
    listener.addEvm(config.evmRpcUrl, config.evmContractAddress, config.evmStartBlock);
  }
  if (config.sorobanRpcUrl && config.sorobanContractIds.length > 0) {
    listener.addSoroban(config.sorobanRpcUrl, config.sorobanContractIds);
  }

  async function handleEvent(event: AccessRequestEvent): Promise<void> {
    eventsDetected += 1;
    console.log(
      `[relayer] AccessRequested detected: ${event.id} (request ${event.requestId}, document ${event.documentId})`,
    );
    if (!resolver) {
      console.warn("[relayer] No RELAYER_GUARDIAN_CONTACTS_URL configured; dropping event");
      return;
    }
    try {
      const contacts = await resolver.resolve(event);
      const jobs = notifier.buildJobs(event, contacts);
      for (const job of jobs) {
        if (queue.enqueue(job.id, job)) notificationsQueued += 1;
      }
    } catch (err) {
      // Resolution failure must not lose the event: rethrowing would only kill
      // the poll loop, so log loudly instead; listeners keep their cursors and
      // the registry can be retried on the next matching event.
      console.error(`[relayer] Failed to dispatch event ${event.id}:`, err);
    }
  }

  return {
    async start(): Promise<void> {
      await listener.start();
      queue.start();
      console.log(
        `[relayer] Started: poll=${config.pollIntervalMs}ms, chains=` +
          [
            config.evmContractAddress ? "evm" : null,
            config.sorobanContractIds.length > 0 ? "soroban" : null,
          ]
            .filter(Boolean)
            .join(","),
      );
    },

    async stop(): Promise<void> {
      listener.stop();
      await queue.stop();
    },

    health(): Record<string, unknown> {
      return {
        status: "ok",
        uptimeMs: Date.now() - startedAtMs,
        pollIntervalMs: config.pollIntervalMs,
        chains: {
          evm: config.evmContractAddress ?? null,
          sorobanContracts: config.sorobanContractIds,
        },
        eventsDetected,
        notificationsQueued,
        queue: queue.stats(),
      };
    },
  };
}

function startHealthServer(relayer: Relayer, port: number): Server {
  const server = createServer((req, res) => {
    if (req.url === "/health" || req.url === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(relayer.health()));
      return;
    }
    res.writeHead(404).end();
  });
  server.listen(port);
  return server;
}

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.evmContractAddress && config.sorobanContractIds.length === 0) {
    console.error(
      "No chains configured. Set RELAYER_EVM_CONTRACT_ADDRESS and/or RELAYER_SOROBAN_CONTRACT_IDS.",
    );
    process.exit(1);
  }
  if (!config.guardianContactsUrl) {
    console.error("RELAYER_GUARDIAN_CONTACTS_URL is required to resolve guardians.");
    process.exit(1);
  }

  const relayer = createRelayer(config);
  await relayer.start();

  const healthServer = config.healthPort
    ? startHealthServer(relayer, config.healthPort)
    : null;
  if (healthServer) {
    console.log(`[relayer] Health endpoint on http://localhost:${config.healthPort}/health`);
  }

  const shutdown = (signal: string): void => {
    console.log(`[relayer] ${signal} received, shutting down...`);
    void relayer.stop().then(() => {
      healthServer?.close();
      process.exit(0);
    });
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

const isEntrypoint =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isEntrypoint) {
  main().catch((err) => {
    console.error("[relayer] Fatal:", err);
    process.exit(1);
  });
}
