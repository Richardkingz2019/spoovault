/**
 * @file relayer/config.ts
 * @description Environment-driven configuration for the guardian relayer.
 *
 * Loads `.env` from the repo root when present (no dotenv dependency) and
 * exposes typed settings with safe defaults. Every knob can also be injected
 * directly, which the integration test uses to run against local mock servers.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");

function loadDotEnv(path: string): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf-8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx < 0) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) process.env[key] = value;
  }
}

function num(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export interface RelayerConfig {
  // ── EVM chain listener ───────────────────────────────────────────────────
  evmRpcUrl?: string;
  evmContractAddress?: string;
  /** Block to start scanning from; defaults to "latest minus 0". */
  evmStartBlock?: number;

  // ── Soroban chain listener ──────────────────────────────────────────────
  sorobanRpcUrl?: string;
  sorobanContractIds: string[];

  /** Poll cadence for both listeners. Must stay well under the 3s SLA. */
  pollIntervalMs: number;

  // ── Guardian resolver ────────────────────────────────────────────────────
  /**
   * Contacts registry endpoint queried for every detected request:
   * GET <url>?chain=..&requestId=..&documentId=..&requester=..
   * Expected JSON: GuardianContact[].
   */
  guardianContactsUrl?: string;
  /** Optional static bearer token sent to the contacts registry. */
  guardianContactsToken?: string;

  // ── Notification channels ────────────────────────────────────────────────
  telegramBotToken?: string;
  emailWebhookUrl?: string;
  approvalUiBaseUrl: string;

  // ── Queue / retries ──────────────────────────────────────────────────────
  stateDir: string;
  maxAttempts: number;
  retryBaseMs: number;
  retryMaxBackoffMs: number;
  workerTickMs: number;

  healthPort?: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayerConfig {
  loadDotEnv(resolve(REPO_ROOT, ".env"));

  return {
    evmRpcUrl: env.RELAYER_EVM_RPC_URL || undefined,
    evmContractAddress: env.RELAYER_EVM_CONTRACT_ADDRESS || undefined,
    evmStartBlock: env.RELAYER_EVM_START_BLOCK ? Number(env.RELAYER_EVM_START_BLOCK) : undefined,

    sorobanRpcUrl: env.RELAYER_SOROBAN_RPC_URL || undefined,
    sorobanContractIds: (env.RELAYER_SOROBAN_CONTRACT_IDS || "")
      .split(",")
      .map((id) => id.trim())
      .filter(Boolean),

    pollIntervalMs: num(env.RELAYER_POLL_INTERVAL_MS, 1500),

    guardianContactsUrl: env.RELAYER_GUARDIAN_CONTACTS_URL || undefined,
    guardianContactsToken: env.RELAYER_GUARDIAN_CONTACTS_TOKEN || undefined,

    telegramBotToken: env.TELEGRAM_BOT_TOKEN || undefined,
    emailWebhookUrl: env.RELAYER_EMAIL_WEBHOOK_URL || undefined,
    approvalUiBaseUrl: env.RELAYER_APPROVAL_UI_BASE_URL || "http://localhost:5173",

    stateDir: env.RELAYER_STATE_DIR || resolve(REPO_ROOT, "relayer", ".state"),
    maxAttempts: num(env.RELAYER_MAX_ATTEMPTS, 5),
    retryBaseMs: num(env.RELAYER_RETRY_BASE_MS, 500),
    retryMaxBackoffMs: num(env.RELAYER_RETRY_MAX_BACKOFF_MS, 30_000),
    workerTickMs: num(env.RELAYER_WORKER_TICK_MS, 200),

    healthPort: env.RELAYER_HEALTH_PORT ? Number(env.RELAYER_HEALTH_PORT) : undefined,
  };
}
