/**
 * @file relayer/types.ts
 * @description Shared types for the SpooVault guardian notification relayer.
 */

/** Chain identifier for a normalized access-request event. */
export type ChainId = "evm" | "soroban";

/**
 * Normalized `AccessRequested` event emitted by either chain.
 * Both the EVM listener (eth_getLogs) and the Soroban listener
 * (getEvents) produce this shape so downstream stages stay chain-agnostic.
 */
export interface AccessRequestEvent {
  /** Globally unique id: `<chain>:<contractOrRpcKey>:<eventIdentifier>`. */
  id: string;
  chain: ChainId;
  /** Contract address / contract id that emitted the event. */
  contractId: string;
  /** Numeric request id from the event (0 when unavailable). */
  requestId: number;
  documentId: number;
  /** Requester address (EVM hex address or Stellar account id). */
  requester: string;
  /** EVM block number or Soroban ledger sequence. */
  blockNumber: number;
  /** ISO timestamp of block/ledger close, when known. */
  confirmedAt: string;
  detectedAtMs: number;
}

/** Delivery channels a guardian can be reached on. */
export interface GuardianChannels {
  /** Push gateway endpoint receiving the encrypted payload via HTTP POST. */
  pushWebhook?: string;
  /** Telegram chat id; requires TELEGRAM_BOT_TOKEN to be set. */
  telegramChatId?: string;
  /** Email address; requires RELAYER_EMAIL_WEBHOOK_URL to be set. */
  email?: string;
}

/** A guardian contact record resolved from the contacts registry endpoint. */
export interface GuardianContact {
  /** Guardian address (EVM hex or Stellar account id), lowercased key. */
  guardian: string;
  /**
   * Base64-encoded 32-byte X25519 public key. When present every dispatched
   * payload is encrypted to this key before leaving the relayer.
   */
  publicKey?: string;
  channels?: GuardianChannels;
}

/** Structured notification body delivered to guardians. */
export interface AccessRequestNotification {
  type: "access_request";
  title: string;
  body: string;
  requestId: number;
  documentId: number;
  vaultId?: number;
  requester: string;
  chain: ChainId;
  contractId: string;
  /** Direct deep link into the guardian approval UI (/access). */
  deepLink: string;
  confirmedAt: string;
  expiresAt?: string;
}

/** Queue job wrapping a notification dispatch for one guardian. */
export interface DispatchJob {
  id: string;
  eventId: string;
  contact: GuardianContact;
  notification: AccessRequestNotification;
  /** Pre-encrypted envelope when the guardian published a public key. */
  encryptedPayload?: string;
  createdAtMs: number;
}
