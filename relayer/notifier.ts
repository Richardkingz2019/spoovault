/**
 * @file relayer/notifier.ts
 * @description Builds structured guardian notifications and dispatches them
 * through Push / Email / Telegram channels.
 *
 * Every notification embeds a deep link straight into the approval UI
 * (`/access`). When a guardian published an X25519 public key, the full
 * notification is encrypted to that key and channels only carry the opaque
 * envelope plus a short plaintext pointer.
 */

import { encryptForGuardian } from "./crypto.ts";
import type {
  AccessRequestEvent,
  AccessRequestNotification,
  DispatchJob,
  GuardianContact,
} from "./types.ts";

export interface NotifierOptions {
  approvalUiBaseUrl: string;
  telegramBotToken?: string;
  emailWebhookUrl?: string;
  /** Timeout applied to every outbound channel request. */
  requestTimeoutMs?: number;
}

export function buildNotification(
  event: AccessRequestEvent,
  opts: Pick<NotifierOptions, "approvalUiBaseUrl">,
): AccessRequestNotification {
  const base = opts.approvalUiBaseUrl.replace(/\/+$/, "");
  const params = new URLSearchParams({
    requestId: String(event.requestId),
    documentId: String(event.documentId),
    chain: event.chain,
  });
  return {
    type: "access_request",
    title: `Guardian approval requested (#${event.requestId})`,
    body:
      `An access request for document ${event.documentId} was filed on ${event.chain}. ` +
      `Review and approve it in the SpooVault access center.`,
    requestId: event.requestId,
    documentId: event.documentId,
    requester: event.requester,
    chain: event.chain,
    contractId: event.contractId,
    deepLink: `${base}/access?${params.toString()}`,
    confirmedAt: event.confirmedAt,
  };
}

export class NotificationService {
  readonly approvalUiBaseUrl: string;
  private readonly telegramBotToken?: string;
  private readonly emailWebhookUrl?: string;
  private readonly requestTimeoutMs: number;

  constructor(opts: NotifierOptions) {
    this.approvalUiBaseUrl = opts.approvalUiBaseUrl;
    this.telegramBotToken = opts.telegramBotToken;
    this.emailWebhookUrl = opts.emailWebhookUrl;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 10_000;
  }

  /** Create one durable dispatch job per reachable guardian contact. */
  buildJobs(event: AccessRequestEvent, contacts: GuardianContact[]): DispatchJob[] {
    const notification = buildNotification(event, this);
    const jobs: DispatchJob[] = [];

    for (const contact of contacts) {
      if (!this.isReachable(contact)) continue;
      jobs.push({
        id: `${event.id}:${contact.guardian.toLowerCase()}`,
        eventId: event.id,
        contact,
        notification,
        encryptedPayload: contact.publicKey
          ? encryptForGuardian(contact.publicKey, notification)
          : undefined,
        createdAtMs: Date.now(),
      });
    }
    return jobs;
  }

  /**
   * Queue worker handler. Throws when a delivery attempt fails so the
   * queue schedules an automatic retry with backoff.
   */
  async dispatch(job: DispatchJob): Promise<void> {
    const delivered: string[] = [];
    const failed: string[] = [];

    const pushWebhook = job.contact.channels?.pushWebhook;
    if (pushWebhook) {
      try {
        await postJson(pushWebhook, this.envelope(job), this.requestTimeoutMs);
        delivered.push("push");
      } catch (err) {
        failed.push(`push: ${message(err)}`);
      }
    }

    const telegramChatId = job.contact.channels?.telegramChatId;
    if (telegramChatId && this.telegramBotToken) {
      try {
        await postJson(
          `https://api.telegram.org/bot${this.telegramBotToken}/sendMessage`,
          {
            chat_id: telegramChatId,
            text: renderText(job),
            disable_web_page_preview: false,
          },
          this.requestTimeoutMs,
        );
        delivered.push("telegram");
      } catch (err) {
        failed.push(`telegram: ${message(err)}`);
      }
    }

    const email = job.contact.channels?.email;
    if (email && this.emailWebhookUrl) {
      try {
        await postJson(
          this.emailWebhookUrl,
          { to: email, subject: job.notification.title, text: renderText(job) },
          this.requestTimeoutMs,
        );
        delivered.push("email");
      } catch (err) {
        failed.push(`email: ${message(err)}`);
      }
    }

    if (delivered.length === 0 && failed.length > 0) {
      throw new Error(`All channels failed for ${job.id}: ${failed.join("; ")}`);
    }
  }

  /** Wire-format payload sent to channels: encrypted envelope when available. */
  private envelope(job: DispatchJob): Record<string, unknown> {
    if (!job.encryptedPayload) {
      return { v: 1, kind: "spoovault.guardian.notification", notification: job.notification };
    }
    return {
      v: 1,
      kind: "spoovault.guardian.encrypted",
      pointer: job.notification.title,
      envelope: job.encryptedPayload,
    };
  }

  private isReachable(contact: GuardianContact): boolean {
    const channels = contact.channels ?? {};
    return Boolean(
      channels.pushWebhook ||
        (channels.telegramChatId && this.telegramBotToken) ||
        (channels.email && this.emailWebhookUrl),
    );
  }
}

/** Human-readable message body used by Telegram/Email transports. */
export function renderText(job: DispatchJob): string {
  const n = job.notification;
  const lines = [
    n.title,
    "",
    n.body,
    "",
    `Chain: ${n.chain} | Request: #${n.requestId} | Document: ${n.documentId}`,
    `Approve: ${n.deepLink}`,
  ];
  if (job.encryptedPayload) lines.push("", `[encrypted] ${job.encryptedPayload}`);
  return lines.join("\n");
}

async function postJson(url: string, body: unknown, timeoutMs: number): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`${url} responded ${response.status}`);
  } finally {
    clearTimeout(timer);
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
