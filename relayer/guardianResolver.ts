/**
 * @file relayer/guardianResolver.ts
 * @description Guardian resolver for the relayer.
 *
 * For every detected AccessRequested event the resolver queries the guardian
 * contacts registry endpoint with the request context and receives the list
 * of guardians that must be notified together with their public keys and
 * delivery channels:
 *
 *   GET {url}?chain=..&requestId=..&documentId=..&requester=..
 *   -> GuardianContact[]
 */

import type { AccessRequestEvent, GuardianContact } from "./types.ts";

export interface GuardianResolverOptions {
  contactsUrl: string;
  token?: string;
  timeoutMs?: number;
}

export class GuardianResolver {
  private readonly contactsUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;
  private readonly cache = new Map<string, { atMs: number; contacts: GuardianContact[] }>();

  constructor(opts: GuardianResolverOptions) {
    this.contactsUrl = opts.contactsUrl;
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  /** Resolve guardian contacts for an access-request event. */
  async resolve(event: AccessRequestEvent): Promise<GuardianContact[]> {
    const url = new URL(this.contactsUrl);
    url.searchParams.set("chain", event.chain);
    url.searchParams.set("contractId", event.contractId);
    url.searchParams.set("requestId", String(event.requestId));
    url.searchParams.set("documentId", String(event.documentId));
    if (event.requester) url.searchParams.set("requester", event.requester.toLowerCase());

    const cacheKey = url.toString();
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.atMs < 30_000) return cached.contacts;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(url, {
        headers: this.token ? { Authorization: `Bearer ${this.token}` } : undefined,
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Contacts registry ${response.status}`);

      const body = (await response.json()) as unknown;
      const contacts = normalizeContacts(body);
      this.cache.set(cacheKey, { atMs: Date.now(), contacts });
      return contacts;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Accepts either a bare array or `{ guardians: [...] }` responses. */
export function normalizeContacts(body: unknown): GuardianContact[] {
  const raw = Array.isArray(body)
    ? body
    : body && typeof body === "object" && Array.isArray((body as { guardians?: unknown }).guardians)
      ? ((body as { guardians: unknown[] }).guardians)
      : [];

  const out: GuardianContact[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const obj = entry as Record<string, unknown>;
    const guardian = typeof obj["guardian"] === "string" ? obj["guardian"] : undefined;
    if (!guardian) continue;

    const channelsRaw = (obj["channels"] ?? {}) as Record<string, unknown>;
    out.push({
      guardian: guardian.toLowerCase(),
      publicKey: typeof obj["publicKey"] === "string" ? obj["publicKey"] : undefined,
      channels: {
        pushWebhook: asString(channelsRaw["pushWebhook"]),
        telegramChatId: asString(channelsRaw["telegramChatId"]),
        email: asString(channelsRaw["email"]),
      },
    });
  }
  return out;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
