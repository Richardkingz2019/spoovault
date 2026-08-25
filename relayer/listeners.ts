/**
 * @file relayer/listeners.ts
 * @description Multi-chain AccessRequested event listeners.
 *
 * - EvmAccessRequestListener: polls an EVM RPC via ethers queryFilter for
 *   SpooVault's AccessRequested(requestId, documentId, requester) events.
 * - SorobanAccessRequestListener: polls Soroban RPC `getEvents` for
 *   AccessRequested contract events, resuming from an in-memory cursor.
 *
 * Both normalize into {@link AccessRequestEvent}; MultiChainListener merges
 * streams from all configured chains and dedupes by event id.
 */

import type { AccessRequestEvent } from "./types.ts";

export interface ListenerOptions {
  pollIntervalMs: number;
  /** Called for every newly detected event. */
  onEvent: (event: AccessRequestEvent) => void;
  onError?: (source: string, err: unknown) => void;
}

interface EthersLikeProvider {
  getBlockNumber(): Promise<number>;
  destroy?(): void;
}

export class EvmAccessRequestListener {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;
  private lastBlock: number | null = null;
  private provider: EthersLikeProvider | null = null;
  // Dynamically imported ethers Contract, loosely typed on purpose.
  private contract: any = null;

  private readonly rpcUrl: string;
  private readonly contractAddress: string;
  private readonly opts: ListenerOptions;
  private readonly startBlock: number | undefined;

  constructor(rpcUrl: string, contractAddress: string, opts: ListenerOptions, startBlock?: number) {
    this.rpcUrl = rpcUrl;
    this.contractAddress = contractAddress;
    this.opts = opts;
    this.startBlock = startBlock;
  }

  async start(): Promise<void> {
    const { ethers } = await import("ethers");
    const provider = new ethers.JsonRpcProvider(this.rpcUrl, undefined, {
      staticNetwork: true,
      batchMaxCount: 1,
    });
    this.provider = provider;
    this.contract = new ethers.Contract(
      this.contractAddress,
      [
        "event AccessRequested(uint256 indexed requestId, uint256 indexed documentId, address indexed requester)",
      ],
      provider,
    );

    const current = Number(await provider.getBlockNumber());
    const startBlock = this.startBlock ?? 0;
    this.lastBlock = startBlock > 0 ? Math.min(startBlock - 1, current) : current;

    this.running = true;
    const tick = async (): Promise<void> => {
      if (!this.running) return;
      try {
        await this.poll();
      } catch (err) {
        this.opts.onError?.(`evm:${this.contractAddress}`, err);
      }
      if (this.running) this.timer = setTimeout(() => void tick(), this.opts.pollIntervalMs);
    };
    void tick();
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.provider?.destroy?.();
    this.provider = null;
    this.contract = null;
  }

  private async poll(): Promise<void> {
    if (!this.provider || this.lastBlock === null) return;
    const head = Number(await this.provider.getBlockNumber());

    // Cap each sweep so a cold start cannot request an enormous range.
    const toBlock = Math.min(head, this.lastBlock + 5000);
    if (toBlock <= this.lastBlock) return;

    const filter = this.contract.filters.AccessRequested();
    const logs = await this.contract.queryFilter(filter, this.lastBlock + 1, toBlock);

    for (const log of logs) {
      const args = log.args as unknown[];
      this.opts.onEvent({
        id: `evm:${this.contractAddress.toLowerCase()}:${log.blockNumber}:${log.index}`,
        chain: "evm",
        contractId: this.contractAddress,
        requestId: Number(args[0]),
        documentId: Number(args[1]),
        requester: String(args[2]),
        blockNumber: Number(log.blockNumber),
        confirmedAt: new Date().toISOString(),
        detectedAtMs: Date.now(),
      });
    }
    this.lastBlock = toBlock;
  }
}

export class SorobanAccessRequestListener {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;
  private cursors = new Map<string, string>();
  private readonly rpcUrl: string;
  private readonly contractIds: string[];
  private readonly opts: ListenerOptions;

  constructor(rpcUrl: string, contractIds: string[], opts: ListenerOptions) {
    this.rpcUrl = rpcUrl;
    this.contractIds = contractIds;
    this.opts = opts;
  }

  start(): void {
    this.running = true;
    const tick = async (): Promise<void> => {
      if (!this.running) return;
      await Promise.allSettled(this.contractIds.map((id) => this.pollContract(id)));
      if (this.running) this.timer = setTimeout(() => void tick(), this.opts.pollIntervalMs);
    };
    void tick();
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async pollContract(contractId: string): Promise<void> {
    const cursor = this.cursors.get(contractId);
    let response: Response;
    try {
      response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getEvents",
          params: {
            filters: [{ type: "contract", contractIds: [contractId] }],
            pagination: { limit: 100, ...(cursor ? { cursor } : {}) },
          },
        }),
      });
    } catch (err) {
      this.opts.onError?.(`soroban:${contractId}`, err);
      return;
    }
    if (!response.ok) {
      this.opts.onError?.(`soroban:${contractId}`, new Error(`Soroban RPC ${response.status}`));
      return;
    }

    const body = (await response.json()) as {
      error?: { message?: string };
      result?: { events?: RawSorobanEvent[] };
    };
    if (body.error) {
      this.opts.onError?.(`soroban:${contractId}`, new Error(body.error.message ?? "rpc error"));
      return;
    }

    for (const raw of body.result?.events ?? []) {
      const cursorToken = raw.pagingToken ?? raw.id;
      if (!cursorToken) continue;
      this.cursors.set(contractId, cursorToken);

      const topics = (raw.topic ?? []).map((t) => JSON.stringify(t));
      if (!topics.some((t) => t.includes("AccessRequested"))) continue;

      const info = extractSorobanRequestInfo(raw.value);
      this.opts.onEvent({
        id: `soroban:${contractId}:${raw.id ?? cursorToken}`,
        chain: "soroban",
        contractId,
        requestId: info.requestId,
        documentId: info.documentId,
        requester: info.requester ?? "",
        blockNumber: Number(raw.ledger ?? 0),
        confirmedAt: raw.ledgerClosedAt ?? new Date().toISOString(),
        detectedAtMs: Date.now(),
      });
    }
  }
}

interface RawSorobanEvent {
  id?: string;
  pagingToken?: string;
  contractId?: string;
  ledger?: number;
  ledgerClosedAt?: string;
  topic?: unknown[];
  value?: unknown;
}

/** Best-effort extraction of request ids from Soroban SCVal-shaped payloads. */
function extractSorobanRequestInfo(value: unknown): {
  requestId: number;
  documentId: number;
  requester?: string;
} {
  const out = { requestId: 0, documentId: 0, requester: undefined as string | undefined };

  const readNumber = (v: unknown): number => {
    if (typeof v === "number") return v;
    if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
    if (v && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      for (const key of ["u64", "u32", "i64", "u128", "value"]) {
        if (key in obj) return readNumber(obj[key]);
      }
    }
    return 0;
  };
  const readString = (v: unknown): string | undefined => {
    if (typeof v === "string") return v;
    if (v && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      if (typeof obj["symbol"] === "string") return obj["symbol"];
      if (typeof obj["string"] === "string") return obj["string"];
    }
    return undefined;
  };

  if (Array.isArray(value)) {
    out.requestId = readNumber(value[0]);
    out.documentId = readNumber(value[1]);
    out.requester = readString(value[2]);
  } else if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const key of ["request_id", "requestId"]) {
      if (key in obj) out.requestId = readNumber(obj[key]);
    }
    for (const key of ["document_id", "documentId"]) {
      if (key in obj) out.documentId = readNumber(obj[key]);
    }
    out.requester = readString(obj["requester"]);
  }
  return out;
}

/** Fans normalized events out to a single consumer, deduping across chains. */
export class MultiChainListener {
  private readonly seen = new Set<string>();
  private readonly sources: Array<EvmAccessRequestListener | SorobanAccessRequestListener> = [];
  private readonly opts: ListenerOptions;

  constructor(opts: ListenerOptions) {
    this.opts = opts;
  }

  addEvm(rpcUrl: string, contractAddress: string, startBlock?: number): void {
    this.sources.push(new EvmAccessRequestListener(rpcUrl, contractAddress, this.childOpts(), startBlock));
  }

  addSoroban(rpcUrl: string, contractIds: string[]): void {
    this.sources.push(new SorobanAccessRequestListener(rpcUrl, contractIds, this.childOpts()));
  }

  async start(): Promise<void> {
    await Promise.all(this.sources.map((source) => source.start()));
  }

  async stop(): Promise<void> {
    await Promise.all(this.sources.map((source) => source.stop()));
  }

  stats(): number {
    return this.seen.size;
  }

  private emitNew(event: AccessRequestEvent): void {
    if (this.seen.has(event.id)) return;
    this.seen.add(event.id);
    this.opts.onEvent(event);
  }

  private childOpts(): ListenerOptions {
    return {
      pollIntervalMs: this.opts.pollIntervalMs,
      onEvent: (event) => this.emitNew(event),
      onError: (source, err) => this.opts.onError?.(source, err),
    };
  }
}
