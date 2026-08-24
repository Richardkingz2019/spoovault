/**
 * @file pir.service.ts
 * @description Private Information Retrieval (PIR) service for oblivious IPFS document fetching.
 *
 * Implements PIR principles to prevent IPFS gateway nodes from correlating beneficiary
 * IP addresses with specific vault document CIDs through:
 * 1. PIR dummy query batching, dispatched concurrently with jitter
 * 2. Keyed CID hashing (deterministic when a shared key is supplied)
 *
 * Architecture:
 * - PirService: Main service orchestrating oblivious fetches
 * - TorProxyClient: reports whether a real SOCKS5/mixnet proxy is available
 * - DummyQueryBatcher: Generates dummy queries to obscure real requests
 * - HomomorphicHash: CID obfuscation via keyed SHA-256
 *
 * Threat model / honesty note: browsers cannot originate raw SOCKS5
 * connections, so genuine Tor/mixnet IP-hiding is not possible from
 * client-side JavaScript alone — it requires a trusted server-side proxy
 * that holds the real Tor circuit (see #124 for the follow-up on building
 * one, analogous to scripts/pinata-proxy.mjs). `TorProxyClient` therefore
 * always reports itself unavailable in-browser, and `PirService` fails
 * closed (refuses the fetch) rather than silently falling back to a direct,
 * unprotected request when the caller explicitly opted into `useTorProxy`.
 * What this module *does* deliver on its own: dummy-query batching that
 * hides which CID out of a batch was the real target, as long as the
 * caller supplies real, existing decoy CIDs (e.g. sibling documents in the
 * same vault) — see `decoyCids` on `fetchDocument`. Without a real decoy
 * pool, synthetic random-looking CIDs are used as a weaker fallback; they
 * will typically 404 and so are distinguishable from the real request by
 * anyone inspecting gateway response codes.
 */

import { ipfsGateway } from "./ipfsGateway";

// ─── Configuration ───────────────────────────────────────────────────────────────

const TOR_SOCKS_PORT = 9050;
const DEFAULT_DUMMY_QUERY_COUNT = 5;
const DEFAULT_BATCH_DELAY_MS = 100;

// ─── Types ───────────────────────────────────────────────────────────────────────

export interface PirConfig {
  enabled: boolean;
  useTorProxy: boolean;
  torSocksHost?: string;
  torSocksPort?: number;
  dummyQueryCount?: number;
  batchDelayMs?: number;
  /**
   * Optional shared key for deterministic CID hashing (see HomomorphicHash).
   * Without it, getCidHash()/verifyCid() are only self-consistent within
   * this PirService instance, not usable as a cross-party shared index.
   */
  cidIndexKey?: string;
}

export interface PirFetchResult {
  success: boolean;
  data?: ArrayBuffer;
  error?: string;
  gatewayUsed?: string;
  proxied: boolean;
  dummyQueriesIssued: number;
}

export interface DummyQuery {
  cid: string;
  isReal: boolean;
  timestamp: number;
}

// ─── Homomorphic Hash for CID Obfuscation ─────────────────────────────────────────

/**
 * Keyed SHA-256 hash for CID obfuscation ("homomorphic" here refers to the
 * masking use case, not an algebraic homomorphism — this is a plain salted
 * hash, not a homomorphic encryption/hash scheme).
 *
 * When constructed with a shared `key` (e.g. a vault-level secret every
 * guardian/beneficiary with legitimate access already holds), the hash is
 * deterministic across instances/sessions, so it can serve as a real,
 * independently-computable masked index for a given CID. Without a key, it
 * falls back to a random per-instance salt (self-consistent only within
 * that instance) — safe for local use, but not usable as a shared index.
 */
export class HomomorphicHash {
  private salt: string;

  constructor(key?: string) {
    this.salt = key ? key : this.generateSalt();
  }

  private generateSalt(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Generate a hash for a CID. The same CID always produces the same hash
   * for a given salt/key; two instances constructed with the same `key`
   * produce identical hashes for the same CID.
   */
  async hashCid(cid: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(this.salt + cid);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Verify a CID against its homomorphic hash.
   */
  async verifyCid(cid: string, hash: string): Promise<boolean> {
    const computedHash = await this.hashCid(cid);
    return computedHash === hash;
  }

  getSalt(): string {
    return this.salt;
  }
}

// ─── Dummy Query Batcher ─────────────────────────────────────────────────────────

/**
 * Generates dummy IPFS queries to obscure real document fetches.
 * Implements PIR by batching real queries with dummy queries.
 */
export class DummyQueryBatcher {
  private dummyQueryCount: number;
  private batchDelayMs: number;

  constructor(dummyQueryCount: number = DEFAULT_DUMMY_QUERY_COUNT, batchDelayMs: number = DEFAULT_BATCH_DELAY_MS) {
    this.dummyQueryCount = dummyQueryCount;
    this.batchDelayMs = batchDelayMs;
  }

  /**
   * Generate a dummy CID that looks like a real IPFS CID.
   * Uses the CIDv0 format (base58 encoded SHA-256 hash).
   */
  private generateDummyCid(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    
    // Add CIDv0 prefix (0x12 for SHA-256, 0x20 for 32 bytes)
    const prefixed = new Uint8Array(34);
    prefixed[0] = 0x12;
    prefixed[1] = 0x20;
    prefixed.set(array, 2);
    
    // Base58 encode (simplified implementation)
    return this.base58Encode(prefixed.slice(2));
  }

  private base58Encode(bytes: Uint8Array): string {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const digits = [0];
    
    for (let i = 0; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = (carry / 58) | 0;
      }
    }
    
    let result = "";
    for (let i = 0; i < digits.length; i++) {
      result += alphabet[digits[i]];
    }
    
    return result;
  }

  /**
   * Create a batch of queries containing the real query and dummy queries.
   *
   * @param realCid   The CID actually being fetched.
   * @param decoyPool Real, existing CIDs to use as decoys (e.g. sibling
   *                  documents in the same vault). Using real CIDs means
   *                  every request in the batch resolves successfully, so a
   *                  gateway operator can't single out the real request by
   *                  response code/size. If the pool is smaller than
   *                  `dummyQueryCount`, the shortfall is padded with
   *                  synthetic random-looking CIDs (weaker — those will
   *                  typically 404 and are distinguishable). With no pool at
   *                  all, every decoy is synthetic (legacy behavior).
   */
  createBatch(realCid: string, decoyPool: string[] = []): DummyQuery[] {
    const batch: DummyQuery[] = [
      {
        cid: realCid,
        isReal: true,
        timestamp: Date.now(),
      },
    ];

    const realDecoys = this.sampleRealDecoys(realCid, decoyPool, this.dummyQueryCount);
    for (const cid of realDecoys) {
      batch.push({ cid, isReal: false, timestamp: Date.now() });
    }

    const syntheticNeeded = this.dummyQueryCount - realDecoys.length;
    for (let i = 0; i < syntheticNeeded; i++) {
      batch.push({
        cid: this.generateDummyCid(),
        isReal: false,
        timestamp: Date.now(),
      });
    }

    // Shuffle the batch to obscure which query is real
    return this.shuffleArray(batch);
  }

  /** Randomly sample up to `count` distinct real CIDs from `pool`, excluding `realCid`. */
  private sampleRealDecoys(realCid: string, pool: string[], count: number): string[] {
    const candidates = [...new Set(pool)].filter((cid) => cid !== realCid);
    const shuffled = this.shuffleArray(candidates);
    return shuffled.slice(0, count);
  }

  private shuffleArray<T>(array: T[]): T[] {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  /**
   * Execute a batch of queries concurrently, returning only the result of
   * the real query.
   *
   * Queries are dispatched together (not one-at-a-time in array order) with
   * independent random jitter, so an observer watching request arrival
   * order/timing at the gateway can't infer batch position from dispatch
   * order — a sequential for-loop would issue the "real" request at a fixed
   * point in the shuffled order every time it happened to be there, which
   * plus real per-query timestamps would leak more than shuffling alone.
   */
  async executeBatch(
    batch: DummyQuery[],
    fetchFn: (cid: string) => Promise<Response>
  ): Promise<{ realResult: Response; dummyCount: number }> {
    const jitter = () =>
      new Promise<void>((resolve) => setTimeout(resolve, Math.random() * this.batchDelayMs));

    const results = await Promise.allSettled(
      batch.map(async (query) => {
        await jitter();
        const response = await fetchFn(query.cid);
        return { query, response };
      })
    );

    let realResult: Response | null = null;
    let dummyCount = 0;

    for (const result of results) {
      if (result.status === "fulfilled") {
        if (result.value.query.isReal) {
          realResult = result.value.response;
        } else {
          dummyCount++;
        }
      } else {
        // A rejected query is counted as a (failed) dummy. If the real query
        // is the one that rejected, realResult stays null and the check
        // below throws with a dedicated error — this count is only returned
        // on the success path, where the real query must have fulfilled.
        dummyCount++;
      }
    }

    if (!realResult) {
      throw new Error("Real query failed to execute");
    }

    return { realResult, dummyCount };
  }
}

// ─── Tor Proxy Client ─────────────────────────────────────────────────────────────

/**
 * Reports whether a genuine Tor/mixnet SOCKS5 proxy is available for
 * routing IPFS requests.
 *
 * Browsers have no API to originate raw SOCKS5 connections, so this can
 * never be genuinely satisfied from client-side JavaScript alone — doing so
 * requires a trusted server-side proxy holding the real Tor circuit
 * (analogous to scripts/pinata-proxy.mjs, which already proxies Pinata
 * uploads server-side for a similar reason). `isAvailable()` therefore
 * always reports `false` by default; `probeFn` exists only so a future
 * server-side proxy integration (or a test) can supply a real check without
 * changing this class's public shape.
 */
class TorProxyClient {
  private enabled: boolean;
  private probeFn: () => Promise<boolean>;

  constructor(
    _host: string = "127.0.0.1",
    _port: number = TOR_SOCKS_PORT,
    enabled: boolean = false,
    probeFn: () => Promise<boolean> = async () => false
  ) {
    this.enabled = enabled;
    this.probeFn = probeFn;
  }

  /** Whether a real proxy is available right now. Honest default: never, in-browser. */
  async isAvailable(): Promise<boolean> {
    if (!this.enabled) return false;
    return this.probeFn();
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }
}

// ─── PIR Service ─────────────────────────────────────────────────────────────────

/**
 * Main PIR service orchestrating oblivious IPFS fetches.
 */
export class PirService {
  private config: PirConfig;
  private homomorphicHash: HomomorphicHash;
  private dummyBatcher: DummyQueryBatcher;
  private torProxy: TorProxyClient;

  constructor(config: PirConfig = { enabled: true, useTorProxy: false }) {
    this.config = {
      dummyQueryCount: DEFAULT_DUMMY_QUERY_COUNT,
      batchDelayMs: DEFAULT_BATCH_DELAY_MS,
      ...config,
    };

    this.homomorphicHash = new HomomorphicHash(this.config.cidIndexKey);
    this.dummyBatcher = new DummyQueryBatcher(
      this.config.dummyQueryCount,
      this.config.batchDelayMs
    );
    this.torProxy = new TorProxyClient(
      this.config.torSocksHost || "127.0.0.1",
      this.config.torSocksPort || TOR_SOCKS_PORT,
      this.config.useTorProxy
    );
  }

  /**
   * Fetch a document from IPFS using PIR principles.
   *
   * @param decoyCids Real, existing CIDs to batch alongside the real
   *                  request as decoys (e.g. sibling documents in the same
   *                  vault). Strongly recommended — see DummyQueryBatcher.
   */
  async fetchDocument(
    cid: string,
    signal?: AbortSignal,
    decoyCids: string[] = []
  ): Promise<PirFetchResult> {
    if (!this.config.enabled) {
      // Fallback to standard IPFS fetch if PIR is disabled
      return this.standardFetch(cid, signal);
    }

    if (this.config.useTorProxy) {
      const torAvailable = await this.torProxy.isAvailable();
      if (!torAvailable) {
        // Fail closed: the caller explicitly asked for IP-hiding via a
        // mixnet/Tor proxy. Falling back to a direct, unprotected fetch
        // here would silently give them less protection than requested —
        // refuse instead so the caller (and ultimately the user) knows
        // their IP was not protected, rather than believing it was.
        return {
          success: false,
          error:
            "Tor/mixnet proxy routing was requested but is not available " +
            "(browsers cannot originate SOCKS5 connections directly; a " +
            "server-side proxy is required). Refusing to fall back to an " +
            "unprotected direct fetch.",
          proxied: false,
          dummyQueriesIssued: 0,
        };
      }
    }

    try {
      // Create query batch with dummy queries
      const batch = this.dummyBatcher.createBatch(cid, decoyCids);

      // Execute batch
      const { realResult, dummyCount } = await this.dummyBatcher.executeBatch(
        batch,
        (queryCid) => fetch(ipfsGateway.getURL(queryCid), { signal })
      );

      if (!realResult.ok) {
        return {
          success: false,
          error: `HTTP ${realResult.status}`,
          proxied: false,
          dummyQueriesIssued: dummyCount,
        };
      }

      const data = await realResult.arrayBuffer();

      return {
        success: true,
        data,
        gatewayUsed: ipfsGateway.getURL(cid),
        proxied: false,
        dummyQueriesIssued: dummyCount,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        proxied: false,
        dummyQueriesIssued: 0,
      };
    }
  }

  /**
   * Standard IPFS fetch without PIR (fallback).
   */
  private async standardFetch(cid: string, signal?: AbortSignal): Promise<PirFetchResult> {
    try {
      const response = await ipfsGateway.fetchFile(cid, { signal });
      const data = await response.arrayBuffer();

      return {
        success: true,
        data,
        gatewayUsed: ipfsGateway.getURL(cid),
        proxied: false,
        dummyQueriesIssued: 0,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        proxied: false,
        dummyQueriesIssued: 0,
      };
    }
  }

  /**
   * Get the homomorphic hash for a CID.
   */
  async getCidHash(cid: string): Promise<string> {
    return this.homomorphicHash.hashCid(cid);
  }

  /**
   * Verify a CID against its homomorphic hash.
   */
  async verifyCid(cid: string, hash: string): Promise<boolean> {
    return this.homomorphicHash.verifyCid(cid, hash);
  }

  /**
   * Update PIR configuration.
   */
  updateConfig(config: Partial<PirConfig>): void {
    this.config = { ...this.config, ...config };
    
    if (config.useTorProxy !== undefined) {
      this.torProxy.setEnabled(config.useTorProxy);
    }
    
    if (config.dummyQueryCount !== undefined) {
      this.dummyBatcher = new DummyQueryBatcher(
        config.dummyQueryCount,
        this.config.batchDelayMs || DEFAULT_BATCH_DELAY_MS
      );
    }

    if (config.cidIndexKey !== undefined) {
      this.homomorphicHash = new HomomorphicHash(config.cidIndexKey);
    }
  }

  /**
   * Get current PIR configuration.
   */
  getConfig(): PirConfig {
    return { ...this.config };
  }

  /**
   * Check if Tor proxy is available.
   */
  async isTorAvailable(): Promise<boolean> {
    return this.torProxy.isAvailable();
  }
}

// ─── Singleton Export ─────────────────────────────────────────────────────────────

// Bracket-notation lookup (not `import.meta.env.VITE_X`) is deliberate: Vite
// statically inlines literal dot-access member expressions at build time,
// which would bake in whatever value was present at build and make this
// unresponsive to runtime/test env changes. Mirrors the `envString` helper
// used by storageProvider.service.ts and erasureCoding.service.ts.
const envVar = (name: string): string | undefined => {
  const value = (import.meta.env as Record<string, unknown>)[name];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
};

export const pirService = new PirService({
  enabled: envVar("VITE_PIR_ENABLED") === "true",
  useTorProxy: envVar("VITE_PIR_USE_TOR") === "true",
  torSocksHost: envVar("VITE_PIR_TOR_HOST"),
  torSocksPort: envVar("VITE_PIR_TOR_PORT") ? Number(envVar("VITE_PIR_TOR_PORT")) : undefined,
  dummyQueryCount: envVar("VITE_PIR_DUMMY_COUNT") ? Number(envVar("VITE_PIR_DUMMY_COUNT")) : undefined,
  batchDelayMs: envVar("VITE_PIR_BATCH_DELAY") ? Number(envVar("VITE_PIR_BATCH_DELAY")) : undefined,
  cidIndexKey: envVar("VITE_PIR_CID_INDEX_KEY"),
});
