/**
 * Reed-Solomon Erasure Coding Service
 *
 * Splits an encrypted payload into M data shards + P parity shards (N = M + P)
 * using systematic Reed-Solomon codes over GF(2^8) with the Cauchy matrix
 * construction.  Any K = M shards (data or parity) are sufficient to
 * reconstruct the original payload.
 *
 * The GF(2^8) field uses the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
 * (0x11D), which is the same polynomial used by AES — well-studied and widely
 * compatible.
 *
 * Architecture:
 *   encode(data, M, P) → ShardSet          — split + compute parity
 *   decode(shards, M, P) → Uint8Array      — reconstruct original payload
 *   distributeShards(shards)               — pin each shard to a distinct node
 *   retrieveShards(manifest)               — fetch shards from IPFS nodes
 *   reconstructFromManifest(manifest)      — fetch + decode in one call
 */

// ─── GF(2^8) arithmetic ──────────────────────────────────────────────────────

/** GF(2^8) primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D */
const GF_PRIMITIVE = 0x11d;
const GF_SIZE = 256;

/** Precomputed exp and log tables for fast GF multiplication / division. */
const gfExp: Uint8Array = new Uint8Array(512); // double-length for wrap-around
const gfLog: Uint8Array = new Uint8Array(GF_SIZE);

(function buildTables() {
  let x = 1;
  for (let i = 0; i < GF_SIZE - 1; i++) {
    gfExp[i] = x;
    gfLog[x] = i;
    x <<= 1;
    if (x >= GF_SIZE) x ^= GF_PRIMITIVE;
  }
  // Mirror first 255 entries into positions 255–509 so gfExp[a + b] never
  // needs a modulo when a and b are both in [0, 254].
  for (let i = 0; i < GF_SIZE - 1; i++) gfExp[i + GF_SIZE - 1] = gfExp[i];
})();

/** Multiply two GF(2^8) elements. */
function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return gfExp[gfLog[a] + gfLog[b]];
}

/** Divide two GF(2^8) elements (b ≠ 0). */
function gfDiv(a: number, b: number): number {
  if (b === 0) throw new RangeError("GF division by zero");
  if (a === 0) return 0;
  return gfExp[gfLog[a] + (GF_SIZE - 1) - gfLog[b]];
}

/** Add two GF(2^8) elements (identical to subtraction in GF(2^8)). */
function gfAdd(a: number, b: number): number {
  return a ^ b;
}

// ─── Matrix operations ────────────────────────────────────────────────────────

/**
 * A flat row-major matrix of GF(2^8) elements.
 * Entry (r, c) is stored at index r * cols + c.
 */
class GFMatrix {
  readonly rows: number;
  readonly cols: number;
  readonly data: Uint8Array;

  constructor(rows: number, cols: number, data?: Uint8Array) {
    this.rows = rows;
    this.cols = cols;
    this.data = data ?? new Uint8Array(rows * cols);
  }

  get(r: number, c: number): number {
    return this.data[r * this.cols + c];
  }

  set(r: number, c: number, v: number): void {
    this.data[r * this.cols + c] = v;
  }

  /** Return a copy of this matrix. */
  clone(): GFMatrix {
    return new GFMatrix(this.rows, this.cols, new Uint8Array(this.data));
  }

  /** Multiply this × other in GF(2^8). */
  multiply(other: GFMatrix): GFMatrix {
    if (this.cols !== other.rows) {
      throw new RangeError(
        `Matrix dimension mismatch: (${this.rows}×${this.cols}) × (${other.rows}×${other.cols})`
      );
    }
    const result = new GFMatrix(this.rows, other.cols);
    for (let r = 0; r < this.rows; r++) {
      for (let c = 0; c < other.cols; c++) {
        let sum = 0;
        for (let k = 0; k < this.cols; k++) {
          sum = gfAdd(sum, gfMul(this.get(r, k), other.get(k, c)));
        }
        result.set(r, c, sum);
      }
    }
    return result;
  }

  /**
   * Return the sub-matrix consisting of the specified row indices.
   */
  subsetRows(rowIndices: number[]): GFMatrix {
    const m = new GFMatrix(rowIndices.length, this.cols);
    rowIndices.forEach((srcRow, dstRow) => {
      for (let c = 0; c < this.cols; c++) {
        m.set(dstRow, c, this.get(srcRow, c));
      }
    });
    return m;
  }

  /**
   * Gaussian elimination inversion in GF(2^8).
   * Matrix must be square.  Throws if singular.
   */
  invert(): GFMatrix {
    if (this.rows !== this.cols) throw new RangeError("invert requires a square matrix");
    const n = this.rows;
    const aug = new GFMatrix(n, n * 2);

    // Augment with identity
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        aug.set(r, c, this.get(r, c));
        aug.set(r, c + n, r === c ? 1 : 0);
      }
    }

    // Forward elimination with partial pivoting
    for (let col = 0; col < n; col++) {
      // Find pivot
      let pivotRow = -1;
      for (let r = col; r < n; r++) {
        if (aug.get(r, col) !== 0) {
          pivotRow = r;
          break;
        }
      }
      if (pivotRow === -1) throw new Error("Matrix is singular — cannot invert");

      // Swap rows
      if (pivotRow !== col) {
        for (let c = 0; c < n * 2; c++) {
          const tmp = aug.get(col, c);
          aug.set(col, c, aug.get(pivotRow, c));
          aug.set(pivotRow, c, tmp);
        }
      }

      // Scale pivot row so diagonal becomes 1
      const scale = aug.get(col, col);
      for (let c = 0; c < n * 2; c++) {
        aug.set(col, c, gfDiv(aug.get(col, c), scale));
      }

      // Eliminate other rows
      for (let r = 0; r < n; r++) {
        if (r === col) continue;
        const factor = aug.get(r, col);
        if (factor === 0) continue;
        for (let c = 0; c < n * 2; c++) {
          aug.set(r, c, gfAdd(aug.get(r, c), gfMul(factor, aug.get(col, c))));
        }
      }
    }

    // Extract right half
    const inv = new GFMatrix(n, n);
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        inv.set(r, c, aug.get(r, c + n));
      }
    }
    return inv;
  }
}

/**
 * Build a Vandermonde-style Cauchy matrix of shape (rows × cols) in GF(2^8).
 *
 * Entry (i, j) = 1 / (x_i XOR y_j) where x_i and y_j are drawn from
 * distinct parts of GF(2^8) \ {0}.  This guarantees every square sub-matrix
 * is invertible, which is the key property needed for erasure recovery.
 */
function buildCauchyMatrix(rows: number, cols: number): GFMatrix {
  if (rows + cols > GF_SIZE)
    throw new RangeError(
      `rows (${rows}) + cols (${cols}) exceeds GF(2^8) capacity (256)`
    );
  const m = new GFMatrix(rows, cols);
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      // x values: 0..cols-1, y values: cols..cols+rows-1
      m.set(r, c, gfDiv(1, gfAdd(c, cols + r)));
    }
  }
  return m;
}

/**
 * Build the (M+P) × M encoding matrix.
 * Top M×M block is the identity (systematic form — data shards pass through
 * unchanged).  Bottom P×M block is a Cauchy matrix.
 */
function buildEncodingMatrix(dataShards: number, parityShards: number): GFMatrix {
  const total = dataShards + parityShards;
  const enc = new GFMatrix(total, dataShards);

  // Identity block
  for (let r = 0; r < dataShards; r++) enc.set(r, r, 1);

  // Cauchy block
  const cauchy = buildCauchyMatrix(parityShards, dataShards);
  for (let r = 0; r < parityShards; r++) {
    for (let c = 0; c < dataShards; c++) {
      enc.set(r + dataShards, c, cauchy.get(r, c));
    }
  }
  return enc;
}

// ─── Public types ─────────────────────────────────────────────────────────────

/** A single shard produced by encoding. */
export interface Shard {
  /** 0-based shard index (0..M-1 are data shards, M..N-1 are parity). */
  index: number;
  /** Whether this shard is a data shard (false = parity). */
  isData: boolean;
  /** Raw bytes of this shard. */
  data: Uint8Array;
  /** IPFS CID after pinning (set by distributeShards). */
  cid?: string;
  /** Pinning node that holds this shard (set by distributeShards). */
  node?: string;
}

/** Configuration for a sharding operation. */
export interface ShardConfig {
  /** Number of data shards M (minimum shards needed to reconstruct). */
  dataShards: number;
  /** Number of parity shards P (maximum tolerable loss). */
  parityShards: number;
}

/** Default configuration: 4 data + 2 parity → tolerates any 2 failures. */
export const DEFAULT_SHARD_CONFIG: ShardConfig = {
  dataShards: 4,
  parityShards: 2,
};

/** Manifest stored on-chain or in IPFS — everything needed to reconstruct. */
export interface ShardManifest {
  /** Total shard count N = M + P. */
  totalShards: number;
  /** Data shard count M. */
  dataShards: number;
  /** Parity shard count P. */
  parityShards: number;
  /** Original payload byte length (needed to strip padding on reconstruction). */
  originalSize: number;
  /** Per-shard metadata. */
  shards: Array<{
    index: number;
    isData: boolean;
    cid: string;
    node: string;
  }>;
}

/** IPFS pinning node descriptor. */
export interface PinningNode {
  name: string;
  uploadFn: (data: Uint8Array, name: string) => Promise<string>; // returns CID
  fetchFn: (cid: string) => Promise<Uint8Array>;
}

/** Result of a distribution attempt. */
export interface DistributionResult {
  manifest: ShardManifest;
  /** Shards that failed to pin, if any. */
  failed: Array<{ index: number; error: string }>;
}

// ─── Core encode / decode ─────────────────────────────────────────────────────

/**
 * Pad `data` to a length that is a multiple of `dataShards`, then split into
 * equal-length data shards.
 */
function padAndSplit(data: Uint8Array, dataShards: number): Uint8Array[] {
  const shardSize = Math.ceil(data.length / dataShards);
  const paddedLength = shardSize * dataShards;
  const padded = new Uint8Array(paddedLength);
  padded.set(data);
  // Zero-padding ensures deterministic behaviour; original length is preserved
  // in the manifest so padding is stripped during reconstruction.

  const shards: Uint8Array[] = [];
  for (let i = 0; i < dataShards; i++) {
    shards.push(padded.slice(i * shardSize, (i + 1) * shardSize));
  }
  return shards;
}

/**
 * Encode `data` into M data shards + P parity shards.
 *
 * @param data          Encrypted file bytes.
 * @param dataShards    M — number of data shards.
 * @param parityShards  P — number of parity shards.
 * @returns             Array of M + P shards.
 */
export function encode(
  data: Uint8Array,
  dataShards: number = DEFAULT_SHARD_CONFIG.dataShards,
  parityShards: number = DEFAULT_SHARD_CONFIG.parityShards
): Shard[] {
  if (dataShards < 1) throw new RangeError("dataShards must be ≥ 1");
  if (parityShards < 1) throw new RangeError("parityShards must be ≥ 1");
  if (dataShards + parityShards > GF_SIZE - 1)
    throw new RangeError(
      `Total shards (${dataShards + parityShards}) exceeds GF(2^8) limit`
    );

  const rawDataShards = padAndSplit(data, dataShards);
  const shardSize = rawDataShards[0].length;
  const encMatrix = buildEncodingMatrix(dataShards, parityShards);

  // Allocate output buffer: (M + P) × shardSize
  const outputData: Uint8Array[] = [
    ...rawDataShards,
    ...Array.from({ length: parityShards }, () => new Uint8Array(shardSize)),
  ];

  // Compute parity shards via matrix–vector product per byte position
  for (let bytePos = 0; bytePos < shardSize; bytePos++) {
    for (let p = 0; p < parityShards; p++) {
      let val = 0;
      for (let d = 0; d < dataShards; d++) {
        val = gfAdd(val, gfMul(encMatrix.get(dataShards + p, d), rawDataShards[d][bytePos]));
      }
      outputData[dataShards + p][bytePos] = val;
    }
  }

  return outputData.map((shardData, index) => ({
    index,
    isData: index < dataShards,
    data: shardData,
  }));
}

/**
 * Decode / reconstruct the original payload from any M shards (data or parity).
 *
 * @param availableShards  At least M shards (with correct index set).
 * @param dataShards       M — the same value used during encoding.
 * @param parityShards     P — the same value used during encoding.
 * @param originalSize     Byte length of the original payload (strips padding).
 * @returns                Reconstructed payload (without padding).
 */
export function decode(
  availableShards: Shard[],
  dataShards: number = DEFAULT_SHARD_CONFIG.dataShards,
  parityShards: number = DEFAULT_SHARD_CONFIG.parityShards,
  originalSize?: number
): Uint8Array {
  if (availableShards.length < dataShards) {
    throw new Error(
      `Not enough shards to reconstruct: have ${availableShards.length}, need ${dataShards}`
    );
  }

  // Use the first M shards (sorted by index for determinism)
  const selected = [...availableShards]
    .sort((a, b) => a.index - b.index)
    .slice(0, dataShards);

  const shardSize = selected[0].data.length;
  const encMatrix = buildEncodingMatrix(dataShards, parityShards);

  // Build the M×M sub-matrix corresponding to the selected shard rows
  const subMatrix = encMatrix.subsetRows(selected.map((s) => s.index));
  const invMatrix = subMatrix.invert();

  // Reconstruct all M data shards
  const reconstructed: Uint8Array[] = Array.from({ length: dataShards }, () =>
    new Uint8Array(shardSize)
  );

  for (let bytePos = 0; bytePos < shardSize; bytePos++) {
    for (let d = 0; d < dataShards; d++) {
      let val = 0;
      for (let s = 0; s < dataShards; s++) {
        val = gfAdd(val, gfMul(invMatrix.get(d, s), selected[s].data[bytePos]));
      }
      reconstructed[d][bytePos] = val;
    }
  }

  // Concatenate data shards and strip padding
  const fullData = new Uint8Array(dataShards * shardSize);
  reconstructed.forEach((shard, i) => fullData.set(shard, i * shardSize));

  return originalSize !== undefined ? fullData.slice(0, originalSize) : fullData;
}

// ─── IPFS distribution ────────────────────────────────────────────────────────

/**
 * Default pinning nodes drawn from env-level configuration.
 * Each node gets a round-robin allocation of shards so that no single
 * provider holds more than ceil(N / nodeCount) shards.
 *
 * Consumers may inject custom nodes via `distributeShards({ nodes: [...] })`.
 */
export function buildDefaultNodes(): PinningNode[] {
  const pinataJwt =
    typeof import.meta !== "undefined"
      ? (import.meta as any).env?.VITE_PINATA_JWT
      : undefined;

  const nodes: PinningNode[] = [];

  // Pinata
  if (pinataJwt) {
    nodes.push({
      name: "pinata",
      uploadFn: async (data: Uint8Array, name: string): Promise<string> => {
        const formData = new FormData();
        formData.append("file", new Blob([data.buffer as ArrayBuffer], { type: "application/octet-stream" }), name);
        const resp = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
          method: "POST",
          headers: { Authorization: `Bearer ${pinataJwt}` },
          body: formData,
        });
        if (!resp.ok) throw new Error(`Pinata upload failed: ${resp.status}`);
        const json = await resp.json();
        return json.IpfsHash as string;
      },
      fetchFn: async (cid: string): Promise<Uint8Array> => {
        const resp = await fetch(`https://gateway.pinata.cloud/ipfs/${cid}`);
        if (!resp.ok) throw new Error(`Pinata fetch failed: ${resp.status}`);
        return new Uint8Array(await resp.arrayBuffer());
      },
    });
  }

  // Fallback public gateway (read-only, for fetch)
  nodes.push({
    name: "ipfs.io",
    uploadFn: async (_data: Uint8Array, _name: string): Promise<string> => {
      throw new Error("ipfs.io is a read-only gateway — cannot pin");
    },
    fetchFn: async (cid: string): Promise<Uint8Array> => {
      const resp = await fetch(`https://ipfs.io/ipfs/${cid}`);
      if (!resp.ok) throw new Error(`ipfs.io fetch failed: ${resp.status}`);
      return new Uint8Array(await resp.arrayBuffer());
    },
  });

  return nodes;
}

/**
 * Pin each shard to a distinct pinning node using round-robin assignment.
 *
 * @param shards   Encoded shards produced by `encode`.
 * @param options  Optional nodes array and AbortSignal.
 * @returns        DistributionResult with a ShardManifest and any failures.
 */
export async function distributeShards(
  shards: Shard[],
  options: {
    nodes?: PinningNode[];
    originalSize: number;
    signal?: AbortSignal;
  }
): Promise<DistributionResult> {
  const dataShards = shards.filter((s) => s.isData).length;
  const parityShards = shards.filter((s) => !s.isData).length;
  const nodes = options.nodes ?? buildDefaultNodes();

  if (nodes.length === 0) throw new Error("No pinning nodes available");

  const failed: Array<{ index: number; error: string }> = [];
  const pinned: Array<{ index: number; isData: boolean; cid: string; node: string }> = [];

  await Promise.allSettled(
    shards.map(async (shard, i) => {
      if (options.signal?.aborted) {
        failed.push({ index: shard.index, error: "Aborted" });
        return;
      }
      const node = nodes[i % nodes.length];
      const shardName = `shard-${shard.index}-${shard.isData ? "data" : "parity"}`;
      try {
        const cid = await node.uploadFn(shard.data, shardName);
        pinned.push({ index: shard.index, isData: shard.isData, cid, node: node.name });
      } catch (err: any) {
        failed.push({ index: shard.index, error: err?.message ?? String(err) });
      }
    })
  );

  // Sort manifest by shard index for stable ordering
  pinned.sort((a, b) => a.index - b.index);

  const manifest: ShardManifest = {
    totalShards: shards.length,
    dataShards,
    parityShards,
    originalSize: options.originalSize,
    shards: pinned,
  };

  return { manifest, failed };
}

/**
 * Retrieve shards from IPFS nodes as listed in the manifest.
 * Tolerates up to `parityShards` fetch failures.
 *
 * @param manifest  The ShardManifest produced by distributeShards.
 * @param nodes     Pinning nodes with fetch capability.
 * @param signal    Optional AbortSignal.
 * @returns         Array of successfully retrieved Shards.
 */
export async function retrieveShards(
  manifest: ShardManifest,
  nodes: PinningNode[],
  signal?: AbortSignal
): Promise<Shard[]> {
  const nodeMap = new Map<string, PinningNode>(nodes.map((n) => [n.name, n]));

  const results = await Promise.allSettled(
    manifest.shards.map(async (entry) => {
      if (signal?.aborted) throw new Error("Aborted");
      const node = nodeMap.get(entry.node);
      if (!node) throw new Error(`Unknown node: ${entry.node}`);
      const data = await node.fetchFn(entry.cid);
      return {
        index: entry.index,
        isData: entry.isData,
        data,
        cid: entry.cid,
        node: entry.node,
      } satisfies Shard;
    })
  );

  const retrieved: Shard[] = [];
  let fetchFailures = 0;

  for (const result of results) {
    if (result.status === "fulfilled") {
      retrieved.push(result.value);
    } else {
      fetchFailures++;
    }
  }

  if (retrieved.length < manifest.dataShards) {
    throw new Error(
      `Too many fetch failures (${fetchFailures}): only ${retrieved.length}/${manifest.totalShards} shards retrieved, need at least ${manifest.dataShards}`
    );
  }

  return retrieved;
}

/**
 * Convenience: encode an encrypted payload, distribute shards, and return
 * the manifest and any distribution failures.
 *
 * @param encryptedData  Ciphertext bytes to protect with erasure coding.
 * @param config         Shard configuration (dataShards, parityShards).
 * @param nodes          IPFS pinning nodes.
 * @param signal         Optional AbortSignal.
 */
export async function encodeAndDistribute(
  encryptedData: Uint8Array,
  config: ShardConfig = DEFAULT_SHARD_CONFIG,
  nodes?: PinningNode[],
  signal?: AbortSignal
): Promise<DistributionResult> {
  const shards = encode(encryptedData, config.dataShards, config.parityShards);
  return distributeShards(shards, {
    nodes,
    originalSize: encryptedData.length,
    signal,
  });
}

/**
 * Convenience: retrieve shards from the manifest, then reconstruct the
 * original encrypted payload.
 *
 * @param manifest  ShardManifest from encodeAndDistribute.
 * @param nodes     Pinning nodes with fetch capability.
 * @param signal    Optional AbortSignal.
 * @returns         Reconstructed ciphertext bytes (same as input to encodeAndDistribute).
 */
export async function reconstructFromManifest(
  manifest: ShardManifest,
  nodes: PinningNode[],
  signal?: AbortSignal
): Promise<Uint8Array> {
  const shards = await retrieveShards(manifest, nodes, signal);
  return decode(shards, manifest.dataShards, manifest.parityShards, manifest.originalSize);
}

// ─── Shard integrity helpers ──────────────────────────────────────────────────

/**
 * Verify that a set of all N = M + P shards is internally consistent.
 *
 * Strategy:
 *  1. Reconstruct the original payload from the parity shards alone (using
 *     the parity rows of the encoding matrix as an independent witness).
 *     If we can't (e.g. parityShards < dataShards), fall through to step 2.
 *  2. Re-encode the full data payload and compare every shard against the
 *     canonical expected value to locate discrepancies.
 *
 * This detects corruption in both data and parity shards.
 *
 * @param shards       All N shards (data + parity).
 * @param dataShards   M value used during encoding.
 * @param parityShards P value used during encoding.
 * @returns            Sorted array of shard indices where corruption was detected.
 */
export function verifyShards(shards: Shard[], dataShards: number, parityShards: number): number[] {
  const allSorted = [...shards].sort((a, b) => a.index - b.index);
  const shardSize = allSorted[0].data.length;

  // ── Step 1: derive canonical payload from parity shards only (independent of
  //    data shards, so it will disagree if a data shard is corrupt). ─────────
  let canonicalData: Uint8Array[] | null = null;

  const parityShardsAvailable = allSorted.filter((s) => !s.isData);
  if (parityShardsAvailable.length >= dataShards) {
    try {
      // decode() accepts any M-shard subset — use parity shards as that subset
      const paritySubset = parityShardsAvailable.slice(0, dataShards);
      const reconstructed = decode(
        paritySubset,
        dataShards,
        parityShards,
        dataShards * shardSize // no strip — we want the full padded payload
      );
      canonicalData = [];
      for (let i = 0; i < dataShards; i++) {
        canonicalData.push(reconstructed.slice(i * shardSize, (i + 1) * shardSize));
      }
    } catch {
      // If reconstruction fails the shards are definitely corrupt; fall through
      // to the parity-driven comparison path below.
      canonicalData = null;
    }
  }

  // ── Step 2: re-encode from canonical data and compare every shard ─────────
  // When canonicalData is null (not enough parity shards), fall back to
  // re-encoding from the stored data shards.  This still catches parity
  // corruption even if it can't distinguish a corrupted data shard.
  let reEncodedInput: Uint8Array;
  if (canonicalData !== null) {
    reEncodedInput = new Uint8Array(dataShards * shardSize);
    canonicalData.forEach((d, i) => reEncodedInput.set(d, i * shardSize));
  } else {
    const storedData = allSorted
      .filter((s) => s.isData)
      .sort((a, b) => a.index - b.index);
    if (storedData.length !== dataShards)
      throw new Error(`Expected ${dataShards} data shards, got ${storedData.length}`);
    reEncodedInput = new Uint8Array(dataShards * shardSize);
    storedData.forEach((s, i) => reEncodedInput.set(s.data, i * shardSize));
  }

  const reEncoded = encode(reEncodedInput, dataShards, parityShards);
  const corrupted: number[] = [];

  allSorted.forEach((shard) => {
    const expected = reEncoded[shard.index];
    for (let i = 0; i < shard.data.length; i++) {
      if (shard.data[i] !== expected.data[i]) {
        corrupted.push(shard.index);
        return;
      }
    }
  });

  return corrupted;
}

// ─── Named service export (matches project service pattern) ──────────────────

export const erasureCodingService = {
  encode,
  decode,
  distributeShards,
  retrieveShards,
  encodeAndDistribute,
  reconstructFromManifest,
  verifyShards,
  buildDefaultNodes,
};
