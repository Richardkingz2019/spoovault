/**
 * Unit tests for the Reed-Solomon erasure coding service.
 *
 * Coverage:
 *  - GF(2^8) encode: correct shard count, shard size, data shard passthrough
 *  - Decode: reconstruct from all data shards
 *  - Decode: reconstruct when data shards are missing (parity-only recovery)
 *  - Decode: reconstruct from any M-shard subset (mixed data + parity)
 *  - Decode: throws when fewer than M shards are provided
 *  - Padding: odd-sized payloads are correctly padded and stripped
 *  - shard distribution: calls uploadFn per shard, builds correct manifest
 *  - shard distribution: records failed uploads without throwing
 *  - retrieveShards: calls fetchFn, returns populated Shard array
 *  - retrieveShards: throws when too many fetches fail
 *  - encodeAndDistribute: end-to-end happy path
 *  - reconstructFromManifest: end-to-end happy path
 *  - reconstructFromManifest: reconstructs when P shards are unreachable
 *  - verifyShards: returns empty array for uncorrupted shards
 *  - verifyShards: detects corrupted parity shard
 *  - config boundary: single parity shard (minimum)
 *  - config boundary: throws on 0 data or parity shards
 */

import { describe, it, expect, vi } from "vitest";
import {
  encode,
  decode,
  distributeShards,
  retrieveShards,
  encodeAndDistribute,
  reconstructFromManifest,
  verifyShards,
  erasureCodingService,
  DEFAULT_SHARD_CONFIG,
  type PinningNode,
} from "../services/erasureCoding.service";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a deterministic test payload of a given byte length. */
function makePayload(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  for (let i = 0; i < length; i++) buf[i] = (i * 7 + 13) & 0xff;
  return buf;
}

/**
 * Build a pair of mock pinning nodes that use an in-memory CID→data store.
 * Returns both nodes and a direct reference to the store for test assertions.
 */
function makeMockNodes(
  count: number = 2
): { nodes: PinningNode[]; store: Map<string, Uint8Array> } {
  const store = new Map<string, Uint8Array>();
  let cidCounter = 0;

  const nodes: PinningNode[] = Array.from({ length: count }, (_, i) => ({
    name: `mock-node-${i}`,
    uploadFn: vi.fn(async (data: Uint8Array, name: string): Promise<string> => {
      const cid = `bafy${++cidCounter}-${name}`;
      store.set(cid, new Uint8Array(data));
      return cid;
    }),
    fetchFn: vi.fn(async (cid: string): Promise<Uint8Array> => {
      const data = store.get(cid);
      if (!data) throw new Error(`CID not found in mock store: ${cid}`);
      return new Uint8Array(data);
    }),
  }));

  return { nodes, store };
}

// ─── GF(2^8) encode ───────────────────────────────────────────────────────────

describe("encode", () => {
  it("returns M + P shards", () => {
    const shards = encode(makePayload(64), 4, 2);
    expect(shards).toHaveLength(6);
  });

  it("marks first M shards as data and remainder as parity", () => {
    const shards = encode(makePayload(128), 4, 3);
    const dataShards = shards.filter((s) => s.isData);
    const parityShards = shards.filter((s) => !s.isData);
    expect(dataShards).toHaveLength(4);
    expect(parityShards).toHaveLength(3);
    dataShards.forEach((s, i) => expect(s.index).toBe(i));
    parityShards.forEach((s, i) => expect(s.index).toBe(4 + i));
  });

  it("all shards have equal byte length", () => {
    const shards = encode(makePayload(100), 4, 2);
    const size = shards[0].data.length;
    shards.forEach((s) => expect(s.data.length).toBe(size));
  });

  it("data shards concatenate to the padded original payload", () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const dataShards = shards.filter((s) => s.isData).sort((a, b) => a.index - b.index);
    const reconstructed = new Uint8Array(dataShards.reduce((sum, s) => sum + s.data.length, 0));
    dataShards.forEach((s, i) => {
      reconstructed.set(s.data, i * s.data.length);
    });
    // Original payload should be a prefix of the reconstructed bytes
    expect(reconstructed.slice(0, payload.length)).toEqual(payload);
  });

  it("throws when dataShards < 1", () => {
    expect(() => encode(makePayload(32), 0, 2)).toThrow("dataShards must be ≥ 1");
  });

  it("throws when parityShards < 1", () => {
    expect(() => encode(makePayload(32), 4, 0)).toThrow("parityShards must be ≥ 1");
  });

  it("works with a single-byte payload", () => {
    const shards = encode(new Uint8Array([0xab]), 4, 2);
    expect(shards).toHaveLength(6);
    shards.forEach((s) => expect(s.data.length).toBe(1));
  });

  it("produces different data for parity vs data shards", () => {
    // Parity shards should not be simple copies of data shards for non-trivial input
    const payload = makePayload(256);
    const shards = encode(payload, 4, 2);
    const dataBytes = shards.filter((s) => s.isData).map((s) => Array.from(s.data));
    const parityBytes = shards.filter((s) => !s.isData).map((s) => Array.from(s.data));
    expect(dataBytes).not.toEqual(parityBytes.slice(0, 2));
  });
});

// ─── decode: full reconstruction ─────────────────────────────────────────────

describe("decode — all data shards available", () => {
  it("reconstructs payload exactly from data shards only", () => {
    const payload = makePayload(256);
    const shards = encode(payload, 4, 2);
    const dataShards = shards.filter((s) => s.isData);
    const result = decode(dataShards, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });

  it("strips padding correctly for a payload not divisible by M", () => {
    const payload = makePayload(57); // 57 is not divisible by 4
    const shards = encode(payload, 4, 2);
    const dataShards = shards.filter((s) => s.isData);
    const result = decode(dataShards, 4, 2, payload.length);
    expect(result).toEqual(payload);
    expect(result.length).toBe(57);
  });

  it("reconstructs a large payload (4 KiB)", () => {
    const payload = makePayload(4096);
    const shards = encode(payload, 4, 2);
    const dataShards = shards.filter((s) => s.isData);
    const result = decode(dataShards, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });
});

// ─── decode: erasure recovery ─────────────────────────────────────────────────

describe("decode — parity-assisted recovery", () => {
  it("recovers when 1 data shard is lost (4+2 config)", () => {
    const payload = makePayload(256);
    const shards = encode(payload, 4, 2);
    // Drop data shard at index 0, supply remaining 3 data + 2 parity = 5 ≥ M=4
    const available = shards.filter((s) => s.index !== 0);
    const result = decode(available, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });

  it("recovers when 2 data shards are lost (4+2 config)", () => {
    const payload = makePayload(256);
    const shards = encode(payload, 4, 2);
    // Drop data shards 1 and 2; remaining: [0, 3, p0, p1] = exactly M=4
    const available = shards.filter((s) => s.index !== 1 && s.index !== 2);
    const result = decode(available, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });

  it("recovers using only parity shards when all data shards are lost (3+3 config)", () => {
    const payload = makePayload(192);
    const shards = encode(payload, 3, 3);
    // Keep only the 3 parity shards (indices 3, 4, 5)
    const available = shards.filter((s) => !s.isData);
    const result = decode(available, 3, 3, payload.length);
    expect(result).toEqual(payload);
  });

  it("recovers using a mixed subset of M shards (data + parity)", () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    // Provide data shard 0, data shard 2, parity shard 0, parity shard 1
    const available = shards.filter((s) => [0, 2, 4, 5].includes(s.index));
    const result = decode(available, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });

  it("throws when fewer than M shards are provided", () => {
    const shards = encode(makePayload(128), 4, 2);
    const tooFew = shards.slice(0, 3);
    expect(() => decode(tooFew, 4, 2)).toThrow(
      /Not enough shards to reconstruct/
    );
  });

  it("recovers with minimum 1 data + 1 parity shard in (2+2) config", () => {
    const payload = makePayload(64);
    const shards = encode(payload, 2, 2);
    // Drop data shard 0, use data shard 1 + parity shard 0
    const available = shards.filter((s) => [1, 2].includes(s.index));
    const result = decode(available, 2, 2, payload.length);
    expect(result).toEqual(payload);
  });
});

// ─── edge cases ───────────────────────────────────────────────────────────────

describe("encode/decode edge cases", () => {
  it("handles payload of exactly M bytes (1 byte per shard)", () => {
    const payload = new Uint8Array([10, 20, 30, 40]);
    const shards = encode(payload, 4, 2);
    const available = shards.filter((s) => s.index !== 0 && s.index !== 3);
    const result = decode(available, 4, 2, payload.length);
    expect(result).toEqual(payload);
  });

  it("works with minimum config (1 data + 1 parity)", () => {
    const payload = makePayload(32);
    const shards = encode(payload, 1, 1);
    expect(shards).toHaveLength(2);
    // Recover from parity shard only
    const parityOnly = shards.filter((s) => !s.isData);
    const result = decode(parityOnly, 1, 1, payload.length);
    expect(result).toEqual(payload);
  });

  it("is deterministic: same input always produces same shards", () => {
    const payload = makePayload(64);
    const shards1 = encode(payload, 4, 2);
    const shards2 = encode(payload, 4, 2);
    shards1.forEach((s, i) => {
      expect(s.data).toEqual(shards2[i].data);
    });
  });

  it("different payloads produce different shards", () => {
    const shards1 = encode(makePayload(64), 4, 2);
    const shards2 = encode(makePayload(64).map((b) => b ^ 0xff) as Uint8Array, 4, 2);
    // At least one shard should differ
    const anyDiff = shards1.some((s, i) =>
      s.data.some((byte, j) => byte !== shards2[i].data[j])
    );
    expect(anyDiff).toBe(true);
  });
});

// ─── distributeShards ─────────────────────────────────────────────────────────

describe("distributeShards", () => {
  it("calls uploadFn for every shard across available nodes", async () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(3);

    const { manifest, failed } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    expect(failed).toHaveLength(0);
    expect(manifest.shards).toHaveLength(6);
    // Every shard in the manifest should have a CID
    manifest.shards.forEach((entry) => {
      expect(entry.cid).toMatch(/^bafy/);
      expect(entry.node).toMatch(/^mock-node-/);
    });
  });

  it("builds manifest with correct totalShards, dataShards, parityShards", async () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(2);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    expect(manifest.totalShards).toBe(6);
    expect(manifest.dataShards).toBe(4);
    expect(manifest.parityShards).toBe(2);
    expect(manifest.originalSize).toBe(payload.length);
  });

  it("records upload failures without throwing", async () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(2);

    // Make the first node's upload always fail
    (nodes[0].uploadFn as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("Pinning service unavailable")
    );

    const { failed } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    // Shards 0, 2, 4 go to node-0 (round-robin of 6 shards across 2 nodes)
    expect(failed.length).toBeGreaterThan(0);
    failed.forEach((f) => expect(f.error).toContain("Pinning service unavailable"));
  });

  it("distributes shards across nodes in round-robin order", async () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(3);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    // Each node should get at least 1 shard when we have 6 shards across 3 nodes
    const nodeNames = manifest.shards.map((s) => s.node);
    const unique = new Set(nodeNames);
    expect(unique.size).toBe(3);
  });

  it("throws when no nodes are provided", async () => {
    const shards = encode(makePayload(32), 4, 2);
    await expect(
      distributeShards(shards, { nodes: [], originalSize: 32 })
    ).rejects.toThrow("No pinning nodes available");
  });
});

// ─── retrieveShards ───────────────────────────────────────────────────────────

describe("retrieveShards", () => {
  it("fetches all shards from their respective nodes", async () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(2);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    const retrieved = await retrieveShards(manifest, nodes);
    expect(retrieved).toHaveLength(6);
    retrieved.forEach((s) => expect(s.data.length).toBeGreaterThan(0));
  });

  it("returns Shard objects with correct index and isData fields", async () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(2);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    const retrieved = await retrieveShards(manifest, nodes);
    const byIndex = new Map(retrieved.map((s) => [s.index, s]));
    for (let i = 0; i < 6; i++) {
      const s = byIndex.get(i)!;
      expect(s).toBeDefined();
      expect(s.isData).toBe(i < 4);
    }
  });

  it("throws when too many shards are unreachable", async () => {
    const payload = makePayload(64);
    const shards = encode(payload, 4, 2);
    const { nodes } = makeMockNodes(2);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    // Make all fetches fail
    nodes.forEach((n) => {
      (n.fetchFn as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("Gateway unreachable")
      );
    });

    await expect(retrieveShards(manifest, nodes)).rejects.toThrow(
      /Too many fetch failures/
    );
  });

  it("succeeds when only M shards are retrievable (tolerates P failures)", async () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    const { nodes, store } = makeMockNodes(2);

    const { manifest } = await distributeShards(shards, {
      nodes,
      originalSize: payload.length,
    });

    // Poison 2 out of 6 CIDs (parity shards, highest indices)
    const cidsToDrop = manifest.shards
      .filter((s) => !s.isData)
      .map((s) => s.cid);
    cidsToDrop.forEach((cid) => store.delete(cid));

    const retrieved = await retrieveShards(manifest, nodes);
    // Should still retrieve 4 data shards successfully
    expect(retrieved.length).toBeGreaterThanOrEqual(4);
  });
});

// ─── end-to-end: encodeAndDistribute + reconstructFromManifest ────────────────

describe("encodeAndDistribute + reconstructFromManifest (end-to-end)", () => {
  it("round-trips payload through mock IPFS nodes", async () => {
    const payload = makePayload(512);
    const { nodes } = makeMockNodes(3);

    const { manifest, failed } = await encodeAndDistribute(
      payload,
      DEFAULT_SHARD_CONFIG,
      nodes
    );
    expect(failed).toHaveLength(0);

    const reconstructed = await reconstructFromManifest(manifest, nodes);
    expect(reconstructed).toEqual(payload);
  });

  it("reconstructs correctly when P shards are unreachable", async () => {
    const payload = makePayload(256);
    const { nodes, store } = makeMockNodes(2);

    const { manifest } = await encodeAndDistribute(
      payload,
      { dataShards: 4, parityShards: 2 },
      nodes
    );

    // Simulate IPFS nodes dropping 2 parity shards
    const parityEntries = manifest.shards.filter((s) => !s.isData);
    parityEntries.forEach((e) => store.delete(e.cid));

    const reconstructed = await reconstructFromManifest(manifest, nodes);
    expect(reconstructed).toEqual(payload);
  });

  it("reconstructs correctly when P data shards are unreachable (parity recovery)", async () => {
    const payload = makePayload(256);
    const { nodes, store } = makeMockNodes(4);

    const { manifest } = await encodeAndDistribute(
      payload,
      { dataShards: 4, parityShards: 2 },
      nodes
    );

    // Drop data shards 0 and 1
    const dataToDrop = manifest.shards.filter((s) => s.isData).slice(0, 2);
    dataToDrop.forEach((e) => store.delete(e.cid));

    const reconstructed = await reconstructFromManifest(manifest, nodes);
    expect(reconstructed).toEqual(payload);
  });

  it("preserves exact byte content for binary payloads with all 256 byte values", async () => {
    // Payload containing every possible byte value (0x00–0xff) twice
    const payload = new Uint8Array(512);
    for (let i = 0; i < 512; i++) payload[i] = i & 0xff;

    const { nodes } = makeMockNodes(2);
    const { manifest } = await encodeAndDistribute(
      payload,
      { dataShards: 4, parityShards: 2 },
      nodes
    );

    const reconstructed = await reconstructFromManifest(manifest, nodes);
    expect(reconstructed).toEqual(payload);
  });

  it("works with a (6+3) high-redundancy configuration", async () => {
    const payload = makePayload(360);
    const { nodes, store } = makeMockNodes(4);

    const { manifest } = await encodeAndDistribute(
      payload,
      { dataShards: 6, parityShards: 3 },
      nodes
    );

    // Drop 3 arbitrary shards (maximum tolerable loss)
    const toDrop = manifest.shards.slice(0, 3);
    toDrop.forEach((e) => store.delete(e.cid));

    const reconstructed = await reconstructFromManifest(manifest, nodes);
    expect(reconstructed).toEqual(payload);
  });
});

// ─── verifyShards ──────────────────────────────────────────────────────────────

describe("verifyShards", () => {
  it("returns an empty array for a pristine shard set", () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    const corrupted = verifyShards(shards, 4, 2);
    expect(corrupted).toEqual([]);
  });

  it("detects a corrupted parity shard (directly flagged)", () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    // Flip a bit in the first parity shard
    const parityIdx = shards.findIndex((s) => !s.isData);
    shards[parityIdx].data[0] ^= 0x55;
    const corrupted = verifyShards(shards, 4, 2);
    expect(corrupted).toContain(shards[parityIdx].index);
  });

  it("detects a corrupted data shard via inconsistent parity (4+2 config)", () => {
    // When P=2 < M=4, we cannot reconstruct canonical data from parity alone.
    // verifyShards re-encodes from the stored (corrupted) data shards, which
    // produces parity that differs from what was stored — parity shards are
    // flagged as inconsistent signalling that something in the set is wrong.
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    shards[2].data[3] ^= 0xff;
    const corrupted = verifyShards(shards, 4, 2);
    // At least one discrepancy detected (parity no longer matches)
    expect(corrupted.length).toBeGreaterThan(0);
  });

  it("detects a corrupted data shard directly when P >= M (3+3 config)", () => {
    // With parityShards (3) >= dataShards (3), verifyShards reconstructs
    // canonical data from parity shards alone and pinpoints the exact bad shard.
    const payload = makePayload(192);
    const shards = encode(payload, 3, 3);
    shards[1].data[0] ^= 0xff;
    const corrupted = verifyShards(shards, 3, 3);
    expect(corrupted).toContain(1);
  });

  it("detects multiple corrupted shards and reports all inconsistencies", () => {
    const payload = makePayload(128);
    const shards = encode(payload, 4, 2);
    shards[0].data[0] ^= 0x01;
    shards[4].data[1] ^= 0x80; // parity shard
    const corrupted = verifyShards(shards, 4, 2);
    // Multiple discrepancies — at least something must be reported
    expect(corrupted.length).toBeGreaterThan(0);
    // The explicitly corrupted parity shard must appear in the set
    expect(corrupted).toContain(4);
  });
});

// ─── erasureCodingService singleton ──────────────────────────────────────────

describe("erasureCodingService singleton", () => {
  it("exposes all public methods", () => {
    expect(typeof erasureCodingService.encode).toBe("function");
    expect(typeof erasureCodingService.decode).toBe("function");
    expect(typeof erasureCodingService.distributeShards).toBe("function");
    expect(typeof erasureCodingService.retrieveShards).toBe("function");
    expect(typeof erasureCodingService.encodeAndDistribute).toBe("function");
    expect(typeof erasureCodingService.reconstructFromManifest).toBe("function");
    expect(typeof erasureCodingService.verifyShards).toBe("function");
    expect(typeof erasureCodingService.buildDefaultNodes).toBe("function");
  });

  it("encode via singleton returns the same result as the named export", () => {
    const payload = makePayload(64);
    const shards1 = erasureCodingService.encode(payload, 4, 2);
    const shards2 = encode(payload, 4, 2);
    shards1.forEach((s, i) => expect(s.data).toEqual(shards2[i].data));
  });
});

// ─── DEFAULT_SHARD_CONFIG ─────────────────────────────────────────────────────

describe("DEFAULT_SHARD_CONFIG", () => {
  it("has dataShards=4 and parityShards=2", () => {
    expect(DEFAULT_SHARD_CONFIG.dataShards).toBe(4);
    expect(DEFAULT_SHARD_CONFIG.parityShards).toBe(2);
  });

  it("encode/decode round-trip with DEFAULT_SHARD_CONFIG works", () => {
    const payload = makePayload(64);
    const shards = encode(payload);
    expect(shards).toHaveLength(
      DEFAULT_SHARD_CONFIG.dataShards + DEFAULT_SHARD_CONFIG.parityShards
    );
    const result = decode(shards.filter((s) => s.isData), undefined, undefined, payload.length);
    expect(result).toEqual(payload);
  });
});
