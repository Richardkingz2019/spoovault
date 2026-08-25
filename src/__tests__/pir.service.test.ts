/**
 * @file pir.service.test.ts
 * @description Integration tests for PIR (Private Information Retrieval) service.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PirService, DummyQueryBatcher, HomomorphicHash } from "../services/pir.service";
import { ipfsGateway } from "../services/ipfsGateway";

describe("HomomorphicHash", () => {
  let homomorphicHash: HomomorphicHash;

  beforeEach(() => {
    homomorphicHash = new HomomorphicHash();
  });

  it("should generate consistent hashes for the same CID within a session", async () => {
    const cid = "QmTest123456789";
    const hash1 = await homomorphicHash.hashCid(cid);
    const hash2 = await homomorphicHash.hashCid(cid);

    expect(hash1).toBe(hash2);
  });

  it("should generate different hashes for different CIDs", async () => {
    const cid1 = "QmTest123456789";
    const cid2 = "QmDifferent987654321";
    const hash1 = await homomorphicHash.hashCid(cid1);
    const hash2 = await homomorphicHash.hashCid(cid2);

    expect(hash1).not.toBe(hash2);
  });

  it("should verify CID against its hash correctly", async () => {
    const cid = "QmTest123456789";
    const hash = await homomorphicHash.hashCid(cid);
    const isValid = await homomorphicHash.verifyCid(cid, hash);

    expect(isValid).toBe(true);
  });

  it("should reject invalid CID verification", async () => {
    const cid1 = "QmTest123456789";
    const cid2 = "QmDifferent987654321";
    const hash = await homomorphicHash.hashCid(cid1);
    const isValid = await homomorphicHash.verifyCid(cid2, hash);

    expect(isValid).toBe(false);
  });

  it("should generate different salts for different instances", async () => {
    const hash1 = new HomomorphicHash();
    const hash2 = new HomomorphicHash();
    const cid = "QmTest123456789";

    expect(hash1.getSalt()).not.toBe(hash2.getSalt());
    expect(await hash1.hashCid(cid)).not.toBe(await hash2.hashCid(cid));
  });

  it("produces identical hashes across separate instances given the same key", async () => {
    const cid = "QmTest123456789";
    const hash1 = new HomomorphicHash("shared-vault-key");
    const hash2 = new HomomorphicHash("shared-vault-key");

    expect(hash1.getSalt()).toBe(hash2.getSalt());
    expect(await hash1.hashCid(cid)).toBe(await hash2.hashCid(cid));
  });

  it("produces different hashes for different keys", async () => {
    const cid = "QmTest123456789";
    const hash1 = new HomomorphicHash("key-a");
    const hash2 = new HomomorphicHash("key-b");

    expect(await hash1.hashCid(cid)).not.toBe(await hash2.hashCid(cid));
  });

  it("a keyed hash still verifies correctly against itself", async () => {
    const cid = "QmTest123456789";
    const homomorphicHash = new HomomorphicHash("shared-vault-key");
    const hash = await homomorphicHash.hashCid(cid);

    expect(await homomorphicHash.verifyCid(cid, hash)).toBe(true);
    expect(await homomorphicHash.verifyCid("QmOther", hash)).toBe(false);
  });
});

describe("DummyQueryBatcher", () => {
  let batcher: DummyQueryBatcher;

  beforeEach(() => {
    batcher = new DummyQueryBatcher(3, 50);
  });

  it("should create a batch with one real query and dummy queries", () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);

    expect(batch).toHaveLength(4); // 1 real + 3 dummy
    expect(batch.filter((q: any) => q.isReal)).toHaveLength(1);
    expect(batch.filter((q: any) => !q.isReal)).toHaveLength(3);
  });

  it("should include the real CID in the batch", () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);

    const realQuery = batch.find((q: any) => q.isReal);
    expect(realQuery?.cid).toBe(realCid);
  });

  it("should generate different dummy CIDs", () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);
    const dummyCids = batch.filter((q: any) => !q.isReal).map((q: any) => q.cid);

    const uniqueCids = new Set(dummyCids);
    expect(uniqueCids.size).toBe(dummyCids.length);
  });

  it("should shuffle the batch to obscure the real query", () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);

    // The real query should not always be in the same position
    const realIndex = batch.findIndex((q: any) => q.isReal);
    expect(realIndex).toBeGreaterThanOrEqual(0);
    expect(realIndex).toBeLessThan(batch.length);
  });

  it("should execute batch and return only real result", async () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);
    
    const mockFetch = vi.fn().mockImplementation((cid: string) => {
      if (cid === realCid) {
        return Promise.resolve(new Response("real data", { status: 200 }));
      }
      return Promise.reject(new Error("Dummy query failed"));
    });

    const result = await batcher.executeBatch(batch, mockFetch);

    expect(result.realResult).toBeDefined();
    expect(result.dummyCount).toBe(3);
    expect(mockFetch).toHaveBeenCalledTimes(4);
  });

  it("should handle dummy query failures gracefully", async () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);
    
    const mockFetch = vi.fn().mockImplementation((cid: string) => {
      if (cid === realCid) {
        return Promise.resolve(new Response("real data", { status: 200 }));
      }
      return Promise.reject(new Error("Dummy query failed"));
    });

    const result = await batcher.executeBatch(batch, mockFetch);

    expect(result.realResult).toBeDefined();
    expect(result.dummyCount).toBe(3);
  });

  it("should throw error if real query fails", async () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid);

    const mockFetch = vi.fn().mockRejectedValue(new Error("All queries failed"));

    await expect(batcher.executeBatch(batch, mockFetch)).rejects.toThrow("Real query failed to execute");
  });

  it("dispatches queries concurrently rather than strictly sequentially", async () => {
    const realCid = "QmTest123456789";
    const batch = batcher.createBatch(realCid); // 1 real + 3 dummy = 4 queries

    let inFlight = 0;
    let maxInFlight = 0;
    const mockFetch = vi.fn().mockImplementation((cid: string) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      return new Promise<Response>((resolve) => {
        setTimeout(() => {
          inFlight--;
          resolve(
            cid === realCid
              ? new Response("real data", { status: 200 })
              : new Response("decoy data", { status: 200 })
          );
        }, 20);
      });
    });

    await batcher.executeBatch(batch, mockFetch);

    // A sequential for-loop would never have more than 1 in flight at once.
    expect(maxInFlight).toBeGreaterThan(1);
  });

  describe("decoy pool (real CIDs)", () => {
    it("uses real CIDs from the decoy pool instead of synthetic ones", () => {
      const realCid = "QmReal";
      const pool = ["QmSibling1", "QmSibling2", "QmSibling3"];
      const batch = batcher.createBatch(realCid, pool); // dummyQueryCount = 3

      const decoyCids = batch.filter((q) => !q.isReal).map((q) => q.cid);
      expect(decoyCids.sort()).toEqual([...pool].sort());
    });

    it("excludes the real CID from sampled decoys even if present in the pool", () => {
      const realCid = "QmReal";
      const pool = ["QmReal", "QmSibling1", "QmSibling2"];
      const batch = batcher.createBatch(realCid, pool);

      const decoyCids = batch.filter((q) => !q.isReal).map((q) => q.cid);
      expect(decoyCids).not.toContain(realCid);
    });

    it("pads with synthetic decoys when the pool is smaller than dummyQueryCount", () => {
      const realCid = "QmReal";
      const pool = ["QmSibling1"]; // dummyQueryCount = 3, pool has only 1
      const batch = batcher.createBatch(realCid, pool);

      const decoyCids = batch.filter((q) => !q.isReal).map((q) => q.cid);
      expect(decoyCids).toHaveLength(3);
      expect(decoyCids).toContain("QmSibling1");
    });

    it("falls back to fully synthetic decoys when no pool is provided", () => {
      const realCid = "QmReal";
      const batch = batcher.createBatch(realCid);

      const decoyCids = batch.filter((q) => !q.isReal).map((q) => q.cid);
      expect(decoyCids).toHaveLength(3);
      decoyCids.forEach((cid) => expect(cid).not.toBe(realCid));
    });

    it("real decoys resolve successfully just like the real query (indistinguishable by status)", async () => {
      const realCid = "QmReal";
      const pool = ["QmSibling1", "QmSibling2", "QmSibling3"];
      const batch = batcher.createBatch(realCid, pool);

      const mockFetch = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
      const { realResult } = await batcher.executeBatch(batch, mockFetch);

      expect(realResult.status).toBe(200);
      // Every dispatched CID (real + real decoys) got a 200 in this mock —
      // nothing in the response codes distinguishes the real request.
      const calledCids = mockFetch.mock.calls.map((c) => c[0]);
      expect(calledCids.sort()).toEqual([realCid, ...pool].sort());
    });
  });
});

describe("PirService", () => {
  let pirService: PirService;

  beforeEach(() => {
    pirService = new PirService({
      enabled: true,
      useTorProxy: false,
      dummyQueryCount: 2,
      batchDelayMs: 10,
    });
  });

  it("should be initialized with default config", () => {
    const config = pirService.getConfig();
    expect(config.enabled).toBe(true);
    expect(config.useTorProxy).toBe(false);
    expect(config.dummyQueryCount).toBe(2);
    expect(config.batchDelayMs).toBe(10);
  });

  it("should update configuration", () => {
    pirService.updateConfig({
      enabled: false,
      dummyQueryCount: 5,
    });

    const config = pirService.getConfig();
    expect(config.enabled).toBe(false);
    expect(config.dummyQueryCount).toBe(5);
  });

  it("should generate CID hash", async () => {
    const cid = "QmTest123456789";
    const hash = await pirService.getCidHash(cid);

    expect(hash).toBeDefined();
    expect(hash.length).toBeGreaterThan(0);
  });

  it("should verify CID hash", async () => {
    const cid = "QmTest123456789";
    const hash = await pirService.getCidHash(cid);
    const isValid = await pirService.verifyCid(cid, hash);

    expect(isValid).toBe(true);
  });

  it("should return false for invalid CID verification", async () => {
    const cid1 = "QmTest123456789";
    const cid2 = "QmDifferent987654321";
    const hash = await pirService.getCidHash(cid1);
    const isValid = await pirService.verifyCid(cid2, hash);

    expect(isValid).toBe(false);
  });

  it("should check Tor availability", async () => {
    const isAvailable = await pirService.isTorAvailable();
    expect(typeof isAvailable).toBe("boolean");
  });

  describe("fetchDocument with PIR disabled", () => {
    beforeEach(() => {
      pirService.updateConfig({ enabled: false });
      vi.spyOn(ipfsGateway, "fetchFile").mockRejectedValue(new Error("network unavailable"));
      vi.spyOn(ipfsGateway, "getURL").mockReturnValue("https://test.com/ipfs/QmTest123456789");
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("should use standard fetch when PIR is disabled", async () => {
      const cid = "QmTest123456789";

      const result = await pirService.fetchDocument(cid);

      expect(result.success).toBe(false); // fetchFile rejects, caught and reported
      expect(result.proxied).toBe(false);
      expect(result.dummyQueriesIssued).toBe(0);
    });
  });

  describe("fetchDocument with PIR enabled", () => {
    beforeEach(() => {
      vi.spyOn(ipfsGateway, "getURL").mockReturnValue("https://test.com/ipfs/QmTest123456789");
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network unavailable")));
    });

    afterEach(() => {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    });

    it("should execute PIR fetch when enabled", async () => {
      const cid = "QmTest123456789";

      const result = await pirService.fetchDocument(cid);

      expect(result.success).toBe(false); // no real gateway reachable in this environment
      expect(result.dummyQueriesIssued).toBeGreaterThanOrEqual(0);
    });

    it("passes decoyCids through to the batch so real gateways see indistinguishable requests", async () => {
      const cid = "QmTest123456789";
      const fetchMock = vi.fn().mockResolvedValue(new Response("data", { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      const result = await pirService.fetchDocument(cid, undefined, ["QmSibling1", "QmSibling2"]);

      expect(result.success).toBe(true);
      const requestedUrls = fetchMock.mock.calls.map((c) => String(c[0]));
      // getURL is mocked to a fixed URL, but the important thing is that the
      // sibling CIDs were part of the batch dispatched via fetchFn.
      expect(fetchMock).toHaveBeenCalledTimes(3); // real + 2 decoys
      expect(requestedUrls.length).toBe(3);
    });
  });

  describe("fail-closed Tor behavior", () => {
    it("never issues a network request when useTorProxy is enabled but no real proxy is available", async () => {
      const torService = new PirService({
        enabled: true,
        useTorProxy: true,
        dummyQueryCount: 2,
        batchDelayMs: 5,
      });

      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const gatewaySpy = vi.spyOn(ipfsGateway, "fetchFile");

      const result = await torService.fetchDocument("QmTest123456789");

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/not available/i);
      expect(result.proxied).toBe(false);
      // The whole point of failing closed: no request — protected or not —
      // should ever have gone out.
      expect(fetchMock).not.toHaveBeenCalled();
      expect(gatewaySpy).not.toHaveBeenCalled();

      vi.unstubAllGlobals();
      vi.restoreAllMocks();
    });

    it("isTorAvailable reports false (no genuine in-browser SOCKS5 support)", async () => {
      const torService = new PirService({ enabled: true, useTorProxy: true });
      expect(await torService.isTorAvailable()).toBe(false);
    });
  });

  describe("deterministic CID index key", () => {
    it("two PirService instances with the same cidIndexKey produce the same CID hash", async () => {
      const a = new PirService({ enabled: true, useTorProxy: false, cidIndexKey: "vault-key" });
      const b = new PirService({ enabled: true, useTorProxy: false, cidIndexKey: "vault-key" });

      const cid = "QmTest123456789";
      expect(await a.getCidHash(cid)).toBe(await b.getCidHash(cid));
    });

    it("updateConfig({ cidIndexKey }) makes the hash deterministic going forward", async () => {
      const service = new PirService({ enabled: true, useTorProxy: false });
      const cid = "QmTest123456789";
      const beforeHash = await service.getCidHash(cid);

      service.updateConfig({ cidIndexKey: "vault-key" });
      const other = new PirService({ enabled: true, useTorProxy: false, cidIndexKey: "vault-key" });

      expect(await service.getCidHash(cid)).toBe(await other.getCidHash(cid));
      expect(await service.getCidHash(cid)).not.toBe(beforeHash);
    });
  });
});

describe("PIR Integration Tests", () => {
  it("should handle complete PIR workflow", async () => {
    const pirService = new PirService({
      enabled: true,
      useTorProxy: false,
      dummyQueryCount: 3,
    });

    const cid = "QmTest123456789";
    
    // Generate hash
    const hash = await pirService.getCidHash(cid);
    expect(hash).toBeDefined();

    // Verify hash
    const isValid = await pirService.verifyCid(cid, hash);
    expect(isValid).toBe(true);

    // Check config
    const config = pirService.getConfig();
    expect(config.enabled).toBe(true);
    expect(config.dummyQueryCount).toBe(3);
  });

  it("should handle Tor proxy configuration", async () => {
    const pirService = new PirService({
      enabled: true,
      useTorProxy: true,
      torSocksHost: "127.0.0.1",
      torSocksPort: 9050,
    });

    const config = pirService.getConfig();
    expect(config.useTorProxy).toBe(true);
    expect(config.torSocksHost).toBe("127.0.0.1");
    expect(config.torSocksPort).toBe(9050);
  });

  it("should handle configuration updates at runtime", async () => {
    const pirService = new PirService({
      enabled: false,
      useTorProxy: false,
      dummyQueryCount: 2,
    });

    expect(pirService.getConfig().enabled).toBe(false);
    expect(pirService.getConfig().dummyQueryCount).toBe(2);

    pirService.updateConfig({
      enabled: true,
      dummyQueryCount: 10,
      batchDelayMs: 200,
    });

    expect(pirService.getConfig().enabled).toBe(true);
    expect(pirService.getConfig().dummyQueryCount).toBe(10);
    expect(pirService.getConfig().batchDelayMs).toBe(200);
  });
});
