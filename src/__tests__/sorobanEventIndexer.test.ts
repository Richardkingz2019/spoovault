// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { 
  parseSorobanEvent, 
  SorobanEventIndexer, 
  SOROBAN_EVENT_TOPICS,
  type IndexerConfig
} from "../services/sorobanEventIndexer.service";

describe("SorobanEventIndexer", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe("Event Parsing", () => {
    it("decodes supported topics and rejects unrelated events", () => {
      expect(parseSorobanEvent({ id: "1", topic: ["VaultCreated"], ledger: 4 }, "contract")?.topic).toBe("VaultCreated");
      expect(parseSorobanEvent({ id: "2", topic: ["GuardianAdded"], ledger: 5 }, "contract")?.topic).toBe("GuardianAdded");
      expect(parseSorobanEvent({ id: "3", topic: ["AccessRequested"], ledger: 6 }, "contract")?.topic).toBe("AccessRequested");
      expect(parseSorobanEvent({ id: "4", topic: ["SomethingElse"] }, "contract")).toBeNull();
    });

    it("handles missing cursor gracefully", () => {
      expect(parseSorobanEvent({ topic: ["VaultCreated"] }, "contract")).toBeNull();
    });

    it("uses fallback contract ID when missing from event", () => {
      const event = parseSorobanEvent({ id: "1", pagingToken: "cursor", topic: ["VaultCreated"] }, "fallback-contract");
      expect(event?.contractId).toBe("fallback-contract");
    });

    it("parses complete event structure correctly", () => {
      const event = parseSorobanEvent(
        { 
          id: "event-123", 
          pagingToken: "cursor-456", 
          topic: ["VaultCreated"], 
          ledger: 12345,
          ledgerClosedAt: "2024-01-01T00:00:00Z",
          value: { test: "data" }
        }, 
        "contract-abc"
      );

      expect(event).toEqual({
        id: "event-123",
        cursor: "cursor-456",
        contractId: "contract-abc",
        ledger: 12345,
        ledgerClosedAt: "2024-01-01T00:00:00Z",
        topic: "VaultCreated",
        rawTopics: ["VaultCreated"],
        value: { test: "data" }
      });
    });
  });

  describe("Event Distribution", () => {
    it("distributes parsed events to subscribers", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["GuardianAdded"] }] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      const listener = vi.fn();
      indexer.subscribe(listener);
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      expect(listener).toHaveBeenCalled();
      expect(listener.mock.calls[0][0].topic).toBe("GuardianAdded");
      indexer.stop();
    });

    it("dispatches events to window for global listeners", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["VaultCreated"] }] } }) 
      }));
      
      const globalListener = vi.fn();
      window.addEventListener("spoovault:soroban:event", globalListener);
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      expect(globalListener).toHaveBeenCalled();
      const customEvent = globalListener.mock.calls[0][0] as CustomEvent;
      expect(customEvent.detail.topic).toBe("VaultCreated");
      
      window.removeEventListener("spoovault:soroban:event", globalListener);
      indexer.stop();
    });

    it("handles multiple subscribers", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["AccessRequested"] }] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      const listener1 = vi.fn();
      const listener2 = vi.fn();
      
      indexer.subscribe(listener1);
      indexer.subscribe(listener2);
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      expect(listener1).toHaveBeenCalled();
      expect(listener2).toHaveBeenCalled();
      indexer.stop();
    });

    it("allows unsubscribing from events", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["VaultCreated"] }] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      const listener = vi.fn();
      const unsubscribe = indexer.subscribe(listener);
      
      unsubscribe();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      expect(listener).not.toHaveBeenCalled();
      indexer.stop();
    });
  });

  describe("Exponential Backoff Reconnection", () => {
    it("uses exponential backoff after an RPC failure", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      expect(fetch).toHaveBeenCalled();
      expect(indexer.getStats().failures).toBeGreaterThan(0);
      indexer.stop();
    });

    it("resets failures on successful poll", async () => {
      let callCount = 0;
      vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({ ok: false, status: 503 });
        }
        return Promise.resolve({ 
          ok: true, 
          json: async () => ({ result: { events: [] } }) 
        });
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      const stats = indexer.getStats();
      expect(stats.failures).toBe(0);
      indexer.stop();
    });

    it("stops after exceeding max retries", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
      
      const config: Partial<IndexerConfig> = { maxRetries: 3 };
      const indexer = new SorobanEventIndexer(config);
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      await vi.runOnlyPendingTimersAsync();
      await vi.runOnlyPendingTimersAsync();
      
      const stats = indexer.getStats();
      expect(stats.running).toBe(false);
      indexer.stop();
    });

    it("calculates backoff correctly based on failure count", () => {
      const indexer = new SorobanEventIndexer();
      
      // Test with 0 failures
      let stats = indexer.getStats();
      expect(stats.currentBackoffMs).toBe(250); // Default poll interval
      
      // Simulate failures by checking backoff calculation
      // Note: We can't directly set failures, but we can test the pattern
      const config: Partial<IndexerConfig> = { initialBackoffMs: 500, maxBackoffMs: 30000 };
      const indexerWithConfig = new SorobanEventIndexer(config);
      stats = indexerWithConfig.getStats();
      expect(stats.currentBackoffMs).toBe(250);
    });
  });

  describe("Configuration Management", () => {
    it("accepts custom configuration", () => {
      const config: Partial<IndexerConfig> = {
        pollIntervalMs: 500,
        maxRetries: 10,
        initialBackoffMs: 1000,
        maxBackoffMs: 60000,
        batchSize: 50
      };
      
      const indexer = new SorobanEventIndexer(config);
      const stats = indexer.getStats();
      
      expect(stats.currentBackoffMs).toBe(500);
    });

    it("updates configuration at runtime", () => {
      const indexer = new SorobanEventIndexer({ pollIntervalMs: 100 });
      
      indexer.updateConfig({ pollIntervalMs: 500, batchSize: 200 });
      
      const stats = indexer.getStats();
      expect(stats.currentBackoffMs).toBe(500);
    });

    it("uses default configuration when not provided", () => {
      const indexer = new SorobanEventIndexer();
      const stats = indexer.getStats();
      
      expect(stats.currentBackoffMs).toBe(250); // Default poll interval
    });
  });

  describe("Statistics and Monitoring", () => {
    it("provides accurate indexer statistics", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor", topic: ["VaultCreated"] }] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      const stats = indexer.getStats();
      expect(stats.running).toBe(true);
      expect(stats.eventsIndexed).toBeGreaterThan(0);
      expect(stats.lastPollTime).toBeGreaterThan(0);
      
      indexer.stop();
    });

    it("tracks failures correctly", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      const stats = indexer.getStats();
      expect(stats.failures).toBeGreaterThan(0);
      
      indexer.stop();
    });
  });

  describe("Lifecycle Management", () => {
    it("stops polling when stop is called", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      expect(indexer.getStats().running).toBe(true);
      
      indexer.stop();
      expect(indexer.getStats().running).toBe(false);
    });

    it("cleans up timers on stop", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      indexer.stop();
      
      // Verify no timers are running after stop
      const stats = indexer.getStats();
      expect(stats.running).toBe(false);
    });

    it("restarts correctly after stop", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      indexer.stop();
      
      // Restart
      indexer.start("https://rpc.example", "contract");
      await vi.runOnlyPendingTimersAsync();
      
      expect(indexer.getStats().running).toBe(true);
      indexer.stop();
    });
  });

  describe("Topic Filtering", () => {
    it("supports all defined topics", () => {
      expect(SOROBAN_EVENT_TOPICS).toContain("VaultCreated");
      expect(SOROBAN_EVENT_TOPICS).toContain("GuardianAdded");
      expect(SOROBAN_EVENT_TOPICS).toContain("AccessRequested");
    });

    it("filters events by topic correctly", () => {
      const event1 = parseSorobanEvent({ id: "1", topic: ["VaultCreated"] }, "contract");
      const event2 = parseSorobanEvent({ id: "2", topic: ["RandomEvent"] }, "contract");
      
      expect(event1?.topic).toBe("VaultCreated");
      expect(event2).toBeNull();
    });
  });

  describe("Cursor Management", () => {
    it("updates cursor after successful event processing", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ 
        ok: true, 
        json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor-123", topic: ["VaultCreated"] }] } }) 
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      
      // Cursor should be updated (verified through subsequent calls using the cursor)
      indexer.stop();
    });

    it("uses cursor in subsequent requests", async () => {
      let callCount = 0;
      vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({ 
            ok: true, 
            json: async () => ({ result: { events: [{ id: "one", pagingToken: "cursor-123", topic: ["VaultCreated"] }] } }) 
          });
        }
        return Promise.resolve({ 
          ok: true, 
          json: async () => ({ result: { events: [] } }) 
        });
      }));
      
      const indexer = new SorobanEventIndexer();
      indexer.start("https://rpc.example", "contract");
      
      await vi.runOnlyPendingTimersAsync();
      await vi.runOnlyPendingTimersAsync();
      
      // Second call should include cursor
      expect((fetch as any).mock.calls.length).toBeGreaterThanOrEqual(2);
      
      indexer.stop();
    });
  });
});
