/**
 * @file sorobanEventIndexer.service.ts
 * @description High-performance Soroban contract event indexer with WebSocket real-time broadcast.
 *
 * Implements real-time event indexing for Soroban contract events (VaultCreated, GuardianAdded, AccessRequested)
 * with exponential backoff reconnection, IndexedDB persistence, and WebSocket gateway integration.
 *
 * Architecture:
 * - SorobanEventIndexer: Main indexer with RPC polling and WebSocket relay
 * - EventStore: IndexedDB persistence with enhanced indexing
 * - Exponential backoff reconnection logic for RPC connection drops
 * - WebSocket gateway integration for real-time frontend updates
 */

export const SOROBAN_EVENT_TOPICS = ["VaultCreated", "GuardianAdded", "AccessRequested"] as const;
export type SorobanEventTopic = (typeof SOROBAN_EVENT_TOPICS)[number];

export interface IndexedSorobanEvent {
  id: string;
  cursor: string;
  contractId: string;
  ledger: number;
  ledgerClosedAt: string;
  topic: SorobanEventTopic;
  rawTopics: string[];
  value: unknown;
}

export interface IndexerConfig {
  pollIntervalMs: number;
  maxRetries: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  batchSize: number;
}

export interface IndexerStats {
  running: boolean;
  failures: number;
  lastPollTime: number;
  eventsIndexed: number;
  currentBackoffMs: number;
}

type RpcEvent = {
  id?: string;
  pagingToken?: string;
  contractId?: string;
  ledger?: number;
  ledgerClosedAt?: string;
  topic?: unknown[];
  value?: unknown;
};

type Listener = (event: IndexedSorobanEvent) => void;
const DB_NAME = "spoovault-soroban-events";
const STORE = "events";
const INDEX_STORE = "events-by-topic";
const CURSOR_STORE = "cursors";

// Default configuration
const DEFAULT_CONFIG: IndexerConfig = {
  pollIntervalMs: 250,
  maxRetries: Infinity,
  initialBackoffMs: 500,
  maxBackoffMs: 30_000,
  batchSize: 100,
};

function topicFrom(rawTopics: unknown[] = []): SorobanEventTopic | null {
  const text = rawTopics.map(String).join(" ");
  return SOROBAN_EVENT_TOPICS.find((topic) => text.includes(topic)) ?? null;
}

export function parseSorobanEvent(raw: RpcEvent, fallbackContractId: string): IndexedSorobanEvent | null {
  const rawTopics = (raw.topic ?? []).map(String);
  const topic = topicFrom(rawTopics);
  const cursor = raw.pagingToken ?? raw.id;
  if (!topic || !cursor) return null;
  return {
    id: raw.id ?? cursor,
    cursor,
    contractId: raw.contractId ?? fallbackContractId,
    ledger: Number(raw.ledger ?? 0),
    ledgerClosedAt: raw.ledgerClosedAt ?? new Date().toISOString(),
    topic,
    rawTopics,
    value: raw.value,
  };
}

/**
 * Enhanced EventStore with IndexedDB persistence and topic-based indexing
 * for instant UI rendering and efficient queries.
 */
class EventStore {
  private memory = new Map<string, IndexedSorobanEvent>();
  private topicIndex = new Map<SorobanEventTopic, Set<string>>();
  private dbPromise: Promise<IDBDatabase> | null = null;
  private eventsIndexed = 0;

  private db() {
    if (typeof indexedDB === "undefined") return Promise.reject(new Error("IndexedDB unavailable"));
    if (!this.dbPromise) this.dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 2);
      request.onupgradeneeded = (_event) => {
        const db = request.result;
        
        // Main events store
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE, { keyPath: "id" });
        }
        
        // Topic-based index for efficient queries
        if (!db.objectStoreNames.contains(INDEX_STORE)) {
          const topicStore = db.createObjectStore(INDEX_STORE, { keyPath: "topic" });
          topicStore.createIndex("eventId", "eventId", { unique: false });
        }
        
        // Cursor persistence store
        if (!db.objectStoreNames.contains(CURSOR_STORE)) {
          db.createObjectStore(CURSOR_STORE, { keyPath: "contractId" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return this.dbPromise;
  }

  async put(event: IndexedSorobanEvent) {
    this.memory.set(event.id, event);
    
    // Update topic index
    if (!this.topicIndex.has(event.topic)) {
      this.topicIndex.set(event.topic, new Set());
    }
    this.topicIndex.get(event.topic)!.add(event.id);
    
    this.eventsIndexed++;
    
    try {
      const db = await this.db();
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction([STORE, INDEX_STORE, CURSOR_STORE], "readwrite");
        
        // Store event
        tx.objectStore(STORE).put(event);
        
        // Update topic index
        const topicStore = tx.objectStore(INDEX_STORE);
        topicStore.put({ topic: event.topic, eventId: event.id });
        
        // Update cursor
        const cursorStore = tx.objectStore(CURSOR_STORE);
        cursorStore.put({ contractId: event.contractId, cursor: event.cursor });
        
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch { /* SSR/private-mode fallback remains in memory. */ }
  }

  async getByTopic(topic: SorobanEventTopic): Promise<IndexedSorobanEvent[]> {
    const memoryIds = this.topicIndex.get(topic);
    if (memoryIds) {
      return Array.from(memoryIds)
        .map(id => this.memory.get(id))
        .filter((e): e is IndexedSorobanEvent => e !== undefined);
    }

    try {
      const db = await this.db();
      return new Promise((resolve, reject) => {
        const tx = db.transaction([STORE, INDEX_STORE], "readonly");
        const indexStore = tx.objectStore(INDEX_STORE);
        const request = indexStore.getAll(topic);
        
        request.onsuccess = () => {
          const entries = request.result || [];
          const eventIds = entries.map((e: any) => e.eventId);
          
          const eventsStore = tx.objectStore(STORE);
          const events: IndexedSorobanEvent[] = [];
          
          let completed = 0;
          for (const eventId of eventIds) {
            const eventRequest = eventsStore.get(eventId);
            eventRequest.onsuccess = () => {
              if (eventRequest.result) {
                events.push(eventRequest.result);
              }
              completed++;
              if (completed === eventIds.length) {
                resolve(events);
              }
            };
            eventRequest.onerror = () => {
              completed++;
              if (completed === eventIds.length) {
                resolve(events);
              }
            };
          }
          
          if (eventIds.length === 0) resolve([]);
        };
        request.onerror = () => reject(request.error);
      });
    } catch {
      return [];
    }
  }

  async getCursor(contractId: string): Promise<string | undefined> {
    try {
      const db = await this.db();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(CURSOR_STORE, "readonly");
        const request = tx.objectStore(CURSOR_STORE).get(contractId);
        request.onsuccess = () => resolve(request.result?.cursor);
        request.onerror = () => reject(request.error);
      });
    } catch {
      return undefined;
    }
  }

  async getAll(): Promise<IndexedSorobanEvent[]> {
    return Array.from(this.memory.values());
  }

  getStats() {
    return {
      eventsIndexed: this.eventsIndexed,
      memorySize: this.memory.size,
      topicIndexSize: this.topicIndex.size,
    };
  }
}

/**
 * High-performance Soroban event indexer with exponential backoff reconnection
 * and WebSocket gateway integration for real-time frontend updates.
 */
export class SorobanEventIndexer {
  private running = false;
  private cursor?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private failures = 0;
  private rpcUrl = "";
  private contractId = "";
  private listeners = new Set<Listener>();
  private socket?: WebSocket;
  private store = new EventStore();
  private config: IndexerConfig;
  private lastPollTime = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;

  constructor(config: Partial<IndexerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Start the event indexer with RPC polling and optional WebSocket relay.
   */
  start(rpcUrl: string, contractId: string, relayUrl = import.meta.env.VITE_SOROBAN_EVENT_RELAY_URL as string | undefined) {
    this.stop();
    this.running = true;
    this.rpcUrl = rpcUrl;
    this.contractId = contractId;
    
    // Load persisted cursor
    void this.store.getCursor(contractId).then(persistedCursor => {
      if (persistedCursor) {
        this.cursor = persistedCursor;
      }
    });

    if (relayUrl) {
      this.connectRelay(relayUrl);
    }
    
    void this.poll();
  }

  /**
   * Stop the event indexer and clean up resources.
   */
  stop() {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.timer = undefined;
    this.reconnectTimer = undefined;
    this.socket?.close();
    this.socket = undefined;
  }

  /**
   * Subscribe to indexed events.
   */
  subscribe(listener: Listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Get current indexer statistics.
   */
  getStats(): IndexerStats {
    return {
      running: this.running,
      failures: this.failures,
      lastPollTime: this.lastPollTime,
      eventsIndexed: this.store.getStats().eventsIndexed,
      currentBackoffMs: this.calculateBackoff(),
    };
  }

  /**
   * Get events by topic for efficient UI rendering.
   */
  async getEventsByTopic(topic: SorobanEventTopic): Promise<IndexedSorobanEvent[]> {
    return this.store.getByTopic(topic);
  }

  /**
   * Update indexer configuration at runtime.
   */
  updateConfig(config: Partial<IndexerConfig>) {
    this.config = { ...this.config, ...config };
  }

  private connectRelay(url: string) {
    if (typeof WebSocket === "undefined") return;
    
    this.socket = new WebSocket(url);
    
    this.socket.onopen = () => {
      console.log("Soroban event indexer connected to WebSocket relay");
      this.failures = 0;
    };
    
    this.socket.onmessage = (message) => {
      try {
        const event = parseSorobanEvent(JSON.parse(message.data), this.contractId);
        if (event) void this.publish(event);
      } catch {
        /* Ignore malformed relay payloads. */
      }
    };
    
    this.socket.onerror = (error) => {
      console.warn("WebSocket relay error:", error);
      this.failures++;
    };
    
    this.socket.onclose = () => {
      console.log("WebSocket relay closed, attempting reconnection...");
      this.scheduleReconnect(url);
    };
  }

  private scheduleReconnect(relayUrl: string) {
    if (!this.running) return;
    
    const backoff = this.calculateBackoff();
    this.reconnectTimer = setTimeout(() => {
      this.connectRelay(relayUrl);
    }, backoff);
  }

  private calculateBackoff(): number {
    if (this.failures === 0) return this.config.pollIntervalMs;
    const exponentialBackoff = this.config.initialBackoffMs * Math.pow(2, Math.min(this.failures - 1, 6));
    return Math.min(exponentialBackoff, this.config.maxBackoffMs);
  }

  private async poll(): Promise<void> {
    if (!this.running) return;
    
    this.lastPollTime = Date.now();
    
    try {
      const params: Record<string, unknown> = {
        filters: [{ type: "contract", contractIds: [this.contractId] }],
        pagination: { 
          limit: this.config.batchSize,
          ...(this.cursor ? { cursor: this.cursor } : {}) 
        },
      };
      
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getEvents",
          params
        })
      });
      
      if (!response.ok) {
        throw new Error(`Soroban RPC ${response.status}`);
      }
      
      const body = await response.json();
      if (body.error) {
        throw new Error(body.error.message);
      }
      
      const events = body.result?.events ?? [];
      for (const raw of events) {
        const event = parseSorobanEvent(raw, this.contractId);
        if (event) {
          this.cursor = event.cursor;
          await this.publish(event);
        }
      }
      
      // Reset failures on successful poll
      this.failures = 0;
      
    } catch (error) {
      this.failures++;
      console.warn("Soroban event indexer poll failed, will retry with backoff:", error);
      
      // Check if we've exceeded max retries
      if (this.failures >= this.config.maxRetries) {
        console.error("Soroban event indexer exceeded max retries, stopping");
        this.stop();
        return;
      }
    }
    
    if (this.running) {
      const delay = this.calculateBackoff();
      this.timer = setTimeout(() => void this.poll(), delay);
    }
  }

  private async publish(event: IndexedSorobanEvent) {
    await this.store.put(event);
    
    // Notify all listeners
    this.listeners.forEach((listener) => {
      try {
        listener(event);
      } catch (error) {
        console.error("Error in event listener:", error);
      }
    });
    
    // Dispatch to window for global listeners
    window.dispatchEvent(new CustomEvent("spoovault:soroban:event", { detail: event }));
    
    // Forward to WebSocket relay if connected
    if (this.socket?.readyState === WebSocket.OPEN) {
      try {
        this.socket.send(JSON.stringify(event));
      } catch (error) {
        console.warn("Failed to send event to WebSocket relay:", error);
      }
    }
  }
}

export const sorobanEventIndexer = new SorobanEventIndexer();
