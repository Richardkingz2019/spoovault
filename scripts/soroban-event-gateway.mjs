/**
 * @file soroban-event-gateway.mjs
 * @description WebSocket gateway server for real-time Soroban contract event broadcasting.
 *
 * This Node.js server provides a WebSocket gateway that:
 * - Polls Soroban RPC for contract events
 * - Broadcasts events to connected frontend clients via WebSocket
 * - Handles connection management with exponential backoff reconnection
 * - Supports multiple contract subscriptions
 *
 * Usage: node scripts/soroban-event-gateway.mjs
 * Environment variables:
 * - SOROBAN_RPC_URL: Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
 * - SOROBAN_CONTRACT_IDS: Comma-separated list of contract IDs to monitor
 * - WS_PORT: WebSocket server port (default: 8080)
 * - POLL_INTERVAL_MS: Event polling interval (default: 250)
 */

import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const SOROBAN_RPC_URL = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const SOROBAN_CONTRACT_IDS = (process.env.SOROBAN_CONTRACT_IDS || '').split(',').filter(Boolean);
const WS_PORT = parseInt(process.env.WS_PORT || '8080', 10);
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '250', 10);
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES || 'Infinity', 10);
const INITIAL_BACKOFF_MS = parseInt(process.env.INITIAL_BACKOFF_MS || '500', 10);
const MAX_BACKOFF_MS = parseInt(process.env.MAX_BACKOFF_MS || '30000', 10);
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || '100', 10);

// Event topics to monitor
const EVENT_TOPICS = ['VaultCreated', 'GuardianAdded', 'AccessRequested'];

// Contract state management
const contractStates = new Map();

// WebSocket clients
const clients = new Set();

// Initialize contract states
for (const contractId of SOROBAN_CONTRACT_IDS) {
  contractStates.set(contractId, {
    cursor: null,
    failures: 0,
    lastPollTime: 0,
    eventsIndexed: 0,
  });
}

/**
 * Calculate exponential backoff delay
 */
function calculateBackoff(failures) {
  if (failures === 0) return POLL_INTERVAL_MS;
  const exponentialBackoff = INITIAL_BACKOFF_MS * Math.pow(2, Math.min(failures - 1, 6));
  return Math.min(exponentialBackoff, MAX_BACKOFF_MS);
}

/**
 * Parse Soroban event from RPC response
 */
function parseSorobanEvent(raw, contractId) {
  const rawTopics = (raw.topic || []).map(String);
  const topicText = rawTopics.join(' ');
  const topic = EVENT_TOPICS.find(t => topicText.includes(t));
  const cursor = raw.pagingToken || raw.id;
  
  if (!topic || !cursor) return null;
  
  return {
    id: raw.id || cursor,
    cursor,
    contractId: raw.contractId || contractId,
    ledger: Number(raw.ledger || 0),
    ledgerClosedAt: raw.ledgerClosedAt || new Date().toISOString(),
    topic,
    rawTopics,
    value: raw.value,
  };
}

/**
 * Fetch events from Soroban RPC
 */
async function fetchEvents(rpcUrl, contractId, cursor) {
  const params = {
    filters: [{ type: 'contract', contractIds: [contractId] }],
    pagination: {
      limit: BATCH_SIZE,
      ...(cursor ? { cursor } : {}),
    },
  };

  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'getEvents',
      params,
    }),
  });

  if (!response.ok) {
    throw new Error(`Soroban RPC ${response.status}`);
  }

  const body = await response.json();
  if (body.error) {
    throw new Error(body.error.message);
  }

  return body.result?.events || [];
}

/**
 * Poll events for a specific contract
 */
async function pollContract(contractId) {
  const state = contractStates.get(contractId);
  if (!state) return;

  state.lastPollTime = Date.now();

  try {
    const events = await fetchEvents(SOROBAN_RPC_URL, contractId, state.cursor);
    
    for (const raw of events) {
      const event = parseSorobanEvent(raw, contractId);
      if (event) {
        state.cursor = event.cursor;
        state.eventsIndexed++;
        broadcastEvent(event);
      }
    }

    // Reset failures on successful poll
    state.failures = 0;

  } catch (error) {
    state.failures++;
    console.error(`[Contract ${contractId}] Poll failed (attempt ${state.failures}):`, error.message);

    // Check if we've exceeded max retries
    if (state.failures >= MAX_RETRIES) {
      console.error(`[Contract ${contractId}] Exceeded max retries, stopping polling`);
      return;
    }
  }

  // Schedule next poll
  if (state.failures < MAX_RETRIES) {
    const delay = calculateBackoff(state.failures);
    setTimeout(() => pollContract(contractId), delay);
  }
}

/**
 * Broadcast event to all connected WebSocket clients
 */
function broadcastEvent(event) {
  const message = JSON.stringify(event);
  
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(message);
      } catch (error) {
        console.error('Failed to send event to client:', error);
        clients.delete(client);
      }
    }
  });

  console.log(`[Broadcast] ${event.topic} for contract ${event.contractId} (ledger ${event.ledger})`);
}

/**
 * Start polling for all contracts
 */
function startPolling() {
  console.log(`Starting event polling for ${SOROBAN_CONTRACT_IDS.length} contracts`);
  
  for (const contractId of SOROBAN_CONTRACT_IDS) {
    console.log(`[Contract ${contractId}] Starting polling`);
    pollContract(contractId);
  }
}

/**
 * Create HTTP server with WebSocket upgrade
 */
const server = createServer((req, res) => {
  // Health check endpoint
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      contracts: Array.from(contractStates.entries()).map(([id, state]) => ({
        contractId: id,
        failures: state.failures,
        eventsIndexed: state.eventsIndexed,
        lastPollTime: state.lastPollTime,
      })),
      connectedClients: clients.size,
    }));
    return;
  }

  // Default response
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Soroban Event WebSocket Gateway\n');
});

/**
 * Create WebSocket server
 */
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`[WebSocket] Client connected from ${clientIp}`);
  clients.add(ws);

  // Send current state to new client
  ws.send(JSON.stringify({
    type: 'connected',
    contracts: Array.from(contractStates.keys()),
    timestamp: Date.now(),
  }));

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      // Handle client subscriptions
      if (data.type === 'subscribe') {
        const contractIds = data.contractIds || [];
        console.log(`[WebSocket] Client subscribed to contracts:`, contractIds);
      }
    } catch (error) {
      console.error('Failed to parse client message:', error);
    }
  });

  ws.on('close', () => {
    console.log(`[WebSocket] Client disconnected from ${clientIp}`);
    clients.delete(ws);
  });

  ws.on('error', (error) => {
    console.error('[WebSocket] Client error:', error);
    clients.delete(ws);
  });
});

/**
 * Start the server
 */
server.listen(WS_PORT, () => {
  console.log(`Soroban Event WebSocket Gateway listening on port ${WS_PORT}`);
  console.log(`RPC URL: ${SOROBAN_RPC_URL}`);
  console.log(`Monitoring contracts: ${SOROBAN_CONTRACT_IDS.join(', ')}`);
  console.log(`Health check: http://localhost:${WS_PORT}/health`);
  
  // Start polling after server is ready
  if (SOROBAN_CONTRACT_IDS.length > 0) {
    startPolling();
  } else {
    console.warn('No contracts configured for monitoring. Set SOROBAN_CONTRACT_IDS environment variable.');
  }
});

/**
 * Graceful shutdown
 */
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
