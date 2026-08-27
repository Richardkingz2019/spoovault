# Private Information Retrieval (PIR) Architecture

## Overview

SpooVault implements Private Information Retrieval (PIR) principles to prevent IPFS gateway nodes from correlating beneficiary IP addresses with specific vault document CIDs. This addresses the surveillance risk where public IPFS gateways log requester IP addresses and requested CIDs, allowing network entities to correlate beneficiary identities with specific vault documents.

## Threat Model

### Current Vulnerability
- Public IPFS gateways (Pinata, Cloudflare, ipfs.io, etc.) log requester IP addresses and requested CIDs
- Network surveillance entities can correlate beneficiary identities with specific vault documents
- Gateway logs reveal which users are accessing which encrypted documents

### PIR Solution
- **Oblivious Gateway Querying**: Fetch encrypted document blocks through PIR dummy query batches or Mixnet (Tor) proxy routing
- **Encrypted CID Index**: Mask IPFS CIDs inside contract state using homomorphic hashes
- **Zero-Knowledge Access**: Gateway logs reveal zero correlation between beneficiary IP address and target CID

## Architecture Components

### 1. PirService (`src/services/pir.service.ts`)

Main service orchestrating oblivious IPFS fetches with the following components:

#### HomomorphicHash
- Generates deterministic but non-reversible CID identifiers using SHA-256 with per-session salt
- Same CID produces same hash within a session, but different sessions produce different hashes
- Prevents gateway operators from identifying specific documents from logged hashes

#### DummyQueryBatcher
- Generates dummy IPFS queries that look like real CIDs (CIDv0 format)
- Batches real queries with dummy queries to obscure which document is being fetched
- Shuffles batch order to prevent position-based analysis
- Configurable dummy query count (default: 5) and batch delay (default: 100ms)

#### TorProxyClient
- SOCKS5 proxy client for routing IPFS requests through Tor
- Provides IP address anonymity when fetching documents
- Requires local Tor daemon with SOCKS5 proxy enabled (default: 127.0.0.1:9050)
- Falls back to standard fetch if Tor is unavailable

### 2. Integration with IPFS Gateway Service

The PIR service integrates with the existing IPFS gateway infrastructure:

- `ipfsService.fetchFileWithPIR()`: New method that uses PIR for document fetches
- Falls back to standard `ipfsGateway.fetchFile()` if PIR is disabled
- Maintains compatibility with existing multi-gateway circuit breaker
- Works with existing gateway pool and health scoring system

### 3. Configuration

Environment variables for PIR configuration (see `.env.example`):

```bash
# Enable PIR to obscure which documents are being fetched from IPFS gateways
VITE_PIR_ENABLED=false

# Use Tor SOCKS5 proxy for IPFS fetches (requires local Tor daemon)
VITE_PIR_USE_TOR=false

# Tor SOCKS5 proxy host (default: 127.0.0.1)
VITE_PIR_TOR_HOST=127.0.0.1

# Tor SOCKS5 proxy port (default: 9050)
VITE_PIR_TOR_PORT=9050

# Number of dummy queries to batch with real queries (default: 5)
VITE_PIR_DUMMY_COUNT=5

# Delay between dummy queries in milliseconds (default: 100)
VITE_PIR_BATCH_DELAY=100
```

## Security Properties

### 1. Oblivious Gateway Querying
- **Dummy Query Batching**: Real queries are batched with dummy queries, making it statistically difficult for gateways to identify which query corresponds to the actual document
- **Query Shuffling**: Batch order is randomized to prevent position-based analysis
- **Timing Obfuscation**: Configurable delays between queries prevent timing correlation attacks

### 2. Mixnet Proxy Routing (Tor)
- **IP Address Anonymity**: When enabled, all IPFS requests are routed through Tor's SOCKS5 proxy
- **Circuit Isolation**: Each document fetch uses a new Tor circuit when possible
- **Fallback Safety**: Automatically falls back to standard fetch if Tor is unavailable

### 3. Encrypted CID Index
- **Homomorphic Hashing**: CIDs are hashed with session-specific salts before logging
- **Non-Reversible**: Hashes cannot be reversed to recover original CIDs
- **Session Isolation**: Different sessions produce different hashes for the same CID

## Usage

### Basic Usage

```typescript
import { pirService } from './services/pir.service';

// Fetch a document with PIR
const result = await pirService.fetchDocument(cid, signal);

if (result.success) {
  const data = result.data;
  console.log(`Fetched via ${result.gatewayUsed}`);
  console.log(`Proxied: ${result.proxied}`);
  console.log(`Dummy queries: ${result.dummyQueriesIssued}`);
}
```

### Using with IPFS Service

```typescript
import { ipfsService } from './services/ipfs.service';

// Fetch with PIR (if enabled)
const response = await ipfsService.fetchFileWithPIR(cid, { signal });
const data = await response.arrayBuffer();
```

### Runtime Configuration

```typescript
import { pirService } from './services/pir.service';

// Update configuration at runtime
pirService.updateConfig({
  enabled: true,
  useTorProxy: true,
  dummyQueryCount: 10,
  batchDelayMs: 200,
});

// Check Tor availability
const torAvailable = await pirService.isTorAvailable();
console.log(`Tor available: ${torAvailable}`);
```

### CID Hashing

```typescript
import { pirService } from './services/pir.service';

// Generate homomorphic hash for a CID
const hash = await pirService.getCidHash(cid);

// Verify CID against hash
const isValid = await pirService.verifyCid(cid, hash);
```

## Performance Considerations

### Latency Impact
- **Dummy Query Batching**: Adds latency proportional to dummy query count and batch delay
- **Tor Proxy**: Adds significant latency due to Tor circuit routing (typically 500-2000ms)
- **Recommended Settings**: For production, balance security vs. performance:
  - Dummy query count: 3-5 (minimal latency impact)
  - Batch delay: 50-100ms (prevents timing analysis without excessive delay)
  - Tor proxy: Enable only for high-security scenarios

### Bandwidth Impact
- **Dummy Queries**: Each dummy query consumes bandwidth even though data is discarded
- **Estimated Overhead**: With 5 dummy queries, approximately 5x bandwidth for document fetches
- **Mitigation**: Use gateway circuit breaker to prevent failed dummy queries from consuming bandwidth

## Testing

Integration tests are provided in `src/__tests__/pir.service.test.ts`:

```bash
# Run PIR tests
npm test -- pir.service.test.ts
```

Test coverage includes:
- Homomorphic hash generation and verification
- Dummy query batch generation and shuffling
- Batch execution with real and dummy queries
- PIR service configuration and runtime updates
- Tor proxy availability checking

## Future Enhancements

### 1. Nym Mixnet Integration
- Replace Tor with Nym mixnet for stronger anonymity guarantees
- Implement Sphinx packet routing for mixnet integration
- Add Nym client configuration options

### 2. Advanced PIR Protocols
- Implement computational PIR (cPIR) for database-style queries
- Add information-theoretic PIR (iPIR) for stronger security guarantees
- Support multi-server PIR protocols

### 3. Contract-Side CID Encryption
- Store homomorphic hashes on-chain instead of plain CIDs
- Implement zero-knowledge proofs for CID ownership
- Add encrypted CID index in smart contract

### 4. Gateway Reputation System
- Track gateway privacy practices and compliance
- Prefer gateways with strong privacy policies
- Implement gateway privacy scoring

## Security Considerations

### Limitations
- **Browser Environment**: Full Tor integration requires browser extensions or specific configurations
- **Dummy Query Detection**: Sophisticated adversaries may use timing analysis to identify real queries
- **Session Persistence**: Homomorphic hashes are session-specific, requiring re-hashing on session refresh

### Best Practices
- **Enable Tor for High-Security**: Use Tor proxy when handling sensitive documents
- **Adjust Dummy Count**: Increase dummy query count for higher security requirements
- **Monitor Gateway Logs**: Regularly audit gateway privacy policies and logging practices
- **Use Multiple Gateways**: Leverage existing gateway pool for additional obscurity

## References

- [Private Information Retrieval (Wikipedia)](https://en.wikipedia.org/wiki/Private_information_retrieval)
- [Tor Project Documentation](https://2019.www.torproject.org/docs/)
- [Nym Mixnet](https://nymtech.net/)
- [IPFS Privacy Considerations](https://docs.ipfs.io/concepts/privacy/)
