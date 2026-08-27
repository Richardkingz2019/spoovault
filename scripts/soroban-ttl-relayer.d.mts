export interface RelayerConfig {
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  secretKey?: string;
  ttlThreshold?: number;
  maxTtl?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  batchSize?: number;
  maxEntriesPerType?: number;
  dryRun?: boolean;
}

export interface RelayerStats {
  scanned: number;
  bumped: number;
  errors: number;
}

export function loadSdk(): Promise<any>;
export function validateConfig(cfg: RelayerConfig): void;
export function buildDataKeyLedgerKey(contractId: string, dataKeyScVal: any): any;
export function queryEntityCount(server: any, contractId: string, counterKeyName: string): Promise<bigint>;
export function queryTtlRemaining(server: any, ledgerKey: any, latestLedger: number): Promise<number | null>;
export function withRetry<T>(fn: () => Promise<T>, maxRetries?: number, delayMs?: number, label?: string): Promise<T>;
export function scanAndBumpEntityType(opts: any): Promise<RelayerStats>;
export function runRelayerCycle(cfgOverride?: RelayerConfig): Promise<RelayerStats>;
export function startDaemon(intervalMs?: number, cfgOverride?: RelayerConfig): Promise<void>;
