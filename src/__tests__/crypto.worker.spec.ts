import { describe, it, expect, vi } from 'vitest';
import { CryptoClientService } from '../../services/crypto-client';

describe('CryptoWorker Zero-Copy Transfer (#42)', () => {
  it('detaches ArrayBuffer ownership upon postMessage invocation', async () => {
    const client = new CryptoClientService();
    const buffer = new ArrayBuffer(1024 * 1024); // 1 MB payload

    expect(buffer.byteLength).toBe(1024 * 1024);

    const promise = client.computeHash(buffer);

    // Verify zero-copy detachment: sender side buffer byteLength becomes 0 after transfer
    expect(buffer.byteLength).toBe(0);

    client.terminate();
  });
});