import { afterEach, describe, expect, it, vi } from 'vitest';
import { CryptoClientService } from '../services/crypto-client';

// Vitest's Node "forks" project has no `window`/`Worker` globals, so the real
// worker cannot be constructed. Stub a MockWorker that performs a genuine
// structured-clone-with-transfer on every postMessage — exactly like a real
// Worker — so ArrayBuffer transfers really detach instead of merely being
// asserted about. (Same pattern as cryptoWorker.pool.test.ts.)

class MockWorker {
  static instances: MockWorker[] = [];

  onmessage:
    | ((event: MessageEvent<{ status: string; hash: ArrayBuffer }>) => void)
    | null = null;
  onerror: ((event: unknown) => void) | null = null;
  terminated = false;

  constructor(_url?: unknown, _opts?: unknown) {
    MockWorker.instances.push(this);
  }

  postMessage(message: { type: string; buffer: ArrayBuffer }, transfer?: Transferable[]) {
    // Genuinely transfers (detaches) any ArrayBuffers in `transfer`, mirroring
    // a real Worker's postMessage(data, [data.buffer]) semantics, so the
    // caller's buffer is actually neutered rather than just copied.
    structuredClone(message, { transfer });

    queueMicrotask(() => {
      this.onmessage?.({
        data: { status: 'SUCCESS', hash: new ArrayBuffer(0) },
      } as MessageEvent<{ status: string; hash: ArrayBuffer }>);
    });
  }

  terminate() {
    this.terminated = true;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  MockWorker.instances = [];
});

describe('CryptoWorker Zero-Copy Transfer (#42)', () => {
  it('detaches ArrayBuffer ownership upon postMessage invocation', () => {
    vi.stubGlobal('Worker', MockWorker);

    const client = new CryptoClientService();
    const buffer = new ArrayBuffer(1024 * 1024); // 1 MB payload

    expect(buffer.byteLength).toBe(1024 * 1024);

    client.computeHash(buffer);

    // Verify zero-copy detachment: sender side buffer byteLength becomes 0 after transfer
    expect(buffer.byteLength).toBe(0);

    client.terminate();
  });
});
