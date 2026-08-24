export class CryptoClientService {
  private worker: Worker;

  constructor() {
    this.worker = new Worker(
      new URL('../workers/crypto.worker.ts', import.meta.url),
      { type: 'module' }
    );
  }

  public computeHash(payloadBuffer: ArrayBuffer): Promise<{ status: string; hash: ArrayBuffer }> {
    return new Promise((resolve, reject) => {
      this.worker.onmessage = (event: MessageEvent<{ status: string; hash: ArrayBuffer }>) => {
        resolve(event.data);
      };

      this.worker.onerror = (error) => {
        reject(error);
      };

      // Zero-copy transfer: Passing buffer in the transferable list detaches it from the main thread
      this.worker.postMessage(
        { type: 'COMPUTE_HASH', buffer: payloadBuffer },
        [payloadBuffer]
      );
    });
  }

  public terminate(): void {
    this.worker.terminate();
  }
}