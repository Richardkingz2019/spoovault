import { argon2id } from "hash-wasm";

/**
 * Argon2id key derivation Web Worker (issue #74).
 *
 * Runs the memory-hard Argon2id hash off the main thread so a slow,
 * intentionally expensive derivation (M=64MB, t=3, p=4 by default) never
 * blocks UI frame rendering. Only the derived key bytes cross back over
 * `postMessage` -- the passphrase itself never leaves this worker's stack.
 */
export interface Argon2WorkerRequest {
  id: string;
  type: "DERIVE_KEY";
  payload: {
    password: string;
    salt: Uint8Array;
    memorySize: number;
    iterations: number;
    parallelism: number;
    hashLength: number;
  };
}

export type Argon2WorkerResponse =
  | {
      id: string;
      type: "DERIVE_KEY_SUCCESS";
      result: Uint8Array;
    }
  | {
      id: string;
      type: "ERROR";
      error: string;
    };

self.onmessage = async (event: MessageEvent<Argon2WorkerRequest>) => {
  const { id, type, payload } = event.data;

  try {
    if (type !== "DERIVE_KEY") {
      throw new Error(`Unsupported argon2 worker operation type: ${type}`);
    }

    const derived = await argon2id({
      password: payload.password,
      salt: payload.salt,
      memorySize: payload.memorySize,
      iterations: payload.iterations,
      parallelism: payload.parallelism,
      hashLength: payload.hashLength,
      outputType: "binary",
    });

    const response: Argon2WorkerResponse = {
      id,
      type: "DERIVE_KEY_SUCCESS",
      result: derived,
    };
    (self as any).postMessage(response, [response.result.buffer]);
  } catch (err: any) {
    const response: Argon2WorkerResponse = {
      id,
      type: "ERROR",
      error: err?.message || "Argon2id derivation failed",
    };
    self.postMessage(response);
  }
};
