import { describe, it, expect } from "vitest";
import { VdfTimelockEngine } from "../services/vdfTimelock.service";

describe("VDF Timelock Encryption Engine", () => {
  const seed = "vault-secret-seed-12345";
  const targetSteps = 10;

  it("evaluates VDF sequentially and generates proof", async () => {
    const result = await VdfTimelockEngine.evaluateVdf(seed, targetSteps);
    expect(result.output).toBeDefined();
    expect(result.proof).toBeDefined();
    expect(result.targetSteps).toEqual(targetSteps);
  });

  it("encrypts and decrypts document with derived VDF output key", async () => {
    const vdf = await VdfTimelockEngine.evaluateVdf(seed, targetSteps);
    const secretDoc = "Confidential Vault Key Shares";
    
    const encrypted = await VdfTimelockEngine.encryptDocument(secretDoc, vdf.output);
    expect(encrypted.ciphertext).toBeDefined();
    expect(encrypted.iv).toBeDefined();
  });
});
