import { describe, it, expect } from "vitest";
import {
  fheKeyGen,
  fheEncrypt,
  fheDecrypt,
  fheDecryptToHex,
  fheAdd,
  fheScalarMul,
  computeLagrangeCoefficients,
  serializeFheCiphertext,
  deserializeFheCiphertext,
  modQ,
} from "../utils/fheEngine";
import { fheService } from "../services/fhe.service";

describe("Fully Homomorphic Encryption (FHE) Engine", () => {
  const SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  it("generates a valid FHE keypair", () => {
    const keypair = fheKeyGen();
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey.a.length).toBeGreaterThan(0);
    expect(keypair.privateKey.s.length).toBe(keypair.publicKey.a[0].length);
  });

  it("encrypts and decrypts a 256-bit secret with exact precision", () => {
    const keypair = fheKeyGen();
    const ct = fheEncrypt(SECRET_HEX, keypair.publicKey);
    const decryptedHex = fheDecryptToHex(ct, keypair.privateKey);
    expect(decryptedHex).toBe(SECRET_HEX);
  });

  it("performs homomorphic addition: Enc(m1) (+) Enc(m2) = Enc(m1 + m2 mod q)", () => {
    const keypair = fheKeyGen();
    const m1 = 0x1234567890abcdefn;
    const m2 = 0xfedcba0987654321n;

    const ct1 = fheEncrypt(m1, keypair.publicKey);
    const ct2 = fheEncrypt(m2, keypair.publicKey);

    const ctSum = fheAdd(ct1, ct2);
    const decryptedSum = fheDecrypt(ctSum, keypair.privateKey);

    expect(decryptedSum).toBe(modQ(m1 + m2));
  });

  it("performs homomorphic scalar multiplication: lambda (*) Enc(m) = Enc(lambda * m mod q)", () => {
    const keypair = fheKeyGen();
    const m = 0xabcdef1234567890n;
    const lambda = 42n;

    const ct = fheEncrypt(m, keypair.publicKey);
    const ctScaled = fheScalarMul(lambda, ct);

    const decryptedScaled = fheDecrypt(ctScaled, keypair.privateKey);
    expect(decryptedScaled).toBe(modQ(lambda * m));
  });

  it("computes Lagrange basis coefficients correctly", () => {
    const indices = [1n, 2n, 3n];
    const lambdas = computeLagrangeCoefficients(indices);

    // Sum of Lagrange polynomials at x = 0 with constant 1 polynomial must equal 1
    const sum = lambdas.reduce((acc, val) => modQ(acc + val), 0n);
    expect(sum).toBe(1n);
  });

  it("homomorphically aggregates (3, 5) Shamir threshold shares to recover the exact master key", () => {
    const keypair = fheKeyGen();
    const n = 5;
    const k = 3;

    const { sharesFHE } = fheService.createThresholdSharesFHE(
      SECRET_HEX,
      n,
      k,
      keypair.publicKey
    );

    expect(sharesFHE.length).toBe(n);

    // Subset 1: Guardians 1, 2, 3
    const subset1 = [sharesFHE[0], sharesFHE[1], sharesFHE[2]];
    const agg1Hex = fheService.aggregateThresholdShares(subset1, k);
    const recoveredHex1 = fheService.decryptAggregateCiphertext(agg1Hex, keypair.privateKey);
    expect(recoveredHex1).toBe(SECRET_HEX);

    // Subset 2: Guardians 2, 4, 5
    const subset2 = [sharesFHE[1], sharesFHE[3], sharesFHE[4]];
    const agg2Hex = fheService.aggregateThresholdShares(subset2, k);
    const recoveredHex2 = fheService.decryptAggregateCiphertext(agg2Hex, keypair.privateKey);
    expect(recoveredHex2).toBe(SECRET_HEX);

    // Subset 3: Guardians 1, 3, 5
    const subset3 = [sharesFHE[0], sharesFHE[2], sharesFHE[4]];
    const agg3Hex = fheService.aggregateThresholdShares(subset3, k);
    const recoveredHex3 = fheService.decryptAggregateCiphertext(agg3Hex, keypair.privateKey);
    expect(recoveredHex3).toBe(SECRET_HEX);
  });

  it("homomorphically aggregates additive secret shares to recover the exact master key", () => {
    const keypair = fheKeyGen();
    const guardianCount = 4;

    const { sharesFHE } = fheService.createAdditiveSharesFHE(
      SECRET_HEX,
      guardianCount,
      keypair.publicKey
    );

    expect(sharesFHE.length).toBe(guardianCount);

    const aggHex = fheService.aggregateAdditiveShares(sharesFHE);
    const recoveredHex = fheService.decryptAggregateCiphertext(aggHex, keypair.privateKey);
    expect(recoveredHex).toBe(SECRET_HEX);
  });

  it("correctly serializes and deserializes FHE ciphertexts to ABI-compatible hex bytes", () => {
    const keypair = fheKeyGen();
    const ct = fheEncrypt(SECRET_HEX, keypair.publicKey);

    const serialized = serializeFheCiphertext(ct);
    expect(serialized.startsWith("0x")).toBe(true);

    const deserialized = deserializeFheCiphertext(serialized);
    expect(deserialized.a.length).toBe(ct.a.length);
    for (let i = 0; i < ct.a.length; i++) {
      expect(deserialized.a[i]).toBe(ct.a[i]);
    }
    expect(deserialized.b).toBe(ct.b);

    const decrypted = fheDecryptToHex(deserialized, keypair.privateKey);
    expect(decrypted).toBe(SECRET_HEX);
  });

  it("ensures zero plaintext share leakage in ciphertext", () => {
    const keypair = fheKeyGen();
    const ct = fheEncrypt(SECRET_HEX, keypair.publicKey);
    const serialized = serializeFheCiphertext(ct);

    // Raw secret must not appear anywhere as a substring in the ciphertext hex
    expect(serialized.includes(SECRET_HEX)).toBe(false);
    expect(serialized.toLowerCase().includes(SECRET_HEX.toLowerCase())).toBe(false);
  });
});
