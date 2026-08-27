import { describe, it, expect } from "vitest";
import { generateECIESKeyPairBase64 } from "../utils/crypto";
import {
  privateKeyToMnemonic,
  mnemonicToKeyPair,
  mnemonicToShares,
  sharesToMnemonic,
  validateMnemonic,
  normalizeMnemonic,
  DEFAULT_SHARE_COUNT,
  DEFAULT_SHARE_THRESHOLD,
} from "../services/mnemonicKeyring.service";

describe("mnemonicKeyring.service — BIP-39 master mnemonic (issue #155)", () => {
  it("exports the master key as a 24-word mnemonic that passes BIP-39 checksum validation", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);

    expect(mnemonic.split(" ")).toHaveLength(24);
    expect(validateMnemonic(mnemonic)).toBe(true);
  });

  it("round-trips: mnemonic reconstructs the exact same keypair (PKCS#8 + SPKI)", async () => {
    const original = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(original.privateKey);
    const restored = await mnemonicToKeyPair(mnemonic);

    // Same public key ⇒ same underlying scalar ⇒ same master key.
    expect(restored.publicKey).toBe(original.publicKey);
    // And the mnemonic derived from the restored private key is identical.
    expect(await privateKeyToMnemonic(restored.privateKey)).toBe(mnemonic);
  });

  it("is tolerant of case/whitespace on entry but strict on the checksum", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);

    const sloppy = `  ${mnemonic.toUpperCase().split(" ").join("   ")}  `;
    expect(normalizeMnemonic(sloppy)).toBe(mnemonic);
    expect(validateMnemonic(sloppy)).toBe(true);

    // Corrupt one word → checksum must fail, and recovery must refuse.
    const words = mnemonic.split(" ");
    words[3] = words[3] === "abandon" ? "ability" : "abandon";
    const corrupted = words.join(" ");
    expect(validateMnemonic(corrupted)).toBe(false);
    await expect(mnemonicToKeyPair(corrupted)).rejects.toThrow(/checksum|wordlist/i);
  });

  it("rejects phrases that are not 24 words of the wordlist", async () => {
    expect(validateMnemonic("definitely not a mnemonic")).toBe(false);
    await expect(mnemonicToKeyPair("definitely not a mnemonic")).rejects.toThrow();
  });
});

describe("mnemonicKeyring.service — SLIP-0039 3-of-5 shares (issue #155)", () => {
  it("splits into 5 shares and recovers the master with any 3", async () => {
    const { privateKey, publicKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);
    const shares = mnemonicToShares(mnemonic);

    expect(shares).toHaveLength(DEFAULT_SHARE_COUNT);
    expect(DEFAULT_SHARE_THRESHOLD).toBe(3);

    // Two different 3-subsets both recover the identical master mnemonic…
    const recoveredA = sharesToMnemonic([shares[0], shares[2], shares[4]]);
    const recoveredB = sharesToMnemonic([shares[1], shares[2], shares[3]]);
    expect(recoveredA).toBe(mnemonic);
    expect(recoveredB).toBe(mnemonic);

    // …and the recovered mnemonic reconstructs the same keypair end-to-end.
    const restored = await mnemonicToKeyPair(recoveredA);
    expect(restored.publicKey).toBe(publicKey);
  });

  it("fails to recover with fewer than threshold shares", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);
    const shares = mnemonicToShares(mnemonic);

    expect(() => sharesToMnemonic([shares[0], shares[1]])).toThrow();
  });

  it("rejects a share whose words were tampered with (SLIP-0039 checksum)", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);
    const shares = mnemonicToShares(mnemonic);

    const words = shares[0].split(" ");
    words[words.length - 1] = words[words.length - 1] === "academic" ? "acid" : "academic";
    const tampered = words.join(" ");

    expect(() => sharesToMnemonic([tampered, shares[1], shares[2]])).toThrow();
  });

  it("supports a custom M-of-N scheme and rejects invalid schemes", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);

    const shares = mnemonicToShares(mnemonic, { count: 4, threshold: 2 });
    expect(shares).toHaveLength(4);
    expect(sharesToMnemonic([shares[3], shares[0]])).toBe(mnemonic);

    expect(() => mnemonicToShares(mnemonic, { count: 3, threshold: 4 })).toThrow(/Invalid scheme/);
    expect(() => mnemonicToShares(mnemonic, { count: 5, threshold: 1 })).toThrow(/Invalid scheme/);
  });

  it("honors the SLIP-0039 passphrase on split and recover", async () => {
    const { privateKey } = await generateECIESKeyPairBase64();
    const mnemonic = await privateKeyToMnemonic(privateKey);
    const shares = mnemonicToShares(mnemonic, { passphrase: "hunter2" });

    expect(sharesToMnemonic([shares[0], shares[1], shares[2]], "hunter2")).toBe(mnemonic);
    // SLIP-0039 passphrase decryption is not authenticated: a wrong passphrase
    // yields a *different* master secret rather than an error.
    expect(sharesToMnemonic([shares[0], shares[1], shares[2]], "wrong")).not.toBe(mnemonic);
  });
});
