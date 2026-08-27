import { describe, it, expect } from "vitest";
import {
  PBKDF2_ITERATIONS,
  PBKDF2_PAYLOAD_VERSION,
  ARGON2ID_PAYLOAD_VERSION,
  deriveKeyFromPassphrase,
  deriveKeyFromPassphraseArgon2id,
  encryptWithPassphrase,
  decryptWithPassphrase,
} from "../services/secrets.service";
import { ARGON2ID_DEFAULTS, argon2WorkerService } from "../services/argon2Worker.service";

describe(
  "Passphrase-based key derivation (issue #20, migrated to Argon2id in issue #74)",
  { timeout: 30000 },
  () => {
    it("should use 600,000 PBKDF2 iterations by default for the legacy KDF", () => {
      expect(PBKDF2_ITERATIONS).toBe(600_000);
    });

    describe("deriveKeyFromPassphrase (legacy PBKDF2)", () => {
      it("should derive a non-extractable AES-256-GCM CryptoKey", async () => {
        const salt = new Uint8Array(16).fill(7);
        const key = await deriveKeyFromPassphrase(
          "correct horse battery staple",
          salt
        );

        expect(key.algorithm.name).toBe("AES-GCM");
        expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
        expect(key.extractable).toBe(false);
        expect(key.usages).toEqual(
          expect.arrayContaining(["encrypt", "decrypt"])
        );
      });

      it("should reject an empty passphrase", async () => {
        const salt = new Uint8Array(16);
        await expect(deriveKeyFromPassphrase("", salt)).rejects.toThrow();
      });
    });

    describe("deriveKeyFromPassphraseArgon2id (issue #74)", () => {
      it("should derive a non-extractable AES-256-GCM CryptoKey with memory-hard defaults (M=64MB, t=3, p=4)", async () => {
        expect(ARGON2ID_DEFAULTS.memorySize).toBe(65536);
        expect(ARGON2ID_DEFAULTS.iterations).toBe(3);
        expect(ARGON2ID_DEFAULTS.parallelism).toBe(4);

        const salt = new Uint8Array(16).fill(9);
        const key = await deriveKeyFromPassphraseArgon2id(
          "correct horse battery staple",
          salt
        );

        expect(key.algorithm.name).toBe("AES-GCM");
        expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
        expect(key.extractable).toBe(false);
        expect(key.usages).toEqual(
          expect.arrayContaining(["encrypt", "decrypt"])
        );
      });

      it("should reject an empty passphrase", async () => {
        const salt = new Uint8Array(16);
        await expect(deriveKeyFromPassphraseArgon2id("", salt)).rejects.toThrow();
      });

      it("should derive identical key bytes for the same passphrase and salt (deterministic)", async () => {
        const salt = new Uint8Array(16).fill(3);
        const a = await argon2WorkerService.deriveKeyBytesAsync("same-passphrase", salt);
        const b = await argon2WorkerService.deriveKeyBytesAsync("same-passphrase", salt);
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
      });

      it("should fall back to an inline (non-Worker) derivation in environments without Web Workers", async () => {
        // In this Vitest/jsdom environment `Worker` is undefined, so
        // argon2WorkerService transparently falls back to running Argon2id
        // on the calling thread. This test asserts that fallback actually
        // produces a usable, correctly-sized key.
        const salt = new Uint8Array(16).fill(1);
        const keyBytes = await argon2WorkerService.deriveKeyBytesAsync("fallback-path", salt);
        expect(keyBytes).toBeInstanceOf(Uint8Array);
        expect(keyBytes.length).toBe(ARGON2ID_DEFAULTS.hashLength);
      });
    });

    describe("encryptWithPassphrase / decryptWithPassphrase round trip", () => {
      it("should encrypt and decrypt a backup payload with the correct passphrase (Argon2id by default)", async () => {
        const secret = "ab12cd34ef56-vault-backup-key";
        const passphrase = "a reasonably strong passphrase";

        const encrypted = await encryptWithPassphrase(secret, passphrase);
        const decrypted = await decryptWithPassphrase(encrypted, passphrase);

        expect(decrypted).toBe(secret);
      });

      it("should default to the memory-hard Argon2id envelope and never store the raw passphrase or a derived key", async () => {
        const passphrase = "super-secret-passphrase";
        const encrypted = await encryptWithPassphrase(
          "some backup data",
          passphrase
        );
        const parsed = JSON.parse(encrypted);

        expect(encrypted).not.toContain(passphrase);
        expect(parsed).toHaveProperty("salt");
        expect(parsed).toHaveProperty("iv");
        expect(parsed).toHaveProperty("ciphertext");
        expect(parsed.version).toBe(ARGON2ID_PAYLOAD_VERSION);
        expect(parsed.algorithm).toBe("argon2id");
        expect(parsed.memorySize).toBe(ARGON2ID_DEFAULTS.memorySize);
        expect(parsed.iterations).toBe(ARGON2ID_DEFAULTS.iterations);
        expect(parsed.parallelism).toBe(ARGON2ID_DEFAULTS.parallelism);
      });

      it("should still support producing a legacy PBKDF2 envelope on request", async () => {
        const passphrase = "legacy-passphrase";
        const encrypted = await encryptWithPassphrase(
          "legacy payload",
          passphrase,
          { algorithm: "pbkdf2" }
        );
        const parsed = JSON.parse(encrypted);

        expect(parsed.version).toBe(PBKDF2_PAYLOAD_VERSION);
        expect(parsed.algorithm).toBe("pbkdf2");
        expect(parsed.iterations).toBe(PBKDF2_ITERATIONS);

        const decrypted = await decryptWithPassphrase(encrypted, passphrase);
        expect(decrypted).toBe("legacy payload");
      });

      it("should decrypt a pre-existing legacy PBKDF2 payload (numeric iterations shorthand) unchanged", async () => {
        // Simulates a backup file created before the issue #74 migration.
        const passphrase = "old-backup-passphrase";
        const legacyEncrypted = await encryptWithPassphrase(
          "pre-migration vault key",
          passphrase,
          600_000
        );
        const parsed = JSON.parse(legacyEncrypted);
        expect(parsed.version).toBe(PBKDF2_PAYLOAD_VERSION);

        const decrypted = await decryptWithPassphrase(legacyEncrypted, passphrase);
        expect(decrypted).toBe("pre-migration vault key");
      });

      it("should reject decryption with the wrong passphrase", async () => {
        const encrypted = await encryptWithPassphrase(
          "vault backup contents",
          "right-passphrase"
        );
        await expect(
          decryptWithPassphrase(encrypted, "wrong-passphrase")
        ).rejects.toThrow();
      });

      it("should produce different ciphertext and salt for the same plaintext and passphrase (unique salt per encryption)", async () => {
        const plaintext = "identical-secret";
        const passphrase = "identical-passphrase";

        const first = JSON.parse(
          await encryptWithPassphrase(plaintext, passphrase, { algorithm: "pbkdf2" })
        );
        const second = JSON.parse(
          await encryptWithPassphrase(plaintext, passphrase, { algorithm: "pbkdf2" })
        );

        expect(first.salt).not.toBe(second.salt);
        expect(first.ciphertext).not.toBe(second.ciphertext);
      });

      it("should reject a corrupted or malformed payload", async () => {
        await expect(
          decryptWithPassphrase("not-json", "any-passphrase")
        ).rejects.toThrow();
        await expect(
          decryptWithPassphrase(
            JSON.stringify({ version: "unknown-version" }),
            "any-passphrase"
          )
        ).rejects.toThrow();
      });
    });
  }
);
