/**
 * mnemonicKeyring.service — BIP-39 / SLIP-0039 mnemonic backup & recovery for
 * the master keyring (issue #155).
 *
 * The keyring's master key is a WebCrypto ECDH P-256 keypair
 * (src/utils/crypto.ts), stored as base64 PKCS#8 / SPKI. The mnemonic must
 * therefore encode the key's *entropy* — the 32-byte private scalar `d` — not
 * any derived material, so that a recovered mnemonic reconstructs the exact
 * same keypair:
 *
 *   PKCS#8 ── WebCrypto JWK export ──► d (32 bytes) ── BIP-39 ──► 24 words
 *   24 words ── BIP-39 ──► d ── @noble/curves P-256 ──► (x, y) ── JWK import
 *            ──► identical PKCS#8 / SPKI pair
 *
 * SLIP-0039 (Shamir) splits the same 32-byte secret into standard 3-of-5
 * paper-mnemonic shares using the `slip39` reference implementation. Note:
 * the repo's own GF(256) Shamir (secrets.service.ts splitSecret) produces hex
 * shares, not the standardized SLIP-0039 wordlist format this issue asks for.
 *
 * Core functions are pure over key material (unit-testable in Node); the
 * account-bound wrappers at the bottom integrate with clientKeyringService.
 */

import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { p256 } from "@noble/curves/nist.js";
// slip39 is a CJS module; interop default import.
import Slip39 from "slip39";

import {
  importECIESPrivateKey,
  importECIESPublicKey,
  exportECIESPublicKey,
  uint8ArrayToBase64,
} from "../utils/crypto";

/** WebCrypto accessor (browser + Node ≥19 both expose globalThis.crypto). */
function getSubtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto not available in this environment");
  return c.subtle;
}
import { clientKeyringService } from "./clientKeyring.service";

/** 3-of-5 by default, per the issue. */
export const DEFAULT_SHARE_COUNT = 5;
export const DEFAULT_SHARE_THRESHOLD = 3;

// ─── base64url helpers (JWK fields) ─────────────────────────────────────────

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let raw = "";
  for (let i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ─── pure core: PKCS#8 ⇄ mnemonic ───────────────────────────────────────────

/**
 * Extract the 32-byte P-256 private scalar from a base64 PKCS#8 key and
 * encode it as a 24-word BIP-39 mnemonic (256-bit entropy, checksummed).
 */
export async function privateKeyToMnemonic(privateKeyBase64: string): Promise<string> {
  const subtle = getSubtle();
  const key = await importECIESPrivateKey(privateKeyBase64);
  const jwk = await subtle.exportKey("jwk", key);
  if (!jwk.d) throw new Error("Private key export did not include the scalar");
  const scalar = base64UrlToBytes(jwk.d);
  if (scalar.length !== 32) {
    throw new Error(`Unexpected P-256 scalar length: ${scalar.length}`);
  }
  return bip39.entropyToMnemonic(scalar, wordlist);
}

/** BIP-39 checksum + wordlist validation. */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(normalizeMnemonic(mnemonic), wordlist);
}

/** Collapse whitespace/case so hand-typed phrases validate predictably. */
export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().toLowerCase().split(/\s+/).join(" ");
}

/**
 * Rebuild the exact ECDH P-256 keypair (base64 SPKI/PKCS#8, the keyring's
 * storage format) from a 24-word BIP-39 mnemonic.
 */
export async function mnemonicToKeyPair(
  mnemonic: string
): Promise<{ publicKey: string; privateKey: string }> {
  const normalized = normalizeMnemonic(mnemonic);
  if (!bip39.validateMnemonic(normalized, wordlist)) {
    throw new Error("Invalid mnemonic: checksum or wordlist mismatch");
  }
  const scalar = bip39.mnemonicToEntropy(normalized, wordlist);
  if (scalar.length !== 32) {
    throw new Error("Mnemonic must encode 256-bit entropy (24 words)");
  }

  // Derive the public point. Throws if the scalar is not a valid P-256 key
  // (never the case for mnemonics produced by privateKeyToMnemonic).
  let publicUncompressed: Uint8Array;
  try {
    publicUncompressed = p256.getPublicKey(scalar, false); // 65 bytes, 0x04 || x || y
  } catch {
    throw new Error("Mnemonic does not encode a valid P-256 private key");
  }

  const subtle = getSubtle();
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: bytesToBase64Url(scalar),
    x: bytesToBase64Url(publicUncompressed.slice(1, 33)),
    y: bytesToBase64Url(publicUncompressed.slice(33, 65)),
    ext: true,
  };
  const privateKey = await subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
  const pkcs8 = await subtle.exportKey("pkcs8", privateKey);

  // Reuse the existing raw-65-byte import path, then export standard SPKI.
  const publicKey = await importECIESPublicKey(uint8ArrayToBase64(publicUncompressed));
  const spkiBase64 = await exportECIESPublicKey(publicKey);

  return {
    publicKey: spkiBase64,
    privateKey: uint8ArrayToBase64(new Uint8Array(pkcs8)),
  };
}

// ─── pure core: SLIP-0039 shares ────────────────────────────────────────────

export interface ShareOptions {
  count?: number; // total shares (default 5)
  threshold?: number; // shares required to recover (default 3)
  passphrase?: string; // SLIP-0039 passphrase (default empty)
}

/**
 * Split a 24-word master mnemonic into SLIP-0039 paper-mnemonic shares
 * (default 3-of-5). Each share is itself a word phrase with a SLIP-0039
 * checksum; any `threshold` of them recovers the master.
 */
export function mnemonicToShares(mnemonic: string, opts: ShareOptions = {}): string[] {
  const { count = DEFAULT_SHARE_COUNT, threshold = DEFAULT_SHARE_THRESHOLD, passphrase = "" } =
    opts;
  if (threshold < 2 || threshold > count) {
    throw new Error(`Invalid scheme: threshold ${threshold} of ${count}`);
  }
  const normalized = normalizeMnemonic(mnemonic);
  if (!bip39.validateMnemonic(normalized, wordlist)) {
    throw new Error("Invalid mnemonic: checksum or wordlist mismatch");
  }
  const masterSecret = Array.from(bip39.mnemonicToEntropy(normalized, wordlist));

  const slip = Slip39.fromArray(masterSecret, {
    passphrase,
    threshold: 1, // one group…
    groups: [[threshold, count, "spoovault master keyring"]], // …of threshold-of-count members
  });
  return slip.fromPath("r/0").mnemonics;
}

/**
 * Recover the 24-word master mnemonic from ≥ threshold SLIP-0039 shares.
 */
export function sharesToMnemonic(shares: string[], passphrase = ""): string {
  const secret = Slip39.recoverSecret(shares, passphrase);
  return bip39.entropyToMnemonic(Uint8Array.from(secret), wordlist);
}

// ─── account-bound wrappers (IndexedDB-backed keyring integration) ──────────

export const mnemonicKeyringService = {
  /** Export the account's master key as a 24-word BIP-39 mnemonic. */
  async exportMnemonic(account: string, currentPin?: string): Promise<string> {
    const privateKey = await clientKeyringService.getDecryptedPrivateKey(
      account.toLowerCase(),
      currentPin
    );
    return privateKeyToMnemonic(privateKey);
  },

  /** Export the account's master key as SLIP-0039 shares (default 3-of-5). */
  async exportShares(
    account: string,
    currentPin?: string,
    opts: ShareOptions = {}
  ): Promise<string[]> {
    const mnemonic = await this.exportMnemonic(account, currentPin);
    return mnemonicToShares(mnemonic, opts);
  },

  /**
   * Restore a keypair from a mnemonic (or SLIP-0039 shares) and return it in
   * the keyring's base64 SPKI/PKCS#8 format for the existing import flow.
   */
  async recoverKeyPair(
    input: { mnemonic: string } | { shares: string[]; passphrase?: string }
  ): Promise<{ publicKey: string; privateKey: string }> {
    const mnemonic =
      "mnemonic" in input
        ? input.mnemonic
        : sharesToMnemonic(input.shares, input.passphrase ?? "");
    return mnemonicToKeyPair(mnemonic);
  },

  validateMnemonic,
};
