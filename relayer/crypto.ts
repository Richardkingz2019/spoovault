/**
 * @file relayer/crypto.ts
 * @description Payload encryption for guardian notifications.
 *
 * Guardians publish a base64 X25519 public key in the contacts registry. The
 * relayer encrypts every notification to that key using an ephemeral box
 * (nacl.box with a random nonce, ephemeral public key prepended) so only the
 * guardian's private key can decrypt the payload.
 */

import nacl from "tweetnacl";

export function generateGuardianKeyPair(): { publicKey: string; secretKey: string } {
  const pair = nacl.box.keyPair();
  return {
    publicKey: Buffer.from(pair.publicKey).toString("base64"),
    secretKey: Buffer.from(pair.secretKey).toString("base64"),
  };
}

/** Encrypt a JSON-serializable payload to a guardian's base64 X25519 public key. */
export function encryptForGuardian(publicKeyB64: string, payload: unknown): string {
  const recipient = decodeBase64Key(publicKeyB64, "guardian public key");
  if (recipient.length !== nacl.box.publicKeyLength) {
    throw new Error(`Invalid guardian public key length: ${recipient.length}`);
  }

  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf-8");
  const ciphertext = nacl.box(plaintext, nonce, recipient, ephemeral.secretKey);

  // Envelope: version || ephemeralPublicKey || nonce || ciphertext (all base64)
  return Buffer.concat([
    Buffer.from([1]),
    Buffer.from(ephemeral.publicKey),
    nonce,
    ciphertext,
  ]).toString("base64");
}

/** Decrypt an envelope produced by {@link encryptForGuardian}. */
export function decryptFromRelayer(secretKeyB64: string, envelopeB64: string): unknown {
  const secret = decodeBase64Key(secretKeyB64, "guardian secret key");
  const envelope = Buffer.from(envelopeB64, "base64");
  const version = envelope[0];
  const pkLen = nacl.box.publicKeyLength;
  const nonceLen = nacl.box.nonceLength;
  if (version !== 1 || envelope.length < 1 + pkLen + nonceLen + nacl.box.overheadLength) {
    throw new Error("Malformed encrypted envelope");
  }

  const ephemeralPk = new Uint8Array(envelope.subarray(1, 1 + pkLen));
  const nonce = new Uint8Array(envelope.subarray(1 + pkLen, 1 + pkLen + nonceLen));
  const ciphertext = new Uint8Array(envelope.subarray(1 + pkLen + nonceLen));
  const opened = nacl.box.open(ciphertext, nonce, ephemeralPk, secret);
  if (!opened) throw new Error("Decryption failed");
  return JSON.parse(Buffer.from(opened).toString("utf-8"));
}

function decodeBase64Key(value: string, label: string): Uint8Array {
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0) throw new Error(`Could not decode ${label}`);
  return new Uint8Array(bytes);
}
