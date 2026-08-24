import {
  fheKeyGen,
  fheEncrypt,
  fheDecryptToHex,
  fheThresholdAggregate,
  fheAdditiveAggregate,
  serializeFheCiphertext,
  deserializeFheCiphertext,
  FHEKeypair,
  FHEPublicKey,
  FHEPrivateKey,
  FHEThresholdShare,
  modQ,
  secretToBigInt,
} from "../utils/fheEngine";

export interface FheDocumentShares {
  documentId?: string | number;
  publicKey: FHEPublicKey;
  guardianCiphertexts: string[]; // Serialized hex FHECiphertext strings
  threshold: number;
}

export class FHEService {
  /**
   * Generate an FHE Keypair for a document or beneficiary
   */
  public generateKeypair(): FHEKeypair {
    return fheKeyGen();
  }

  /**
   * Split a 256-bit symmetric key into N additive secret shares
   * where Sum(s_i) = S mod q, and encrypt each share under the FHE public key.
   */
  public createAdditiveSharesFHE(
    secretHex: string,
    guardianCount: number,
    publicKey: FHEPublicKey
  ): { sharesPlaintext: bigint[]; sharesFHE: string[] } {
    if (guardianCount < 1) {
      throw new Error("Guardian count must be at least 1");
    }

    const secretVal = secretToBigInt(secretHex);
    const sharesPlaintext: bigint[] = [];
    let sum = 0n;

    for (let i = 0; i < guardianCount - 1; i++) {
      const share = modQ(secretToBigInt(crypto.getRandomValues(new Uint8Array(32))));
      sharesPlaintext.push(share);
      sum = modQ(sum + share);
    }

    // Last share completes the sum to equal secretVal mod q
    const lastShare = modQ(secretVal - sum);
    sharesPlaintext.push(lastShare);

    const sharesFHE = sharesPlaintext.map((share) => {
      const ct = fheEncrypt(share, publicKey);
      return serializeFheCiphertext(ct);
    });

    return { sharesPlaintext, sharesFHE };
  }

  /**
   * Split a 256-bit symmetric key into N Shamir secret shares (evaluation points x = 1..N)
   * and encrypt each share under the FHE public key.
   */
  public createThresholdSharesFHE(
    secretHex: string,
    n: number,
    threshold: number,
    publicKey: FHEPublicKey
  ): { sharesPlaintext: { index: number; value: bigint }[]; sharesFHE: { index: number; ciphertextHex: string }[] } {
    if (threshold < 1 || threshold > n) {
      throw new Error("Threshold must satisfy 1 <= threshold <= n");
    }

    const secretVal = secretToBigInt(secretHex);
    // Polynomial coefficients: f(x) = secretVal + a_1*x + ... + a_{k-1}*x^{k-1}
    const coeffs: bigint[] = [secretVal];
    for (let i = 1; i < threshold; i++) {
      coeffs.push(modQ(secretToBigInt(crypto.getRandomValues(new Uint8Array(32)))));
    }

    const sharesPlaintext: { index: number; value: bigint }[] = [];
    const sharesFHE: { index: number; ciphertextHex: string }[] = [];

    for (let j = 1; j <= n; j++) {
      const x = BigInt(j);
      let y = 0n;
      // Horner evaluation
      for (let c = coeffs.length - 1; c >= 0; c--) {
        y = modQ(y * x + coeffs[c]);
      }

      sharesPlaintext.push({ index: j, value: y });
      const ct = fheEncrypt(y, publicKey);
      sharesFHE.push({ index: j, ciphertextHex: serializeFheCiphertext(ct) });
    }

    return { sharesPlaintext, sharesFHE };
  }

  /**
   * Reconstruct symmetric key from on-chain aggregate ciphertext
   */
  public decryptAggregateCiphertext(
    aggregateCiphertextHex: string,
    privateKey: FHEPrivateKey
  ): string {
    const ct = deserializeFheCiphertext(aggregateCiphertextHex);
    return fheDecryptToHex(ct, privateKey);
  }

  /**
   * Client-side homomorphic threshold aggregation
   */
  public aggregateThresholdShares(
    shares: { index: number; ciphertextHex: string }[],
    threshold: number
  ): string {
    const fheShares: FHEThresholdShare[] = shares.map((s) => ({
      index: s.index,
      ciphertext: deserializeFheCiphertext(s.ciphertextHex),
    }));
    const aggregate = fheThresholdAggregate(fheShares, threshold);
    return serializeFheCiphertext(aggregate);
  }

  /**
   * Client-side homomorphic additive aggregation
   */
  public aggregateAdditiveShares(ciphertextsHex: string[]): string {
    const cts = ciphertextsHex.map((hex) => deserializeFheCiphertext(hex));
    const aggregate = fheAdditiveAggregate(cts);
    return serializeFheCiphertext(aggregate);
  }
}

export const fheService = new FHEService();
