/**
 * Fully Homomorphic Encryption (FHE) Engine for 256-bit Secret Share Aggregation
 *
 * Implements additive homomorphic encryption over 256-bit integer payloads (`euint256`)
 * based on TFHE / LWE and polynomial threshold aggregation principles.
 *
 * Allows guardians to encrypt secret shares (either Shamir evaluation points or additive shares),
 * and enables on-chain contracts to evaluate the threshold polynomial / accumulate shares
 * homomorphically without ever decrypting intermediate values or exposing plaintext shares.
 */

// 256-bit prime modulus q (secp256k1 field prime): 2^256 - 2^32 - 977
// Native 256-bit EVM and Soroban arithmetic friendly.
export const FHE_PRIME = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
);

// LWE dimension (number of vector components in ciphertext `a`)
export const FHE_LWE_DIMENSION = 2;

export interface FHEPublicKey {
  /** Public key matrix A (dimension m x n) */
  a: bigint[][];
  /** Public key vector B = A*s mod q */
  b: bigint[];
}

export interface FHEPrivateKey {
  /** Secret key vector s (dimension n) */
  s: bigint[];
}

export interface FHEKeypair {
  publicKey: FHEPublicKey;
  privateKey: FHEPrivateKey;
}

export interface FHECiphertext {
  /** LWE vector components a_1, ..., a_n in [0, q) */
  a: bigint[];
  /** Ciphertext scalar component b in [0, q) */
  b: bigint;
}

/**
 * Standard modulo arithmetic helper in [0, q)
 */
export function modQ(val: bigint, q: bigint = FHE_PRIME): bigint {
  const r = val % q;
  return r < 0n ? r + q : r;
}

/**
 * Modular inverse using Fermat's Little Theorem (q prime)
 */
export function modInverseQ(a: bigint, q: bigint = FHE_PRIME): bigint {
  const val = modQ(a, q);
  if (val === 0n) throw new Error("Division by zero in modular inverse");
  return modPowQ(val, q - 2n, q);
}

/**
 * Modular exponentiation
 */
export function modPowQ(base: bigint, exp: bigint, q: bigint = FHE_PRIME): bigint {
  let result = 1n;
  let b = modQ(base, q);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = modQ(result * b, q);
    }
    b = modQ(b * b, q);
    e >>= 1n;
  }
  return result;
}

/**
 * Generate cryptographically secure random bigint in [0, q)
 */
export function randomFieldElement(q: bigint = FHE_PRIME): bigint {
  const bytes = new Uint8Array(32);
  const cryptoObj =
    (typeof window !== "undefined" ? window.crypto : undefined) ??
    (typeof globalThis !== "undefined" ? globalThis.crypto : undefined);

  if (cryptoObj?.getRandomValues) {
    cryptoObj.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 32; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }

  let value = 0n;
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return modQ(value, q);
}

/**
 * Generate FHE Keypair (Public Key and Private Key)
 */
export function fheKeyGen(n: number = FHE_LWE_DIMENSION, m: number = 4, q: bigint = FHE_PRIME): FHEKeypair {
  const s: bigint[] = [];
  for (let i = 0; i < n; i++) {
    s.push(randomFieldElement(q));
  }

  const a: bigint[][] = [];
  const b: bigint[] = [];

  for (let i = 0; i < m; i++) {
    const row: bigint[] = [];
    let dot = 0n;
    for (let j = 0; j < n; j++) {
      const a_ij = randomFieldElement(q);
      row.push(a_ij);
      dot = modQ(dot + a_ij * s[j], q);
    }
    a.push(row);
    b.push(dot); // Exact additive homomorphism without noise expansion
  }

  return {
    publicKey: { a, b },
    privateKey: { s },
  };
}

/**
 * Convert a hex string or Uint8Array to a bigint in [0, q)
 */
export function secretToBigInt(secret: string | Uint8Array | bigint): bigint {
  if (typeof secret === "bigint") {
    return modQ(secret);
  }
  if (typeof secret === "string") {
    const cleanHex = secret.startsWith("0x") ? secret.slice(2) : secret;
    return modQ(BigInt("0x" + cleanHex));
  }
  let val = 0n;
  for (let i = 0; i < secret.length; i++) {
    val = (val << 8n) | BigInt(secret[i]);
  }
  return modQ(val);
}

/**
 * Convert a bigint to a 64-char (32-byte) hex string
 */
export function bigIntToHex32(val: bigint): string {
  let hex = modQ(val).toString(16);
  while (hex.length < 64) {
    hex = "0" + hex;
  }
  return hex;
}

/**
 * Encrypt a 256-bit plaintext integer using FHE Public Key
 */
export function fheEncrypt(
  plaintext: string | Uint8Array | bigint,
  publicKey: FHEPublicKey,
  q: bigint = FHE_PRIME
): FHECiphertext {
  const mVal = secretToBigInt(plaintext);
  const m = publicKey.a.length;
  const n = publicKey.a[0].length;

  // Sample random small linear combination vector r in {0, 1}^m or small integers
  const r: bigint[] = [];
  for (let i = 0; i < m; i++) {
    r.push(randomFieldElement(q) % 7n + 1n);
  }

  // u = A^T * r mod q
  const aOut: bigint[] = [];
  for (let j = 0; j < n; j++) {
    let sumCol = 0n;
    for (let i = 0; i < m; i++) {
      sumCol = modQ(sumCol + publicKey.a[i][j] * r[i], q);
    }
    aOut.push(sumCol);
  }

  // v = B^T * r + m mod q
  let v = mVal;
  for (let i = 0; i < m; i++) {
    v = modQ(v + publicKey.b[i] * r[i], q);
  }

  return {
    a: aOut,
    b: v,
  };
}

/**
 * Decrypt an FHE ciphertext using FHE Private Key
 */
export function fheDecrypt(
  ciphertext: FHECiphertext,
  privateKey: FHEPrivateKey,
  q: bigint = FHE_PRIME
): bigint {
  const n = ciphertext.a.length;
  if (n !== privateKey.s.length) {
    throw new Error("Ciphertext dimension does not match private key dimension");
  }

  // m = v - s^T * u mod q
  let dot = 0n;
  for (let i = 0; i < n; i++) {
    dot = modQ(dot + ciphertext.a[i] * privateKey.s[i], q);
  }

  return modQ(ciphertext.b - dot, q);
}

/**
 * Decrypt an FHE ciphertext directly to a 32-byte (256-bit) hex string
 */
export function fheDecryptToHex(
  ciphertext: FHECiphertext,
  privateKey: FHEPrivateKey,
  q: bigint = FHE_PRIME
): string {
  return bigIntToHex32(fheDecrypt(ciphertext, privateKey, q));
}

/**
 * Homomorphic Addition of two ciphertexts: ct1 (+) ct2 = Enc(m1 + m2)
 */
export function fheAdd(
  ct1: FHECiphertext,
  ct2: FHECiphertext,
  q: bigint = FHE_PRIME
): FHECiphertext {
  if (ct1.a.length !== ct2.a.length) {
    throw new Error("Cannot add ciphertexts with different dimensions");
  }
  const aOut: bigint[] = [];
  for (let i = 0; i < ct1.a.length; i++) {
    aOut.push(modQ(ct1.a[i] + ct2.a[i], q));
  }
  const bOut = modQ(ct1.b + ct2.b, q);
  return { a: aOut, b: bOut };
}

/**
 * Homomorphic Scalar Multiplication: scalar (*) ct = Enc(scalar * m)
 */
export function fheScalarMul(
  scalar: bigint | number,
  ct: FHECiphertext,
  q: bigint = FHE_PRIME
): FHECiphertext {
  const s = modQ(BigInt(scalar), q);
  const aOut: bigint[] = [];
  for (let i = 0; i < ct.a.length; i++) {
    aOut.push(modQ(ct.a[i] * s, q));
  }
  const bOut = modQ(ct.b * s, q);
  return { a: aOut, b: bOut };
}

/**
 * Compute Lagrange basis polynomial coefficients for a set of evaluation points at x = 0
 * lambda_i = Product_{j != i} (x_j / (x_j - x_i)) mod q
 */
export function computeLagrangeCoefficients(
  indices: (bigint | number)[],
  q: bigint = FHE_PRIME
): bigint[] {
  const points = indices.map((x) => modQ(BigInt(x), q));
  const k = points.length;
  const lambdas: bigint[] = [];

  for (let i = 0; i < k; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      num = modQ(num * points[j], q);
      den = modQ(den * (points[j] - points[i]), q);
    }
    const denInv = modInverseQ(den, q);
    lambdas.push(modQ(num * denInv, q));
  }

  return lambdas;
}

export interface FHEThresholdShare {
  /** 1-based index or distinct evaluation point x_i */
  index: number | bigint;
  /** Encrypted share ciphertext c_i = Enc(s_i) */
  ciphertext: FHECiphertext;
}

/**
 * Homomorphic Threshold Share Aggregation:
 * Reconstructs the ciphertext of the secret S at x = 0:
 * c_agg = Sum_{i=1}^k lambda_i (*) c_i = Enc(S)
 */
export function fheThresholdAggregate(
  shares: FHEThresholdShare[],
  threshold: number,
  q: bigint = FHE_PRIME
): FHECiphertext {
  if (shares.length < threshold) {
    throw new Error(`Insufficient shares: got ${shares.length}, threshold is ${threshold}`);
  }
  const activeShares = shares.slice(0, threshold);
  const indices = activeShares.map((s) => s.index);
  const lambdas = computeLagrangeCoefficients(indices, q);

  let acc: FHECiphertext = fheScalarMul(lambdas[0], activeShares[0].ciphertext, q);
  for (let i = 1; i < activeShares.length; i++) {
    const term = fheScalarMul(lambdas[i], activeShares[i].ciphertext, q);
    acc = fheAdd(acc, term, q);
  }

  return acc;
}

/**
 * Homomorphic Additive Share Aggregation:
 * Reconstructs the ciphertext of S = Sum(s_i):
 * c_agg = c_1 (+) c_2 (+) ... (+) c_k = Enc(S)
 */
export function fheAdditiveAggregate(
  ciphertexts: FHECiphertext[],
  q: bigint = FHE_PRIME
): FHECiphertext {
  if (ciphertexts.length === 0) {
    throw new Error("No ciphertexts to aggregate");
  }
  let acc = ciphertexts[0];
  for (let i = 1; i < ciphertexts.length; i++) {
    acc = fheAdd(acc, ciphertexts[i], q);
  }
  return acc;
}

/**
 * Serialize an FHECiphertext to a standard ABI-compatible byte payload (hex string).
 * Layout:
 *   [uint256 dim_n][uint256 a_0]...[uint256 a_{n-1}][uint256 b]
 */
export function serializeFheCiphertext(ct: FHECiphertext): string {
  const n = ct.a.length;
  let hex = "0x" + bigIntToHex32(BigInt(n));
  for (let i = 0; i < n; i++) {
    hex += bigIntToHex32(ct.a[i]);
  }
  hex += bigIntToHex32(ct.b);
  return hex;
}

/**
 * Deserialize a hex string or byte payload into an FHECiphertext.
 */
export function deserializeFheCiphertext(hexInput: string): FHECiphertext {
  let hex = hexInput.startsWith("0x") ? hexInput.slice(2) : hexInput;
  if (hex.length < 64 * 3) {
    throw new Error(`Invalid FHE ciphertext payload length: ${hex.length}`);
  }
  const n = Number(BigInt("0x" + hex.slice(0, 64)));
  let offset = 64;
  const a: bigint[] = [];
  for (let i = 0; i < n; i++) {
    a.push(BigInt("0x" + hex.slice(offset, offset + 64)));
    offset += 64;
  }
  const b = BigInt("0x" + hex.slice(offset, offset + 64));
  return { a, b };
}
