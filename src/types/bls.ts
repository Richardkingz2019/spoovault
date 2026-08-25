/**
 * BLS12-381 Threshold Signature Types
 * Supports BLS12-381 G1 public keys (48 bytes compressed / 96 bytes hex)
 * and G2 signatures (96 bytes compressed / 192 bytes hex).
 */

export interface BLSKeyPair {
  /** 32-byte private key in hex (0x prefix) */
  privateKey: string;
  /** 48-byte G1 compressed public key in hex (0x prefix) */
  publicKey: string;
  /** Proof of Possession: 96-byte G2 signature over publicKey */
  proofOfPossession: string;
  /** Creation timestamp in milliseconds */
  createdAt: number;
  /** Associated vault IDs if any */
  vaultIds?: number[];
  /** Associated guardian Ethereum address */
  guardianAddress?: string;
}

export interface BLSSignatureShare {
  guardianAddress: string;
  guardianIndex?: number;
  publicKey: string;
  signature: string; // 96 bytes hex
  requestId: number;
  vaultId: number;
  documentId: number;
  beneficiary: string;
  timestamp: number;
  encryptedBeneficiaryShare?: string;
  fheBeneficiaryShare?: string;
}

export interface BLSAggregatedApprovalPayload {
  requestId: number;
  vaultId: number;
  documentId: number;
  beneficiary: string;
  guardianAddresses: string[];
  guardianIndices: number[];
  publicKeys: string[]; // 48-byte compressed G1 hex strings
  aggregatedPublicKey: string; // 48-byte compressed G1 hex string
  aggregatedSignature: string; // 96-byte compressed G2 hex string
  encryptedSharesForBeneficiary: string[];
  messageDigest: string; // bytes32 hex
}

export interface BLSGuardianRegistration {
  vaultId: number;
  guardianAddress: string;
  blsPublicKey: string; // 48 bytes hex
  proofOfPossession: string; // 96 bytes hex
  registeredAt: number;
  isActive: boolean;
}

export interface BLSThresholdVerificationResult {
  isValid: boolean;
  thresholdReached: boolean;
  requiredThreshold: number;
  participatingGuardians: number;
  aggregatedPublicKey: string;
  aggregatedSignature: string;
  error?: string;
}

export interface BLSKeyBackup {
  version: '1.0';
  guardianAddress: string;
  encryptedPrivateKey: string; // AES-GCM encrypted
  salt: string;
  iv: string;
  publicKey: string;
  proofOfPossession: string;
  createdAt: number;
}
