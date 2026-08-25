import { describe, it, expect } from 'vitest';
import {
  generateBLSKeyPair,
  deriveBLSKeyFromMnemonic,
  verifyProofOfPossession,
  encodeApprovalMessage,
  signBLS,
  verifyBLSSignature,
  aggregateBLSSignatures,
  aggregateBLSPublicKeys,
  verifyAggregatedBLSSignature,
  aggregateGuardianApprovalShares
} from '../utils/blsCrypto';
import { BLSSignatureShare } from '../types/bls';

describe('BLS12-381 Cryptographic Primitives & Aggregation', () => {
  it('generates well-formed keypair with Proof of Possession', () => {
    const keyPair = generateBLSKeyPair();
    expect(keyPair.privateKey).toMatch(/^0x[a-f0-9]{64}$/);
    expect(keyPair.publicKey).toMatch(/^0x[a-f0-9]{96}$/); // 48 bytes = 96 hex chars
    expect(keyPair.proofOfPossession).toMatch(/^0x[a-f0-9]{192}$/); // 96 bytes = 192 hex chars

    const isPoPValid = verifyProofOfPossession(keyPair.publicKey, keyPair.proofOfPossession);
    expect(isPoPValid).toBe(true);
  });

  it('rejects invalid or tampered Proof of Possession', () => {
    const keyPair1 = generateBLSKeyPair();
    const keyPair2 = generateBLSKeyPair();

    // Swapping PoP between keys must fail
    expect(verifyProofOfPossession(keyPair1.publicKey, keyPair2.proofOfPossession)).toBe(false);
    // Corrupted PoP hex must fail
    expect(verifyProofOfPossession(keyPair1.publicKey, '0x1234')).toBe(false);
  });

  it('deterministically derives BLS keypair from BIP-39 mnemonic', () => {
    const mnemonic = 'test test test test test test test test test test test junk';
    const key1 = deriveBLSKeyFromMnemonic(mnemonic, 0);
    const key2 = deriveBLSKeyFromMnemonic(mnemonic, 0);
    const key3 = deriveBLSKeyFromMnemonic(mnemonic, 1);

    expect(key1.privateKey).toBe(key2.privateKey);
    expect(key1.publicKey).toBe(key2.publicKey);
    expect(key1.privateKey).not.toBe(key3.privateKey);
  });

  it('signs and verifies single BLS12-381 signature', () => {
    const key = generateBLSKeyPair();
    const msg = encodeApprovalMessage(1, 100, 5, '0x1111111111111111111111111111111111111111', 31337);
    const sig = signBLS(msg, key.privateKey);

    expect(sig).toMatch(/^0x[a-f0-9]{192}$/);
    expect(verifyBLSSignature(sig, msg, key.publicKey)).toBe(true);

    // Tampered message should fail
    const tamperedMsg = encodeApprovalMessage(2, 100, 5, '0x1111111111111111111111111111111111111111', 31337);
    expect(verifyBLSSignature(sig, tamperedMsg, key.publicKey)).toBe(false);
  });

  it('aggregates K=5 guardian signatures and verifies in 1 pairing check', () => {
    const K = 5;
    const guardians = Array.from({ length: K }, () => generateBLSKeyPair());
    const msg = encodeApprovalMessage(10, 42, 7, '0x2222222222222222222222222222222222222222', 31337);

    const signatures = guardians.map(g => signBLS(msg, g.privateKey));
    const publicKeys = guardians.map(g => g.publicKey);

    const aggSig = aggregateBLSSignatures(signatures);
    const aggPk = aggregateBLSPublicKeys(publicKeys);

    expect(aggSig).toMatch(/^0x[a-f0-9]{192}$/);
    expect(aggPk).toMatch(/^0x[a-f0-9]{96}$/);

    const isValid = verifyAggregatedBLSSignature(aggSig, msg, aggPk);
    expect(isValid).toBe(true);
  });

  it('aggregates K=10 guardian signatures and verifies in 1 pairing check', () => {
    const K = 10;
    const guardians = Array.from({ length: K }, () => generateBLSKeyPair());
    const msg = encodeApprovalMessage(99, 101, 88, '0x3333333333333333333333333333333333333333', 31337);

    const signatures = guardians.map(g => signBLS(msg, g.privateKey));
    const publicKeys = guardians.map(g => g.publicKey);

    const aggSig = aggregateBLSSignatures(signatures);
    const aggPk = aggregateBLSPublicKeys(publicKeys);

    const isValid = verifyAggregatedBLSSignature(aggSig, msg, aggPk);
    expect(isValid).toBe(true);
  });

  it('rejects aggregated signature if any single guardian signature is invalid or missing', () => {
    const guardians = Array.from({ length: 4 }, () => generateBLSKeyPair());
    const rogueKey = generateBLSKeyPair();
    const msg = encodeApprovalMessage(1, 2, 3, '0x4444444444444444444444444444444444444444', 31337);

    // 3 honest signatures + 1 rogue signature on different message
    const sig1 = signBLS(msg, guardians[0].privateKey);
    const sig2 = signBLS(msg, guardians[1].privateKey);
    const sig3 = signBLS(msg, guardians[2].privateKey);
    const rogueSig = signBLS(new TextEncoder().encode('corrupted'), rogueKey.privateKey);

    const aggSig = aggregateBLSSignatures([sig1, sig2, sig3, rogueSig]);
    const aggPk = aggregateBLSPublicKeys([...guardians.slice(0, 3).map(g => g.publicKey), rogueKey.publicKey]);

    expect(verifyAggregatedBLSSignature(aggSig, msg, aggPk)).toBe(false);
  });

  it('correctly collects and aggregates guardian approval shares with threshold', () => {
    const threshold = 3;
    const keys = Array.from({ length: 5 }, () => generateBLSKeyPair());
    const guardianAddresses = [
      '0x1111111111111111111111111111111111111111',
      '0x2222222222222222222222222222222222222222',
      '0x3333333333333333333333333333333333333333',
      '0x4444444444444444444444444444444444444444',
      '0x5555555555555555555555555555555555555555'
    ];

    const requestId = 10;
    const vaultId = 1;
    const documentId = 5;
    const beneficiary = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const msg = encodeApprovalMessage(requestId, vaultId, documentId, beneficiary, 31337);

    const shares: BLSSignatureShare[] = keys.slice(0, 4).map((k, idx) => ({
      guardianAddress: guardianAddresses[idx],
      guardianIndex: idx,
      publicKey: k.publicKey,
      signature: signBLS(msg, k.privateKey),
      requestId,
      vaultId,
      documentId,
      beneficiary,
      timestamp: Date.now(),
      encryptedBeneficiaryShare: `encrypted_share_${idx}`
    }));

    const payload = aggregateGuardianApprovalShares(
      shares,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      threshold,
      31337
    );

    expect(payload.guardianAddresses.length).toBe(threshold);
    expect(payload.aggregatedSignature).toMatch(/^0x[a-f0-9]{192}$/);
    expect(payload.aggregatedPublicKey).toMatch(/^0x[a-f0-9]{96}$/);
    expect(payload.encryptedSharesForBeneficiary.length).toBe(threshold);

    const isValid = verifyAggregatedBLSSignature(payload.aggregatedSignature, msg, payload.aggregatedPublicKey);
    expect(isValid).toBe(true);
  });

  it('fails if submitted shares are below threshold', () => {
    const keys = Array.from({ length: 2 }, () => generateBLSKeyPair());
    const shares: BLSSignatureShare[] = keys.map((k, idx) => ({
      guardianAddress: `0x${(idx + 1).toString().padStart(40, '0')}`,
      publicKey: k.publicKey,
      signature: signBLS('test', k.privateKey),
      requestId: 1,
      vaultId: 1,
      documentId: 1,
      beneficiary: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      timestamp: Date.now()
    }));

    expect(() => {
      aggregateGuardianApprovalShares(
        shares,
        1,
        1,
        1,
        '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        3, // threshold 3
        31337
      );
    }).toThrow(/Insufficient guardian shares/);
  });
});
