import { describe, it, expect } from 'vitest';
import { blsKeyringService } from '../services/blsKeyring.service';
import 'fake-indexeddb/auto';

describe('BLSKeyringService', () => {
  const guardian1 = '0x1111111111111111111111111111111111111111';
  const guardian2 = '0x2222222222222222222222222222222222222222';
  const guardian3 = '0x3333333333333333333333333333333333333333';
  const beneficiary = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  it('generates, stores, and retrieves BLS key for a guardian', async () => {
    const key = await blsKeyringService.generateKeyForGuardian(guardian1);
    expect(key).toBeDefined();
    expect(key.guardianAddress?.toLowerCase()).toBe(guardian1.toLowerCase());
    expect(key.publicKey).toMatch(/^0x[a-f0-9]{96}$/);

    const retrieved = await blsKeyringService.getKeyForGuardian(guardian1);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.publicKey).toBe(key.publicKey);

    const hasKey = await blsKeyringService.hasKeyForGuardian(guardian1);
    expect(hasKey).toBe(true);
  });

  it('derives BLS key from mnemonic seed phrase', async () => {
    const mnemonic = 'apple banana cherry dragon eagle fox grape honey ice jazz kite lion';
    const key = await blsKeyringService.deriveFromMnemonic(guardian2, mnemonic, 0);
    expect(key.publicKey).toMatch(/^0x[a-f0-9]{96}$/);

    const retrieved = await blsKeyringService.getKeyForGuardian(guardian2);
    expect(retrieved?.publicKey).toBe(key.publicKey);
  });

  it('signs access approval for a pending document request', async () => {
    await blsKeyringService.generateKeyForGuardian(guardian1);
    const requestId = 101;
    const vaultId = 1;
    const documentId = 5;

    const share = await blsKeyringService.signAccessApproval(
      guardian1,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      'encrypted_beneficiary_share_data'
    );

    expect(share.guardianAddress.toLowerCase()).toBe(guardian1.toLowerCase());
    expect(share.requestId).toBe(requestId);
    expect(share.signature).toMatch(/^0x[a-f0-9]{192}$/);
    expect(share.encryptedBeneficiaryShare).toBe('encrypted_beneficiary_share_data');
  });

  it('aggregates multi-guardian approval shares and validates threshold', async () => {
    await blsKeyringService.generateKeyForGuardian(guardian1);
    await blsKeyringService.generateKeyForGuardian(guardian2);
    await blsKeyringService.generateKeyForGuardian(guardian3);

    const requestId = 200;
    const vaultId = 2;
    const documentId = 10;

    const share1 = await blsKeyringService.signAccessApproval(
      guardian1,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      'share_1'
    );

    const share2 = await blsKeyringService.signAccessApproval(
      guardian2,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      'share_2'
    );

    const share3 = await blsKeyringService.signAccessApproval(
      guardian3,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      'share_3'
    );

    const payload = blsKeyringService.aggregateApprovalShares(
      [share1, share2, share3],
      requestId,
      vaultId,
      documentId,
      beneficiary,
      2 // threshold = 2
    );

    expect(payload.guardianAddresses.length).toBe(2);
    expect(payload.aggregatedSignature).toMatch(/^0x[a-f0-9]{192}$/);
    expect(payload.aggregatedPublicKey).toMatch(/^0x[a-f0-9]{96}$/);

    const verification = blsKeyringService.verifyAggregatedApproval(payload, 2);
    expect(verification.isValid).toBe(true);
    expect(verification.thresholdReached).toBe(true);
  });

  it('exports and imports encrypted backup with password', async () => {
    const originalKey = await blsKeyringService.generateKeyForGuardian(guardian1);
    const password = 'UltraSecurePassword123!';

    const backup = await blsKeyringService.exportEncryptedBackup(guardian1, password);
    expect(backup.version).toBe('1.0');
    expect(backup.encryptedPrivateKey).toBeDefined();
    expect(backup.publicKey).toBe(originalKey.publicKey);

    // Import into a new guardian address to verify
    const importedAddress = '0x9999999999999999999999999999999999999999';
    backup.guardianAddress = importedAddress;

    const importedKey = await blsKeyringService.importEncryptedBackup(backup, password);
    expect(importedKey.publicKey).toBe(originalKey.publicKey);
    expect(importedKey.privateKey).toBe(originalKey.privateKey);
  });

  it('links vault IDs to stored key', async () => {
    await blsKeyringService.generateKeyForGuardian(guardian1);
    await blsKeyringService.linkVaultToKey(guardian1, 42);
    await blsKeyringService.linkVaultToKey(guardian1, 99);

    const key = await blsKeyringService.getKeyForGuardian(guardian1);
    expect(key?.vaultIds).toContain(42);
    expect(key?.vaultIds).toContain(99);
  });
});
