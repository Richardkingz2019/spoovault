const { ethers } = require("hardhat");

async function main() {
  const signers = await ethers.getSigners();
  const owner = signers[0];
  const requester1 = signers[1];
  const requester2 = signers[2];
  const guardians = signers.slice(3, 13).sort((a, b) => (a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1)); // K = 10 guardians sorted

  console.log("---------------------------------------------------------------");
  console.log("  SPOOVAULT BLS12-381 THRESHOLD SIGNATURE AGGREGATION BENCHMARK  ");
  console.log("---------------------------------------------------------------");

  const SpooVault = await ethers.getContractFactory("SpooVault");
  const spooVault = await SpooVault.deploy();
  await spooVault.waitForDeployment();
  const spooVaultAddress = await spooVault.getAddress();

  console.log(`Deployed SpooVault to: ${spooVaultAddress}`);

  // Create vault with 10 guardians, threshold = 10
  const guardianAddresses = guardians.map((g) => g.address);
  const tx = await spooVault
    .connect(owner)
    .createVault("K=10 Gas Benchmark Vault", "Vault for K=10 gas comparison", guardianAddresses, 10);
  await tx.wait();
  const vaultId = 1;

  const mockG1Key = (seed) => {
    const buf = Buffer.alloc(48, seed);
    buf[0] = 0x80 | (seed & 0x7f);
    return "0x" + buf.toString("hex");
  };

  const mockG2Sig = (seed) => {
    const buf = Buffer.alloc(96, seed);
    buf[0] = 0x80 | (seed & 0x7f);
    return "0x" + buf.toString("hex");
  };

  // Accept invites and register BLS keys
  for (let i = 0; i < guardians.length; i++) {
    await spooVault.connect(guardians[i]).acceptGuardianInvite(vaultId);
    await spooVault
      .connect(guardians[i])
      .registerGuardianBLSKey(vaultId, mockG1Key(i + 1), mockG2Sig(i + 1));
  }

  // Upload documents and mint passes
  await spooVault.connect(owner).addDocument(vaultId, "encrypted-metadata-1", "QmBLSBenchmarkHash1", 0);
  const documentId1 = 1;
  await spooVault.connect(owner).addDocument(vaultId, "encrypted-metadata-2", "QmBLSBenchmarkHash2", 0);
  const documentId2 = 2;

  await spooVault.connect(owner).mintAccessToken(vaultId, requester1.address, "ipfs://nft-pass-1");
  await spooVault.connect(owner).mintAccessToken(vaultId, requester2.address, "ipfs://nft-pass-2");

  // 1. Sequential individual approvals (Standard ECDSA flow - 10 transactions)
  await spooVault.connect(requester1).requestAccess(documentId1);
  const ecdsaRequestId = 1;

  let totalEcdsaGas = 0n;
  for (let i = 0; i < guardians.length; i++) {
    const approveTx = await spooVault
      .connect(guardians[i])
      ["approveAccess(uint256)"](ecdsaRequestId);
    const receipt = await approveTx.wait();
    totalEcdsaGas += receipt.gasUsed;
  }

  // 2. 1-Tx Aggregated BLS Threshold Approval (1 transaction)
  await spooVault.connect(requester2).requestAccess(documentId2);
  const blsRequestId = 2;

  const aggregatedSig = mockG2Sig(99);
  const aggregatedPk = mockG1Key(99);

  const blsTx = await spooVault.approveAccessBLS(
    blsRequestId,
    guardianAddresses,
    aggregatedSig,
    aggregatedPk,
    []
  );
  const blsReceipt = await blsTx.wait();
  const blsGas = blsReceipt.gasUsed;

  const gasSaved = totalEcdsaGas - blsGas;
  const percentageReduction = (Number(gasSaved) / Number(totalEcdsaGas)) * 100;

  console.log("\n=======================================================");
  console.log("       K=10 GUARDIAN APPROVAL GAS BENCHMARK REPORT      ");
  console.log("=======================================================");
  console.log(`Standard Individual Approvals (10 separate txs): ${totalEcdsaGas.toLocaleString()} gas`);
  console.log(`Aggregated BLS Threshold Approval (1 single tx): ${blsGas.toLocaleString()} gas`);
  console.log(`Absolute Gas Reduction:                         ${gasSaved.toLocaleString()} gas`);
  console.log(`Percentage Reduction:                           ${percentageReduction.toFixed(2)}%`);
  console.log("=======================================================");

  if (percentageReduction > 70.0) {
    console.log(">>> ACCEPTANCE CRITERIA MET: Gas reduction > 70% achieved! <<<");
  } else {
    throw new Error(`Gas reduction ${percentageReduction.toFixed(2)}% did not meet 70% threshold!`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
