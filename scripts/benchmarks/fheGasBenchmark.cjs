const { ethers } = require("hardhat");

async function main() {
  const [owner, guardian1, guardian2, guardian3, beneficiary] = await ethers.getSigners();
  const SpooVault = await ethers.getContractFactory("SpooVault");
  const spooVault = await SpooVault.deploy();
  await spooVault.waitForDeployment();

  const vaultTx = await spooVault.createVault(
    "FHE Benchmark Vault",
    "Gas benchmarking for FHE on-chain operations",
    [guardian1.address, guardian2.address, guardian3.address],
    2
  );
  await vaultTx.wait();

  // Accept invites
  await spooVault.connect(guardian1).acceptGuardianInvite(1);
  await spooVault.connect(guardian2).acceptGuardianInvite(1);
  await spooVault.connect(guardian3).acceptGuardianInvite(1);

  // Mint access token
  await spooVault.mintAccessToken(1, beneficiary.address, "ipfs://nft-pass-uri");

  const docTx = await spooVault.addDocument(
    1,
    "encrypted-meta",
    "QmTestIPFS",
    0 // Read
  );
  await docTx.wait();

  // Create 128-byte ciphertexts (dimension = 2)
  const ct1 = "0x" + "0".repeat(62) + "02" + "0".repeat(62) + "0a" + "0".repeat(62) + "14" + "0".repeat(62) + "64";
  const ct2 = "0x" + "0".repeat(62) + "02" + "0".repeat(62) + "0b" + "0".repeat(62) + "15" + "0".repeat(62) + "c8";

  // 1. Benchmark saveGuardianSharesFHE (3 guardians)
  const saveTx = await spooVault.saveGuardianSharesFHE(
    1,
    [guardian1.address, guardian2.address, guardian3.address],
    [ct1, ct2, ct2]
  );
  const saveReceipt = await saveTx.wait();
  console.log("saveGuardianSharesFHE (3 guardians, 128B each):", saveReceipt.gasUsed.toString(), "gas");

  // 2. Benchmark requestAccess
  const reqTx = await spooVault.connect(beneficiary).requestAccess(1);
  await reqTx.wait();

  // 3. Benchmark approveAccessFHE (First approval - initializes accumulator)
  const approve1Tx = await spooVault.connect(guardian1).approveAccessFHE(1, ct1);
  const approve1Receipt = await approve1Tx.wait();
  console.log("approveAccessFHE (1st approval - init accumulator):", approve1Receipt.gasUsed.toString(), "gas");

  // 4. Benchmark approveAccessFHE (Second approval - homomorphic addition + threshold reached)
  const approve2Tx = await spooVault.connect(guardian2).approveAccessFHE(1, ct2);
  const approve2Receipt = await approve2Tx.wait();
  console.log("approveAccessFHE (2nd approval - homomorphic add + threshold grant):", approve2Receipt.gasUsed.toString(), "gas");
}

main().then(() => process.exit(0)).catch(err => { console.error(err); process.exit(1); });
