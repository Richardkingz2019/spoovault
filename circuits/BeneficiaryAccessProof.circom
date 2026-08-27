pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

template BeneficiaryAccessProof() {
    // Private Inputs
    signal input privateKey;
    signal input secretShare;
    signal input blindingFactor;

    // Public Inputs
    signal input vaultRootCommitment;
    signal input nullifierHash;
    signal input documentId;

    // Signal verification outputs
    signal computedCommitment;
    signal computedNullifier;

    // 1. Verify Commitment: Hash(privateKey, secretShare, blindingFactor)
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== privateKey;
    commitmentHasher.inputs[1] <== secretShare;
    commitmentHasher.inputs[2] <== blindingFactor;
    computedCommitment <== commitmentHasher.out;

    vaultRootCommitment === computedCommitment;

    // 2. Compute Nullifier: Hash(privateKey, documentId)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== privateKey;
    nullifierHasher.inputs[1] <== documentId;
    computedNullifier <== nullifierHasher.out;

    nullifierHash === computedNullifier;
}

component main {public [vaultRootCommitment, nullifierHash, documentId]} = BeneficiaryAccessProof();
