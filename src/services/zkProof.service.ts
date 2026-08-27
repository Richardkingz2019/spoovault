// Declare untyped module locally for snarkjs
// @ts-ignore
import * as snarkjs from 'snarkjs';

export interface ProofInputs {
  privateKey: string;
  secretShare: string;
  blindingFactor: string;
  vaultRootCommitment: string;
  nullifierHash: string;
  documentId: string;
}

export class ZkProofService {
  static async generateAccessProof(inputs: ProofInputs, wasmPath: string, zkeyPath: string) {
    const { proof, publicSignals } = await (snarkjs as any).groth16.fullProve(
      inputs,
      wasmPath,
      zkeyPath
    );
    return { proof, publicSignals };
  }

  static async verifyProof(vKey: object, publicSignals: string[], proof: object): Promise<boolean> {
    return await (snarkjs as any).groth16.verify(vKey, publicSignals, proof);
  }
}
