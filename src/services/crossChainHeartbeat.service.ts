import { ethers } from "ethers";
import { contractService } from "./contract.service";
import { stellarService } from "./stellar.service";

export interface HeartbeatPayload {
  gid: string;
  gidHash: string;
  vaultId: number;
  evmOwner: string;
  timestamp: number;
}

export interface HeartbeatSignature {
  signature: string;
  recoveryId: number;
}

export interface CrossChainHeartbeatResult {
  evmTransactionHash: string;
  payload: HeartbeatPayload;
  signature: HeartbeatSignature;
  stellarSynchronized: boolean;
}

const HEARTBEAT_PREFIX = "SpooVaultProofOfLife";

export const buildHeartbeatPayload = (
  gid: string,
  vaultId: number,
  evmOwner: string,
  timestamp: number
): HeartbeatPayload => {
  const gidHash = ethers.keccak256(ethers.toUtf8Bytes(gid));
  return { gid, gidHash, vaultId, evmOwner, timestamp };
};

export const buildHeartbeatDigest = (payload: HeartbeatPayload): string => {
  const encoded = ethers.concat([
    ethers.toUtf8Bytes(HEARTBEAT_PREFIX),
    payload.gidHash,
    ethers.zeroPadValue(ethers.toBeHex(payload.vaultId), 8),
    payload.evmOwner,
    ethers.zeroPadValue(ethers.toBeHex(payload.timestamp), 8),
  ]);
  return ethers.keccak256(encoded);
};

export const signHeartbeatPayload = async (
  payload: HeartbeatPayload,
  signer: ethers.Signer
): Promise<HeartbeatSignature> => {
  const digest = buildHeartbeatDigest(payload);
  const signature = await signer.signMessage(ethers.getBytes(digest));
  const parsed = ethers.Signature.from(signature);
  return { signature, recoveryId: parsed.yParity };
};

export const synchronizeHeartbeat = async (
  vaultId: number,
  stellarVaultId: number,
  relayer: string,
  signer: ethers.Signer
): Promise<CrossChainHeartbeatResult> => {
  const evmOwner = await signer.getAddress();
  const gid = await contractService.getVaultGID(vaultId);
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = buildHeartbeatPayload(gid, vaultId, evmOwner, timestamp);
  const signature = await signHeartbeatPayload(payload, signer);
  const evmTransactionHash = await contractService.recordProofOfLife(vaultId);

  await stellarService.syncProofOfLife(
    stellarVaultId,
    vaultId,
    payload.gidHash,
    evmOwner,
    timestamp,
    signature.signature,
    signature.recoveryId,
    relayer
  );

  return {
    evmTransactionHash,
    payload,
    signature,
    stellarSynchronized: true,
  };
};
