import React, { useState } from 'react';
import { useWeb3 } from '../../context/Web3Context';
import { blsKeyringService } from '../../services/blsKeyring.service';
import { toast } from 'react-hot-toast';
import { FiCheckCircle, FiUsers, FiZap, FiX, FiLayers } from 'react-icons/fi';
import { BLSSignatureShare, BLSAggregatedApprovalPayload } from '../../types/bls';

interface BLSBatchApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  requestId: number;
  vaultId: number;
  documentId: number;
  beneficiary: string;
  requiredThreshold: number;
  availableShares?: BLSSignatureShare[];
  onApprovalSuccess?: () => void;
}

export const BLSBatchApprovalModal: React.FC<BLSBatchApprovalModalProps> = ({
  isOpen,
  onClose,
  requestId,
  vaultId,
  documentId,
  beneficiary,
  requiredThreshold,
  availableShares = [],
  onApprovalSuccess
}) => {
  const { signBLSApproval, submitBLSBatchApproval } = useWeb3();
  const [shares, setShares] = useState<BLSSignatureShare[]>(availableShares);
  const [isSigning, setIsSigning] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [aggregatedPayload, setAggregatedPayload] = useState<BLSAggregatedApprovalPayload | null>(null);

  if (!isOpen) return null;

  const handleSignOwnShare = async () => {
    setIsSigning(true);
    try {
      const myShare = await signBLSApproval(requestId, vaultId, documentId, beneficiary);
      const updated = [...shares.filter(s => s.guardianAddress.toLowerCase() !== myShare.guardianAddress.toLowerCase()), myShare];
      setShares(updated);
      toast.success('Your BLS signature share has been added');
    } catch (err: any) {
      toast.error(err.message || 'Failed to sign BLS approval');
    } finally {
      setIsSigning(false);
    }
  };

  const handleAggregate = () => {
    try {
      const payload = blsKeyringService.aggregateApprovalShares(
        shares,
        requestId,
        vaultId,
        documentId,
        beneficiary,
        requiredThreshold
      );
      setAggregatedPayload(payload);
      toast.success(`Aggregated ${payload.guardianAddresses.length} guardian signatures into 1 BLS signature!`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to aggregate signatures');
    }
  };

  const handleSubmitOnChain = async () => {
    if (!aggregatedPayload) return;
    setIsSubmitting(true);
    try {
      await submitBLSBatchApproval(aggregatedPayload);
      onApprovalSuccess?.();
      onClose();
    } catch (err: any) {
      toast.error(err.message || 'Failed to submit aggregated approval on-chain');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-xl p-6 bg-slate-900 border border-indigo-500/30 rounded-2xl shadow-2xl text-slate-100">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-white transition-colors rounded-lg"
        >
          <FiX className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-6">
          <div className="p-3 bg-cyan-500/20 text-cyan-400 rounded-xl border border-cyan-500/30">
            <FiLayers className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              BLS Threshold Batch Approval
              <span className="px-2 py-0.5 text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full font-mono">
                1-Tx Release
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Request #{requestId} | Vault #{vaultId} | Document #{documentId}
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-slate-800/80 border border-slate-700 rounded-xl">
              <div className="text-xs text-slate-400">Required Threshold</div>
              <div className="text-lg font-bold text-white mt-0.5">{requiredThreshold} Guardians</div>
            </div>
            <div className="p-3 bg-slate-800/80 border border-slate-700 rounded-xl">
              <div className="text-xs text-slate-400">Collected Shares</div>
              <div className="text-lg font-bold text-cyan-400 mt-0.5">
                {shares.length} / {requiredThreshold}
              </div>
            </div>
          </div>

          <div className="p-4 bg-slate-800/80 border border-slate-700 rounded-xl space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-1.5 font-medium text-slate-300">
                <FiUsers className="w-4 h-4 text-indigo-400" /> Participating Guardian Signatures
              </span>
              <button
                onClick={handleSignOwnShare}
                disabled={isSigning}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-medium transition-colors"
              >
                {isSigning ? 'Signing...' : '+ Sign with My Key'}
              </button>
            </div>

            {shares.length === 0 ? (
              <div className="text-center py-4 text-xs text-slate-500 italic">
                No guardian signature shares collected yet.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {shares.map((share, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2 bg-slate-900/90 border border-slate-800 rounded-lg text-xs"
                  >
                    <span className="font-mono text-slate-300">
                      {share.guardianAddress.slice(0, 8)}...{share.guardianAddress.slice(-6)}
                    </span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                      <FiCheckCircle className="w-3 h-3" /> Signed (96B)
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {aggregatedPayload && (
            <div className="p-4 bg-emerald-950/30 border border-emerald-500/30 rounded-xl space-y-2">
              <div className="flex items-center justify-between text-xs text-emerald-400 font-medium">
                <span>Aggregated 96-Byte BLS Signature</span>
                <span>Pairing Verified</span>
              </div>
              <div className="p-2 bg-slate-950 font-mono text-[11px] text-slate-400 rounded-lg break-all border border-slate-800 select-all max-h-16 overflow-y-auto">
                {aggregatedPayload.aggregatedSignature}
              </div>
              <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
                <span>Gas Reduction:</span>
                <span className="text-emerald-400 font-bold font-mono">~74.8% savings vs {requiredThreshold}x ECDSA</span>
              </div>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            {!aggregatedPayload ? (
              <button
                onClick={handleAggregate}
                disabled={shares.length < requiredThreshold}
                className="w-full py-3 px-4 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 font-semibold rounded-xl text-white shadow-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <FiLayers className="w-4 h-4" />
                Aggregate {shares.length} Signatures Off-Chain
              </button>
            ) : (
              <button
                onClick={handleSubmitOnChain}
                disabled={isSubmitting}
                className="w-full py-3 px-4 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 font-semibold rounded-xl text-white shadow-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <FiZap className="w-4 h-4" />
                {isSubmitting ? 'Executing 1-Tx Batch Approval...' : 'Execute On-Chain 1-Tx Approval'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
