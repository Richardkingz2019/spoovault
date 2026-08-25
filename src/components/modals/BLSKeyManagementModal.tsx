import React, { useState } from 'react';
import { useWeb3 } from '../../context/Web3Context';
import { blsKeyringService } from '../../services/blsKeyring.service';
import { toast } from 'react-hot-toast';
import { FiKey, FiShield, FiCheckCircle, FiDownload, FiZap, FiX } from 'react-icons/fi';

interface BLSKeyManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
  vaultId?: number;
}

export const BLSKeyManagementModal: React.FC<BLSKeyManagementModalProps> = ({
  isOpen,
  onClose,
  vaultId
}) => {
  const { account, blsKeyPair, generateBLSKey, registerBLSKeyForVault } = useWeb3();
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [backupPassword, setBackupPassword] = useState('');
  const [showBackupPrompt, setShowBackupPrompt] = useState(false);

  if (!isOpen) return null;

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      await generateBLSKey();
    } catch (err: any) {
      toast.error(err.message || 'Failed to generate BLS key');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRegister = async () => {
    if (!vaultId) {
      toast.error('No vault specified for registration');
      return;
    }
    setIsRegistering(true);
    try {
      await registerBLSKeyForVault(vaultId);
    } catch (err: any) {
      toast.error(err.message || 'Failed to register BLS key on-chain');
    } finally {
      setIsRegistering(false);
    }
  };

  const handleExportBackup = async () => {
    if (!account || !blsKeyPair) return;
    if (!backupPassword) {
      toast.error('Please enter a password to encrypt your backup');
      return;
    }
    try {
      const backup = await blsKeyringService.exportEncryptedBackup(account, backupPassword);
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(backup, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `spoovault-bls-backup-${account.slice(0, 8)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      toast.success('BLS key backup downloaded successfully');
      setShowBackupPrompt(false);
      setBackupPassword('');
    } catch (err: any) {
      toast.error(err.message || 'Failed to export BLS backup');
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
          <div className="p-3 bg-indigo-500/20 text-indigo-400 rounded-xl border border-indigo-500/30">
            <FiShield className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              BLS12-381 Guardian Keyring
              <span className="px-2 py-0.5 text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full font-mono">
                &gt;70% Gas Savings
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Aggregated threshold signature support for multi-chain guardian approvals
            </p>
          </div>
        </div>

        {blsKeyPair ? (
          <div className="space-y-4">
            <div className="p-4 bg-slate-800/80 border border-slate-700 rounded-xl space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>G1 Compressed Public Key (48 Bytes)</span>
                <span className="flex items-center gap-1 text-emerald-400 font-medium">
                  <FiCheckCircle className="w-3.5 h-3.5" /> PoP Verified
                </span>
              </div>
              <div className="p-2.5 bg-slate-950 font-mono text-xs text-indigo-300 rounded-lg break-all border border-slate-800 select-all">
                {blsKeyPair.publicKey}
              </div>

              <div className="text-xs text-slate-400 pt-1">
                <span>Proof of Possession Signature (96 Bytes)</span>
              </div>
              <div className="p-2.5 bg-slate-950 font-mono text-xs text-slate-400 rounded-lg break-all border border-slate-800 select-all max-h-20 overflow-y-auto">
                {blsKeyPair.proofOfPossession}
              </div>
            </div>

            <div className="flex gap-3">
              {vaultId && (
                <button
                  onClick={handleRegister}
                  disabled={isRegistering}
                  className="flex-1 py-3 px-4 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 font-semibold rounded-xl text-white shadow-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <FiZap className="w-4 h-4" />
                  {isRegistering ? 'Registering On-Chain...' : `Register for Vault #${vaultId}`}
                </button>
              )}
              <button
                onClick={() => setShowBackupPrompt(!showBackupPrompt)}
                className="py-3 px-4 bg-slate-800 hover:bg-slate-700 border border-slate-700 font-medium rounded-xl text-slate-200 transition-all flex items-center gap-2"
              >
                <FiDownload className="w-4 h-4" />
                Backup Key
              </button>
            </div>

            {showBackupPrompt && (
              <div className="p-4 bg-slate-800/90 border border-indigo-500/30 rounded-xl space-y-3 mt-3">
                <label className="block text-xs font-medium text-slate-300">
                  Enter Password to Encrypt Backup (AES-GCM-256)
                </label>
                <input
                  type="password"
                  value={backupPassword}
                  onChange={(e) => setBackupPassword(e.target.value)}
                  placeholder="Strong backup passphrase"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
                <button
                  onClick={handleExportBackup}
                  className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-500 font-medium rounded-lg text-white text-xs transition-all"
                >
                  Download Encrypted JSON
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-8 space-y-4">
            <div className="w-16 h-16 bg-indigo-500/10 border border-indigo-500/30 rounded-2xl flex items-center justify-center mx-auto text-indigo-400">
              <FiKey className="w-8 h-8" />
            </div>
            <div>
              <h4 className="font-semibold text-lg text-white">No BLS Keypair Found</h4>
              <p className="text-sm text-slate-400 max-w-sm mx-auto mt-1">
                Generate a BLS12-381 keypair with Proof of Possession to enable 1-transaction threshold approvals.
              </p>
            </div>
            <button
              onClick={handleGenerate}
              disabled={isGenerating}
              className="py-3 px-6 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 font-semibold rounded-xl text-white shadow-lg transition-all inline-flex items-center gap-2 disabled:opacity-50"
            >
              <FiKey className="w-4 h-4" />
              {isGenerating ? 'Generating BLS Key...' : 'Generate BLS12-381 Keypair'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
