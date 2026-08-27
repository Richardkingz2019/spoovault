/**
 * Seed-phrase entry + checksum verification UI for the master keyring
 * (issue #155).
 *
 * - MnemonicBackupView: displays a freshly exported 24-word mnemonic (and
 *   optional SLIP-0039 shares) for the user to write down.
 * - MnemonicRecoveryForm: interactive 24-word entry with per-word wordlist
 *   feedback and live BIP-39 checksum validation; only a fully valid phrase
 *   enables recovery.
 */

import React, { useMemo, useState } from "react";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import {
  validateMnemonic,
  normalizeMnemonic,
  mnemonicToKeyPair,
} from "../../services/mnemonicKeyring.service";

const WORD_COUNT = 24;
const WORD_SET = new Set(wordlist);

// ─── Backup display ─────────────────────────────────────────────────────────

export interface MnemonicBackupViewProps {
  mnemonic: string;
  shares?: string[];
}

export const MnemonicBackupView: React.FC<MnemonicBackupViewProps> = ({ mnemonic, shares }) => {
  const words = normalizeMnemonic(mnemonic).split(" ");
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">
        Write these {words.length} words down in order and store them offline. Anyone with this
        phrase controls the master key.
      </p>
      <ol className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {words.map((word, i) => (
          <li
            key={`${i}-${word}`}
            className="flex items-center gap-2 rounded bg-slate-800 px-3 py-2 text-sm"
          >
            <span className="w-6 text-right text-slate-500">{i + 1}.</span>
            <span className="font-mono">{word}</span>
          </li>
        ))}
      </ol>
      {shares && shares.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm text-slate-400">
            SLIP-0039 recovery shares (any 3 of {shares.length} restore the key — store each with
            a different guardian):
          </p>
          {shares.map((share, i) => (
            <div key={i} className="rounded bg-slate-800 px-3 py-2 font-mono text-xs break-words">
              <span className="mr-2 text-slate-500">Share {i + 1}:</span>
              {share}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Interactive entry + checksum verification ──────────────────────────────

export interface MnemonicRecoveryFormProps {
  onRecovered: (keyPair: { publicKey: string; privateKey: string }) => void;
  onError?: (message: string) => void;
}

export const MnemonicRecoveryForm: React.FC<MnemonicRecoveryFormProps> = ({
  onRecovered,
  onError,
}) => {
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState(false);

  const words = useMemo(
    () => (phrase.trim() ? normalizeMnemonic(phrase).split(" ") : []),
    [phrase]
  );
  const unknownWords = useMemo(() => words.filter((w) => !WORD_SET.has(w)), [words]);
  const complete = words.length === WORD_COUNT;
  const checksumOk = complete && unknownWords.length === 0 && validateMnemonic(phrase);

  const status = !phrase.trim()
    ? { tone: "text-slate-500", message: `Enter your ${WORD_COUNT}-word recovery phrase.` }
    : unknownWords.length > 0
      ? {
          tone: "text-rose-500",
          message: `Not in the BIP-39 wordlist: ${unknownWords.slice(0, 3).join(", ")}${
            unknownWords.length > 3 ? "…" : ""
          }`,
        }
      : !complete
        ? { tone: "text-amber-500", message: `${words.length}/${WORD_COUNT} words entered.` }
        : checksumOk
          ? { tone: "text-emerald-500", message: "Checksum valid — phrase verified." }
          : {
              tone: "text-rose-500",
              message: "Checksum failed — a word is wrong or out of order.",
            };

  const handleRecover = async () => {
    if (!checksumOk || busy) return;
    setBusy(true);
    try {
      onRecovered(await mnemonicToKeyPair(phrase));
    } catch (err) {
      onError?.(err instanceof Error ? err.message : "Recovery failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <textarea
        value={phrase}
        onChange={(e) => setPhrase(e.target.value)}
        rows={3}
        spellCheck={false}
        autoComplete="off"
        placeholder="witch collapse practice feed shame open despair creek road again ice least …"
        className="w-full rounded border border-slate-700 bg-slate-900 p-3 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500"
        aria-label="Recovery phrase"
      />
      <p className={`text-sm ${status.tone}`} role="status">
        {status.message}
      </p>
      <button
        type="button"
        onClick={handleRecover}
        disabled={!checksumOk || busy}
        className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-40 hover:bg-emerald-500"
      >
        {busy ? "Recovering…" : "Recover master key"}
      </button>
    </div>
  );
};
