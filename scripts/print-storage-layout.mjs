// @ts-check
/**
 * Prints the solc-computed storage layout (slot/offset/bytes per state
 * variable) for a contract, read from the most recent Hardhat build-info
 * artifact. Requires `outputSelection: { "*": { "*": ["storageLayout"] } }`
 * in hardhat.config.cjs (already configured) and a prior `npx hardhat
 * compile`.
 *
 * Usage: node scripts/print-storage-layout.mjs [ContractName] [source/path.sol]
 * Defaults to SpooVault / contracts/SpooVault.sol.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const ROOT = process.cwd();
const BUILD_INFO_DIR = path.join(ROOT, "artifacts", "build-info");

const contractName = process.argv[2] || "SpooVault";
const sourcePath = process.argv[3] || "contracts/SpooVault.sol";

const buildInfoFiles = fs
  .readdirSync(BUILD_INFO_DIR)
  .filter((f) => f.endsWith(".json"))
  .map((f) => {
    const full = path.join(BUILD_INFO_DIR, f);
    return { full, mtime: fs.statSync(full).mtimeMs };
  })
  .sort((a, b) => b.mtime - a.mtime);

if (buildInfoFiles.length === 0) {
  console.error("No build-info artifacts found. Run `npx hardhat compile` first.");
  process.exit(1);
}

let layout = null;
for (const { full } of buildInfoFiles) {
  const data = JSON.parse(fs.readFileSync(full, "utf8"));
  const contract = data.output?.contracts?.[sourcePath]?.[contractName];
  if (contract?.storageLayout) {
    layout = contract.storageLayout;
    break;
  }
}

if (!layout) {
  console.error(
    `No storageLayout found for ${contractName} (${sourcePath}) in any build-info artifact. ` +
      "Ensure outputSelection includes storageLayout and recompile."
  );
  process.exit(1);
}

const typeInfo = layout.types || {};
const rows = layout.storage.map((entry) => {
  const t = typeInfo[entry.type];
  return {
    slot: entry.slot,
    offset: entry.offset,
    bytes: t?.numberOfBytes ?? "?",
    label: entry.label,
    type: t?.label ?? entry.type,
  };
});

console.log(`Storage layout: ${contractName} (${sourcePath})\n`);
console.log("slot".padEnd(6) + "offset".padEnd(8) + "bytes".padEnd(7) + "label".padEnd(24) + "type");
console.log("-".repeat(90));
for (const r of rows) {
  console.log(
    String(r.slot).padEnd(6) + String(r.offset).padEnd(8) + String(r.bytes).padEnd(7) + r.label.padEnd(24) + r.type
  );
}

const slotCount = new Set(rows.map((r) => r.slot)).size;
console.log(`\n${rows.length} state variable(s) across ${slotCount} top-level slot(s).`);

// Top-level slots are mostly mapping bases, which say little about actual
// packing. The interesting verification is per-struct: how each struct
// TYPE's own fields are laid out across ITS instance's slots.
const structTypeKeys = Object.keys(typeInfo).filter((k) => k.startsWith("t_struct(") && k.endsWith("_storage"));
console.log(`\nStruct field packing (${structTypeKeys.length} struct type(s) referenced):\n`);
for (const key of structTypeKeys) {
  const t = typeInfo[key];
  if (!t.members) continue;
  const structName = key.match(/^t_struct\(([^)]+)\)/)?.[1] ?? key;
  const totalBytes = t.numberOfBytes;
  const totalSlots = Math.ceil(totalBytes / 32);
  console.log(`${structName} — ${totalBytes} bytes (${totalSlots} slot${totalSlots === 1 ? "" : "s"})`);
  for (const m of t.members) {
    const memberType = typeInfo[m.type];
    console.log(
      `  slot ${m.slot}  offset ${String(m.offset).padStart(2)}  ${String(memberType?.numberOfBytes ?? "?").padStart(
        2
      )}B  ${m.label.padEnd(20)} ${memberType?.label ?? m.type}`
    );
  }
  console.log("");
}
