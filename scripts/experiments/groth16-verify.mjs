import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const snarkjsPath = resolve(scriptDir, "../../node_modules/.bin/snarkjs");

export const verifyGroth16WithPinnedCli = ({
  verificationKey,
  publicSignals,
  proof,
}) => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "civicos-experiment-verify-"));
  try {
    const verificationKeyPath = join(temporaryDirectory, "verification-key.json");
    const publicSignalsPath = join(temporaryDirectory, "public.json");
    const proofPath = join(temporaryDirectory, "proof.json");
    writeFileSync(verificationKeyPath, `${JSON.stringify(verificationKey)}\n`, { mode: 0o600 });
    writeFileSync(publicSignalsPath, `${JSON.stringify(publicSignals)}\n`, { mode: 0o600 });
    writeFileSync(proofPath, `${JSON.stringify(proof)}\n`, { mode: 0o600 });
    execFileSync(
      snarkjsPath,
      ["groth16", "verify", verificationKeyPath, publicSignalsPath, proofPath],
      { stdio: "ignore", timeout: 30_000 },
    );
    return { accepted: true, errorClass: null };
  } catch (error) {
    return {
      accepted: false,
      errorClass: error?.code === "ETIMEDOUT" ? "VERIFY_TIMEOUT" : "VERIFIER_REJECTED",
    };
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
};

export default verifyGroth16WithPinnedCli;
