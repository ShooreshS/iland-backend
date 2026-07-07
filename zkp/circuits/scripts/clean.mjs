import { rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

rmSync(resolve(packageRoot, "build"), { recursive: true, force: true });
for (const file of [
  "credential_commitment_vote.valid.proof.json",
  "credential_commitment_vote.valid.public.proof.json",
]) {
  rmSync(resolve(packageRoot, "test-vectors", file), {
    recursive: false,
    force: true,
  });
}

console.log("Removed local circuit build/proof outputs.");
