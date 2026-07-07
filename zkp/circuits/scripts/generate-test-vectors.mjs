import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createInvalidWrongCredentialRootInput,
  createInvalidWrongNullifierInput,
  deriveCircuitValues,
} from "./test-vector-lib.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorDir = resolve(packageRoot, "test-vectors");

const writeJson = (path, value) => {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
};

mkdirSync(vectorDir, { recursive: true });

const valid = await deriveCircuitValues();
writeJson(
  resolve(vectorDir, "credential_commitment_vote.valid.input.json"),
  valid.input,
);
writeJson(
  resolve(vectorDir, "credential_commitment_vote.valid.public.json"),
  valid.publicSignals,
);
writeJson(
  resolve(vectorDir, "credential_commitment_vote.valid.public.named.json"),
  valid.publicSignalsByName,
);
writeJson(
  resolve(vectorDir, "credential_commitment_vote.invalid_wrong_nullifier.input.json"),
  createInvalidWrongNullifierInput(valid.input),
);
writeJson(
  resolve(
    vectorDir,
    "credential_commitment_vote.invalid_wrong_credential_root.input.json",
  ),
  createInvalidWrongCredentialRootInput(valid.input),
);
writeJson(resolve(vectorDir, "credential_commitment_vote.summary.json"), {
  ...valid.metadata,
  credentialCommitment: valid.credentialCommitment,
  validInput: "credential_commitment_vote.valid.input.json",
  validPublicSignals: "credential_commitment_vote.valid.public.json",
  validPublicSignalsByName: "credential_commitment_vote.valid.public.named.json",
  invalidVectors: [
    {
      name: "wrong_nullifier",
      input: "credential_commitment_vote.invalid_wrong_nullifier.input.json",
      expected: "witness_generation_fails",
    },
    {
      name: "wrong_credential_root",
      input: "credential_commitment_vote.invalid_wrong_credential_root.input.json",
      expected: "witness_generation_fails",
    },
  ],
});

console.log(`Wrote CredentialCommitmentVote vectors to ${vectorDir}`);
