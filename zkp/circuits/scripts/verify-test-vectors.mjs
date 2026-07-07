import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

import {
  createInvalidWrongCredentialRootInput,
  createInvalidWrongNullifierInput,
  deriveCircuitValues,
} from "./test-vector-lib.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorDir = resolve(packageRoot, "test-vectors");

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

const expected = await deriveCircuitValues();

assert.deepEqual(
  readJson(resolve(vectorDir, "credential_commitment_vote.valid.input.json")),
  expected.input,
  "valid circuit input vector drifted",
);
assert.deepEqual(
  readJson(resolve(vectorDir, "credential_commitment_vote.valid.public.json")),
  expected.publicSignals,
  "valid public signal vector drifted",
);
assert.deepEqual(
  readJson(resolve(vectorDir, "credential_commitment_vote.valid.public.named.json")),
  expected.publicSignalsByName,
  "named public signal vector drifted",
);
assert.deepEqual(
  readJson(
    resolve(
      vectorDir,
      "credential_commitment_vote.invalid_wrong_nullifier.input.json",
    ),
  ),
  createInvalidWrongNullifierInput(expected.input),
  "invalid nullifier vector drifted",
);
assert.deepEqual(
  readJson(
    resolve(
      vectorDir,
      "credential_commitment_vote.invalid_wrong_credential_root.input.json",
    ),
  ),
  createInvalidWrongCredentialRootInput(expected.input),
  "invalid credential-root vector drifted",
);

console.log("CredentialCommitmentVote test vectors verified.");
