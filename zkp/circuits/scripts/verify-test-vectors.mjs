import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

import {
  createInvalidOutOfRangeOptionInput,
  createInvalidTallyCommitmentMismatchInput,
  createInvalidTallyOutOfRangeOptionInput,
  createInvalidWrongCredentialRootInput,
  createInvalidWrongNullifierInput,
  deriveCircuitValues,
  deriveTallyCircuitValues,
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
assert.deepEqual(
  readJson(
    resolve(
      vectorDir,
      "credential_commitment_vote.invalid_out_of_range_option.input.json",
    ),
  ),
  createInvalidOutOfRangeOptionInput(expected.input),
  "invalid out-of-range option vector drifted",
);

console.log("CredentialCommitmentVote test vectors verified.");

const expectedTally = await deriveTallyCircuitValues();

assert.deepEqual(
  readJson(resolve(vectorDir, "encrypted_choice_tally.valid.input.json")),
  expectedTally.input,
  "valid tally circuit input vector drifted",
);
assert.deepEqual(
  readJson(resolve(vectorDir, "encrypted_choice_tally.valid.public.json")),
  expectedTally.publicSignals,
  "valid tally public signal vector drifted",
);
assert.deepEqual(
  readJson(resolve(vectorDir, "encrypted_choice_tally.valid.public.named.json")),
  expectedTally.publicSignalsByName,
  "named tally public signal vector drifted",
);
assert.deepEqual(
  readJson(
    resolve(
      vectorDir,
      "encrypted_choice_tally.invalid_out_of_range_option.input.json",
    ),
  ),
  createInvalidTallyOutOfRangeOptionInput(expectedTally.input),
  "invalid tally out-of-range option vector drifted",
);
assert.deepEqual(
  readJson(
    resolve(
      vectorDir,
      "encrypted_choice_tally.invalid_encrypted_vote_commitment_mismatch.input.json",
    ),
  ),
  createInvalidTallyCommitmentMismatchInput(expectedTally.input),
  "invalid tally encrypted vote commitment vector drifted",
);

console.log("EncryptedChoiceTally test vectors verified.");
