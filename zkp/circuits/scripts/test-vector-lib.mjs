import { buildPoseidon } from "circomlibjs";

export const CIRCUIT_ID = "civicos-groth16-vote-circuit-v1";
export const TALLY_CIRCUIT_ID = "civicos-groth16-tally-circuit-v1";
export const PUBLIC_INPUT_SCHEMA_VERSION =
  "civicos-groth16-vote-public-inputs-v1";
export const TALLY_PUBLIC_INPUT_SCHEMA_VERSION =
  "civicos-groth16-tally-public-inputs-v1";
export const HASH_SUITE = "poseidon-bn254-v1";
export const MERKLE_DEPTH = 4;
export const TALLY_MAX_VOTES = 1;
export const TALLY_MAX_OPTIONS = 2;

const ENCRYPTED_VOTE_TAG = "1001";
const NULLIFIER_LEAF_TAG = "1101";
const VOTE_COMMITMENT_LEAF_TAG = "1102";
const ENCRYPTED_VOTE_LEAF_TAG = "1103";
const OPTION_COUNTS_TAG = "1201";

const toDecimalString = (value) => BigInt(value).toString(10);

export const PUBLIC_SIGNAL_NAMES = Object.freeze([
  "pollId",
  "pollPolicyHash",
  "credentialSchemaHash",
  "optionSetHash",
  "credentialRoot",
  "nullifier",
  "voteCommitment",
  "encryptedVoteHash",
]);

export const TALLY_PUBLIC_SIGNAL_NAMES = Object.freeze([
  "pollId",
  "pollPolicyHash",
  "credentialSchemaHash",
  "optionSetHash",
  "nullifierRoot",
  "voteCommitmentRoot",
  "encryptedVoteRoot",
  "acceptedVoteCount",
  "optionCountsHash",
]);

export const createBaseWitness = () => ({
  pollId: "101",
  pollPolicyHash: "202",
  credentialSchemaHash: "303",
  optionSetHash: "404",
  identitySecret: "7001",
  credentialSalt: "7002",
  optionIndex: "1",
  optionIndexBits: ["1", "0"],
  encryptedVoteRandomness: "7004",
  voteRandomness: "7003",
  documentValid: "1",
  livenessPassed: "1",
  faceMatchedDocument: "1",
  ageEligible: "1",
  countryEligible: "1",
  homeAreaEligible: "1",
  landEligible: "1",
  credentialRootSiblings: ["9001", "9002", "9003", "9004"],
  credentialRootPathIndices: ["0", "1", "0", "1"],
});

export const createPoseidonContext = async () => {
  const poseidon = await buildPoseidon();
  const poseidonHash = (inputs) =>
    poseidon.F.toString(poseidon(inputs.map((input) => BigInt(input))));

  return { poseidonHash };
};

export const deriveCredentialCommitment = ({ poseidonHash, witness }) =>
  poseidonHash([
    witness.identitySecret,
    witness.credentialSchemaHash,
    witness.credentialSalt,
    witness.documentValid,
    witness.livenessPassed,
    witness.faceMatchedDocument,
    witness.ageEligible,
    witness.countryEligible,
    witness.homeAreaEligible,
    witness.landEligible,
  ]);

export const deriveMerkleRoot = ({ poseidonHash, leaf, siblings, pathIndices }) =>
  siblings.reduce((current, sibling, index) => {
    const pathIndex = BigInt(pathIndices[index]);
    const left = pathIndex === 0n ? current : sibling;
    const right = pathIndex === 0n ? sibling : current;
    return poseidonHash([left, right]);
  }, leaf);

const deriveFixedPoseidonRoot = ({ poseidonHash, leaves }) => {
  if (leaves.length === 0) {
    return "0";
  }

  let level = leaves.map(toDecimalString);
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(poseidonHash([level[index], level[index + 1] ?? level[index]]));
    }
    level = next;
  }
  return level[0];
};

export const deriveCircuitValues = async (witness = createBaseWitness()) => {
  const { poseidonHash } = await createPoseidonContext();
  const credentialCommitment = deriveCredentialCommitment({
    poseidonHash,
    witness,
  });
  const credentialRoot = deriveMerkleRoot({
    poseidonHash,
    leaf: credentialCommitment,
    siblings: witness.credentialRootSiblings,
    pathIndices: witness.credentialRootPathIndices,
  });
  const nullifier = poseidonHash([
    witness.identitySecret,
    witness.pollId,
    witness.pollPolicyHash,
  ]);
  const encryptedVoteHash = poseidonHash([
    ENCRYPTED_VOTE_TAG,
    witness.optionIndex,
    witness.encryptedVoteRandomness,
    witness.optionSetHash,
  ]);
  const voteCommitment = poseidonHash([
    nullifier,
    encryptedVoteHash,
    witness.optionSetHash,
    witness.voteRandomness,
  ]);

  const input = {
    ...witness,
    credentialRoot,
    nullifier,
    voteCommitment,
    encryptedVoteHash,
  };

  const publicSignalsByName = {
    pollId: toDecimalString(input.pollId),
    pollPolicyHash: toDecimalString(input.pollPolicyHash),
    credentialSchemaHash: toDecimalString(input.credentialSchemaHash),
    optionSetHash: toDecimalString(input.optionSetHash),
    credentialRoot: toDecimalString(input.credentialRoot),
    nullifier: toDecimalString(input.nullifier),
    voteCommitment: toDecimalString(input.voteCommitment),
    encryptedVoteHash: toDecimalString(input.encryptedVoteHash),
  };

  return {
    metadata: {
      circuitId: CIRCUIT_ID,
      publicInputSchemaVersion: PUBLIC_INPUT_SCHEMA_VERSION,
      hashSuite: HASH_SUITE,
      merkleDepth: MERKLE_DEPTH,
      publicSignalNames: PUBLIC_SIGNAL_NAMES,
    },
    credentialCommitment,
    input,
    publicSignalsByName,
    publicSignals: PUBLIC_SIGNAL_NAMES.map((name) => publicSignalsByName[name]),
  };
};

export const createInvalidWrongNullifierInput = (validInput) => ({
  ...validInput,
  nullifier: (BigInt(validInput.nullifier) + 1n).toString(10),
});

export const createInvalidWrongCredentialRootInput = (validInput) => ({
  ...validInput,
  credentialRoot: (BigInt(validInput.credentialRoot) + 1n).toString(10),
});

export const createBaseTallyWitness = () => ({
  pollId: "101",
  pollPolicyHash: "202",
  credentialSchemaHash: "303",
  optionSetHash: "404",
  isActive: ["1"],
  nullifiers: ["2101"],
  encryptedVoteRandomness: ["3101"],
  voteRandomness: ["4101"],
  optionSelections: [
    ["0", "1"],
  ],
});

const selectedOptionIndex = (selection) =>
  selection.reduce(
    (selected, value, index) => selected + Number(BigInt(value)) * index,
    0,
  );

export const deriveTallyCircuitValues = async (
  witness = createBaseTallyWitness(),
) => {
  const { poseidonHash } = await createPoseidonContext();

  const acceptedVoteCount = witness.isActive.reduce(
    (total, value) => total + Number(BigInt(value)),
    0,
  );
  const optionCounts = Array.from({ length: TALLY_MAX_OPTIONS }, (_, optionIndex) =>
    witness.optionSelections
      .reduce((total, selection) => total + Number(BigInt(selection[optionIndex])), 0)
      .toString(10),
  );

  const encryptedVoteHashes = witness.isActive.map((active, index) => {
    if (BigInt(active) === 0n) {
      return "0";
    }
    return poseidonHash([
      ENCRYPTED_VOTE_TAG,
      selectedOptionIndex(witness.optionSelections[index]).toString(10),
      witness.encryptedVoteRandomness[index],
      witness.optionSetHash,
    ]);
  });

  const voteCommitments = encryptedVoteHashes.map((encryptedVoteHash, index) =>
    poseidonHash([
      witness.nullifiers[index],
      encryptedVoteHash,
      witness.optionSetHash,
      witness.voteRandomness[index],
    ]),
  );

  const nullifierLeaves = witness.nullifiers.map((nullifier, index) =>
    BigInt(witness.isActive[index]) === 0n
      ? "0"
      : poseidonHash([NULLIFIER_LEAF_TAG, nullifier]),
  );
  const voteCommitmentLeaves = voteCommitments.map((voteCommitment, index) =>
    BigInt(witness.isActive[index]) === 0n
      ? "0"
      : poseidonHash([VOTE_COMMITMENT_LEAF_TAG, voteCommitment]),
  );
  const encryptedVoteLeaves = encryptedVoteHashes.map((encryptedVoteHash, index) =>
    BigInt(witness.isActive[index]) === 0n
      ? "0"
      : poseidonHash([ENCRYPTED_VOTE_LEAF_TAG, encryptedVoteHash]),
  );

  const nullifierRoot = deriveFixedPoseidonRoot({
    poseidonHash,
    leaves: nullifierLeaves,
  });
  const voteCommitmentRoot = deriveFixedPoseidonRoot({
    poseidonHash,
    leaves: voteCommitmentLeaves,
  });
  const encryptedVoteRoot = deriveFixedPoseidonRoot({
    poseidonHash,
    leaves: encryptedVoteLeaves,
  });
  const optionCountsHash = poseidonHash([OPTION_COUNTS_TAG, ...optionCounts]);

  const input = {
    ...witness,
    encryptedVoteHashes,
    optionCounts,
    nullifierRoot,
    voteCommitmentRoot,
    encryptedVoteRoot,
    acceptedVoteCount: acceptedVoteCount.toString(10),
    optionCountsHash,
  };

  const publicSignalsByName = {
    pollId: toDecimalString(input.pollId),
    pollPolicyHash: toDecimalString(input.pollPolicyHash),
    credentialSchemaHash: toDecimalString(input.credentialSchemaHash),
    optionSetHash: toDecimalString(input.optionSetHash),
    nullifierRoot: toDecimalString(input.nullifierRoot),
    voteCommitmentRoot: toDecimalString(input.voteCommitmentRoot),
    encryptedVoteRoot: toDecimalString(input.encryptedVoteRoot),
    acceptedVoteCount: toDecimalString(input.acceptedVoteCount),
    optionCountsHash: toDecimalString(input.optionCountsHash),
  };

  return {
    metadata: {
      circuitId: TALLY_CIRCUIT_ID,
      publicInputSchemaVersion: TALLY_PUBLIC_INPUT_SCHEMA_VERSION,
      hashSuite: HASH_SUITE,
      maxVotes: TALLY_MAX_VOTES,
      maxOptions: TALLY_MAX_OPTIONS,
      publicSignalNames: TALLY_PUBLIC_SIGNAL_NAMES,
    },
    encryptedVoteHashes,
    voteCommitments,
    nullifierLeaves,
    voteCommitmentLeaves,
    encryptedVoteLeaves,
    input,
    publicSignalsByName,
    publicSignals: TALLY_PUBLIC_SIGNAL_NAMES.map(
      (name) => publicSignalsByName[name],
    ),
  };
};
