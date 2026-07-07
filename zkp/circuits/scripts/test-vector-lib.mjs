import { buildPoseidon } from "circomlibjs";

export const CIRCUIT_ID = "civicos-groth16-vote-circuit-v1";
export const PUBLIC_INPUT_SCHEMA_VERSION =
  "civicos-groth16-vote-public-inputs-v1";
export const HASH_SUITE = "poseidon-bn254-v1";
export const MERKLE_DEPTH = 4;

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

export const createBaseWitness = () => ({
  pollId: "101",
  pollPolicyHash: "202",
  credentialSchemaHash: "303",
  optionSetHash: "404",
  encryptedVoteHash: "505",
  identitySecret: "7001",
  credentialSalt: "7002",
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
  const voteCommitment = poseidonHash([
    nullifier,
    witness.encryptedVoteHash,
    witness.optionSetHash,
    witness.voteRandomness,
  ]);

  const input = {
    ...witness,
    credentialRoot,
    nullifier,
    voteCommitment,
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
