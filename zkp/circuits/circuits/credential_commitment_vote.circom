pragma circom 2.1.6;

include "poseidon.circom";
include "comparators.circom";

template AssertBoolean() {
    signal input in;
    in * (in - 1) === 0;
}

template CredentialCommitmentVote(depth) {
    var ENCRYPTED_VOTE_TAG = 1001;

    // Public poll/proof binding inputs.
    signal input pollId;
    signal input pollPolicyHash;
    signal input credentialSchemaHash;
    signal input optionSetHash;
    signal input optionCount;
    signal input credentialRoot;
    signal input nullifier;
    signal input voteCommitment;
    signal input encryptedVoteCommitment;

    // Private witness material.
    signal input identitySecret;
    signal input identityKeyHash;
    signal input claimsHash;
    signal input optionIndex;
    signal input optionIndexBits[3];
    signal input encryptedVoteRandomness;
    signal input voteRandomness;
    signal input credentialRootSiblings[depth];
    signal input credentialRootPathIndices[depth];

    component optionIndexBitIsBoolean[3];
    component optionCountAtLeastOne = GreaterEqThan(4);
    component optionCountAtMostMax = LessEqThan(4);
    component optionIndexWithinOptions = LessThan(4);

    optionIndexBitIsBoolean[0] = AssertBoolean();
    optionIndexBitIsBoolean[1] = AssertBoolean();
    optionIndexBitIsBoolean[2] = AssertBoolean();
    optionIndexBitIsBoolean[0].in <== optionIndexBits[0];
    optionIndexBitIsBoolean[1].in <== optionIndexBits[1];
    optionIndexBitIsBoolean[2].in <== optionIndexBits[2];

    optionIndex === optionIndexBits[0] + 2 * optionIndexBits[1] + 4 * optionIndexBits[2];
    optionCountAtLeastOne.in[0] <== optionCount;
    optionCountAtLeastOne.in[1] <== 1;
    optionCountAtLeastOne.out === 1;
    optionCountAtMostMax.in[0] <== optionCount;
    optionCountAtMostMax.in[1] <== 8;
    optionCountAtMostMax.out === 1;
    optionIndexWithinOptions.in[0] <== optionIndex;
    optionIndexWithinOptions.in[1] <== optionCount;
    optionIndexWithinOptions.out === 1;

    component credentialCommitmentHasher = Poseidon(4);
    credentialCommitmentHasher.inputs[0] <== identitySecret;
    credentialCommitmentHasher.inputs[1] <== identityKeyHash;
    credentialCommitmentHasher.inputs[2] <== credentialSchemaHash;
    credentialCommitmentHasher.inputs[3] <== claimsHash;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== pollId;
    nullifierHasher.inputs[2] <== pollPolicyHash;
    nullifierHasher.out === nullifier;

    component encryptedVoteHasher = Poseidon(4);
    encryptedVoteHasher.inputs[0] <== ENCRYPTED_VOTE_TAG;
    encryptedVoteHasher.inputs[1] <== optionIndex;
    encryptedVoteHasher.inputs[2] <== encryptedVoteRandomness;
    encryptedVoteHasher.inputs[3] <== optionSetHash;
    encryptedVoteHasher.out === encryptedVoteCommitment;

    component voteCommitmentHasher = Poseidon(4);
    voteCommitmentHasher.inputs[0] <== nullifier;
    voteCommitmentHasher.inputs[1] <== encryptedVoteCommitment;
    voteCommitmentHasher.inputs[2] <== optionSetHash;
    voteCommitmentHasher.inputs[3] <== voteRandomness;
    voteCommitmentHasher.out === voteCommitment;

    signal current[depth + 1];
    signal left[depth];
    signal right[depth];

    current[0] <== credentialCommitmentHasher.out;

    component pathIndexIsBoolean[depth];
    component merkleHasher[depth];
    for (var i = 0; i < depth; i++) {
        pathIndexIsBoolean[i] = AssertBoolean();
        pathIndexIsBoolean[i].in <== credentialRootPathIndices[i];

        left[i] <== current[i] +
            credentialRootPathIndices[i] * (credentialRootSiblings[i] - current[i]);
        right[i] <== credentialRootSiblings[i] +
            credentialRootPathIndices[i] * (current[i] - credentialRootSiblings[i]);

        merkleHasher[i] = Poseidon(2);
        merkleHasher[i].inputs[0] <== left[i];
        merkleHasher[i].inputs[1] <== right[i];
        current[i + 1] <== merkleHasher[i].out;
    }

    current[depth] === credentialRoot;
}

component main {
    public [
        pollId,
        pollPolicyHash,
        credentialSchemaHash,
        optionSetHash,
        optionCount,
        credentialRoot,
        nullifier,
        voteCommitment,
        encryptedVoteCommitment
    ]
} = CredentialCommitmentVote(32);
