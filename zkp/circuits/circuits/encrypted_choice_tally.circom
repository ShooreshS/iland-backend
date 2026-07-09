pragma circom 2.1.6;

include "poseidon.circom";
include "comparators.circom";

template AssertBoolean() {
    signal input in;
    in * (in - 1) === 0;
}

template PoseidonFixedRoot64() {
    signal input leaves[64];
    signal output root;
    signal level1[32];
    signal level2[16];
    signal level3[8];
    signal level4[4];
    signal level5[2];
    component hash1[32];
    component hash2[16];
    component hash3[8];
    component hash4[4];
    component hash5[2];
    component hash6;

    for (var i = 0; i < 32; i++) {
        hash1[i] = Poseidon(2);
        hash1[i].inputs[0] <== leaves[i * 2];
        hash1[i].inputs[1] <== leaves[i * 2 + 1];
        level1[i] <== hash1[i].out;
    }

    for (var i = 0; i < 16; i++) {
        hash2[i] = Poseidon(2);
        hash2[i].inputs[0] <== level1[i * 2];
        hash2[i].inputs[1] <== level1[i * 2 + 1];
        level2[i] <== hash2[i].out;
    }

    for (var i = 0; i < 8; i++) {
        hash3[i] = Poseidon(2);
        hash3[i].inputs[0] <== level2[i * 2];
        hash3[i].inputs[1] <== level2[i * 2 + 1];
        level3[i] <== hash3[i].out;
    }

    for (var i = 0; i < 4; i++) {
        hash4[i] = Poseidon(2);
        hash4[i].inputs[0] <== level3[i * 2];
        hash4[i].inputs[1] <== level3[i * 2 + 1];
        level4[i] <== hash4[i].out;
    }

    for (var i = 0; i < 2; i++) {
        hash5[i] = Poseidon(2);
        hash5[i].inputs[0] <== level4[i * 2];
        hash5[i].inputs[1] <== level4[i * 2 + 1];
        level5[i] <== hash5[i].out;
    }

    hash6 = Poseidon(2);
    hash6.inputs[0] <== level5[0];
    hash6.inputs[1] <== level5[1];
    root <== hash6.out;
}

template EncryptedChoiceTally(maxVotes, maxOptions) {
    var ENCRYPTED_VOTE_TAG = 1001;
    var NULLIFIER_LEAF_TAG = 1101;
    var VOTE_COMMITMENT_LEAF_TAG = 1102;
    var ENCRYPTED_VOTE_LEAF_TAG = 1103;
    var OPTION_COUNTS_TAG = 1201;

    // Public poll/proof binding inputs.
    signal input pollId;
    signal input pollPolicyHash;
    signal input credentialSchemaHash;
    signal input optionSetHash;
    signal input optionCount;
    signal input nullifierRoot;
    signal input voteCommitmentRoot;
    signal input encryptedVoteRoot;
    signal input acceptedVoteCount;
    signal input optionCountsHash;

    // Private vote openings in accepted audit order, padded with inactive slots.
    signal input isActive[maxVotes];
    signal input nullifiers[maxVotes];
    signal input encryptedVoteCommitments[maxVotes];
    signal input encryptedVoteRandomness[maxVotes];
    signal input voteRandomness[maxVotes];
    signal input optionSelections[maxVotes][maxOptions];
    signal input optionCounts[maxOptions];

    component isActiveBoolean[maxVotes];
    component selectionBoolean[maxVotes][maxOptions];
    component encryptedVoteHasher[maxVotes];
    component voteCommitmentHasher[maxVotes];
    component nullifierLeafHasher[maxVotes];
    component voteCommitmentLeafHasher[maxVotes];
    component encryptedVoteLeafHasher[maxVotes];
    component optionCountAtLeastOne = GreaterEqThan(4);
    component optionCountAtMostMax = LessEqThan(4);
    component optionWithinCount[maxOptions];

    signal selectedOptionSums[maxVotes][maxOptions + 1];
    signal rowSelectionSums[maxVotes][maxOptions + 1];
    signal activeSum[maxVotes + 1];
    signal optionCountSums[maxOptions][maxVotes + 1];
    signal optionOutOfRange[maxOptions];
    signal nullifierLeaves[maxVotes];
    signal voteCommitmentLeaves[maxVotes];
    signal encryptedVoteLeaves[maxVotes];
    signal computedEncryptedVoteCommitment[maxVotes];
    signal computedVoteCommitment[maxVotes];

    optionCountAtLeastOne.in[0] <== optionCount;
    optionCountAtLeastOne.in[1] <== 1;
    optionCountAtLeastOne.out === 1;
    optionCountAtMostMax.in[0] <== optionCount;
    optionCountAtMostMax.in[1] <== maxOptions;
    optionCountAtMostMax.out === 1;

    activeSum[0] <== 0;
    for (var j = 0; j < maxOptions; j++) {
        optionWithinCount[j] = LessThan(4);
        optionWithinCount[j].in[0] <== j;
        optionWithinCount[j].in[1] <== optionCount;
        optionOutOfRange[j] <== 1 - optionWithinCount[j].out;
        optionCountSums[j][0] <== 0;
    }

    for (var i = 0; i < maxVotes; i++) {
        isActiveBoolean[i] = AssertBoolean();
        isActiveBoolean[i].in <== isActive[i];

        selectedOptionSums[i][0] <== 0;
        rowSelectionSums[i][0] <== 0;

        for (var j = 0; j < maxOptions; j++) {
            selectionBoolean[i][j] = AssertBoolean();
            selectionBoolean[i][j].in <== optionSelections[i][j];
            optionSelections[i][j] * optionOutOfRange[j] === 0;
            selectedOptionSums[i][j + 1] <==
                selectedOptionSums[i][j] + optionSelections[i][j] * j;
            rowSelectionSums[i][j + 1] <==
                rowSelectionSums[i][j] + optionSelections[i][j];
            optionCountSums[j][i + 1] <== optionCountSums[j][i] + optionSelections[i][j];
        }
        rowSelectionSums[i][maxOptions] === isActive[i];
        activeSum[i + 1] <== activeSum[i] + isActive[i];

        encryptedVoteHasher[i] = Poseidon(4);
        encryptedVoteHasher[i].inputs[0] <== ENCRYPTED_VOTE_TAG;
        encryptedVoteHasher[i].inputs[1] <== selectedOptionSums[i][maxOptions];
        encryptedVoteHasher[i].inputs[2] <== encryptedVoteRandomness[i];
        encryptedVoteHasher[i].inputs[3] <== optionSetHash;
        computedEncryptedVoteCommitment[i] <== encryptedVoteHasher[i].out;
        encryptedVoteCommitments[i] === isActive[i] * computedEncryptedVoteCommitment[i];

        voteCommitmentHasher[i] = Poseidon(4);
        voteCommitmentHasher[i].inputs[0] <== nullifiers[i];
        voteCommitmentHasher[i].inputs[1] <== encryptedVoteCommitments[i];
        voteCommitmentHasher[i].inputs[2] <== optionSetHash;
        voteCommitmentHasher[i].inputs[3] <== voteRandomness[i];
        computedVoteCommitment[i] <== voteCommitmentHasher[i].out;

        nullifierLeafHasher[i] = Poseidon(2);
        nullifierLeafHasher[i].inputs[0] <== NULLIFIER_LEAF_TAG;
        nullifierLeafHasher[i].inputs[1] <== nullifiers[i];
        nullifierLeaves[i] <== isActive[i] * nullifierLeafHasher[i].out;

        voteCommitmentLeafHasher[i] = Poseidon(2);
        voteCommitmentLeafHasher[i].inputs[0] <== VOTE_COMMITMENT_LEAF_TAG;
        voteCommitmentLeafHasher[i].inputs[1] <== computedVoteCommitment[i];
        voteCommitmentLeaves[i] <== isActive[i] * voteCommitmentLeafHasher[i].out;

        encryptedVoteLeafHasher[i] = Poseidon(2);
        encryptedVoteLeafHasher[i].inputs[0] <== ENCRYPTED_VOTE_LEAF_TAG;
        encryptedVoteLeafHasher[i].inputs[1] <== encryptedVoteCommitments[i];
        encryptedVoteLeaves[i] <== isActive[i] * encryptedVoteLeafHasher[i].out;
    }

    activeSum[maxVotes] === acceptedVoteCount;
    for (var j = 0; j < maxOptions; j++) {
        optionCountSums[j][maxVotes] === optionCounts[j];
        optionCounts[j] * optionOutOfRange[j] === 0;
    }

    component optionCountsHasher = Poseidon(maxOptions + 1);
    optionCountsHasher.inputs[0] <== OPTION_COUNTS_TAG;
    for (var j = 0; j < maxOptions; j++) {
        optionCountsHasher.inputs[j + 1] <== optionCounts[j];
    }
    optionCountsHasher.out === optionCountsHash;

    component nullifierTree = PoseidonFixedRoot64();
    component voteCommitmentTree = PoseidonFixedRoot64();
    component encryptedVoteTree = PoseidonFixedRoot64();

    for (var i = 0; i < maxVotes; i++) {
        nullifierTree.leaves[i] <== nullifierLeaves[i];
        voteCommitmentTree.leaves[i] <== voteCommitmentLeaves[i];
        encryptedVoteTree.leaves[i] <== encryptedVoteLeaves[i];
    }

    nullifierTree.root === nullifierRoot;
    voteCommitmentTree.root === voteCommitmentRoot;
    encryptedVoteTree.root === encryptedVoteRoot;
}

component main {
    public [
        pollId,
        pollPolicyHash,
        credentialSchemaHash,
        optionSetHash,
        optionCount,
        nullifierRoot,
        voteCommitmentRoot,
        encryptedVoteRoot,
        acceptedVoteCount,
        optionCountsHash
    ]
} = EncryptedChoiceTally(64, 8);
