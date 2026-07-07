pragma circom 2.1.6;

include "poseidon.circom";

template AssertBoolean() {
    signal input in;
    in * (in - 1) === 0;
}

template PoseidonFixedRoot1() {
    signal input leaves[1];
    signal output root;

    root <== leaves[0];
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
    signal input nullifierRoot;
    signal input voteCommitmentRoot;
    signal input encryptedVoteRoot;
    signal input acceptedVoteCount;
    signal input optionCountsHash;

    // Private vote openings in accepted audit order, padded with inactive slots.
    signal input isActive[maxVotes];
    signal input nullifiers[maxVotes];
    signal input encryptedVoteHashes[maxVotes];
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

    signal selectedOptionSums[maxVotes][maxOptions + 1];
    signal rowSelectionSums[maxVotes][maxOptions + 1];
    signal activeSum[maxVotes + 1];
    signal optionCountSums[maxOptions][maxVotes + 1];
    signal nullifierLeaves[maxVotes];
    signal voteCommitmentLeaves[maxVotes];
    signal encryptedVoteLeaves[maxVotes];
    signal computedEncryptedVoteHash[maxVotes];
    signal computedVoteCommitment[maxVotes];

    activeSum[0] <== 0;
    for (var j = 0; j < maxOptions; j++) {
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
        computedEncryptedVoteHash[i] <== encryptedVoteHasher[i].out;
        encryptedVoteHashes[i] === isActive[i] * computedEncryptedVoteHash[i];

        voteCommitmentHasher[i] = Poseidon(4);
        voteCommitmentHasher[i].inputs[0] <== nullifiers[i];
        voteCommitmentHasher[i].inputs[1] <== encryptedVoteHashes[i];
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
        encryptedVoteLeafHasher[i].inputs[1] <== encryptedVoteHashes[i];
        encryptedVoteLeaves[i] <== isActive[i] * encryptedVoteLeafHasher[i].out;
    }

    activeSum[maxVotes] === acceptedVoteCount;
    for (var j = 0; j < maxOptions; j++) {
        optionCountSums[j][maxVotes] === optionCounts[j];
    }

    component optionCountsHasher = Poseidon(maxOptions + 1);
    optionCountsHasher.inputs[0] <== OPTION_COUNTS_TAG;
    for (var j = 0; j < maxOptions; j++) {
        optionCountsHasher.inputs[j + 1] <== optionCounts[j];
    }
    optionCountsHasher.out === optionCountsHash;

    component nullifierTree = PoseidonFixedRoot1();
    component voteCommitmentTree = PoseidonFixedRoot1();
    component encryptedVoteTree = PoseidonFixedRoot1();

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
        nullifierRoot,
        voteCommitmentRoot,
        encryptedVoteRoot,
        acceptedVoteCount,
        optionCountsHash
    ]
} = EncryptedChoiceTally(1, 2);
