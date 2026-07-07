pragma circom 2.1.6;

include "poseidon.circom";

template AssertBoolean() {
    signal input in;
    in * (in - 1) === 0;
}

template CredentialCommitmentVote(depth) {
    // Public poll/proof binding inputs.
    signal input pollId;
    signal input pollPolicyHash;
    signal input credentialSchemaHash;
    signal input optionSetHash;
    signal input credentialRoot;
    signal input nullifier;
    signal input voteCommitment;
    signal input encryptedVoteHash;

    // Private witness material.
    signal input identitySecret;
    signal input credentialSalt;
    signal input voteRandomness;
    signal input documentValid;
    signal input livenessPassed;
    signal input faceMatchedDocument;
    signal input ageEligible;
    signal input countryEligible;
    signal input homeAreaEligible;
    signal input landEligible;
    signal input credentialRootSiblings[depth];
    signal input credentialRootPathIndices[depth];

    component documentValidIsBoolean = AssertBoolean();
    component livenessPassedIsBoolean = AssertBoolean();
    component faceMatchedDocumentIsBoolean = AssertBoolean();
    component ageEligibleIsBoolean = AssertBoolean();
    component countryEligibleIsBoolean = AssertBoolean();
    component homeAreaEligibleIsBoolean = AssertBoolean();
    component landEligibleIsBoolean = AssertBoolean();

    documentValidIsBoolean.in <== documentValid;
    livenessPassedIsBoolean.in <== livenessPassed;
    faceMatchedDocumentIsBoolean.in <== faceMatchedDocument;
    ageEligibleIsBoolean.in <== ageEligible;
    countryEligibleIsBoolean.in <== countryEligible;
    homeAreaEligibleIsBoolean.in <== homeAreaEligible;
    landEligibleIsBoolean.in <== landEligible;

    documentValid === 1;
    livenessPassed === 1;
    faceMatchedDocument === 1;
    ageEligible === 1;
    countryEligible === 1;
    homeAreaEligible === 1;
    landEligible === 1;

    component credentialCommitmentHasher = Poseidon(10);
    credentialCommitmentHasher.inputs[0] <== identitySecret;
    credentialCommitmentHasher.inputs[1] <== credentialSchemaHash;
    credentialCommitmentHasher.inputs[2] <== credentialSalt;
    credentialCommitmentHasher.inputs[3] <== documentValid;
    credentialCommitmentHasher.inputs[4] <== livenessPassed;
    credentialCommitmentHasher.inputs[5] <== faceMatchedDocument;
    credentialCommitmentHasher.inputs[6] <== ageEligible;
    credentialCommitmentHasher.inputs[7] <== countryEligible;
    credentialCommitmentHasher.inputs[8] <== homeAreaEligible;
    credentialCommitmentHasher.inputs[9] <== landEligible;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== pollId;
    nullifierHasher.inputs[2] <== pollPolicyHash;
    nullifierHasher.out === nullifier;

    component voteCommitmentHasher = Poseidon(4);
    voteCommitmentHasher.inputs[0] <== nullifier;
    voteCommitmentHasher.inputs[1] <== encryptedVoteHash;
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
        credentialRoot,
        nullifier,
        voteCommitment,
        encryptedVoteHash
    ]
} = CredentialCommitmentVote(4);
