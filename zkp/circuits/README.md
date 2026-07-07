# CivicOS Circom/Groth16 Circuits

This package contains the first production-v1 circuit scaffold for CivicOS
ZKP voting.

## Circuit

`circuits/credential_commitment_vote.circom` proves:

- the voter knows the private `identitySecret` behind a credential commitment
- the credential commitment is included in the public `credentialRoot`
- the credential was issued for the public `credentialSchemaHash`
- required eligibility flags in the committed credential are true
- the public `nullifier` is derived from `(identitySecret, pollId, pollPolicyHash)`
- the public `voteCommitment` binds `(nullifier, encryptedVoteHash, optionSetHash, voteRandomness)`

This is the credential-commitment v1 path. It does not prove native Iranian
National ID document signatures in-circuit yet. The assumption is that CivicOS
has already verified the document and issued a credential commitment into the
credential tree.

The current eligibility inputs are scaffold-level boolean claims. Before a
production ceremony, CivicOS still needs to freeze the exact credential claim
encoding and poll-policy constraint encoding those booleans represent.

## Public Signals

The public signal order is:

1. `pollId`
2. `pollPolicyHash`
3. `credentialSchemaHash`
4. `optionSetHash`
5. `credentialRoot`
6. `nullifier`
7. `voteCommitment`
8. `encryptedVoteHash`

All values are BN254 field elements encoded as decimal strings in local vectors.
The app/backend hex-to-field adapter is a separate integration step.

## Local Use

Install package dependencies:

```sh
npm install
```

Generate deterministic local input/public-signal vectors:

```sh
npm test
```

Compile the circuit:

```sh
npm run build:circuit
```

Create a local development Groth16 setup, produce and verify a proof for the
valid vector, and confirm invalid witness vectors fail:

```sh
npm run setup:dev
npm run prove:dev
```

The `setup:dev` script creates a local, non-production trusted setup. Do not use
its `.zkey`, `.ptau`, verifier key, proof, or manifest output in production.
