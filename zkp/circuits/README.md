# CivicOS Circom/Groth16 Circuits

This package contains the first production-v1 circuit scaffold for CivicOS
ZKP voting.

The frozen Phase 1 production-v1 contract is recorded in
[`FROZEN_CIRCUITS_V1.md`](./FROZEN_CIRCUITS_V1.md). Any future circuit change
must use a new circuit id, new public-input contract, new ceremony, and new
mobile/backend artifacts.

The vote circuit was amended to a depth-32 credential registry before any
production ceremony or production artifact manifest was generated.

## Vote Circuit

`circuits/credential_commitment_vote.circom` proves:

- the voter knows the private `identitySecret` behind a credential commitment
- the credential commitment is included in the public `credentialRoot`
- the credential commitment is bound to private `identitySecret`, private `identityKeyHash`, public `credentialSchemaHash`, and private server-issued `claimsHash`
- the public `nullifier` is derived from `(identitySecret, pollId, pollPolicyHash)`
- the private `optionIndex` is inside the public active `optionCount`
- the public `encryptedVoteCommitment` binds `(optionIndex, encryptedVoteRandomness, optionSetHash)`
- the public `voteCommitment` binds `(nullifier, encryptedVoteCommitment, optionSetHash, voteRandomness)`

This is the credential-commitment v1 path. It does not prove native Iranian
National ID document signatures in-circuit yet. The assumption is that CivicOS
has already verified the document and issued a credential commitment into the
credential tree.

The circuit is document-agnostic: passports, Iranian National ID, and later
document adapters must all emit the same normalized CivicOS credential witness.
The verifier rejects proofs whose public `credentialRoot` is not in the
backend accepted credential-root registry.

## Vote Public Signals

The public signal order is:

1. `pollId`
2. `pollPolicyHash`
3. `credentialSchemaHash`
4. `optionSetHash`
5. `optionCount`
6. `credentialRoot`
7. `nullifier`
8. `voteCommitment`
9. `encryptedVoteCommitment`

## Tally Public Signals

`circuits/encrypted_choice_tally.circom` proves a fixed 64-vote x 8-option
batch over the same Poseidon audit tree used by the backend public audit path.

The public signal order is:

1. `pollId`
2. `pollPolicyHash`
3. `credentialSchemaHash`
4. `optionSetHash`
5. `optionCount`
6. `nullifierRoot`
7. `voteCommitmentRoot`
8. `encryptedVoteRoot`
9. `acceptedVoteCount`
10. `optionCountsHash`

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
valid vector, and confirm invalid witness vectors fail. This is Phase 2-style
artifact work and may be slow for the tally circuit:

```sh
npm run setup:dev
npm run prove:dev
```

The `setup:dev` script creates a local, non-production trusted setup. Do not use
its `.zkey`, `.ptau`, verifier key, proof, or manifest output in production.

For internal release-candidate artifact generation, after the relevant ptau
files exist:

```sh
CIVICOS_GROTH16_SETUP_CIRCUITS=credential_commitment_vote npm run setup:rc
CIVICOS_GROTH16_PROVE_CIRCUITS=credential_commitment_vote npm run prove:dev
CIVICOS_GROTH16_MANIFEST_CIRCUITS=credential_commitment_vote npm run manifests
```

The RC manifest is for devnet/internal testing only until a documented
multi-contributor ceremony replaces it.

Any older depth-24 RC vote `.zkey`, verifier key, manifest, or mobile bundle is
superseded by the depth-32 contract and must not be enabled for production
verification.
