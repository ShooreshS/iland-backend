# CivicOS Circom/Groth16 Circuits

This package contains the first production-v1 circuit scaffold for CivicOS
ZKP voting.

## Circuit

`circuits/credential_commitment_vote.circom` proves:

- the voter knows the private `identitySecret` behind a credential commitment
- the credential commitment is included in the public `credentialRoot`
- the credential commitment is bound to private `identitySecret`, private `identityKeyHash`, public `credentialSchemaHash`, and private server-issued `claimsHash`
- the public `nullifier` is derived from `(identitySecret, pollId, pollPolicyHash)`
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

## Public Signals

The public signal order is:

1. `pollId`
2. `pollPolicyHash`
3. `credentialSchemaHash`
4. `optionSetHash`
5. `credentialRoot`
6. `nullifier`
7. `voteCommitment`
8. `encryptedVoteCommitment`

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

For internal release-candidate artifact generation, after the relevant ptau
files exist:

```sh
CIVICOS_GROTH16_SETUP_CIRCUITS=credential_commitment_vote npm run setup:rc
CIVICOS_GROTH16_PROVE_CIRCUITS=credential_commitment_vote npm run prove:dev
CIVICOS_GROTH16_MANIFEST_CIRCUITS=credential_commitment_vote npm run manifests
```

The RC manifest is for devnet/internal testing only until a documented
multi-contributor ceremony replaces it.
