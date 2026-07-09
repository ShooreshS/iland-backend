# CivicOS Frozen Circuits V1

Status: Phase 1 frozen contract, amended for depth 32 on 2026-07-09 before any production ceremony. Production Groth16 ceremony and pinned production artifacts are Phase 2.

## Shared Decisions

- Proof system: Groth16 over BN254.
- Hash suite: `poseidon-bn254-v1`.
- Credential registry depth: 32.
- Credential claim encoding: `civicos-credential-claims-v1`.
- Poll options: 1 to 8 active options, sorted by `display_order`.
- Tally batch: fixed 64 votes x 8 option bins.
- Larger poll rollup: chain 64-vote batch proofs off-chain by public roots/counts before adding recursion.
- `encryptedVoteHash`: backend envelope hash only; not a circuit public input.
- `encryptedVoteCommitment`: in-circuit Poseidon commitment used by vote, storage, audit tree, and tally.

## Vote Circuit

Circuit file: `circuits/credential_commitment_vote.circom`

Circuit id: `civicos-groth16-vote-circuit-v1`

Public input schema: `civicos-groth16-vote-public-inputs-v1`

Public signal order:

1. `pollId`
2. `pollPolicyHash`
3. `credentialSchemaHash`
4. `optionSetHash`
5. `optionCount`
6. `credentialRoot`
7. `nullifier`
8. `voteCommitment`
9. `encryptedVoteCommitment`

Constraints:

- Credential leaf: `Poseidon(identitySecret, identityKeyHash, credentialSchemaHash, claimsHash)`.
- Registry proof: depth-32 Merkle inclusion to public `credentialRoot`.
- Nullifier: `Poseidon(identitySecret, pollId, pollPolicyHash)`.
- Option index: 3-bit private value, constrained to `optionIndex < optionCount`.
- Option count: public integer constrained to `1 <= optionCount <= 8`.
- Encrypted vote commitment: `Poseidon(1001, optionIndex, encryptedVoteRandomness, optionSetHash)`.
- Vote commitment: `Poseidon(nullifier, encryptedVoteCommitment, optionSetHash, voteRandomness)`.

Current compile size:

- Public inputs: 9.
- Private inputs: 73.
- Non-linear constraints: 9,054.

## Tally Circuit

Circuit file: `circuits/encrypted_choice_tally.circom`

Circuit id: `civicos-groth16-tally-circuit-v1`

Public input schema: `civicos-groth16-tally-public-inputs-v1`

Public signal order:

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

Constraints:

- Batch size: exactly 64 rows, padded with inactive zero rows.
- Option count: public integer constrained to `1 <= optionCount <= 8`.
- Every active row has exactly one selected option.
- Selection and count bins outside `optionCount` are constrained to zero.
- Encrypted vote commitment per active row: `Poseidon(1001, optionIndex, encryptedVoteRandomness, optionSetHash)`.
- Vote commitment per active row: `Poseidon(nullifier, encryptedVoteCommitment, optionSetHash, voteRandomness)`.
- Audit leaves:
  - Nullifier leaf: `Poseidon(1101, nullifier)`.
  - Vote commitment leaf: `Poseidon(1102, voteCommitment)`.
  - Encrypted vote leaf: `Poseidon(1103, encryptedVoteCommitment)`.
- Audit tree nodes: `Poseidon(left, right)` over a fixed 64-leaf tree.
- Option counts hash: `Poseidon(1201, count0, count1, ..., count7)`.

Current compile size:

- Public inputs: 10.
- Private inputs: 840.
- Non-linear constraints: 132,805.

## Verification Status

Completed in Phase 1:

- Deterministic vectors regenerated.
- Vote credential registry depth amended from 24 to 32 before Phase 2 ceremony/artifacts.
- Vote negative vectors:
  - wrong nullifier;
  - wrong credential root;
  - out-of-range option index.
- Tally negative vectors:
  - out-of-range option bin;
  - encrypted vote commitment mismatch.
- Both circuits compile.
- Valid vectors generate witnesses.
- Invalid vectors fail witness generation.
- Backend verifier requires backend-derived option counts.
- Tally verifier requires exact active option IDs in display order.

Pending for Phase 2:

- Run production multi-contributor Phase-2 ceremonies for both frozen circuits.
- Generate fresh proving keys, verification keys, proof fixtures, and artifact manifests from this frozen contract.
- Replace stale pre-freeze local fixture proofs.
- Record production verifier-key hashes, proving-key hashes, transcript hashes, mobile artifact size, and proving timing.
