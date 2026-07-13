# CivicOS ZKP Phase 9 Pre-Ceremony Freeze

Created: 2026-07-13.

This file freezes the non-ceremony production contracts for the public devnet
v0.1 release. The final multi-contributor Groth16 ceremony is still required
before the mainnet v0.1.1 migration.

## Release Direction

- Public campaign release: CivicOS v0.1 on Solana `devnet`.
- Mainnet migration: CivicOS v0.1.1 after funding, final ceremony artifacts,
  and mainnet custody gates are complete.
- SHOLAN remains metadata/audit-only. It is not used for fees, rewards,
  staking, slashing, or governance in v0.1.

## Frozen Contracts

### Identity Secret

- Version: `civicos-identity-secret-v2`.
- Domain: `org.civicos.zkp.identity-secret.v2`.
- Hash suite: `hmac-sha512-bn254-v1`.
- Recovery requirement: reinstall/recovery must reproduce the same local ZKP
  identity secret before voting.

### Vote Circuit

- Circuit id: `civicos-groth16-vote-circuit-v1`.
- Public input schema: `civicos-groth16-vote-public-inputs-v1`.
- Credential registry Merkle depth: `32`.
- Max options: `8`.
- Hash suite: `poseidon-bn254-v1`.
- Proof system: Groth16 over BN254.

Public signal order is defined in
`zkp/circuits/FROZEN_CIRCUITS_V1.md` and must not change without a new circuit id,
new mobile pins, and a new ceremony.

### Tally Circuit

- Circuit id: `civicos-groth16-tally-circuit-v1`.
- Public input schema: `civicos-groth16-tally-public-inputs-v1`.
- Batch size: `64` votes.
- Max options: `8`.
- Hash suite: `poseidon-bn254-v1`.
- Proof system: Groth16 over BN254.

### Mobile Proof And Encrypted Vote Payload

- Mobile prover version: `civicos-mobile-groth16-prover-v1`.
- Mobile vote artifact bundle: `civicos-mobile-groth16-vote-artifacts-depth32-rc2`.
- Production proof envelope: `civicos-groth16-vote-proof-envelope-v1`.
- Encrypted vote payload: `civicos-encrypted-vote-v1`.
- Encrypted vote opening: `civicos-encrypted-vote-opening-v1`.
- Encryption algorithm: `x25519-hkdf-sha256-aes-256-gcm-v1`.
- Encrypted vote commitment scheme:
  `poseidon-encrypted-vote-opening-v1`.

### Custody

- v0.1 devnet custody: `operator_trusted_private_beta`.
- Public claims must not say ballots are secret from CivicOS/operator while
  backend-held decryption keys support provisional counts.
- Mainnet/public-production custody target remains `threshold_trustee_v1`.

### Backend Verifier Env Contract

The backend verifier env contract remains:

- `ZKP_GROTH16_VOTE_VERIFIER_ENABLED`
- `ZKP_GROTH16_VOTE_CIRCUIT_ID`
- `ZKP_GROTH16_VOTE_PUBLIC_INPUT_SCHEMA_VERSION`
- `ZKP_GROTH16_VOTE_VERIFIER_KEY_HASH`
- `ZKP_GROTH16_VOTE_TRUSTED_SETUP_TRANSCRIPT_HASH`
- `ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_PATH`
- `ZKP_GROTH16_VOTE_ARTIFACT_MANIFEST_HASH`
- `ZKP_GROTH16_TALLY_VERIFIER_ENABLED`
- `ZKP_GROTH16_TALLY_CIRCUIT_ID`
- `ZKP_GROTH16_TALLY_PUBLIC_INPUT_SCHEMA_VERSION`
- `ZKP_GROTH16_TALLY_VERIFIER_KEY_HASH`
- `ZKP_GROTH16_TALLY_TRUSTED_SETUP_TRANSCRIPT_HASH`
- `ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH`
- `ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_HASH`

Release-channel env:

- `ZKP_RELEASE_CHANNEL=public_devnet_v0_1` for public v0.1 devnet.
- `ZKP_ARTIFACT_RELEASE_STAGE=ceremony_pending` until final contributor
  outputs are finalized.
- `ZKP_PUBLIC_DEVNET_V0_1_CONFIRMED=true` to acknowledge that v0.1 is public
  but still devnet-bound.
- `ZKP_RELEASE_CHANNEL=mainnet_v0_1_1` only after final ceremony artifacts,
  mainnet program deployment/custody, and data cleanup are complete.

## Current Artifact State

The currently pinned vote and tally manifests are internal release-candidate
artifacts. They are acceptable for devnet v0.1 testing/campaign operation, but
they are not final multi-contributor ceremony artifacts.

Current RC manifest hashes:

- Vote: `9e77769e7fec24d5e860e75976aa0afcac439b93f42b8ed604c9754f95786c4b`
- Tally: `17cd53376ff5e5e8ea61bc50b07bbc8a0c46addc193055814e04992c2a6a2e29`

## Phase 9 Gate

Run:

```sh
bun run phase9:readiness
```

Expected status before contributor outputs return:

```text
ready_for_human_ceremony
```

The only acceptable warning at this point is that final multi-contributor
ceremony artifacts are pending. Any blocker must be fixed before continuing the
ceremony or publishing v0.1.
