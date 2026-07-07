# CivicOS Solana Audit Program

Phase 5 adds an Anchor program for public audit anchoring. It stores poll policy hashes, credential schema hashes, root batches, accepted vote counts, and final result hashes.

This program intentionally does not verify vote ZK proofs on-chain. The v1 trust model remains:

1. CivicOS backend verifies vote legitimacy off-chain.
2. Backend stores accepted vote nullifiers and vote commitments.
3. Backend commits Merkle roots to this Solana program when publishing result/audit material, or earlier if CivicOS later enables periodic anchoring.
4. Public audit tooling compares backend/exported vote records against on-chain roots.

## Program

- Program name: `civicos_audit`
- Source-declared program id: `FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo`
- Anchor version: `0.32.1`

The source-declared program id is the current local deployment key public key. Before any mainnet deployment, create the deployment key through the agreed key-custody process, update `declare_id!` / `Anchor.toml` with that public key, and run `anchor keys sync`. Generated `target/deploy/*-keypair.json` files are ignored and must not be committed.

## Instructions

- `initialize_registry`: creates the global registry PDA and sets signer authority/treasury/token mint/token-program metadata.
- `create_poll`: creates a poll PDA keyed by `poll_id_hash` and stores frozen `poll_policy_hash` / `credential_schema_hash`.
- `commit_roots`: appends a batch root account, verifies previous roots and next batch index, and advances the poll latest roots. Commits are allowed after the poll opens and before finalization, so CivicOS can delay publication until result release.
- `finalize_poll`: stores final vote/nullifier roots and the final result hash after the poll closes.

## Build

```bash
NO_DNA=1 anchor build
```

## Test

```bash
cargo test
```

Deployment and root-publisher signing are intentionally not automated here. Do not use a mainnet program authority or fee payer until the deployment plan and key custody are reviewed.

## Phase 12 Security

- Root publishing must use a dedicated `root_publisher_key` controlled through external KMS/HSM or multisig signing-service custody.
- Do not commit Solana keypair files or private-key material. The backend records only public signer metadata until transaction publication is explicitly enabled.
- Program upgrade authority must not remain with a single developer wallet. Use multisig, a timelock where possible, public upgrade announcements, and versioned program IDs.
- Backend audit decisions are prepared for hash-linked logging through `backend_audit_events`; future root publication can anchor `audit_log_root` alongside poll audit roots.

## SHOLAN Token

The existing SHOLAN mint can be recorded in `PollRegistry` when the registry is initialized:

- Cluster: `mainnet-beta`
- Mint: `GJRpZhWZcLGP8ZUKggxDTw7y5N3LGXa2gWqKRSLDWiBq`
- Token program: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` (`Token-2022`)
- Decimals: `9`
- Mint authority: none
- Freeze authority: none
- Metadata update authority: `4eDFMXLgNxSLstBG2F6wx8w3hiMy753u4bxPnSK1Ghcm`
- Name/symbol from on-chain Token-2022 metadata: `Sholan token` / `SHOLAN`

Because mint and freeze authorities are disabled, future rewards or staking must use funded treasury token accounts rather than newly minted supply.
