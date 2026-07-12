# CivicOS Solana Audit Program

Phase 5 adds an Anchor program for public audit anchoring. It stores poll policy hashes, credential schema hashes, nullifier/vote-commitment/encrypted-vote root batches, accepted vote counts, and final result hashes.

This program intentionally does not verify vote ZK proofs on-chain. The v1 trust model remains:

1. CivicOS backend verifies vote legitimacy off-chain.
2. Backend stores accepted vote nullifiers, vote commitments, and encrypted-vote commitments.
3. Backend commits Merkle roots to this Solana program when publishing result/audit material, or earlier if CivicOS later enables periodic anchoring.
4. Public audit tooling compares backend/exported vote records against on-chain roots.

## Program

- Program name: `civicos_audit`
- Source-declared program id: `FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo`
- Anchor version: `0.32.1`

The source-declared program id is the current local deployment key public key. Before any mainnet deployment, create the deployment key through the agreed key-custody process, update `declare_id!` / `Anchor.toml` with that public key, and run `anchor keys sync`. Generated `target/deploy/*-keypair.json` files are ignored and must not be committed.

## Instructions

- `initialize_registry`: creates the global registry PDA and sets signer registry authority, dedicated root publisher, treasury, and token mint/token-program metadata. Registry authority and root publisher must be different keys.
- `create_poll`: creates a poll PDA keyed by `poll_id_hash` and stores frozen `poll_policy_hash` / `credential_schema_hash`. This is signed by the registry's `root_publisher`.
- `commit_roots`: appends a batch root account, verifies previous nullifier / vote-commitment / encrypted-vote roots and next batch index, and advances the poll latest roots. This is signed by the registry's `root_publisher`. Commits are allowed after the poll opens and before finalization, so CivicOS can delay publication until result release.
- `finalize_poll`: stores final vote/nullifier/encrypted-vote roots and the final result hash after the poll closes. This is signed by the registry's `root_publisher`.

## Minimal Mainnet Footprint

CivicOS v1 keeps user-facing voting operations off-chain. Votes, vote proofs,
backend verification, encrypted ballot payloads, receipts, and receipt lookup
never write to Solana. The only on-chain writes are audit anchors:

| Operation             | Frequency                         | What it creates                                                                     |
| --------------------- | --------------------------------- | ----------------------------------------------------------------------------------- |
| Program deploy        | once, plus rare reviewed upgrades | the `civicos_audit` program                                                         |
| `initialize_registry` | once per deployed audit program   | registry PDA with registry authority, root publisher, treasury, and SHOLAN metadata |
| `create_poll`         | one per poll                      | poll PDA with policy/schema hashes and voting window                                |
| `commit_roots`        | one per sealed 64-vote batch      | chained root PDA for nullifier, vote-commitment, and encrypted-vote roots           |
| `finalize_poll`       | one per poll                      | final result PDA with result hash and tally proof hash                              |

SHOLAN is recorded as token metadata in the registry. It does not execute the
audit logic, store votes/proofs, or pay Solana network fees. Backend-sponsored
root publication fees are paid in SOL by the configured audit fee-payer.

## Build

```bash
NO_DNA=1 anchor build
```

## Test

```bash
cargo test
```

Deployment and root-publisher signing are intentionally not automated here. Do not use a mainnet program authority or fee payer until the deployment plan and key custody are reviewed.

## Phase 7 Devnet Acceptance

After a real app build creates a production `zk_secret_ballot_v1` poll and at
least one phone-generated proof-backed vote is accepted, run the strict Phase 7
publication acceptance from the backend repo:

```bash
cd /Users/shooresh/Documents/hello1/iland24/back

CIVICOS_PHASE7_CONFIRM_SEND=true \
CIVICOS_PHASE7_BACKEND_URL="https://iland-backend-production.up.railway.app" \
CIVICOS_PHASE7_BEARER_TOKEN="<poll-owner bearer access token>" \
CIVICOS_PHASE7_POLL_ID="<poll id>" \
CIVICOS_PHASE7_RECEIPT_VOTE_COMMITMENT="<vote commitment from the app receipt>" \
bun run phase7:acceptance
```

The strict runner requires:

- `/health/zkp` reports configured vote and tally verifiers;
- the poll has accepted proof-backed encrypted votes;
- the poll has a verified tally proof;
- audit publication writes at least one root transaction and a final result
  transaction on devnet;
- the receipt inclusion proof verifies against the public audit JSON.

It writes evidence under `tmp/phase7/<poll-id>-<timestamp>/`, including:

- `PHASE7-TRANSCRIPT.md`;
- `health-zkp.json`;
- `audit-before.json` and `audit-after.json`;
- `publication.json`;
- `receipt.json`;
- `public-audit-verifier.txt`.

Optional duplicate-nullifier drill:

```bash
CIVICOS_PHASE7_DUPLICATE_VOTE_PAYLOAD_FILE="tmp/phase7/vote-payload.json" \
  ...same command...
```

That file must be the exact phone-generated production vote request body that
was already accepted. The script replays it and requires HTTP 409
`ALREADY_VOTED`, proving the duplicate nullifier path fails closed.

For a diagnostic publication-only run against an unfinished poll, set
`CIVICOS_PHASE7_ALLOW_PARTIAL=true`. A partial run is not Phase 7 acceptance.

## Phase 12 Security

- Root publishing must use a dedicated `root_publisher_key` controlled through external KMS/HSM or multisig signing-service custody. It must not be the registry authority or program upgrade authority.
- Registry authority initializes and governs registry configuration. It is not the key used for recurring root publication.
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

## Wallets

| Role                        | Public key   | Keypair file                                          | Balance                              |
| --------------------------- | ------------ | ----------------------------------------------------- | ------------------------------------ |
| Personal/default CLI wallet | 4eDF...Ghcm  | ~/.config/solana/id.json                              | mainnet 0.07509741 SOL, devnet 0 SOL |
| Backend audit fee-payer     | 2s5L...FUhX5 | ~/.config/solana/civicos/devnet-audit-fee-payer.json  | devnet 12 SOL                        |
| Devnet program deployer     | CyB8...KkwC  | ~/.config/solana/civicos/devnet-program-deployer.json | devnet 0 SOL                         |

```
shooresh@MacBookPro solana % NO_DNA=1 solana transfer "$DEPLOYER" 3 \
  --from ~/.config/solana/civicos/devnet-audit-fee-payer.json \
  --fee-payer ~/.config/solana/civicos/devnet-audit-fee-payer.json \
  --url devnet \
  --allow-unfunded-recipient

Signature: 2ANcmzVcTsjLAdx4xsAERDPzxPhSSe7ygWf6cWrDSaDKrRs8PQhzPih8tnFknHxdJTJgcaU9aPRJt3KKgdCbg8o9

shooresh@MacBookPro solana % NO_DNA=1 solana balance "$DEPLOYER" --url devnet
3 SOL
shooresh@MacBookPro solana % cd /Users/shooresh/Documents/hello1/iland24/back/solana

NO_DNA=1 anchor deploy \
  --provider.cluster devnet \
  --provider.wallet ~/.config/solana/civicos/devnet-program-deployer.json
Deploying cluster: https://api.devnet.solana.com
Upgrade authority: /Users/shooresh/.config/solana/civicos/devnet-program-deployer.json
Deploying program "civicos_audit"...
Program path: /Users/shooresh/Documents/hello1/iland24/back/solana/target/deploy/civicos_audit.so...
Program Id: FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo

Signature: 4YHeA1YVcraxnDLwG5UNRRnUPWz1XgRqRZf6ahck2nssmDmJiFyyo8qFmxUzBGBtuLyYx7KtH6E96fK9RoXynjdx

Waiting for program FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo to be confirmed...
Program confirmed on-chain
Idl data length: 1491 bytes
Step 0/1491
Step 600/1491
Step 1200/1491
Idl account created: C5WWz269riZFngbSJSAuiYAUEYbb7FxVe5tpoRPEhgMk
Deploy success
shooresh@MacBookPro solana % NO_DNA=1 solana program show FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo --url devnet

Program Id: FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo
Owner: BPFLoaderUpgradeab1e11111111111111111111111
ProgramData Address: BeHBmueTyD3pxSV33s3BjXoqQXwgBXTUnfwG9Tq8xk7p
Authority: CyB8BhqNfEz3xS5mHc39y6VaJHv2NcU5cof7iY7KkwC
Last Deployed In Slot: 474682189
Data Length: 285472 (0x45b20) bytes
Balance: 1.9880892 SOL

# Registry

Generating a new keypair
Wrote new keypair to /Users/shooresh/.config/solana/civicos/devnet-registry-authority.json
=======================================================================
pubkey: H2t19XHeyNaeLk5WJC1oHEE7V8vSxjoTtJYygGFkvE2F
=======================================================================
Save this seed phrase to recover your new keypair:
cost boss spoon add broccoli skin weird matter rifle ribbon draft total
=======================================================================
REGISTRY_AUTHORITY=H2t19XHeyNaeLk5WJC1oHEE7V8vSxjoTtJYygGFkvE2F
ROOT_PUBLISHER=2s5L3hu9o6nvugVxpYSLu6WqPPjDcm9MKTHEk6tFUhX5
DEPLOYER=CyB8BhqNfEz3xS5mHc39y6VaJHv2NcU5cof7iY7KkwC
FEE_PAYER=2s5L3hu9o6nvugVxpYSLu6WqPPjDcm9MKTHEk6tFUhX5

# extend the program account

shooresh@Shooreshs-MacBook-Pro solana % cd /Users/shooresh/Documents/hello1/iland24/back/solana

export PROGRAM_ID=FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo
export DEPLOYER_KEYPAIR="$HOME/.config/solana/civicos/devnet-program-deployer.json"

NO_DNA=1 solana balance "$DEPLOYER_KEYPAIR" --url devnet
25.98728752 SOL
shooresh@Shooreshs-MacBook-Pro solana % NO_DNA=1 solana program extend "$PROGRAM_ID" 32768 \
  --url devnet \
  --keypair "$DEPLOYER_KEYPAIR"

Extended Program Id FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo by 32768 bytes

shooresh@Shooreshs-MacBook-Pro solana % NO_DNA=1 solana program show "$PROGRAM_ID" --url devnet

Program Id: FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo
Owner: BPFLoaderUpgradeab1e11111111111111111111111
ProgramData Address: BeHBmueTyD3pxSV33s3BjXoqQXwgBXTUnfwG9Tq8xk7p
Authority: CyB8BhqNfEz3xS5mHc39y6VaJHv2NcU5cof7iY7KkwC
Last Deployed In Slot: 475282549
Data Length: 318240 (0x4db20) bytes
Balance: 2.21615448 SOL

# re-deploy
NO_DNA=1 anchor deploy \
  --provider.cluster devnet \
  --provider.wallet "$DEPLOYER_KEYPAIR"
Deploying cluster: https://api.devnet.solana.com
Upgrade authority: /Users/shooresh/.config/solana/civicos/devnet-program-deployer.json
Deploying program "civicos_audit"...
Program path: /Users/shooresh/Documents/hello1/iland24/back/solana/target/deploy/civicos_audit.so...
Program Id: FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo

Signature: QNNFPzKbPkd4vWLBWMFJC7Vs4hTKmxWhhuemryCUNHqSA66wM5yu6wGdrETSzCAtFF8674qLDpknuaBBENyZH4v

Waiting for program FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo to be confirmed...
Program confirmed on-chain
Idl data length: 1574 bytes
Step 0/1574
Step 600/1574
Step 1200/1574
Idl account C5WWz269riZFngbSJSAuiYAUEYbb7FxVe5tpoRPEhgMk successfully upgraded
Deploy success

# init the registry result
registry=GbiuZZynd7mw6LWVKA4yVYdgWtia1g5M8U35jWnSyrMN
registryAuthority=H2t19XHeyNaeLk5WJC1oHEE7V8vSxjoTtJYygGFkvE2F
rootPublisher=2s5L3hu9o6nvugVxpYSLu6WqPPjDcm9MKTHEk6tFUhX5
signature=4atRoxMPwDS1R9JC4viScFqAYGWCUK2zX7wauFpDXTYBFqtsMcqLmPidvzQXqHrn3USudwSkrdSukkMy2kktWinw

```

| Wallet     | pulic key                                    |
| ---------- | -------------------------------------------- |
| program:   | FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo |
| deployer:  | CyB8BhqNfEz3xS5mHc39y6VaJHv2NcU5cof7iY7KkwC  |
| fee payer: | 2s5L3hu9o6nvugVxpYSLu6WqPPjDcm9MKTHEk6tFUhX5 |
