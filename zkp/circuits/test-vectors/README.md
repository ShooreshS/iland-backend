# CredentialCommitmentVote Test Vectors

Tracked files in this directory are deterministic local vectors:

- `credential_commitment_vote.valid.input.json`
- `credential_commitment_vote.valid.public.json`
- `credential_commitment_vote.valid.public.named.json`
- `credential_commitment_vote.invalid_wrong_nullifier.input.json`
- `credential_commitment_vote.invalid_wrong_credential_root.input.json`
- `credential_commitment_vote.summary.json`

`npm run prove:dev` also writes local Groth16 proof/public-output files for the
valid vector. Those files are intentionally ignored because they are generated
from a local-only development trusted setup and are not production artifacts.
