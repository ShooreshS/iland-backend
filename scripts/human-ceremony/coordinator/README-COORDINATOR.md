# Coordinator guide — CivicOS production Groth16 Phase-2 ceremony

This folder is for the ceremony coordinator (CivicOS), not for contributors.
Contributors receive only the `contributor/` folder (README.md, README.pdf, contribute.mjs, input/, output/) — zip that folder, not the kit root.

## The model

Sequential relay over both frozen circuits (`credential_commitment_vote`,
`encrypted_choice_tally`), starting from a **publicly trusted** perpetual
powers-of-tau:

- `zkp/circuits/build/powersOfTau28_hez_final_16.ptau` for
  `credential_commitment_vote.r1cs`
- `zkp/circuits/build/powersOfTau28_hez_final_20.ptau` for
  `encrypted_choice_tally.r1cs`

Never use the internal RC `pot16_final.ptau` or `pot20_final.ptau`, whose
Phase 1 had a single internal contributor.

```
prepare-ceremony.sh          → contributor/input/credential_commitment_vote_0000.zkey
                              → contributor/input/encrypted_choice_tally_0000.zkey
zip kit → contributor #1     → returns output/credential_commitment_vote_0001.zkey
                              → returns output/encrypted_choice_tally_0001.zkey
                              → returns output/ATTESTATION-Shooresh.md
verify, rotate into input/   → re-zip → contributor #2
                              → returns output/credential_commitment_vote_0002.zkey
                              → returns output/encrypted_choice_tally_0002.zkey
                              → returns output/ATTESTATION-matbas.md
... at least THREE independent contributors ...
finalize-ceremony.sh BEACON_HEX → final/credential_commitment_vote_final.zkey
                              → final/credential_commitment_vote.vkey.json
                              → final/encrypted_choice_tally_final.zkey
                              → final/encrypted_choice_tally.vkey.json
                              → coordinator/ceremony-verification-YYYYMMDD-HHMMSS.log
```

The system is sound if at least one contributor was honest. The final beacon
removes any advantage the *last* contributor might have from choosing their
randomness adaptively.

## Step by step

1. **Prepare:** `./coordinator/prepare-ceremony.sh`
   - Confirms the local r1cs files match the frozen manifests (hard stop on
     mismatch — never run a ceremony over unfrozen circuits).
   - Downloads + cryptographically verifies the public ptau files.
   - Writes `contributor/input/credential_commitment_vote_0000.zkey` and
     `contributor/input/encrypted_choice_tally_0000.zkey`.

2. **Announce the beacon in advance.** Before contributor #1 starts, publicly
   commit to the beacon source — e.g. "the drand round at epoch X" or "the
   hash of Bitcoin block N" where X/N are in the future, after the expected
   last contribution. This prevents anyone from grinding the final beacon.

3. **Relay.** For each contributor:
   - Zip the `contributor/` folder and send it.
   - Prefer an archive/folder name without spaces for Windows contributors,
     for example `contributor3.zip` or `contributor3/`. The contributor
     script uses relative `input/...` and `output/...` paths for `snarkjs`,
     but no-space archive names avoid shell edge cases around `npx.cmd`.
   - When `output/` comes back, **verify before accepting**:
     ```sh
     zkp/circuits/node_modules/.bin/snarkjs zkey verify \
       zkp/circuits/build/credential_commitment_vote.r1cs \
       zkp/circuits/build/powersOfTau28_hez_final_16.ptau \
       "scripts/human-ceremony/contributor 1/output/credential_commitment_vote_0001.zkey"

     zkp/circuits/node_modules/.bin/snarkjs zkey verify \
       zkp/circuits/build/encrypted_choice_tally.r1cs \
       zkp/circuits/build/powersOfTau28_hez_final_20.ptau \
       "scripts/human-ceremony/contributor 1/output/encrypted_choice_tally_0001.zkey"
     ```
     For contributor #2, verify:
     ```sh
     zkp/circuits/node_modules/.bin/snarkjs zkey verify \
       zkp/circuits/build/credential_commitment_vote.r1cs \
       zkp/circuits/build/powersOfTau28_hez_final_16.ptau \
       "scripts/human-ceremony/contributor 2/output/credential_commitment_vote_0002.zkey"

     zkp/circuits/node_modules/.bin/snarkjs zkey verify \
       zkp/circuits/build/encrypted_choice_tally.r1cs \
       zkp/circuits/build/powersOfTau28_hez_final_20.ptau \
       "scripts/human-ceremony/contributor 2/output/encrypted_choice_tally_0002.zkey"
     ```
     The listed contributions must be the previous chain plus exactly one new
     entry with the contributor's name. Cross-check the contribution hash
     against `scripts/human-ceremony/contributor 1/output/ATTESTATION-Shooresh.md`
     or `scripts/human-ceremony/contributor 2/output/ATTESTATION-matbas.md`.
   - Archive the previous `input/` zkeys, move the returned zkeys into
     `input/`, keep the attestation, re-zip, send to the next contributor.
   - Contributors should be genuinely independent: different organizations,
     different machines, no shared infrastructure with CivicOS.

4. **Finalize:** after ≥3 contributors,
   `./coordinator/finalize-ceremony.sh BEACON_HEX [iterations]`
   - Applies the pre-announced beacon, verifies the full chain, exports the
     production verifier keys into `final/`, and writes a verification log.
   - Refuses to run with fewer than 3 contributions in the chain.

5. **Pin + publish.** Follow the "Next steps" the finalize script prints:
   copy finals into the frozen build dir, regenerate transcripts/manifests/
   fixtures with `CIVICOS_GROTH16_ARTIFACT_PROFILE=production` and the real
   contributor list + beacon (the manifest writer fails closed without ≥3
   contributors in production mode), refresh `npm run zkp:env` into Railway,
   and publish the verification log, phase2 transcripts, attestations, and
   beacon details with the public audit material.

## Rules that keep the ceremony honest

- Never contribute yourself and call it independent — internal contributions
  don't count toward the three.
- Never accept a returned zkey that fails `zkey verify` or whose chain shows
  anything other than +1 contribution.
- Never reuse RC artifacts, and never let a circuit change slip in mid-way:
  any r1cs change aborts the ceremony and restarts it (new circuit id).
- Keep every intermediate zkey and attestation; they are part of the public
  evidence.
