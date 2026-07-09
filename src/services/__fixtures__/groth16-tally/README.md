# Groth16 Tally Verifier Fixture

Local one-vote/two-option development fixture for backend snarkjs verification tests.

Status: stale after the 2026-07-08 Phase 1 circuit freeze because the tally
public signal order now includes `optionCount`. Backend tests intentionally
reject this pre-freeze fixture until Phase 2 regenerates local/production
Groth16 artifacts from the frozen circuit.
It also predates required manifest `circuitParameters`, so env loading should
fail closed if this manifest is accidentally pointed at the verifier.

This fixture must not be used as a production ceremony artifact.
