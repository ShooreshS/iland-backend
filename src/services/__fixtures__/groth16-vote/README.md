# Groth16 Vote Verifier Fixture

Local development fixture for backend snarkjs verification tests.

Status: stale after the Phase 1 circuit freeze/revision because the vote public
signal order now includes `optionCount` and the credential registry depth is now
32. Backend tests intentionally reject this pre-freeze/depth-24 fixture until
Phase 2 regenerates local/production Groth16 artifacts from the frozen circuit.
It also predates required manifest `circuitParameters`, so env loading should
fail closed if this manifest is accidentally pointed at the verifier.

This fixture must not be used as a production ceremony artifact.
