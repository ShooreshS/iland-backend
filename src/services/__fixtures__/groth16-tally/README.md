# Groth16 Tally Verifier Fixture

Internal release-candidate fixture for backend snarkjs verification tests.

Status: regenerated during Phase 2 on 2026-07-09 from the frozen 64-vote x
8-option tally circuit. This fixture includes `optionCount`, `tallyBatchSize:
64`, and `maxOptions: 8` manifest parameters. Backend tests verify this fixture
through the default snarkjs verifier engine.

This fixture must not be used as a production ceremony artifact. It is a
single-contributor internal release candidate for devnet/internal testing only.
