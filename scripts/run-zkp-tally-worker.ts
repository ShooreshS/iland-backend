// Dedicated Railway background worker for Groth16 tally proof generation.
//
// Keep this default before importing env-bound modules. The worker needs
// Supabase/ZKP config, not mobile attestation or Solana signer validation.
// Final on-chain publication belongs to the main backend replica.
process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";
process.env.ZKP_TALLY_PROVER_MODE = "worker";
process.env.ZKP_TALLY_WORKER_ENABLED = "true";
process.env.ZKP_GROTH16_TALLY_VERIFIER_ENABLED = "true";

const { zkpTallyWorkerService } = await import(
  "../src/services/zkpTallyWorkerService"
);

await zkpTallyWorkerService.startLoop();
