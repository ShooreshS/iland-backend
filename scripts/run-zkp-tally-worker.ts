// Dedicated Railway background worker for Groth16 tally proof generation.
//
// Keep this default before importing env-bound modules. The worker needs
// Supabase/ZKP config, not mobile attestation or Solana signer validation.
// Final on-chain publication belongs to the main backend replica.
process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script";
process.env.SOLANA_AUDIT_TRANSACTIONS_ENABLED = "false";

const { zkpTallyWorkerService } = await import(
  "../src/services/zkpTallyWorkerService"
);

await zkpTallyWorkerService.startLoop();
