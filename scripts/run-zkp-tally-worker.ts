// Dedicated Railway background worker for Groth16 tally proof generation.
//
// Keep this default before importing env-bound modules. The worker needs
// Supabase/ZKP config, not mobile attestation validation. It must still honor
// the real Solana audit transaction env because it publishes final results.
process.env.ILAND_ENV_VALIDATION_SCOPE ||= "supabase-admin-script";

const { zkpTallyWorkerService } = await import(
  "../src/services/zkpTallyWorkerService"
);

await zkpTallyWorkerService.startLoop();
