#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CIRCUIT_ROOT="${BACKEND_ROOT}/zkp/circuits"
SNARKJS="${CIRCUIT_ROOT}/node_modules/.bin/snarkjs"
MODE="${CIVICOS_OVERNIGHT_MODE:-safe-verify}"
LOG_DIR="${CIVICOS_OVERNIGHT_LOG_DIR:-/tmp/civicos-zkp-logs}"
LOG_FILE="${LOG_DIR}/zkp-${MODE}-$(date +%Y%m%d-%H%M%S).log"

mkdir -p "${LOG_DIR}"

log() {
  printf "\n[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/overnight.sh
      Run safe verification only. Does not rewrite artifacts.

  CIVICOS_OVERNIGHT_MODE=phase2-rc-rebuild ./scripts/overnight.sh
      Run the heavy Phase 2 internal-RC rebuild in order:
      clean -> vectors -> ptau16/ptau20 -> Groth16 setup -> proofs ->
      transcripts -> manifests -> fixtures -> verification -> backend checks.
      This rewrites generated circuit build outputs, proof vectors, fixtures,
      and src/zkp-artifacts manifests.

  CIVICOS_OVERNIGHT_MODE=help ./scripts/overnight.sh
      Print this help.

This script does not perform the real multi-contributor production ceremony.
That ceremony needs independent contributors and published transcript evidence.
USAGE
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    printf "Missing required file: %s\n" "${path}" >&2
    exit 1
  fi
}

check_artifact_hashes() {
  local manifest="$1"
  local manifest_dir
  manifest_dir="$(cd "$(dirname "${manifest}")" && pwd)"

  require_file "${manifest}"

  jq -c '.artifacts[]' "${manifest}" | while IFS= read -r artifact; do
    local rel_path artifact_path expected actual role
    rel_path="$(jq -r '.path' <<<"${artifact}")"
    expected="$(jq -r '.sha256' <<<"${artifact}")"
    role="$(jq -r '.role' <<<"${artifact}")"

    if [[ "${rel_path}" = /* ]]; then
      artifact_path="${rel_path}"
    else
      artifact_path="${manifest_dir}/${rel_path}"
    fi

    require_file "${artifact_path}"
    actual="$(shasum -a 256 "${artifact_path}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
      printf "Artifact hash mismatch for %s (%s)\nexpected: %s\nactual:   %s\n" \
        "${role}" "${rel_path}" "${expected}" "${actual}" >&2
      exit 1
    fi
    printf "OK artifact hash: %s %s\n" "${role}" "${rel_path}"
  done
}

verify_circuit_artifacts() {
  require_file "${SNARKJS}"

  cd "${CIRCUIT_ROOT}"

  log "Verifying powers of tau files"
  "${SNARKJS}" powersoftau verify build/pot16_final.ptau
  "${SNARKJS}" powersoftau verify build/pot20_final.ptau

  log "Verifying Groth16 zkeys against frozen circuits"
  "${SNARKJS}" zkey verify \
    build/credential_commitment_vote.r1cs \
    build/pot16_final.ptau \
    build/credential_commitment_vote_final.zkey
  "${SNARKJS}" zkey verify \
    build/encrypted_choice_tally.r1cs \
    build/pot20_final.ptau \
    build/encrypted_choice_tally_final.zkey

  log "Verifying Groth16 proof fixtures"
  "${SNARKJS}" groth16 verify \
    build/credential_commitment_vote.vkey.json \
    test-vectors/credential_commitment_vote.valid.public.proof.json \
    test-vectors/credential_commitment_vote.valid.proof.json
  "${SNARKJS}" groth16 verify \
    build/encrypted_choice_tally.vkey.json \
    test-vectors/encrypted_choice_tally.valid.public.proof.json \
    test-vectors/encrypted_choice_tally.valid.proof.json
}

verify_backend_artifacts() {
  cd "${BACKEND_ROOT}"

  log "Checking local artifact hashes declared by manifests"
  check_artifact_hashes \
    "${BACKEND_ROOT}/src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json"
  check_artifact_hashes \
    "${BACKEND_ROOT}/src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json"

  log "Running focused backend ZKP verifier tests"
  NODE_ENV=test AUTH_ENABLE_TRANSITIONAL_CRYPTO_BYPASS=true bun test \
    src/services/groth16ArtifactManifestService.test.ts \
    src/services/groth16ProofVerifierService.test.ts \
    src/services/groth16TallyProofVerifierService.test.ts \
    src/services/poseidonAuditTreeService.test.ts

  log "Running backend typecheck"
  bunx tsc --noEmit
}

run_safe_verify() {
  log "Starting CivicOS ZKP safe overnight checks"
  log "Backend root: ${BACKEND_ROOT}"
  verify_circuit_artifacts
  verify_backend_artifacts
  log "Safe overnight checks completed successfully"
}

run_phase2_rc_rebuild() {
  log "Starting heavy Phase 2 internal-RC rebuild"
  log "This mode rewrites generated ZKP artifacts. Do not run it while editing those files."

  cd "${CIRCUIT_ROOT}"

  export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=8192}"
  export CIVICOS_GROTH16_ARTIFACT_PROFILE="${CIVICOS_GROTH16_ARTIFACT_PROFILE:-internal-rc}"
  export CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT="${CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  export CIVICOS_GROTH16_MANIFEST_GENERATED_AT="${CIVICOS_GROTH16_MANIFEST_GENERATED_AT:-${CIVICOS_GROTH16_TRANSCRIPT_GENERATED_AT}}"

  log "Cleaning previous local circuit build/proof outputs"
  npm run clean

  log "Regenerating deterministic vectors and validating invalid witnesses"
  npm test

  log "Preparing internal RC powers-of-tau files for vote/tally"
  CIVICOS_GROTH16_PTAU_POWERS=16,20 npm run ptau:rc

  log "Running internal RC Groth16 setup for vote/tally"
  npm run setup:rc

  log "Generating and verifying local Groth16 proof vectors"
  npm run prove:dev

  log "Writing Phase 2 transcript evidence"
  npm run transcripts

  log "Writing artifact manifests from regenerated outputs"
  npm run manifests

  log "Writing backend proof fixtures"
  npm run fixtures

  verify_circuit_artifacts
  verify_backend_artifacts
  log "Heavy Phase 2 internal-RC rebuild completed successfully"
}

run() {
  case "${MODE}" in
    safe-verify)
      run_safe_verify
      ;;
    phase2-rc-rebuild)
      run_phase2_rc_rebuild
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      printf "Unknown CIVICOS_OVERNIGHT_MODE: %s\n\n" "${MODE}" >&2
      usage >&2
      exit 2
      ;;
  esac
}

run 2>&1 | tee "${LOG_FILE}"
printf "\nLog written to %s\n" "${LOG_FILE}"
