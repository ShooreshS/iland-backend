#!/usr/bin/env bash

# CivicOS production ceremony — coordinator step 2 of 2.
#
# Applies the public randomness beacon on top of the last contributor's
# zkeys, verifies the full contribution chain against the frozen circuits
# and the public powers-of-tau, and exports the production verifier keys.
#
# Usage:
#   ./finalize-ceremony.sh <beacon-hex> [iterations]
#
#   beacon-hex  Publicly verifiable randomness announced BEFORE the ceremony
#               ended (e.g. a drand round signature or a specific future
#               Bitcoin/Solana block hash). Hex string, no 0x prefix.
#   iterations  Beacon iteration exponent (default 10 → 2^10 iterations).

set -euo pipefail

BEACON_HEX="${1:-}"
ITERATIONS="${2:-10}"
if [[ -z "${BEACON_HEX}" || ! "${BEACON_HEX}" =~ ^[0-9a-fA-F]+$ ]]; then
  printf "Usage: %s <beacon-hex> [iterations]\n" "$0" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKEND_ROOT="$(cd "${KIT_ROOT}/../.." && pwd)"
CIRCUIT_ROOT="${BACKEND_ROOT}/zkp/circuits"
BUILD_DIR="${CIRCUIT_ROOT}/build"
SNARKJS="${CIRCUIT_ROOT}/node_modules/.bin/snarkjs"
INPUT_DIR="${KIT_ROOT}/contributor/input"
FINAL_DIR="${KIT_ROOT}/final"
VERIFY_LOG="${SCRIPT_DIR}/ceremony-verification-$(date -u +%Y%m%d-%H%M%S).log"

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=16384}"

log() { printf "\n[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

latest_zkey() {
  ls "${INPUT_DIR}/$1"_[0-9][0-9][0-9][0-9].zkey 2>/dev/null | sort | tail -1
}

mkdir -p "${FINAL_DIR}"

CIRCUITS=("credential_commitment_vote:16" "encrypted_choice_tally:20")

{
  for entry in "${CIRCUITS[@]}"; do
    circuit="${entry%%:*}"
    power="${entry##*:}"
    ptau="${BUILD_DIR}/powersOfTau28_hez_final_${power}.ptau"
    last="$(latest_zkey "${circuit}")"

    if [[ -z "${last}" ]]; then
      printf "No %s_XXXX.zkey found in %s\n" "${circuit}" "${INPUT_DIR}" >&2
      exit 1
    fi
    last_index="$(basename "${last}" .zkey | tail -c 5)"
    if [[ "${last_index}" -lt 3 ]]; then
      printf "Only %s contributions found for %s — production requires at least 3 independent contributors.\n" \
        "${last_index}" "${circuit}" >&2
      exit 1
    fi

    log "Applying public beacon on ${circuit} (from $(basename "${last}"))"
    "${SNARKJS}" zkey beacon "${last}" \
      "${FINAL_DIR}/${circuit}_final.zkey" \
      "${BEACON_HEX}" "${ITERATIONS}" \
      -n="CivicOS production ceremony final beacon"

    log "Verifying the FULL contribution chain for ${circuit}"
    "${SNARKJS}" zkey verify \
      "${BUILD_DIR}/${circuit}.r1cs" \
      "${ptau}" \
      "${FINAL_DIR}/${circuit}_final.zkey"

    log "Exporting production verifier key for ${circuit}"
    "${SNARKJS}" zkey export verificationkey \
      "${FINAL_DIR}/${circuit}_final.zkey" \
      "${FINAL_DIR}/${circuit}.vkey.json"

    shasum -a 256 "${FINAL_DIR}/${circuit}_final.zkey" "${FINAL_DIR}/${circuit}.vkey.json"
  done
} 2>&1 | tee "${VERIFY_LOG}"

log "Ceremony finalized. Full verification transcript: ${VERIFY_LOG}"
cat <<NEXT

Next steps (production artifact pinning):
  1. Copy the final artifacts over the RC ones in the frozen build dir:
       cp "${FINAL_DIR}"/credential_commitment_vote_final.zkey "${BUILD_DIR}/"
       cp "${FINAL_DIR}"/credential_commitment_vote.vkey.json  "${BUILD_DIR}/"
       cp "${FINAL_DIR}"/encrypted_choice_tally_final.zkey     "${BUILD_DIR}/"
       cp "${FINAL_DIR}"/encrypted_choice_tally.vkey.json      "${BUILD_DIR}/"
  2. Regenerate proofs, transcripts, manifests and fixtures in production mode
     (contributor names in ceremony order, comma separated):
       cd "${CIRCUIT_ROOT}"
       npm run prove:dev
       CIVICOS_GROTH16_ARTIFACT_PROFILE=production \\
       CIVICOS_GROTH16_CONTRIBUTORS="<name1>,<name2>,<name3>,..." \\
       CIVICOS_GROTH16_BEACON_SOURCE="<where the beacon came from>" \\
       CIVICOS_GROTH16_BEACON_VALUE="${BEACON_HEX}" \\
         bash -c 'npm run transcripts && npm run manifests && npm run fixtures'
  3. Refresh the backend env pins and update Railway:
       cd "${BACKEND_ROOT}" && npm run zkp:env
  4. Publish, alongside the audit material:
       - the ceremony verification transcript (${VERIFY_LOG})
       - the phase2-transcript JSON files from the build dir
       - every contributor attestation
       - the beacon source/value and how to re-check it
  5. Re-run ./scripts/overnight.sh (safe-verify) and the backend test suite.
NEXT
