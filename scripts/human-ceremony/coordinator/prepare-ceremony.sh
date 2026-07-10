#!/usr/bin/env bash

# CivicOS production ceremony — coordinator step 1 of 2.
#
# Prepares the ceremony starting zkeys (`*_0000.zkey`) in ../input from the
# FROZEN circuits and a PUBLICLY TRUSTED perpetual-powers-of-tau file.
# Do not use the internal RC pot16/pot20 files here: their Phase 1 had a
# single (internal) contributor, which is not acceptable for production.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKEND_ROOT="$(cd "${KIT_ROOT}/../.." && pwd)"
CIRCUIT_ROOT="${BACKEND_ROOT}/zkp/circuits"
BUILD_DIR="${CIRCUIT_ROOT}/build"
SNARKJS="${CIRCUIT_ROOT}/node_modules/.bin/snarkjs"
INPUT_DIR="${KIT_ROOT}/input"
PTAU_BASE_URL="https://storage.googleapis.com/zkevm/ptau"

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=16384}"

log() { printf "\n[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

require_file() {
  if [[ ! -f "$1" ]]; then
    printf "Missing required file: %s\n" "$1" >&2
    exit 1
  fi
}

require_file "${SNARKJS}"
mkdir -p "${INPUT_DIR}"

# circuit name -> hez ptau power
CIRCUITS=("credential_commitment_vote:16" "encrypted_choice_tally:20")

check_r1cs_frozen() {
  local circuit="$1" manifest r1cs_hash pinned
  case "${circuit}" in
    credential_commitment_vote)
      manifest="${BACKEND_ROOT}/src/zkp-artifacts/groth16-vote/credential_commitment_vote.manifest.json"
      ;;
    encrypted_choice_tally)
      manifest="${BACKEND_ROOT}/src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json"
      ;;
  esac
  require_file "${manifest}"
  r1cs_hash="$(shasum -a 256 "${BUILD_DIR}/${circuit}.r1cs" | awk '{print $1}')"
  pinned="$(jq -r '.artifacts[] | select(.role == "r1cs") | .sha256' "${manifest}")"
  if [[ "${r1cs_hash}" != "${pinned}" ]]; then
    printf "FROZEN-CIRCUIT MISMATCH for %s:\n  build r1cs:    %s\n  pinned r1cs:   %s\n" \
      "${circuit}" "${r1cs_hash}" "${pinned}" >&2
    printf "The local circuit build does not match the frozen manifest. Stop and investigate.\n" >&2
    exit 1
  fi
  log "Frozen r1cs confirmed for ${circuit}: ${r1cs_hash}"
}

for entry in "${CIRCUITS[@]}"; do
  circuit="${entry%%:*}"
  power="${entry##*:}"
  ptau="${BUILD_DIR}/powersOfTau28_hez_final_${power}.ptau"

  require_file "${BUILD_DIR}/${circuit}.r1cs"
  check_r1cs_frozen "${circuit}"

  if [[ ! -f "${ptau}" ]]; then
    log "Downloading public powers-of-tau (2^${power}) — this is a large file"
    curl -fL --retry 3 -o "${ptau}.partial" \
      "${PTAU_BASE_URL}/powersOfTau28_hez_final_${power}.ptau"
    mv "${ptau}.partial" "${ptau}"
  fi

  log "Cryptographically verifying the public powers-of-tau (2^${power}); pot20 can take a while"
  "${SNARKJS}" powersoftau verify "${ptau}"

  log "Creating ceremony starting zkey for ${circuit}"
  "${SNARKJS}" groth16 setup \
    "${BUILD_DIR}/${circuit}.r1cs" \
    "${ptau}" \
    "${INPUT_DIR}/${circuit}_0000.zkey"
  shasum -a 256 "${INPUT_DIR}/${circuit}_0000.zkey"
done

log "Ceremony inputs ready in ${INPUT_DIR}"
cat <<'NEXT'

Next steps:
  1. Zip the human-ceremony folder and send it to contributor #1.
  2. When their `output` folder comes back:
     - verify each returned zkey extends the chain:
         zkp/circuits/node_modules/.bin/snarkjs zkey verify \
           zkp/circuits/build/<circuit>.r1cs \
           zkp/circuits/build/powersOfTau28_hez_final_<power>.ptau \
           <returned zkey>
     - replace the files in human-ceremony/input/ with the returned zkeys
       (keep their _0001/_0002/... names), archive the previous ones,
       and send the re-zipped kit to the next contributor.
  3. After at least THREE independent contributors, run:
       ./coordinator/finalize-ceremony.sh <beacon-hex> [iterations]
NEXT
