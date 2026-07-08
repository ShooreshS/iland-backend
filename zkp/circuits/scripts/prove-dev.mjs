import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const vectorDir = resolve(packageRoot, "test-vectors");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");
const circuits = Object.freeze([
  "credential_commitment_vote",
  "encrypted_choice_tally",
]);
const selectedCircuitNames = new Set(
  (process.env.CIVICOS_GROTH16_PROVE_CIRCUITS || "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean),
);

const run = (command, args) => {
  console.log(`$ ${command} ${args.join(" ")}`);
  execFileSync(command, args, {
    cwd: packageRoot,
    stdio: "inherit",
  });
};

mkdirSync(buildDir, { recursive: true });

for (const circuit of circuits) {
  if (selectedCircuitNames.size > 0 && !selectedCircuitNames.has(circuit)) {
    continue;
  }

  const witnessGenerator = resolve(
    buildDir,
    `${circuit}_js/generate_witness.js`,
  );
  const wasmPath = resolve(buildDir, `${circuit}_js/${circuit}.wasm`);
  writeFileSync(
    resolve(buildDir, `${circuit}_js/package.json`),
    `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`,
  );

  const validWitness = resolve(buildDir, `${circuit}.valid.wtns`);
  run("node", [
    witnessGenerator,
    wasmPath,
    resolve(vectorDir, `${circuit}.valid.input.json`),
    validWitness,
  ]);
  run(snarkjs, [
    "groth16",
    "prove",
    `build/${circuit}_final.zkey`,
    validWitness,
    `test-vectors/${circuit}.valid.proof.json`,
    `test-vectors/${circuit}.valid.public.proof.json`,
  ]);
  run(snarkjs, [
    "groth16",
    "verify",
    `build/${circuit}.vkey.json`,
    `test-vectors/${circuit}.valid.public.proof.json`,
    `test-vectors/${circuit}.valid.proof.json`,
  ]);
}

if (
  selectedCircuitNames.size === 0 ||
  selectedCircuitNames.has("credential_commitment_vote")
) {
  const witnessGenerator = resolve(
    buildDir,
    "credential_commitment_vote_js/generate_witness.js",
  );
  const wasmPath = resolve(
    buildDir,
    "credential_commitment_vote_js/credential_commitment_vote.wasm",
  );

  const assertInvalidWitnessFails = ({ name, inputFile }) => {
    const invalid = spawnSync(
      "node",
      [
        witnessGenerator,
        wasmPath,
        resolve(vectorDir, inputFile),
        resolve(buildDir, `credential_commitment_vote.${name}.wtns`),
      ],
      {
        cwd: packageRoot,
        encoding: "utf8",
      },
    );

    if (invalid.status === 0) {
      throw new Error(`${name} unexpectedly generated a witness`);
    }
  };

  assertInvalidWitnessFails({
    name: "invalid_wrong_nullifier",
    inputFile: "credential_commitment_vote.invalid_wrong_nullifier.input.json",
  });
  assertInvalidWitnessFails({
    name: "invalid_wrong_credential_root",
    inputFile: "credential_commitment_vote.invalid_wrong_credential_root.input.json",
  });
}

console.log("Local vote/tally proofs generated and invalid vectors rejected.");
