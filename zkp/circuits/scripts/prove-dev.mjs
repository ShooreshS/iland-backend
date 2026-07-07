import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const vectorDir = resolve(packageRoot, "test-vectors");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");
const witnessGenerator = resolve(
  buildDir,
  "credential_commitment_vote_js/generate_witness.js",
);
const wasmPath = resolve(
  buildDir,
  "credential_commitment_vote_js/credential_commitment_vote.wasm",
);

const run = (command, args) => {
  console.log(`$ ${command} ${args.join(" ")}`);
  execFileSync(command, args, {
    cwd: packageRoot,
    stdio: "inherit",
  });
};

mkdirSync(buildDir, { recursive: true });
writeFileSync(
  resolve(buildDir, "credential_commitment_vote_js/package.json"),
  `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`,
);

const validWitness = resolve(buildDir, "credential_commitment_vote.valid.wtns");
run("node", [
  witnessGenerator,
  wasmPath,
  resolve(vectorDir, "credential_commitment_vote.valid.input.json"),
  validWitness,
]);
run(snarkjs, [
  "groth16",
  "prove",
  "build/credential_commitment_vote_final.zkey",
  validWitness,
  "test-vectors/credential_commitment_vote.valid.proof.json",
  "test-vectors/credential_commitment_vote.valid.public.proof.json",
]);
run(snarkjs, [
  "groth16",
  "verify",
  "build/credential_commitment_vote.vkey.json",
  "test-vectors/credential_commitment_vote.valid.public.proof.json",
  "test-vectors/credential_commitment_vote.valid.proof.json",
]);

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

console.log("Local proof generated and invalid vectors rejected.");
