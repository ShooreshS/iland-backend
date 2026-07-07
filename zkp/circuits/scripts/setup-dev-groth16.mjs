import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");

const run = (command, args) => {
  console.log(`$ ${command} ${args.join(" ")}`);
  execFileSync(command, args, {
    cwd: packageRoot,
    stdio: "inherit",
  });
};

mkdirSync(buildDir, { recursive: true });

run(snarkjs, [
  "powersoftau",
  "new",
  "bn128",
  "14",
  "build/pot14_0000.ptau",
]);
run(snarkjs, [
  "powersoftau",
  "contribute",
  "build/pot14_0000.ptau",
  "build/pot14_0001.ptau",
  "--name=CivicOS local dev contribution",
  "-e=civicos-local-dev",
]);
run(snarkjs, [
  "powersoftau",
  "prepare",
  "phase2",
  "build/pot14_0001.ptau",
  "build/pot14_final.ptau",
]);
run(snarkjs, [
  "groth16",
  "setup",
  "build/credential_commitment_vote.r1cs",
  "build/pot14_final.ptau",
  "build/credential_commitment_vote_0000.zkey",
]);
run(snarkjs, [
  "zkey",
  "contribute",
  "build/credential_commitment_vote_0000.zkey",
  "build/credential_commitment_vote_final.zkey",
  "--name=CivicOS local dev zkey contribution",
  "-e=civicos-local-dev-zkey",
]);
run(snarkjs, [
  "zkey",
  "export",
  "verificationkey",
  "build/credential_commitment_vote_final.zkey",
  "build/credential_commitment_vote.vkey.json",
]);

console.log("Local development Groth16 setup complete.");
