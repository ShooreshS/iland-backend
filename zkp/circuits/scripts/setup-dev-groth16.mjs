import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");
const ptauPower = 20;
const circuits = Object.freeze([
  "credential_commitment_vote",
  "encrypted_choice_tally",
]);

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
  String(ptauPower),
  `build/pot${ptauPower}_0000.ptau`,
]);
run(snarkjs, [
  "powersoftau",
  "contribute",
  `build/pot${ptauPower}_0000.ptau`,
  `build/pot${ptauPower}_0001.ptau`,
  "--name=CivicOS local dev contribution",
  "-e=civicos-local-dev",
]);
run(snarkjs, [
  "powersoftau",
  "prepare",
  "phase2",
  `build/pot${ptauPower}_0001.ptau`,
  `build/pot${ptauPower}_final.ptau`,
]);

for (const circuit of circuits) {
  run(snarkjs, [
    "groth16",
    "setup",
    `build/${circuit}.r1cs`,
    `build/pot${ptauPower}_final.ptau`,
    `build/${circuit}_0000.zkey`,
  ]);
  run(snarkjs, [
    "zkey",
    "contribute",
    `build/${circuit}_0000.zkey`,
    `build/${circuit}_final.zkey`,
    `--name=CivicOS local dev ${circuit} zkey contribution`,
    `-e=civicos-local-dev-${circuit}-zkey`,
  ]);
  run(snarkjs, [
    "zkey",
    "export",
    "verificationkey",
    `build/${circuit}_final.zkey`,
    `build/${circuit}.vkey.json`,
  ]);
}

console.log("Local development Groth16 setup complete.");
