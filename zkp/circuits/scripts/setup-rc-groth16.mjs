import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");
const contributionEntropy =
  process.env.CIVICOS_GROTH16_SETUP_ENTROPY ||
  "civicos-internal-release-candidate-not-production";
const circuits = Object.freeze([
  { name: "credential_commitment_vote", ptauPower: 14 },
  { name: "encrypted_choice_tally", ptauPower: 19 },
]);
const selectedCircuitNames = new Set(
  (process.env.CIVICOS_GROTH16_SETUP_CIRCUITS || "")
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

run("npm", ["run", "build:circuit"]);

for (const circuit of circuits) {
  if (selectedCircuitNames.size > 0 && !selectedCircuitNames.has(circuit.name)) {
    continue;
  }
  const ptauPath = `build/pot${circuit.ptauPower}_final.ptau`;
  if (!existsSync(resolve(packageRoot, ptauPath))) {
    throw new Error(
      `${ptauPath} is missing. Run the powers-of-tau ceremony first, then rerun this script.`,
    );
  }

  run(snarkjs, [
    "groth16",
    "setup",
    `build/${circuit.name}.r1cs`,
    ptauPath,
    `build/${circuit.name}_0000.zkey`,
  ]);
  run(snarkjs, [
    "zkey",
    "contribute",
    `build/${circuit.name}_0000.zkey`,
    `build/${circuit.name}_final.zkey`,
    `--name=CivicOS internal RC ${circuit.name} zkey contribution`,
    `-e=${contributionEntropy}-${circuit.name}`,
  ]);
  run(snarkjs, [
    "zkey",
    "export",
    "verificationkey",
    `build/${circuit.name}_final.zkey`,
    `build/${circuit.name}.vkey.json`,
  ]);
}

console.log(
  "Internal release-candidate Groth16 setup complete. This is not a production multi-contributor ceremony.",
);
