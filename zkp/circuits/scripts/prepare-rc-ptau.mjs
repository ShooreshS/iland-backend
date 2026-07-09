import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = resolve(packageRoot, "build");
const snarkjs = resolve(packageRoot, "node_modules/.bin/snarkjs");
const selectedPowers = (
  process.env.CIVICOS_GROTH16_PTAU_POWERS || "16,20"
)
  .split(",")
  .map((entry) => Number(entry.trim()))
  .filter((entry) => Number.isInteger(entry) && entry > 0);

const run = (command, args) => {
  console.log(`$ ${command} ${args.join(" ")}`);
  execFileSync(command, args, {
    cwd: packageRoot,
    stdio: "inherit",
  });
};

mkdirSync(buildDir, { recursive: true });

for (const power of selectedPowers) {
  const finalPath = resolve(buildDir, `pot${power}_final.ptau`);
  if (existsSync(finalPath)) {
    console.log(`build/pot${power}_final.ptau already exists; skipping.`);
    continue;
  }

  run(snarkjs, [
    "powersoftau",
    "new",
    "bn128",
    String(power),
    `build/pot${power}_0000.ptau`,
  ]);
  run(snarkjs, [
    "powersoftau",
    "contribute",
    `build/pot${power}_0000.ptau`,
    `build/pot${power}_0001.ptau`,
    `--name=CivicOS internal RC pot${power}`,
    `-e=civicos-internal-rc-pot${power}`,
  ]);
  run(snarkjs, [
    "powersoftau",
    "prepare",
    "phase2",
    `build/pot${power}_0001.ptau`,
    `build/pot${power}_final.ptau`,
  ]);
}

console.log(
  "Internal release-candidate ptau preparation complete. These files are not a production multi-contributor Phase-1 ceremony.",
);
