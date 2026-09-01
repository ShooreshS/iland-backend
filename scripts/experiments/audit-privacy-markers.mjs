#!/usr/bin/env node

import { createHash, createHmac } from "node:crypto";
import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const args = process.argv.slice(2);
const getArg = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
};
const markerFile = getArg("--markers");
const outputPath = resolve(getArg("--output") || "tmp/experiments/privacy/privacy-marker-audit.json");
const targetArgs = args.filter((entry) => entry.startsWith("--target="));
if (!markerFile || targetArgs.length === 0) {
  throw new Error("Usage: node audit-privacy-markers.mjs --markers <private.json> --target=label=/path [--target=label=/path] [--output file]");
}
const pseudonymKey = String(process.env.CIVICOS_EXPERIMENT_PSEUDONYM_KEY || "").trim();
if (!pseudonymKey) throw new Error("CIVICOS_EXPERIMENT_PSEUDONYM_KEY is required.");
const privateMarkers = JSON.parse(readFileSync(resolve(markerFile), "utf8"));
const markers = Array.isArray(privateMarkers.markers)
  ? privateMarkers.markers
  : Object.entries(privateMarkers).map(([markerClass, value]) => ({ markerClass, value }));
if (markers.length === 0 || markers.some((entry) => typeof entry.value !== "string" || entry.value.length < 8)) {
  throw new Error("Every marker must be a string of at least eight characters.");
}
const targets = targetArgs.map((entry) => {
  const [label, ...pathParts] = entry.slice("--target=".length).split("=");
  if (!label || pathParts.length === 0) throw new Error(`Invalid target: ${entry}`);
  return { label: label.replace(/[^a-z0-9_-]/gi, "_").slice(0, 80), path: resolve(pathParts.join("=")) };
});
const filesUnder = (path) => {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) {
    throw new Error(`Privacy audit target contains a symbolic link: ${path}`);
  }
  if (stat.isFile()) {
    if (stat.size > 100 * 1024 * 1024) {
      throw new Error(`Split files larger than 100 MiB before scanning: ${path}`);
    }
    return [path];
  }
  if (!stat.isDirectory()) return [];
  return readdirSync(path).flatMap((entry) => filesUnder(resolve(path, entry)));
};
const markerCode = (value) => createHmac("sha256", pseudonymKey).update(value).digest("hex").slice(0, 16);
const fileCode = (bytes) => createHash("sha256").update(bytes).digest("hex");
const results = [];
for (const target of targets) {
  const files = filesUnder(target.path);
  const observations = new Map(markers.map((marker) => [markerCode(marker.value), { count: 0, fileHashes: new Set() }]));
  for (const path of files) {
    const bytes = readFileSync(path);
    const text = bytes.toString("utf8");
    for (const marker of markers) {
      const code = markerCode(marker.value);
      let index = 0;
      while ((index = text.indexOf(marker.value, index)) >= 0) {
        observations.get(code).count += 1;
        observations.get(code).fileHashes.add(fileCode(bytes));
        index += marker.value.length;
      }
    }
  }
  results.push({
    target: target.label,
    scannedFiles: files.length,
    matches: [...observations.entries()].map(([code, observation]) => ({
      markerCode: code,
      count: observation.count,
      fileHashes: [...observation.fileHashes],
    })),
  });
}
const report = {
  schemaVersion: "civicos-privacy-marker-audit-v1",
  scannedAt: new Date().toISOString(),
  markerDictionarySha256: createHash("sha256").update(readFileSync(resolve(markerFile))).digest("hex"),
  targets: results,
};
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ outputPath, targets: results.map(({ target, scannedFiles, matches }) => ({ target, scannedFiles, matchCount: matches.reduce((sum, entry) => sum + entry.count, 0) })) }, null, 2));
