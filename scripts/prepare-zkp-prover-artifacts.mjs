#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
  createWriteStream,
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

const DEFAULT_TALLY_MANIFEST_PATH =
  "src/zkp-artifacts/groth16-tally/encrypted_choice_tally.manifest.json";
const DEFAULT_DOWNLOAD_URLS = Object.freeze({
  proving_key:
    "https://drive.google.com/file/d/1oQY8nIEqSYLSEZvOfI02fvj1BZFkL9sC/view?usp=sharing",
  witness_wasm:
    "https://drive.google.com/file/d/1Qbbv3RUzOIMJWjCANfTacp_36Stv2Zvf/view?usp=sharing",
});
const DOWNLOAD_ENV = Object.freeze({
  proving_key: "ZKP_GROTH16_TALLY_PROVING_KEY_URL",
  witness_wasm: "ZKP_GROTH16_TALLY_WASM_URL",
});
const REQUIRED_WITNESS_SUPPORT_FILES = Object.freeze([
  "generate_witness.js",
  "witness_calculator.js",
  "package.json",
]);

const htmlDecode = (value) =>
  value
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");

const resolvePath = (path) => (isAbsolute(path) ? path : resolve(process.cwd(), path));

const sha256File = async (path) => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
};

const artifactByRole = (manifest, role) => {
  const artifact = manifest.artifacts?.find((entry) => entry.role === role);
  if (!artifact?.path || !artifact?.sha256) {
    throw new Error(`Tally artifact manifest does not define ${role}.`);
  }
  return artifact;
};

const artifactPath = (manifestPath, artifact) =>
  isAbsolute(artifact.path)
    ? artifact.path
    : resolve(dirname(manifestPath), artifact.path);

const extractGoogleDriveFileId = (url) => {
  const trimmed = url.trim();
  const filePathMatch = trimmed.match(/\/file\/d\/([^/]+)/);
  if (filePathMatch?.[1]) {
    return filePathMatch[1];
  }
  const parsed = new URL(trimmed);
  return parsed.searchParams.get("id");
};

const toDownloadUrl = (url) => {
  const fileId = extractGoogleDriveFileId(url);
  if (!fileId) {
    return url;
  }
  const direct = new URL("https://drive.google.com/uc");
  direct.searchParams.set("export", "download");
  direct.searchParams.set("confirm", "t");
  direct.searchParams.set("id", fileId);
  return direct.toString();
};

const parseGoogleDriveConfirmUrl = (html, baseUrl) => {
  const formMatch = html.match(
    /<form[^>]+id=["']download-form["'][^>]+action=["']([^"']+)["'][^>]*>/i,
  );
  if (formMatch?.[1]) {
    const next = new URL(htmlDecode(formMatch[1]), baseUrl);
    for (const match of html.matchAll(
      /<input[^>]+name=["']([^"']+)["'][^>]+value=["']([^"']*)["'][^>]*>/gi,
    )) {
      next.searchParams.set(htmlDecode(match[1]), htmlDecode(match[2]));
    }
    return next.toString();
  }

  const hrefMatch = html.match(/href=["']([^"']*uc\?export=download[^"']+)["']/i);
  if (hrefMatch?.[1]) {
    return new URL(htmlDecode(hrefMatch[1]), baseUrl).toString();
  }

  return null;
};

const fetchDownloadResponse = async (url) => {
  let currentUrl = toDownloadUrl(url);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const response = await fetch(currentUrl, { redirect: "follow" });
    if (!response.ok) {
      throw new Error(`Download failed with HTTP ${response.status}: ${currentUrl}`);
    }

    const contentType = response.headers.get("content-type") || "";
    const contentDisposition = response.headers.get("content-disposition") || "";
    if (
      contentDisposition.toLowerCase().includes("attachment") ||
      !contentType.toLowerCase().includes("text/html")
    ) {
      return response;
    }

    const html = await response.text();
    const nextUrl = parseGoogleDriveConfirmUrl(html, currentUrl);
    if (!nextUrl || nextUrl === currentUrl) {
      throw new Error(
        "Google Drive returned an HTML page instead of the artifact. Make sure the file is shared with anyone who has the link.",
      );
    }
    currentUrl = nextUrl;
  }

  throw new Error("Could not resolve Google Drive artifact download URL.");
};

const ensureArtifact = async ({ role, path, expectedHash, downloadUrl }) => {
  if (existsSync(path)) {
    const existingHash = await sha256File(path);
    if (existingHash === expectedHash) {
      console.log(`[zkp-artifacts] ${role} already present: ${path}`);
      return;
    }
    console.warn(
      `[zkp-artifacts] ${role} hash mismatch at ${path}; re-downloading.`,
    );
  }

  if (!downloadUrl) {
    throw new Error(`${DOWNLOAD_ENV[role]} is required to download ${role}.`);
  }

  mkdirSync(dirname(path), { recursive: true });
  const tempPath = `${path}.download`;
  rmSync(tempPath, { force: true });

  console.log(`[zkp-artifacts] downloading ${role} to ${path}`);
  const response = await fetchDownloadResponse(downloadUrl);
  if (!response.body) {
    throw new Error(`Download response for ${role} has no body.`);
  }
  await pipeline(Readable.fromWeb(response.body), createWriteStream(tempPath));

  const actualHash = await sha256File(tempPath);
  if (actualHash !== expectedHash) {
    rmSync(tempPath, { force: true });
    throw new Error(
      `${role} SHA-256 mismatch after download. expected=${expectedHash} actual=${actualHash}`,
    );
  }

  renameSync(tempPath, path);
  console.log(`[zkp-artifacts] ${role} ready: ${path}`);
};

const main = async () => {
  if (process.env.ZKP_PREPARE_PROVER_ARTIFACTS === "false") {
    console.log("[zkp-artifacts] preparation skipped by ZKP_PREPARE_PROVER_ARTIFACTS=false");
    return;
  }

  const manifestPath = resolvePath(
    process.env.ZKP_GROTH16_TALLY_ARTIFACT_MANIFEST_PATH ||
      DEFAULT_TALLY_MANIFEST_PATH,
  );
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const provingKey = artifactByRole(manifest, "proving_key");
  const witnessWasm = artifactByRole(manifest, "witness_wasm");
  const provingKeyPath = artifactPath(manifestPath, provingKey);
  const witnessWasmPath = artifactPath(manifestPath, witnessWasm);

  await ensureArtifact({
    role: "proving_key",
    path: provingKeyPath,
    expectedHash: provingKey.sha256,
    downloadUrl:
      process.env.ZKP_GROTH16_TALLY_PROVING_KEY_URL ||
      DEFAULT_DOWNLOAD_URLS.proving_key,
  });
  await ensureArtifact({
    role: "witness_wasm",
    path: witnessWasmPath,
    expectedHash: witnessWasm.sha256,
    downloadUrl:
      process.env.ZKP_GROTH16_TALLY_WASM_URL ||
      DEFAULT_DOWNLOAD_URLS.witness_wasm,
  });

  const witnessDir = dirname(witnessWasmPath);
  for (const fileName of REQUIRED_WITNESS_SUPPORT_FILES) {
    const path = resolve(witnessDir, fileName);
    if (!existsSync(path)) {
      throw new Error(
        `Missing tally witness support file: ${path}. This file is small and should be committed with the backend source.`,
      );
    }
  }

  console.log("[zkp-artifacts] tally prover artifacts are ready");
};

main().catch((error) => {
  console.error(
    "[zkp-artifacts] failed:",
    error instanceof Error ? error.message : error,
  );
  process.exit(1);
});
