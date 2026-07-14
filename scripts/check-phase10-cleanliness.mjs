#!/usr/bin/env node

import { createClient } from "@supabase/supabase-js";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(backendRoot, "../iland");

const TRUE_VALUES = new Set(["1", "true", "yes"]);

const args = new Set(process.argv.slice(2));
const expectEmptyOperationalDb =
  args.has("--expect-empty-operational") ||
  TRUE_VALUES.has(
    String(process.env.CIVICOS_PHASE10_EXPECT_EMPTY_OPERATIONAL_DB ?? "")
      .trim()
      .toLowerCase(),
  );

const loadDotEnvFile = (filePath) => {
  if (!existsSync(filePath)) {
    return;
  }

  const text = readFileSync(filePath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) {
      continue;
    }

    const [, key, rawValue] = match;
    if (process.env[key] !== undefined) {
      continue;
    }

    let value = rawValue.trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
};

loadDotEnvFile(resolve(backendRoot, ".env"));

const blockers = [];
const warnings = [];
const checks = [];

const record = (ok, label, details = undefined) => {
  checks.push({ ok, label, ...(details === undefined ? {} : { details }) });
  if (!ok) {
    blockers.push(label);
  }
};

const warn = (label, details = undefined) => {
  warnings.push(label);
  checks.push({
    ok: true,
    warning: true,
    label,
    ...(details === undefined ? {} : { details }),
  });
};

const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

record(
  typeof supabaseUrl === "string" && supabaseUrl.startsWith("https://"),
  "SUPABASE_URL is configured",
);
record(
  typeof serviceRoleKey === "string" && serviceRoleKey.length > 20,
  "SUPABASE_SERVICE_ROLE_KEY is configured",
);

const countRows = async (supabase, spec) => {
  let query = supabase
    .from(spec.table)
    .select(spec.selectColumn ?? "id", { count: "exact", head: true });

  for (const filter of spec.filters ?? []) {
    switch (filter.op) {
      case "eq":
        query = query.eq(filter.column, filter.value);
        break;
      case "neq":
        query = query.neq(filter.column, filter.value);
        break;
      case "like":
        query = query.like(filter.column, filter.value);
        break;
      case "in":
        query = query.in(filter.column, filter.value);
        break;
      case "is":
        query = query.is(filter.column, filter.value);
        break;
      case "not.is":
        query = query.not(filter.column, "is", filter.value);
        break;
      default:
        throw new Error(`Unsupported filter op: ${filter.op}`);
    }
  }

  const { count, error } = await query;
  if (error) {
    throw new Error(`${spec.table}: ${error.message}`);
  }

  return count ?? 0;
};

const forbiddenMarkers = Object.freeze([
  {
    label: "synthetic ZKP seed users by username",
    table: "users",
    filters: [{ op: "like", column: "username", value: "zkp-seed-%" }],
  },
  {
    label: "synthetic ZKP seed users by display name",
    table: "users",
    filters: [
      { op: "eq", column: "display_name", value: "CivicOS ZKP seed voter" },
    ],
  },
  {
    label: "synthetic ZKP seed verified identities",
    table: "verified_identities",
    filters: [
      { op: "eq", column: "verification_method", value: "civicos_zkp_seed" },
    ],
  },
  {
    label: "mock identity profiles",
    table: "identity_profiles",
    filters: [{ op: "eq", column: "home_location_source", value: "mock" }],
  },
  {
    label: "synthetic ZKP seed credential registry rows",
    table: "credential_registry",
    filters: [
      {
        op: "eq",
        column: "credential_issuer_id",
        value: "did:iland:backend:zkp-seed-v1",
      },
    ],
  },
  {
    label: "legacy or pre-prover polls",
    table: "polls",
    filters: [
      {
        op: "in",
        column: "vote_privacy_mode",
        value: ["legacy_identity_linked", "zk_preprover_audit"],
      },
    ],
  },
  {
    label: "polls missing frozen policy hash",
    table: "polls",
    filters: [{ op: "is", column: "poll_policy_hash", value: null }],
  },
  {
    label: "legacy identity-linked vote rows",
    table: "votes",
  },
]);

const operationalTables = Object.freeze([
  ["users", "id"],
  ["identity_profiles", "id"],
  ["verified_identities", "id"],
  ["wallet_credentials", "id"],
  ["auth_credentials", "id"],
  ["app_attestation_credentials", "id"],
  ["auth_sessions", "id"],
  ["refresh_token_families", "id"],
  ["auth_challenges", "id"],
  ["auth_audit_events", "id"],
  ["polls", "id"],
  ["poll_options", "id"],
  ["votes", "id"],
  ["poll_zk_votes", "id"],
  ["poll_tally_proofs", "id"],
  ["poll_roots", "id"],
  ["poll_audit_events", "id"],
  ["poll_encryption_keys", "id"],
  ["poll_map_marker_cache", "poll_id"],
  ["poll_map_refresh_queue", "poll_id"],
  ["credential_registry", "id"],
  ["credential_roots", "id"],
  ["oidc_access_tokens", "id"],
  ["oidc_authorize_qr_transactions", "id"],
  ["oidc_authorization_requests", "id"],
  ["oidc_authorization_codes", "id"],
  ["oidc_grants", "id"],
  ["oidc_pairwise_subjects", "id"],
  ["oidc_refresh_token_families", "id"],
  ["oidc_audit_events", "id"],
  ["backend_audit_events", "id"],
]);

const readEnvAssignments = (filePath) => {
  if (!existsSync(filePath)) {
    return new Map();
  }

  const entries = new Map();
  const text = readFileSync(filePath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) {
      continue;
    }

    let value = match[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    entries.set(match[1], value);
  }

  return entries;
};

const isTruthyEnv = (entries, key) =>
  TRUE_VALUES.has(String(entries.get(key) ?? "").trim().toLowerCase());

const appEnv = readEnvAssignments(resolve(appRoot, ".env"));
for (const key of [
  "EXPO_PUBLIC_ENABLE_IDENTITY_DEBUG_PANEL",
  "EXPO_PUBLIC_ENABLE_IDENTITY_MOCK_TOOLS",
  "EXPO_PUBLIC_ENABLE_LEGACY_MOCK_VIEWER_FALLBACK",
  "EXPO_PUBLIC_ENABLE_DEV_LEGACY_VOTE_FALLBACK",
]) {
  record(!isTruthyEnv(appEnv, key), `public app .env does not enable ${key}`);
}

const appLocalEnv = readEnvAssignments(resolve(appRoot, ".env.local"));
for (const key of [
  "EXPO_PUBLIC_ENABLE_IDENTITY_DEBUG_PANEL",
  "EXPO_PUBLIC_ENABLE_IDENTITY_MOCK_TOOLS",
  "EXPO_PUBLIC_ENABLE_LEGACY_MOCK_VIEWER_FALLBACK",
  "EXPO_PUBLIC_ENABLE_DEV_LEGACY_VOTE_FALLBACK",
]) {
  if (isTruthyEnv(appLocalEnv, key)) {
    warn(`local app .env.local enables ${key}; keep it out of release builds`);
  }
}

if (supabaseUrl && serviceRoleKey) {
  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { "X-Client-Info": "iland-phase10-cleanliness" } },
  });

  const markerCounts = {};
  for (const marker of forbiddenMarkers) {
    try {
      const count = await countRows(supabase, marker);
      markerCounts[marker.label] = count;
      record(
        count === 0,
        `no ${marker.label}`,
        count === 0 ? undefined : { count },
      );
    } catch (error) {
      record(false, `count query failed for ${marker.label}`, {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const operationalCounts = {};
  for (const [table, selectColumn] of operationalTables) {
    try {
      operationalCounts[table] = await countRows(supabase, {
        table,
        selectColumn,
      });
    } catch (error) {
      record(false, `count query failed for table ${table}`, {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const nonEmptyOperationalTables = Object.entries(operationalCounts)
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => a.localeCompare(b));

  if (expectEmptyOperationalDb) {
    for (const [table, count] of nonEmptyOperationalTables) {
      record(false, `operational table is empty: ${table}`, { count });
    }
  } else if (nonEmptyOperationalTables.length > 0) {
    warn(
      "operational DB is not empty; pass --expect-empty-operational for the public-launch cleanup gate",
      Object.fromEntries(nonEmptyOperationalTables),
    );
  }
}

const report = {
  status: blockers.length === 0 ? "clean" : "blocked",
  mode: expectEmptyOperationalDb
    ? "public_launch_empty_operational_db"
    : "forbidden_debug_marker_scan",
  destructive: false,
  checkedAt: new Date().toISOString(),
  checks,
  warnings,
  blockers,
};

console.log(JSON.stringify(report, null, 2));
process.exit(blockers.length === 0 ? 0 : 1);
